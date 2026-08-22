package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Window is a recurring weekly maintenance window.
//
// It is a parsed value rather than a string compared at evaluation time because the comparison happens
// inside a root helper, on every privileged job, and string parsing in that position is both a
// needless cost and a needless place for a mistake. Parsing at load also means a malformed window is
// an error an administrator sees when the file is read, rather than a silent refusal at 03:00 on the
// one night it mattered.
//
// A window whose end is at or before its start crosses midnight: "Sat 22:00-02:00" runs from Saturday
// evening into Sunday morning. That reading is the one operators expect, and rejecting it would push
// people to write two windows that do not quite meet.
type Window struct {
	// always reports that no window was configured, so every time is inside it.
	always bool

	// days is the set of weekdays on which the window opens.
	days [7]bool

	// startMinutes is minutes past midnight at which the window opens.
	startMinutes int

	// lengthMinutes is how long the window stays open, always positive.
	lengthMinutes int

	// loc is the zone the window is expressed in.
	loc *time.Location

	// text is the original specification, for display.
	text string
}

// weekdayNames maps the accepted spellings of a weekday to Go's time.Weekday.
//
// Both the three-letter and the full form are accepted because a policy file is written by hand and
// being strict about which of the two obvious spellings is correct buys nothing.
var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "sunday": time.Sunday,
	"mon": time.Monday, "monday": time.Monday,
	"tue": time.Tuesday, "tuesday": time.Tuesday,
	"wed": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thursday": time.Thursday,
	"fri": time.Friday, "friday": time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}

// ParseWindow parses a maintenance window specification such as "Sun 03:00-05:00".
//
// The accepted forms are a day specification followed by a time range, or a bare time range meaning
// every day. The day specification may be a list, a range, or one of the keywords daily, any and *.
// An empty string means no window, which is to say always open.
func ParseWindow(spec string, loc *time.Location) (Window, error) {
	if loc == nil {
		loc = time.UTC
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Window{always: true, loc: loc, text: ""}, nil
	}

	fields := strings.Fields(spec)
	var dayspec, timespec string
	switch len(fields) {
	case 1:
		dayspec, timespec = "daily", fields[0]
	case 2:
		dayspec, timespec = fields[0], fields[1]
	default:
		return Window{}, fmt.Errorf("expected \"<days> HH:MM-HH:MM\" or \"HH:MM-HH:MM\", got %q", spec)
	}

	days, err := parseDays(dayspec)
	if err != nil {
		return Window{}, err
	}
	start, end, err := parseTimeRange(timespec)
	if err != nil {
		return Window{}, err
	}

	length := end - start
	if length <= 0 {
		length += 24 * 60
	}
	return Window{
		days:          days,
		startMinutes:  start,
		lengthMinutes: length,
		loc:           loc,
		text:          spec,
	}, nil
}

// parseDays parses the day half of a window specification into a weekday set.
func parseDays(spec string) ([7]bool, error) {
	var days [7]bool
	lower := strings.ToLower(strings.TrimSpace(spec))
	if lower == "daily" || lower == "any" || lower == "*" || lower == "everyday" {
		for i := range days {
			days[i] = true
		}
		return days, nil
	}
	for _, part := range strings.Split(lower, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		from, to, isRange := strings.Cut(part, "-")
		start, ok := weekdayNames[strings.TrimSpace(from)]
		if !ok {
			return days, fmt.Errorf("%q is not a weekday", from)
		}
		if !isRange {
			days[start] = true
			continue
		}
		end, ok := weekdayNames[strings.TrimSpace(to)]
		if !ok {
			return days, fmt.Errorf("%q is not a weekday", to)
		}
		// Walk forwards from start, wrapping, so that "Fri-Mon" means Friday through Monday rather
		// than being rejected. Wrapping ranges are what people write for weekend windows.
		for d := start; ; d = (d + 1) % 7 {
			days[d] = true
			if d == end {
				break
			}
		}
	}
	for _, set := range days {
		if set {
			return days, nil
		}
	}
	return days, fmt.Errorf("%q selects no days", spec)
}

// parseTimeRange parses "HH:MM-HH:MM" into minutes past midnight.
func parseTimeRange(spec string) (start, end int, err error) {
	from, to, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, fmt.Errorf("%q is not a time range of the form HH:MM-HH:MM", spec)
	}
	start, err = parseClock(from)
	if err != nil {
		return 0, 0, err
	}
	end, err = parseClock(to)
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

// parseClock parses "HH:MM" into minutes past midnight.
//
// It rejects 24:00 even though some tools accept it as end-of-day, because this package already has a
// well-defined meaning for a window whose end is not after its start, and having two spellings of the
// same thing is how the two spellings end up disagreeing.
func parseClock(s string) (int, error) {
	s = strings.TrimSpace(s)
	hh, mm, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("%q is not a time of the form HH:MM", s)
	}
	h, err := strconv.Atoi(hh)
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("%q has an hour outside 00-23", s)
	}
	m, err := strconv.Atoi(mm)
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("%q has a minute outside 00-59", s)
	}
	return h*60 + m, nil
}

// Always reports whether the window is open at all times.
func (w Window) Always() bool { return w.always }

// String returns the original specification, or "always" when none was configured.
func (w Window) String() string {
	if w.always || w.text == "" {
		return "always"
	}
	return w.text
}

// Contains reports whether an instant falls inside the window.
//
// Yesterday's window instance is checked as well as today's, which is what makes a window crossing
// midnight work: at 00:30 on Sunday the open window is Saturday's. Building the instances with
// time.Date rather than by adding a duration means daylight-saving transitions move the window with
// the wall clock, which is what an operator writing "03:00" meant.
func (w Window) Contains(t time.Time) bool {
	if w.always {
		return true
	}
	loc := w.loc
	if loc == nil {
		loc = time.UTC
	}
	local := t.In(loc)
	length := time.Duration(w.lengthMinutes) * time.Minute

	for _, dayOffset := range []int{0, -1} {
		day := local.AddDate(0, 0, dayOffset)
		if !w.days[day.Weekday()] {
			continue
		}
		start := time.Date(day.Year(), day.Month(), day.Day(),
			w.startMinutes/60, w.startMinutes%60, 0, 0, loc)
		if !local.Before(start) && local.Before(start.Add(length)) {
			return true
		}
	}
	return false
}

// NextOpen returns the next instant at which the window opens, at or after the given time.
//
// It exists for the control plane, which shows an operator when a job they are about to sign would
// actually be able to run. Telling somebody "queued" without telling them "until Sunday at 03:00" is
// how a signed job with a thirty-minute validity expires unnoticed.
func (w Window) NextOpen(after time.Time) time.Time {
	if w.always {
		return after
	}
	loc := w.loc
	if loc == nil {
		loc = time.UTC
	}
	local := after.In(loc)
	if w.Contains(after) {
		return after
	}
	for dayOffset := range 8 {
		day := local.AddDate(0, 0, dayOffset)
		if !w.days[day.Weekday()] {
			continue
		}
		start := time.Date(day.Year(), day.Month(), day.Day(),
			w.startMinutes/60, w.startMinutes%60, 0, 0, loc)
		if !start.Before(local) {
			return start
		}
	}
	return time.Time{}
}
