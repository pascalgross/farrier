package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMinNeverReturnsMoreThanEitherInput asserts the clamping rule that the guarantee rests on.
//
// docs/SECURITY.md §2.2 says effective permission is min(central request, local policy), never the
// max. Every privileged path goes through this one function, so a table over every ordered pair —
// including the invalid values a hand-edited file can produce — is cheap insurance against the day
// somebody "simplifies" the comparison.
func TestMinNeverReturnsMoreThanEitherInput(t *testing.T) {
	levels := []Allow{AllowNone, AllowSecurity, AllowAll, "", "ALL", "everything"}
	for _, a := range levels {
		for _, b := range levels {
			got := Min(a, b)
			if !got.Valid() {
				t.Errorf("Min(%q, %q) = %q, which is not a valid level", a, b, got)
				continue
			}
			if a.Valid() && got.rank() > a.rank() {
				t.Errorf("Min(%q, %q) = %q, which exceeds the first input", a, b, got)
			}
			if b.Valid() && got.rank() > b.rank() {
				t.Errorf("Min(%q, %q) = %q, which exceeds the second input", a, b, got)
			}
			if (!a.Valid() || !b.Valid()) && got != AllowNone {
				t.Errorf("Min(%q, %q) = %q; an unrecognised level must clamp to none", a, b, got)
			}
		}
	}
}

// TestParseRejectsUnknownKeys asserts a typo in the policy file is an error rather than a no-op.
//
// A policy file is edited by hand under time pressure. "allow_updates = all" silently doing nothing
// while the operator believes it took effect is worse than a load error, which is at least visible in
// the journal before anything depends on it.
func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("[updates]\nallow = \"all\"\nallow_updates = \"all\"\n"))
	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(err.Error(), "allow_updates") {
		t.Errorf("error %q does not name the offending key", err)
	}
}

// TestParseRejectsInvalidValues covers every field whose value set is closed.
//
// Each of these produces a Closed policy rather than a partially applied one, which is the behaviour
// that matters: a file with one bad line must not leave the host running on the good half of it.
func TestParseRejectsInvalidValues(t *testing.T) {
	cases := map[string]string{
		"bad allow":     "[updates]\nallow = \"everything\"\n",
		"bad reboot":    "[updates]\nreboot = \"always\"\n",
		"bad timezone":  "[updates]\ntimezone = \"Mars/Olympus\"\n",
		"bad window":    "[updates]\nwindow = \"Sun 25:00-05:00\"\n",
		"bad day":       "[updates]\nwindow = \"Funday 03:00-05:00\"\n",
		"zero job age":  "[limits]\nmax_job_age_seconds = 0\n",
		"negative age":  "[limits]\nmax_job_age_seconds = -1\n",
		"bad toml":      "[updates\nallow = \"all\"\n",
		"bad glob":      "[services]\nrestartable = [\"[\"]\n",
		"wrong type":    "[updates]\nauto_apply = \"yes\"\n",
		"window fields": "[updates]\nwindow = \"Sun 03:00 05:00 07:00\"\n",
		// "window" with no window would mean "reboot at any time", because an empty window is always
		// open. That is not what anybody writing it meant, and there is deliberately no
		// `reboot = "always"` — so the only way to say it is to say it in the window.
		"reboot window with no window": "[updates]\nreboot = \"window\"\n",
	}
	for name, body := range cases {
		p, err := Parse([]byte(body))
		if err == nil {
			t.Errorf("%s: accepted %q", name, body)
			continue
		}
		if p.Updates.Allow != AllowNone {
			t.Errorf("%s: a rejected policy did not fail closed: allow = %q", name, p.Updates.Allow)
		}
	}
}

// TestParseAcceptsTheShippedDefaultFile asserts the packaged policy.toml is valid.
//
// Packaging is where greenfield agent projects lose weeks, and shipping a default config that the
// parser rejects is the most embarrassing available way to do it. This reads the real file rather than
// a copy so the two cannot drift.
func TestParseAcceptsTheShippedDefaultFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "policy.toml"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("packaging/policy.toml is not present in this tree")
	}
	if err != nil {
		t.Fatalf("reading the shipped policy: %v", err)
	}
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("the shipped packaging/policy.toml does not parse: %v", err)
	}
	if p.Updates.Reboot != RebootNever {
		t.Errorf("the shipped default permits reboots (%q); a fresh install should not", p.Updates.Reboot)
	}
	if len(p.Services.Restartable) != 0 {
		t.Errorf("the shipped default lists restartable units %v; a fresh install should list none",
			p.Services.Restartable)
	}
}

// TestLoadFromMissingFileReturnsTheBuiltInDefault covers the unconfigured host.
//
// A missing file and an unparseable file mean opposite things and must not be conflated: the first is
// a host nobody has configured, which takes the conservative default; the second is a host whose
// administrator meant something the agent could not read.
func TestLoadFromMissingFileReturnsTheBuiltInDefault(t *testing.T) {
	p, err := LoadFrom(filepath.Join(t.TempDir(), "absent.toml"))
	if !errors.Is(err, ErrNoPolicyFile) {
		t.Fatalf("error %v does not wrap ErrNoPolicyFile", err)
	}
	if p.Updates.Allow != AllowSecurity || !p.Updates.AutoApply {
		t.Errorf("a missing file did not yield the built-in default: %+v", p.Updates)
	}
}

// TestLoadFromUnparseableFileFailsClosed covers the misconfigured host.
func TestLoadFromUnparseableFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte("this is not toml at all ][\n"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	p, err := LoadFrom(path)
	if err == nil {
		t.Fatal("an unparseable policy file was accepted")
	}
	if p.Updates.Allow != AllowNone || p.Updates.Reboot != RebootNever {
		t.Errorf("an unparseable policy file did not fail closed: %+v", p.Updates)
	}
}

// TestRestartableAllowsMatchesGlobs covers the unit allowlist.
//
// The empty-list case is the important one: the shipped default permits no service operations at all,
// and a matcher that treated an empty list as "everything" would quietly invert that.
func TestRestartableAllowsMatchesGlobs(t *testing.T) {
	p := Default()
	if p.RestartableAllows("nginx.service") {
		t.Error("the default policy permits restarting nginx.service; the list should be empty")
	}

	p.Services.Restartable = []string{"nginx.service", "farrier-*.service"}
	for _, unit := range []string{"nginx.service", "farrier-agent.service", "farrier-x.service"} {
		if !p.RestartableAllows(unit) {
			t.Errorf("%q should be permitted", unit)
		}
	}
	for _, unit := range []string{"sshd.service", "nginx.socket", "farrier-agent.timer", "nginx"} {
		if p.RestartableAllows(unit) {
			t.Errorf("%q should not be permitted", unit)
		}
	}
}

// TestPausedAtDetectsTheMarker asserts the kill switch is observed from the filesystem each time.
//
// The marker's whole value is that creating it takes effect immediately and without the agent's
// cooperation, so a cached answer would defeat it.
func TestPausedAtDetectsTheMarker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "paused")
	if pausedAt(marker) {
		t.Fatal("reported paused with no marker present")
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatalf("writing marker: %v", err)
	}
	if !pausedAt(marker) {
		t.Error("did not report paused with the marker present")
	}
}

// mustParseWindow parses a window in a named zone or fails the test.
//
// It exists because the window tests are dense tables and an inline error check at every row would
// bury the thing each row is actually asserting.
func mustParseWindow(t *testing.T, spec, zone string) Window {
	t.Helper()
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Fatalf("loading zone %q: %v", zone, err)
	}
	w, err := ParseWindow(spec, loc)
	if err != nil {
		t.Fatalf("parsing window %q: %v", spec, err)
	}
	return w
}

// TestWindowContains covers the shapes an operator actually writes.
//
// The midnight-crossing rows are the reason this is a table rather than one assertion: "Sat
// 22:00-02:00" is what somebody means by a weekend window, and an implementation that rejected it or
// silently treated it as a four-minute window would pass every test written about the simple case.
func TestWindowContains(t *testing.T) {
	cases := []struct {
		name   string
		spec   string
		zone   string
		at     string
		inside bool
	}{
		{"empty means always", "", "UTC", "2026-08-22T13:00:00Z", true},
		{"inside simple window", "Sun 03:00-05:00", "UTC", "2026-08-23T03:30:00Z", true},
		{"at the open edge", "Sun 03:00-05:00", "UTC", "2026-08-23T03:00:00Z", true},
		{"at the close edge is out", "Sun 03:00-05:00", "UTC", "2026-08-23T05:00:00Z", false},
		{"wrong day", "Sun 03:00-05:00", "UTC", "2026-08-24T03:30:00Z", false},
		{"before opening", "Sun 03:00-05:00", "UTC", "2026-08-23T02:59:00Z", false},
		{"weekday range inside", "Mon-Fri 02:00-04:00", "UTC", "2026-08-19T03:00:00Z", true},
		{"weekday range outside", "Mon-Fri 02:00-04:00", "UTC", "2026-08-23T03:00:00Z", false},
		{"wrapping range", "Fri-Mon 01:00-02:00", "UTC", "2026-08-23T01:30:00Z", true},
		{"list of days", "Sat,Sun 00:00-06:00", "UTC", "2026-08-22T05:00:00Z", true},
		{"daily keyword", "daily 01:00-02:00", "UTC", "2026-08-20T01:30:00Z", true},
		{"bare time range is daily", "01:00-02:00", "UTC", "2026-08-20T01:30:00Z", true},
		{"crossing midnight, before", "Sat 22:00-02:00", "UTC", "2026-08-22T23:00:00Z", true},
		{"crossing midnight, after", "Sat 22:00-02:00", "UTC", "2026-08-23T01:00:00Z", true},
		{"crossing midnight, past end", "Sat 22:00-02:00", "UTC", "2026-08-23T02:30:00Z", false},
		{"zone shifts the window", "Sun 03:00-05:00", "Europe/Berlin", "2026-08-23T01:30:00Z", true},
		{"zone shifts it out", "Sun 03:00-05:00", "Europe/Berlin", "2026-08-23T03:30:00Z", false},
	}
	for _, tc := range cases {
		at, err := time.Parse(time.RFC3339, tc.at)
		if err != nil {
			t.Fatalf("%s: parsing instant: %v", tc.name, err)
		}
		w := mustParseWindow(t, tc.spec, tc.zone)
		if got := w.Contains(at); got != tc.inside {
			t.Errorf("%s: window %q (%s).Contains(%s) = %v, want %v",
				tc.name, tc.spec, tc.zone, tc.at, got, tc.inside)
		}
	}
}

// TestWindowNextOpen asserts the control plane can tell an operator when a job would run.
//
// Telling somebody "queued" without telling them "until Sunday at 03:00" is how a signed job with a
// thirty-minute validity expires unnoticed.
func TestWindowNextOpen(t *testing.T) {
	w := mustParseWindow(t, "Sun 03:00-05:00", "UTC")

	// Saturday afternoon: the next opening is the following morning.
	from := time.Date(2026, 8, 22, 14, 0, 0, 0, time.UTC)
	want := time.Date(2026, 8, 23, 3, 0, 0, 0, time.UTC)
	if got := w.NextOpen(from); !got.Equal(want) {
		t.Errorf("NextOpen(%s) = %s, want %s", from, got, want)
	}

	// Inside the window, the next opening is now.
	inside := time.Date(2026, 8, 23, 4, 0, 0, 0, time.UTC)
	if got := w.NextOpen(inside); !got.Equal(inside) {
		t.Errorf("NextOpen inside the window = %s, want %s", got, inside)
	}

	// An always-open window is always open.
	always := mustParseWindow(t, "", "UTC")
	if got := always.NextOpen(from); !got.Equal(from) {
		t.Errorf("an empty window did not report itself always open: %s", got)
	}
}

// TestParseWindowRejectsNonsense covers the inputs a bad edit produces.
func TestParseWindowRejectsNonsense(t *testing.T) {
	for _, spec := range []string{
		"Sun", "03:00", "Sun 03:00", "Sun 03:00-", "Sun -05:00", "Sun 3-5",
		"Sun 24:00-25:00", "Sun 03:60-05:00", "Nonday 03:00-05:00", "Sun 03:00 - 05:00",
		",, 03:00-05:00", "Sun 03:00-05:00 extra",
	} {
		if _, err := ParseWindow(spec, time.UTC); err == nil {
			t.Errorf("window %q was accepted", spec)
		}
	}
}

// TestWindowBehaviourAcrossDaylightSavingTransitions pins what happens on the two awkward days.
//
// It is not asserting that the behaviour is ideal — it is asserting what the behaviour *is*, so that a
// future change to the window arithmetic is a deliberate act with a failing test rather than a
// discovery somebody makes at 03:00 on the one night it mattered. The reasoning for leaving it as it
// stands is in Contains's doc comment.
func TestWindowBehaviourAcrossDaylightSavingTransitions(t *testing.T) {
	// A window that spans the transition, which is the only interesting case. Europe/Berlin moves at
	// 02:00 CET -> 03:00 CEST in spring and 03:00 CEST -> 02:00 CET in autumn.
	w := mustParseWindow(t, "Sun 02:00-04:00", "Europe/Berlin")

	cases := []struct {
		name   string
		at     string
		inside bool
	}{
		// Spring forward, 2026-03-29. 02:00 local does not exist, so the window opens at 03:00 CEST
		// and runs its full two hours, closing at 05:00 CEST.
		{"before the window, spring", "2026-03-29T00:30:00Z", false},  // 01:30 CET
		{"inside the shifted window", "2026-03-29T01:30:00Z", true},   // 03:30 CEST
		{"still inside, an hour later", "2026-03-29T02:30:00Z", true}, // 04:30 CEST
		{"after the shifted window", "2026-03-29T03:30:00Z", false},   // 05:30 CEST

		// Autumn back, 2026-10-25. 02:00 local happens twice; the second is used, so the first,
		// repeated 02:30 is outside the window and the second is inside.
		{"first repeated hour, outside", "2026-10-25T00:30:00Z", false}, // 02:30 CEST
		{"second repeated hour, inside", "2026-10-25T01:30:00Z", true},  // 02:30 CET
		{"inside, after the repeat", "2026-10-25T02:30:00Z", true},      // 03:30 CET
		{"after the window closes", "2026-10-25T03:30:00Z", false},      // 04:30 CET
	}

	for _, tc := range cases {
		at, err := time.Parse(time.RFC3339, tc.at)
		if err != nil {
			t.Fatalf("%s: parsing the instant: %v", tc.name, err)
		}
		if got := w.Contains(at); got != tc.inside {
			t.Errorf("%s (%s): Contains = %v, want %v", tc.name, tc.at, got, tc.inside)
		}
	}

	// A window that does not span the local transition is unaffected on both days, which is the
	// configuration to recommend and the one docs/SECURITY.md and packaging/policy.toml show.
	safe := mustParseWindow(t, "Sun 03:00-05:00", "Europe/Berlin")
	for _, at := range []string{"2026-03-29T02:00:00Z", "2026-10-25T02:00:00Z"} {
		instant, err := time.Parse(time.RFC3339, at)
		if err != nil {
			t.Fatalf("parsing %s: %v", at, err)
		}
		if !safe.Contains(instant) {
			t.Errorf("a window clear of the transition was closed at %s (%s local)",
				at, instant.In(time.UTC).Format("15:04"))
		}
	}
}

// TestTheBuiltInPoliciesAreSelfConsistent asserts Default and Closed agree with themselves.
//
// Both are hand-assembled and then validated, because a hand-assembled Policy leaves the derived window
// as the zero value — which reports itself closed at every instant while Updates.Window beside it says
// "always". The two disagreeing would be a policy whose behaviour did not match its own display, on
// exactly the hosts nobody has configured.
func TestTheBuiltInPoliciesAreSelfConsistent(t *testing.T) {
	for name, p := range map[string]Policy{"default": Default(), "closed": Closed()} {
		if p.Updates.Window == "" && !p.Window().Always() {
			t.Errorf("the %s policy carries an empty window string but a window that is never open", name)
		}
		if p.Updates.Window == "" && !p.Window().Contains(time.Now()) {
			t.Errorf("the %s policy's window is closed right now despite being unset", name)
		}
		if !p.Updates.Allow.Valid() || !p.Updates.Reboot.Valid() {
			t.Errorf("the %s policy has invalid values: %+v", name, p.Updates)
		}
		if p.Updates.Reboot != RebootNever {
			t.Errorf("the %s policy permits reboots; neither should", name)
		}
	}
}
