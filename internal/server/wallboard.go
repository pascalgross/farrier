package server

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/store"
)

// WallboardPollSeconds is how often a screen should come back for a new summary.
//
// The server sets the pacing rather than the client, for the reason docs/PROTOCOL.md §4.3 gives for the
// heartbeat interval: a number baked into a client is a number that is wrong the moment somebody
// changes it, and a wallboard is the client least likely to be rebuilt. Fifteen seconds is under the
// default heartbeat of sixty, so the screen never lags the data it is showing by more than one beat,
// and far enough above it that a wall of screens is not a load problem.
const WallboardPollSeconds = 15

// MaxWallboardAttention is how many hosts the summary names.
//
// This is what makes the page fit one screen, and it is deliberately a server-side cap rather than a
// stylesheet's `overflow: hidden`. Hiding bounds what is visible while the content grows behind it, and
// what disappears behind that fold is the thirteenth failing host — the thing the screen exists to
// surface, hidden by the mechanism meant to make it readable. A cap plus a count of what did not fit
// turns "hidden" into "counted": the numbers above the grid stay exact, and the page says out loud how
// many examples it is not showing.
//
// Twelve because that is what still lands as a legible grid on a 16:9 panel at three metres — six by
// two — and as one column on a phone without the last tile falling below the fold.
const MaxWallboardAttention = 12

// maxWallboardDetail bounds the sentence beside a named host.
//
// Composed on the server, so two screens showing one fleet say the same words and no client has to know
// Host.Online's grace window or the clock-skew threshold — the same argument hostView.ClockSkewed
// already makes. Bounded because it is rendered at a size chosen for three metres, and a sentence that
// wraps to three lines is a tile that pushes another one off the screen.
const maxWallboardDetail = 60

// The reasons a host is on the attention list, in the order they are chosen.
//
// A closed vocabulary, like the intents and the event kinds, and for the same reason: it is a word a
// screen renders, an operator learns and a translation would key on. The order is fixed and stated here
// rather than emerging from the order of a chain of ifs, because two screens showing one fleet must put
// the same host at the top, and a list that reshuffles between polls is a list nobody can read.
const (
	// reasonOffline is a host that has been heard from, but not recently enough.
	reasonOffline = "offline"

	// reasonUnitFailed is a host reporting at least one failed systemd unit.
	reasonUnitFailed = "unit_failed"

	// reasonClockSkewed is a host whose clock is far enough out to refuse privileged intents.
	reasonClockSkewed = "clock_skewed"

	// reasonNeverSeen is an enrolled host that has never reported at all.
	reasonNeverSeen = "never_seen"

	// reasonPaused is a host carrying /etc/farrier/paused.
	reasonPaused = "paused"

	// reasonFactsUnknown is a host whose last report cannot answer the questions this screen asks.
	reasonFactsUnknown = "facts_unknown"
)

// The three values a host's health takes.
//
// Three rather than two, which is the whole discipline of this file. "Unknown" is already the house
// answer in five places — FactsUnknown, ServicesTruncated, RebootReport.Conclusive,
// ContainerReport.ScanComplete and Subscription.Applicable — and this is the screen where collapsing it
// into "healthy" is most expensive, because the collapse is invisible and the screen is trusted.
const (
	// statusOK is a host that is reporting and has nothing wrong with it.
	statusOK = "ok"

	// statusBad is a host that is definitely wrong.
	statusBad = "bad"

	// statusUnknown is a host this control plane cannot answer for.
	statusUnknown = "unknown"
)

// wallboardView is the whole of what a status screen is told, on either route.
//
// It is a projection built field by field rather than a filtered hostView, and that is a security
// property rather than a style. hostView carries the facts document verbatim, so whatever a future
// collector adds would arrive on a public page without anybody deciding; a projection cannot do that,
// because a new field has to be written here to appear at all.
type wallboardView struct {
	// ServerTime is this control plane's clock at the moment the summary was built.
	//
	// Every age on the screen that concerns the fleet is measured against it rather than against the
	// browser's clock, exactly as the fleet list does. The age of the *summary itself* is the one thing
	// that cannot be: see the page, which measures that on its own clock because this value freezes
	// with the data it arrived in.
	ServerTime time.Time `json:"serverTime"`

	// PollSeconds is how long the screen should wait before asking again.
	PollSeconds int `json:"pollSeconds"`

	// Title is the heading a published screen shows, and is empty on an operator's own board.
	//
	// Empty rather than the fleet's name, because the shell above an operator's board already names the
	// fleet this credential reaches and a second copy of it would be a heading repeating the toolbar.
	// A television has no shell, so its heading is the share's label — which is also the only field on
	// this payload that differs between the two routes.
	Title string `json:"title"`

	// Hosts is the fleet split three ways. ok + bad + unknown == total, always.
	Hosts wallboardCounts `json:"hosts"`

	// Security is the security backlog, and how much of the fleet could not be asked.
	Security wallboardMeasure `json:"security"`

	// Reboots is how many hosts are waiting for one, and how many cannot say.
	Reboots wallboardMeasure `json:"reboots"`

	// Units is how many hosts have a failed unit, and how many cannot say.
	Units wallboardMeasure `json:"units"`

	// Attention names the worst hosts, at most MaxWallboardAttention of them.
	Attention []wallboardEntry `json:"attention"`

	// AttentionOmitted is how many bad-or-unknown hosts did not fit.
	//
	// The counters above are exact whatever this is, which is what makes the cap honest: the grid shows
	// examples and the numbers show the truth.
	AttentionOmitted int `json:"attentionOmitted"`
}

// wallboardCounts is the fleet split into the three health values.
type wallboardCounts struct {
	// Total is every host in the fleet, revoked ones excluded.
	Total int `json:"total"`

	// OK is how many are reporting and have nothing wrong.
	OK int `json:"ok"`

	// Bad is how many are definitely wrong.
	Bad int `json:"bad"`

	// Unknown is how many this control plane cannot answer for.
	Unknown int `json:"unknown"`
}

// wallboardMeasure is one thing counted across the fleet, with the part that could not be measured.
//
// The second number is the reason this is a struct rather than an int. "Six hosts have security
// updates" is a different claim from "six of forty-two hosts have security updates and three of them
// were never asked", and only the second is true. Every counter on this screen carries its own
// unmeasured count for that reason.
type wallboardMeasure struct {
	// Hosts is how many hosts the thing holds for.
	Hosts int `json:"hosts"`

	// Packages is the total across the fleet, used only by the security measure.
	//
	// Zero and omitted elsewhere: a reboot has no quantity and a failed unit is counted per host, so a
	// second number there would be a field whose meaning a reader has to guess.
	Packages int `json:"packages,omitempty"`

	// Unknown is how many hosts could not answer this question.
	Unknown int `json:"unknown"`
}

// wallboardEntry is one named host on the attention grid.
type wallboardEntry struct {
	// Hostname is what the host calls itself, empty for a machine that has never said.
	//
	// Empty rather than falling back to the host's identifier, which was the obvious thing to write and
	// is wrong twice. It would put a control-plane identifier — the one `GET /api/v1/hosts/{id}`,
	// `POST /api/v1/hosts/{id}/revoke` and `POST /api/v1/jobs` all name — onto a page reachable without
	// an account, which docs/SECURITY.md §4.6 says never happens; and it would put it there in twenty-six
	// characters of base32, which is unreadable from three metres and therefore buys the room nothing in
	// exchange. A machine that has never reported has no name a passer-by could act on, and the honest
	// rendering of that is to say so.
	Hostname string `json:"hostname"`

	// Status is "bad" or "unknown". Never "ok" — a healthy host is not on this list.
	Status string `json:"status"`

	// Reason is one word from the closed vocabulary above.
	Reason string `json:"reason"`

	// Detail is one short sentence, composed here so that every screen says the same thing.
	Detail string `json:"detail"`
}

// hostVerdict is one host's health, before the fleet is summarised.
//
// A named type rather than three return values because the sort that picks the attention grid needs all
// of them together, and because a verdict is the thing the tests assert about.
type hostVerdict struct {
	// Status is the three-valued answer.
	Status string

	// Reason is why, empty when the status is ok.
	Reason string

	// Detail is the sentence a screen renders beside the hostname.
	Detail string
}

// wallboardReasonRank orders the attention grid.
//
// Lower sorts first. Bad before unknown, and within each the reason an operator should walk towards
// first: a host nobody can reach outranks a host with a failed unit, which outranks a host whose clock
// will make it refuse work. A map rather than a slice search because the sort calls it twice per
// comparison and the set is six long and closed.
var wallboardReasonRank = map[string]int{
	reasonOffline:      0,
	reasonUnitFailed:   1,
	reasonClockSkewed:  2,
	reasonNeverSeen:    3,
	reasonPaused:       4,
	reasonFactsUnknown: 5,
}

// judgeHost decides one host's health from what it last reported.
//
// The single definition of what this screen means by ok, bad and unknown, written once so that the
// counters and the attention grid cannot disagree — the two are computed from the same call. Three
// decisions in it are worth defending, because each is a place the third value would otherwise collapse
// into the first:
//
// A host that has never reported is *unknown*, not bad. Host.Online treats never-seen as offline while
// the alert evaluator deliberately refuses to fire `host_silent` for it, and they disagree because they
// answer different questions — "may I rely on this host's last report" and "has this host gone quiet".
// This screen asks the first, and the honest answer for a machine that was enrolled an hour ago and has
// not appeared is that nobody knows yet.
//
// A paused host is *unknown*. It reports truthfully and will act on nothing queued for it, so green is
// a lie of a specific and dangerous kind — the screen would say a machine is fine when nothing can be
// done to it — and red blames somebody for a switch they chose deliberately.
//
// A backlog is not a failure. Security updates and a pending reboot are counted, and they do not make a
// host bad. A fleet where every machine has pending updates would otherwise be a wall of red, and this
// codebase already knows what that costs: a screen most of which is tinted is a screen whose reader
// stops seeing the tint.
func (s *Server) judgeHost(h store.Host, now time.Time) hostVerdict {
	if h.LastSeen.IsZero() {
		return hostVerdict{statusUnknown, reasonNeverSeen, "enrolled, never reported"}
	}
	if !h.Online(now, s.cfg.HeartbeatSeconds) {
		return hostVerdict{statusBad, reasonOffline, "no heartbeat for " + describeSilence(now.Sub(h.LastSeen))}
	}

	probe, ok := parseFactsProbe(h.Facts)
	if failed := countFailedUnits(probe); ok && failed > 0 {
		return hostVerdict{statusBad, reasonUnitFailed, pluralUnits(failed) + " failed"}
	}
	if h.ClockOffsetSeconds > protocol.MaxClockSkewSeconds ||
		h.ClockOffsetSeconds < -protocol.MaxClockSkewSeconds {
		return hostVerdict{statusBad, reasonClockSkewed, "clock is out; privileged work will be refused"}
	}
	if h.Paused {
		return hostVerdict{statusUnknown, reasonPaused, "paused on the host; nothing will run"}
	}
	if !ok {
		return hostVerdict{statusUnknown, reasonFactsUnknown, "reporting, but has sent no inventory"}
	}
	return hostVerdict{Status: statusOK}
}

// countFailedUnits reports how many of a host's units are in the failed state.
func countFailedUnits(probe factsProbe) int {
	failed := 0
	for _, unit := range probe.Services {
		if unit.ActiveState == "failed" {
			failed++
		}
	}
	return failed
}

// pluralUnits renders a unit count with its noun, because "1 units failed" is a tell.
func pluralUnits(n int) string {
	if n == 1 {
		return "1 unit"
	}
	return fmt.Sprintf("%d units", n)
}

// describeSilence renders how long a host has been quiet, coarsely and in words.
//
// Coarse on purpose: the screen is read from three metres and the difference between fourteen and
// fifteen minutes changes nothing anybody would do. It is composed here rather than in the browser so
// that a screen showing the fleet and an operator's laptop showing the same fleet do not describe the
// same silence in two different ways.
func describeSilence(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// buildWallboard summarises one fleet into the whole of what a screen is told.
//
// One builder for both routes, called with the same fleet and differing only in the title. That is a
// property worth stating rather than an economy: if the public payload were a redaction of a richer
// one, the redaction would be a rule somebody has to remember on every future field, and the field
// somebody forgets would be the one that mattered. Here the public payload is the only payload, so
// nothing can drift into it.
//
// Revoked hosts are excluded from every number. A revoked host is a machine this control plane has
// stopped accepting, so counting it as offline would put a decommissioning on the screen as an incident
// — and the fleet list already excludes it from nothing, which is the right answer for a page somebody
// is reading and the wrong one for a page nobody is.
func (s *Server) buildWallboard(hosts []store.Host, title string, now time.Time) wallboardView {
	view := wallboardView{
		ServerTime:  now.UTC(),
		PollSeconds: WallboardPollSeconds,
		Title:       title,
		Attention:   []wallboardEntry{},
	}

	// Every bad-or-unknown host, before the cap. The cap is applied after the sort, so the twelve that
	// are shown are the twelve worst rather than the first twelve the store happened to return.
	type ranked struct {
		// entry is what the screen would render for this host.
		entry wallboardEntry

		// rank is the reason's position in the fixed order.
		rank int

		// lastSeen breaks ties, longest-silent first.
		lastSeen time.Time

		// id breaks the remaining ties, so the grid is stable between polls.
		id string
	}
	var attention []ranked

	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		view.Hosts.Total++

		verdict := s.judgeHost(h, now)
		switch verdict.Status {
		case statusOK:
			view.Hosts.OK++
		case statusBad:
			view.Hosts.Bad++
		default:
			view.Hosts.Unknown++
		}

		// The counters are told whether this host's last report can still be relied on, which is a
		// question the verdict has already answered: everything except `never_seen` and `offline`
		// means the host was heard from inside Host.Online's grace window.
		s.measureHost(&view, h, verdict.Reason != reasonOffline && verdict.Reason != reasonNeverSeen)

		if verdict.Status == statusOK {
			continue
		}
		attention = append(attention, ranked{
			entry: wallboardEntry{
				Hostname: h.Hostname,
				Status:   verdict.Status,
				Reason:   verdict.Reason,
				Detail:   truncateDetail(verdict.Detail),
			},
			rank:     wallboardReasonRank[verdict.Reason],
			lastSeen: h.LastSeen,
			id:       h.ID,
		})
	}

	slices.SortFunc(attention, func(a, b ranked) int {
		if a.rank != b.rank {
			return a.rank - b.rank
		}
		if !a.lastSeen.Equal(b.lastSeen) {
			return a.lastSeen.Compare(b.lastSeen)
		}
		return strings.Compare(a.id, b.id)
	})

	if len(attention) > MaxWallboardAttention {
		view.AttentionOmitted = len(attention) - MaxWallboardAttention
		attention = attention[:MaxWallboardAttention]
	}
	for _, r := range attention {
		view.Attention = append(view.Attention, r.entry)
	}
	return view
}

// measureHost adds one host to the three counters that are not health.
//
// Separate from judgeHost because the two answer different questions and a host contributes to both
// independently: a machine can be perfectly healthy and still be carrying forty security updates.
//
// The unmeasured half is the point of this function, and it has two sources rather than one. A host
// that has sent no inventory is not a host with no security updates, and summing with a zero for it —
// which is what the fleet page does in the browser today — quietly turns "nobody has asked this
// machine" into "this machine is fine". And a host that *has* sent one but has since gone silent is
// not a host with a current answer: whatever its last report said was true at some point, and a
// counter that treated it as measured would report a rack that dropped off the network an hour ago as
// a rack with nothing outstanding. So `current` gates both — the verdict already knows whether the
// report can be relied on, and this consults it rather than deciding again.
//
// The direction of that failure is why the gate is here rather than left to a reader's judgement. An
// offline host counted as measured moves a number *towards* healthy on a screen nobody is examining,
// which is the one direction docs/SECURITY.md §4.6 says this feature must never be wrong in.
func (s *Server) measureHost(view *wallboardView, h store.Host, current bool) {
	probe, ok := parseFactsProbe(h.Facts)
	if !ok || !current {
		view.Security.Unknown++
		view.Reboots.Unknown++
		view.Units.Unknown++
		return
	}

	if probe.Packages.UpgradableSecurity > 0 {
		view.Security.Hosts++
		view.Security.Packages += probe.Packages.UpgradableSecurity
	}

	// A reboot report that is not conclusive is counted as unmeasured rather than as "no reboot
	// needed". On Debian that is the common case: the marker file is an Ubuntu convention and
	// needrestart is a Recommends, so `required: false` frequently means nothing on the host could
	// answer. Counting those as healthy is how a fleet nobody can measure renders green.
	switch {
	case probe.Reboot.Required:
		view.Reboots.Hosts++
	case !probe.Reboot.Conclusive:
		view.Reboots.Unknown++
	}

	// Likewise for units, twice over. A truncated list means "no failed unit was reported", which is
	// not the same as "no unit has failed" when the failed one sorts after the cap. And a report with
	// no `services` section at all is a collection that did not happen rather than a machine running
	// nothing: internal/collect omits a section it could not gather, so an absent list is the shape
	// "we could not look" arrives in.
	switch {
	case countFailedUnits(probe) > 0:
		view.Units.Hosts++
	case probe.ServicesTruncated || len(probe.Services) == 0:
		view.Units.Unknown++
	}
}

// truncateDetail keeps a composed sentence inside the bound the screen was laid out for.
//
// It cuts rather than wraps, because every sentence this package composes is already inside the bound
// and the only way past it is a hostname or a count nobody anticipated. An ellipsis marks that
// something was cut, so a reader is not left believing a truncated sentence was the whole one.
func truncateDetail(detail string) string {
	if len(detail) <= maxWallboardDetail {
		return detail
	}
	return detail[:maxWallboardDetail-1] + "…"
}
