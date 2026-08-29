package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/server"
	"github.com/pascalgross/farrier/internal/store"
)

// wallboardFacts renders a facts document with the fields the wallboard reads.
//
// A literal rather than internal/collect's own type, because what is being tested is how the server
// reads a *stored document* — a host on the wire may send more than this build knows about and fewer
// than it hopes for, and a fixture built from the Go struct could never express the second.
func wallboardFacts(t *testing.T, security int, rebootRequired, rebootConclusive bool,
	failedUnits int, truncated bool,
) []byte {
	t.Helper()
	return wallboardFactsWith(t, security, false, rebootRequired, rebootConclusive, failedUnits, truncated)
}

// wallboardFactsWith is wallboardFacts with the package collection's own success flag exposed.
//
// A separate entry point rather than a seventh parameter on every call site, because exactly one test
// cares about the flag and the rest read better without it.
func wallboardFactsWith(t *testing.T, security int, packagesIncomplete, rebootRequired,
	rebootConclusive bool, failedUnits int, truncated bool,
) []byte {
	t.Helper()

	units := make([]map[string]any, 0, failedUnits)
	for i := range failedUnits {
		units = append(units, map[string]any{
			"name":        fmt.Sprintf("broken-%d.service", i),
			"loadState":   "loaded",
			"activeState": "failed",
			"subState":    "failed",
		})
	}
	packages := map[string]any{"upgradableSecurity": security, "upgradableTotal": security}
	if packagesIncomplete {
		packages["incomplete"] = true
	}
	raw, err := json.Marshal(map[string]any{
		"packages":          packages,
		"reboot":            map[string]any{"required": rebootRequired, "conclusive": rebootConclusive},
		"services":          units,
		"servicesTruncated": truncated,
	})
	if err != nil {
		t.Fatalf("encoding a facts fixture: %v", err)
	}
	return raw
}

// putHost writes one host straight into the store, bypassing enrolment.
//
// Enrolment through the agent client is the right fixture when the test is about enrolment; here it
// would be several round trips to arrange a machine that has been silent for an hour, which is a state
// the protocol cannot produce on demand.
func putHost(t *testing.T, scoped store.Scoped, host store.Host) {
	t.Helper()

	if err := scoped.CreateEnrolledHost(context.Background(), host, store.Certificate{
		Fingerprint: "fingerprint-" + host.ID,
		HostID:      host.ID,
		TenantID:    scoped.Tenant(),
		IssuedAt:    time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("storing host %s: %v", host.ID, err)
	}
	if len(host.Facts) > 0 {
		if err := scoped.StoreFacts(context.Background(), host.ID, "digest-"+host.ID, host.Facts); err != nil {
			t.Fatalf("storing facts for %s: %v", host.ID, err)
		}
	}
}

// aFleet writes the fixture every wallboard test below reads.
//
// One host of each verdict, so that a change which collapses two of them into one shows up as a moved
// number rather than as a missing case. It returns nothing: every assertion is made through the API,
// which is where a handler that reached past its scoped store would be visible.
func aFleet(t *testing.T, h *harness) {
	t.Helper()

	now := time.Now()
	scoped := h.scoped()

	// Healthy: seen a moment ago, nothing outstanding, and a reboot report that could answer.
	putHost(t, scoped, store.Host{
		ID: "01HEALTHY", Hostname: "web-01", EnrolledAt: now.Add(-time.Hour), LastSeen: now,
		Facts: wallboardFacts(t, 0, false, true, 0, false),
	})
	// Healthy but carrying a backlog: a backlog is counted and is deliberately not a failure.
	putHost(t, scoped, store.Host{
		ID: "01BACKLOG", Hostname: "web-02", EnrolledAt: now.Add(-time.Hour), LastSeen: now,
		Facts: wallboardFacts(t, 7, true, true, 0, false),
	})
	// Bad: silent for long enough that Host.Online says so.
	putHost(t, scoped, store.Host{
		ID: "01OFFLINE", Hostname: "web-07", EnrolledAt: now.Add(-time.Hour),
		LastSeen: now.Add(-14 * time.Minute),
		Facts:    wallboardFacts(t, 0, false, true, 0, false),
	})
	// Bad: reporting, with two failed units.
	putHost(t, scoped, store.Host{
		ID: "01UNITS", Hostname: "db-02", EnrolledAt: now.Add(-time.Hour), LastSeen: now,
		Facts: wallboardFacts(t, 0, false, true, 2, false),
	})
	// Unknown: enrolled and never heard from.
	putHost(t, scoped, store.Host{
		ID: "01NEVER", Hostname: "edge-11", EnrolledAt: now.Add(-time.Minute),
	})
	// Unknown: heartbeating, but it has never sent an inventory, so none of the three questions this
	// screen asks about a machine can be answered for it.
	putHost(t, scoped, store.Host{
		ID: "01NOFACTS", Hostname: "edge-12", EnrolledAt: now.Add(-time.Hour), LastSeen: now,
	})
	// Healthy at the host level, unmeasurable at the reboot counter — the Debian case. Its units and
	// its package state are known and fine, and only the reboot question has no answer, so it is `ok`
	// on the grid and counted under reboots.unknown. Those are different questions and the fixture is
	// here to keep them apart.
	putHost(t, scoped, store.Host{
		ID: "01DEBIAN", Hostname: "mail-03", EnrolledAt: now.Add(-time.Hour), LastSeen: now,
		Facts: wallboardFacts(t, 0, false, false, 0, false),
	})
	// Revoked: counted nowhere, because a decommissioning is not an incident.
	putHost(t, scoped, store.Host{
		ID: "01GONE", Hostname: "old-01", EnrolledAt: now.Add(-time.Hour),
		LastSeen: now.Add(-time.Hour), Revoked: true,
	})
}

// wallboardOf fetches and decodes one summary.
func wallboardOf(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	var view map[string]any
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decoding a wallboard: %v (%s)", err, raw)
	}
	return view
}

// counts reads one of the summary's counter groups as a map of numbers.
func counts(t *testing.T, view map[string]any, group string) map[string]int {
	t.Helper()

	raw, ok := view[group].(map[string]any)
	if !ok {
		t.Fatalf("the summary has no %q group: %+v", group, view)
	}
	out := map[string]int{}
	for key, value := range raw {
		number, ok := value.(float64)
		if !ok {
			t.Fatalf("%s.%s is %v, which is not a number", group, key, value)
		}
		out[key] = int(number)
	}
	return out
}

// TestTheWallboardCountsEveryHostExactlyOnce is the arithmetic the whole screen rests on.
//
// ok + bad + unknown == total is what makes the three-valued rule legible: a reader who sees the three
// numbers can tell at a glance that nothing has been left out, and a change that quietly stopped
// counting a case would show up as three numbers that no longer add up rather than as a host missing
// from a grid nobody counts.
func TestTheWallboardCountsEveryHostExactlyOnce(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/wallboard returned %d: %s", status, body)
	}
	hosts := counts(t, wallboardOf(t, body), "hosts")

	// Seven live hosts; the revoked one is counted nowhere.
	if hosts["total"] != 7 {
		t.Errorf("total is %d, want 7 — a revoked host is not a fleet member", hosts["total"])
	}
	if sum := hosts["ok"] + hosts["bad"] + hosts["unknown"]; sum != hosts["total"] {
		t.Errorf("ok+bad+unknown is %d and total is %d; a host has fallen through the verdict",
			sum, hosts["total"])
	}
	if hosts["ok"] != 3 {
		t.Errorf("ok is %d, want 3 — a security backlog, a pending reboot and an unanswerable reboot "+
			"question are all counted rather than being failures of the machine", hosts["ok"])
	}
	if hosts["bad"] != 2 {
		t.Errorf("bad is %d, want 2 (one offline, one with failed units)", hosts["bad"])
	}
	if hosts["unknown"] != 2 {
		t.Errorf("unknown is %d, want 2 (one never seen, one with no inventory)", hosts["unknown"])
	}
}

// TestAnInconclusiveRebootReportIsNotCountedAsNoRebootNeeded pins the failure this feature was written
// around.
//
// On Debian the /var/run/reboot-required marker is an Ubuntu convention and needrestart is a Recommends,
// so `required: false` frequently means nothing on the host could answer the question. A screen that
// counts those as "no reboot needed" paints an unmeasurable fleet green — which is the one direction a
// status screen must never be wrong in, and the direction the fleet page's client-side reduce is wrong
// in today.
func TestAnInconclusiveRebootReportIsNotCountedAsNoRebootNeeded(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	_, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard", nil)
	reboots := counts(t, wallboardOf(t, body), "reboots")

	if reboots["hosts"] != 1 {
		t.Errorf("reboots.hosts is %d, want 1", reboots["hosts"])
	}
	if reboots["unknown"] != 4 {
		t.Errorf("reboots.unknown is %d, want 4 — the host whose report cannot answer, the two that "+
			"have sent no report at all, and the one whose report is too old to rely on; none of them "+
			"is 'no reboot needed'", reboots["unknown"])
	}
}

// TestAHostThatHasReportedNothingIsUnknownRatherThanHealthy pins the other half of the same rule.
//
// Summing a security backlog with a zero for a host that has sent no inventory — which is what the
// fleet page does in the browser — turns "nobody has asked this machine" into "this machine is fine".
// Every counter on this screen carries its own unmeasured count so that the sum cannot say that.
func TestAHostThatHasReportedNothingIsUnknownRatherThanHealthy(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	_, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard", nil)
	security := counts(t, wallboardOf(t, body), "security")

	if security["hosts"] != 1 || security["packages"] != 7 {
		t.Errorf("security is %+v, want one host with seven updates", security)
	}
	if security["unknown"] != 3 {
		t.Errorf("security.unknown is %d, want 3 — a host that has sent no inventory cannot be said to "+
			"have no security updates, and neither can one whose last report is an hour old; summing "+
			"either as a zero is exactly how it would be said", security["unknown"])
	}
}

// TestAnOfflineHostsLastReportIsNotCountedAsACurrentMeasurement is the regression test for a counter
// that answered a question nothing had asked recently.
//
// measureHost read whatever facts were stored without consulting whether the host that sent them had
// been heard from since, so a rack that dropped off the network reported as a rack with nothing
// outstanding: the hosts counter went red, correctly, and the three beside it went to zero and stayed
// green, because zero-of-zero-unknown renders as "every host answered". A screen most of whose numbers
// say "all clear" about a fleet nobody can reach is the exact failure this feature exists to prevent,
// and it is invisible — nothing about the number itself says how old the answer behind it is.
func TestAnOfflineHostsLastReportIsNotCountedAsACurrentMeasurement(t *testing.T) {
	h := newHarness(t)

	// Ten hosts, all silent for two hours, every one of whose last report was clean and conclusive.
	silent := time.Now().Add(-2 * time.Hour)
	for i := range 10 {
		putHost(t, h.scoped(), store.Host{
			ID:         fmt.Sprintf("01QUIET%010d", i),
			Hostname:   fmt.Sprintf("rack-%02d", i),
			EnrolledAt: silent.Add(-time.Hour), LastSeen: silent,
			Facts: wallboardFacts(t, 0, false, true, 0, false),
		})
	}

	_, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard", nil)
	view := wallboardOf(t, body)

	if hosts := counts(t, view, "hosts"); hosts["bad"] != 10 {
		t.Fatalf("bad is %d, want 10 — the fixture is wrong, not the rule under test", hosts["bad"])
	}
	for _, group := range []string{"security", "reboots", "units"} {
		measure := counts(t, view, group)
		if measure["unknown"] != 10 {
			t.Errorf("%s.unknown is %d, want 10: a report from two hours ago is not a current answer, "+
				"and counting it as one paints an unreachable fleet green", group, measure["unknown"])
		}
		if measure["hosts"] != 0 {
			t.Errorf("%s.hosts is %d, want 0", group, measure["hosts"])
		}
	}
}

// TestAPackageListThatCouldNotBeGatheredIsNotCountedAsZero is the third instance of one rule.
//
// A PackageReport has no absent value: a host whose apt lock was held by something else sends
// `upgradableSecurity: 0` byte for byte as a freshly patched host does. Without the flag those two are
// one number on this screen, and the shared reading is the reassuring one — which is how a fleet nobody
// could ask reports as a fleet with nothing outstanding.
func TestAPackageListThatCouldNotBeGatheredIsNotCountedAsZero(t *testing.T) {
	h := newHarness(t)
	now := time.Now()

	// One host that genuinely has nothing pending, and one that could not look. Their package sections
	// differ by exactly the flag.
	putHost(t, h.scoped(), store.Host{
		ID: "01PATCHED", Hostname: "web-01", EnrolledAt: now.Add(-time.Hour), LastSeen: now,
		Facts: wallboardFactsWith(t, 0, false, false, true, 0, false),
	})
	putHost(t, h.scoped(), store.Host{
		ID: "01APTLOCK", Hostname: "web-02", EnrolledAt: now.Add(-time.Hour), LastSeen: now,
		Facts: wallboardFactsWith(t, 0, true, false, true, 0, false),
	})

	_, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard", nil)
	security := counts(t, wallboardOf(t, body), "security")

	if security["unknown"] != 1 {
		t.Errorf("security.unknown is %d, want 1 — the host that could not run the query has not "+
			"reported that it has nothing pending", security["unknown"])
	}
	if security["hosts"] != 0 {
		t.Errorf("security.hosts is %d, want 0", security["hosts"])
	}

	// Both hosts are still healthy at the host level: not being able to count updates is not a fault
	// of the machine, and painting it red would be the opposite error.
	if hosts := counts(t, wallboardOf(t, body), "hosts"); hosts["ok"] != 2 {
		t.Errorf("ok is %d, want 2 — an ungatherable package list is an unmeasured counter, not a "+
			"broken host", hosts["ok"])
	}
}

// TestAFloodOfInventedKeysIsRefusedBeforeItAllocatesAnything is the regression test for a rate limiter
// that could be made to grow its own bucket map.
//
// The per-link limiters are keyed on the link, which is what stops one screen spending a bucket the
// whole building shares. The cost of that keying is that the key came from the caller: an
// unauthenticated flood of syntactically valid nonsense allocated a fresh bucket with a full burst per
// request, and the sweep that would have reclaimed them runs only on the path that creates one, only
// past a thousand entries, and only drops entries idle for an hour — so the map grew while every
// insertion scanned all of it. A coarse source-keyed limit now runs first, and the key-scoped bucket is
// reserved for a link that resolved.
func TestAFloodOfInventedKeysIsRefusedBeforeItAllocatesAnything(t *testing.T) {
	h := newHarness(t)

	// Every key here is well-formed and names this fleet; none of them exists. Before the fix each one
	// was answered 404 indefinitely, one bucket and one database transaction at a time.
	var limited int
	for i := range boardFloodAttempts {
		key := "frb_" + string(h.tenant) + "." + fmt.Sprintf("%052d", i)
		status, _ := h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil)
		if status == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatalf("%d invented keys were all answered without the source ever being rate limited",
			boardFloodAttempts)
	}
}

// boardFloodAttempts is how many invented keys the flood test presents.
//
// Comfortably above boardBurst, so the limiter has to answer at least once, and small enough that the
// test stays quick.
const boardFloodAttempts = 200

// TestAHostThatHasNeverReportedIsNamedByNothing keeps docs/SECURITY.md §4.6's list honest.
//
// §4.6 says the published payload carries no host identifiers, and the obvious way to write the
// attention grid breaks that in the one case nobody tests: a machine that has never reported has no
// hostname, so falling back to its identifier put twenty-six characters of control-plane primary key
// onto a page reachable without an account — unreadable from three metres, and the value three write
// routes name.
func TestAHostThatHasNeverReportedIsNamedByNothing(t *testing.T) {
	h := newHarness(t)
	putHost(t, h.scoped(), store.Host{
		ID: "01NEVERREPORTEDANYTHING", EnrolledAt: time.Now().Add(-time.Minute),
	})

	key := publishShare(t, h, "Quiet fleet", "")
	status, body := h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/wallboard/public returned %d: %s", status, body)
	}
	if bytes.Contains(body, []byte("01NEVERREPORTEDANYTHING")) {
		t.Errorf("the published summary names a host by its identifier: %s", body)
	}

	view := wallboardOf(t, body)
	attention, _ := view["attention"].([]any)
	if len(attention) != 1 {
		t.Fatalf("the host is not on the attention grid at all: %s", body)
	}
	entry, _ := attention[0].(map[string]any)
	if entry["hostname"] != "" {
		t.Errorf("a host that has never reported is named %q", entry["hostname"])
	}
	if entry["reason"] != "never_seen" {
		t.Errorf("its reason is %v, want never_seen", entry["reason"])
	}
}

// TestTheAttentionListIsBoundedAndSaysWhatItLeftOut is what makes the page fit one screen.
//
// The bound is on the server, and the count of what did not fit travels with it, so the numbers above
// the grid stay exact whatever the fleet is doing. A stylesheet that hid the overflow instead would
// leave the thirteenth failing host behind the fold — which is the host the screen exists to surface.
func TestTheAttentionListIsBoundedAndSaysWhatItLeftOut(t *testing.T) {
	h := newHarness(t)
	scoped := h.scoped()

	// Twenty hosts, every one of them silent, so the grid overflows by eight.
	silent := time.Now().Add(-time.Hour)
	for i := range 20 {
		putHost(t, scoped, store.Host{
			ID:         fmt.Sprintf("01SILENT%09d", i),
			Hostname:   fmt.Sprintf("node-%02d", i),
			EnrolledAt: silent, LastSeen: silent.Add(time.Duration(i) * time.Minute),
		})
	}

	_, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard", nil)
	view := wallboardOf(t, body)

	attention, ok := view["attention"].([]any)
	if !ok {
		t.Fatalf("the summary has no attention list: %+v", view)
	}
	if len(attention) != server.MaxWallboardAttention {
		t.Fatalf("the attention list holds %d entries, want %d",
			len(attention), server.MaxWallboardAttention)
	}
	if omitted, _ := view["attentionOmitted"].(float64); int(omitted) != 20-server.MaxWallboardAttention {
		t.Errorf("attentionOmitted is %v, want %d", view["attentionOmitted"],
			20-server.MaxWallboardAttention)
	}
	if hosts := counts(t, view, "hosts"); hosts["bad"] != 20 {
		t.Errorf("bad is %d, want 20 — the cap bounds the grid and never the counters", hosts["bad"])
	}

	// The longest-silent host sorts first, so the grid is stable and shows the worst rather than the
	// first twelve the store happened to return.
	first, _ := attention[0].(map[string]any)
	if first["hostname"] != "node-00" {
		t.Errorf("the attention list starts with %v, want the host that has been silent longest",
			first["hostname"])
	}
}

// TestThePublicWallboardCarriesNothingAHostReported is the disclosure boundary, asserted rather than
// assumed.
//
// The summary is a projection built field by field rather than a filtered host document, and this is
// what that buys: every string a host can put into its own facts is seeded here, and none of them may
// appear in a response reachable without an account. A test that checked the shape of the payload would
// pass on the day somebody added a field; this fails.
func TestThePublicWallboardCarriesNothingAHostReported(t *testing.T) {
	h := newHarness(t)

	markers := []string{
		"MARKER-KERNEL", "MARKER-DISTRIBUTION", "MARKER-PACKAGE", "MARKER-UNIT", "MARKER-ADDRESS",
		"MARKER-CONTAINER", "MARKER-GROUP",
	}
	facts, err := json.Marshal(map[string]any{
		"hostname":     "web-07",
		"kernel":       "MARKER-KERNEL",
		"distribution": map[string]any{"prettyName": "MARKER-DISTRIBUTION"},
		"packages": map[string]any{
			"upgradableSecurity": 3,
			"packages":           []map[string]any{{"name": "MARKER-PACKAGE"}},
		},
		"reboot": map[string]any{"required": true, "conclusive": true},
		"services": []map[string]any{
			{"name": "MARKER-UNIT", "loadState": "loaded", "activeState": "failed", "subState": "failed"},
		},
		"extra": map[string]any{
			"network":    map[string]any{"interfaces": []map[string]any{{"name": "MARKER-ADDRESS"}}},
			"containers": map[string]any{"containers": []map[string]any{{"command": "MARKER-CONTAINER"}}},
		},
	})
	if err != nil {
		t.Fatalf("encoding the marker facts: %v", err)
	}
	putHost(t, h.scoped(), store.Host{
		ID: "01MARKED", Hostname: "web-07", Group: "MARKER-GROUP",
		EnrolledAt: time.Now().Add(-time.Hour), LastSeen: time.Now(), Facts: facts,
	})

	key := publishShare(t, h, "Marker fleet", "")
	status, body := h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/wallboard/public returned %d: %s", status, body)
	}
	for _, marker := range markers {
		if bytes.Contains(body, []byte(marker)) {
			t.Errorf("the published summary carries %q, which came from a host's own report: %s",
				marker, body)
		}
	}
	// The host id is not a secret; it is the identifier three write routes name, and it is useless from
	// three metres. It stays off the screen for that reason rather than for a confidentiality one.
	if bytes.Contains(body, []byte("01MARKED")) {
		t.Errorf("the published summary carries a host identifier: %s", body)
	}
	if !bytes.Contains(body, []byte("web-07")) {
		t.Errorf("the published summary names no host, so nobody can tell which machine to walk to: %s",
			body)
	}
}

// TestThePublishedAndSignedInWallboardsAgree is the property that keeps the payload honest.
//
// One builder answers both routes. If the published payload were a redaction of a richer one, the
// redaction would be a rule somebody has to remember on every future field — and the field they forgot
// would be the one that mattered. Here the published payload is the only payload, and this is what
// says so.
func TestThePublishedAndSignedInWallboardsAgree(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	key := publishShare(t, h, "Production — Frankfurt", "")

	_, operatorBody := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard", nil)
	_, publicBody := h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil)

	operatorView, publicView := wallboardOf(t, operatorBody), wallboardOf(t, publicBody)
	if publicView["title"] != "Production — Frankfurt" {
		t.Errorf("the published summary's heading is %v, want the share's label", publicView["title"])
	}
	if operatorView["title"] != "" {
		t.Errorf("the operator's summary carries a heading of %v; the shell already names the fleet",
			operatorView["title"])
	}

	// The two are built a moment apart, so the timestamps differ by construction; everything the fleet
	// decides must not.
	for _, field := range []string{"serverTime", "title"} {
		delete(operatorView, field)
		delete(publicView, field)
	}
	operatorJSON, _ := json.Marshal(operatorView)
	publicJSON, _ := json.Marshal(publicView)
	if !bytes.Equal(operatorJSON, publicJSON) {
		t.Errorf("the two summaries disagree.\noperator: %s\npublic:   %s", operatorJSON, publicJSON)
	}
}

// TestAWallboardKeyReachesOnlyItsOwnFleet is the tenant boundary as this credential meets it.
//
// The tenant travels inside the key, which is what lets the lookup run with farrier.tenant already set
// and therefore what saves this table from needing a fifth farrier.resolve_key exemption. It is safe
// because the digest covers the whole key: editing the tenant segment produces a string that hashes to
// a value no row holds. This asserts the edit is refused rather than trusting the argument.
func TestAWallboardKeyReachesOnlyItsOwnFleet(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	key := publishShare(t, h, "Alpha", "")
	forged := strings.Replace(key, string(h.tenant), string(h.otherTenant), 1)
	if forged == key {
		t.Fatal("the key does not carry its tenant; this test is asserting nothing")
	}

	status, body := h.shareJSON(t, forged, http.MethodGet, "/api/v1/wallboard/public", nil)
	if status != http.StatusNotFound {
		t.Fatalf("a key edited to name another fleet returned %d: %s", status, body)
	}
}

// TestARevokedLinkStopsAnsweringAtOnce is what makes "revocable in one request" true rather than
// claimed.
//
// The row is read on every request rather than cached anywhere, so a withdrawal takes effect at the
// next poll — which is the one property that answers docs/SECURITY.md §4.5's complaint that a shared
// credential "cannot be taken from one person who has left".
func TestARevokedLinkStopsAnsweringAtOnce(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	key := publishShare(t, h, "Temporary", "")
	if status, body := h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil); status != http.StatusOK {
		t.Fatalf("a freshly published link returned %d: %s", status, body)
	}

	shares := listShares(t, h)
	if len(shares) != 1 {
		t.Fatalf("the fleet lists %d links, want 1", len(shares))
	}
	id, _ := shares[0]["id"].(string)
	status, body := h.adminJSON(t, h.adminToken, http.MethodDelete, "/api/v1/wallboard/shares/"+id, nil)
	if status != http.StatusNoContent {
		t.Fatalf("withdrawing the link returned %d: %s", status, body)
	}

	if status, body = h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil); status != http.StatusNotFound {
		t.Fatalf("a withdrawn link returned %d, want 404: %s", status, body)
	}
}

// TestAPassphraseIsRequiredAndAWrongOneLooksLikeAnUnknownLink pins both halves of the second factor.
//
// A screen that has not proved the passphrase is told so, because that is a thing it can act on and it
// discloses only that the link exists — which whoever holds the link already knows. A screen that
// proves it wrongly is told exactly what an unknown link is told, because "this link is real and your
// passphrase is wrong" is the sentence that turns a leaked link into a guessing target.
func TestAPassphraseIsRequiredAndAWrongOneLooksLikeAnUnknownLink(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	const passphrase = "the corridor screen passphrase"
	key := publishShare(t, h, "Corridor", passphrase)

	status, body := h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a locked link answered %d before any passphrase: %s", status, body)
	}
	if !bytes.Contains(body, []byte("passphrase_required")) {
		t.Errorf("a locked link did not say what a screen should do next: %s", body)
	}

	status, body = h.shareJSON(t, key, http.MethodPost, "/api/v1/wallboard/public/unlock",
		map[string]any{"passphrase": "not it"})
	if status != http.StatusNotFound {
		t.Fatalf("a wrong passphrase answered %d, want the same 404 an unknown link gets: %s",
			status, body)
	}
}

// TestAnUnlockedScreenKeepsReadingUntilTheLinkIsWithdrawn is the exchange the passphrase exists for.
//
// A wallboard cannot re-derive Argon2id every fifteen seconds — one derivation allocates 64 MiB and at
// most four run at once — so the passphrase is proved once and exchanged for a cookie. What that costs
// is stated in docs/SECURITY.md §4.6 and asserted here: the cookie is as good as the link plus the
// passphrase until the link is withdrawn.
func TestAnUnlockedScreenKeepsReadingUntilTheLinkIsWithdrawn(t *testing.T) {
	h := newHarness(t)
	aFleet(t, h)

	const passphrase = "the corridor screen passphrase"
	key := publishShare(t, h, "Corridor", passphrase)

	jar := h.shareClient(t)
	status, body := jar.do(t, key, http.MethodPost, "/api/v1/wallboard/public/unlock",
		map[string]any{"passphrase": passphrase})
	if status != http.StatusNoContent {
		t.Fatalf("unlocking returned %d: %s", status, body)
	}
	for range 3 {
		if status, body = jar.do(t, key, http.MethodGet, "/api/v1/wallboard/public", nil); status != http.StatusOK {
			t.Fatalf("an unlocked screen was refused with %d: %s", status, body)
		}
	}

	// A second browser, holding the link and no cookie, is still locked out. The cookie is the proof,
	// not the link.
	if status, body = h.shareJSON(t, key, http.MethodGet, "/api/v1/wallboard/public", nil); status != http.StatusUnauthorized {
		t.Fatalf("a screen with the link but no cookie answered %d: %s", status, body)
	}
}

// TestUnlockAttemptsAreLimitedPerLinkRatherThanPerSource is the one limiter in this server that is not
// keyed on an address, and the reason is worth an assertion rather than only a comment.
//
// A screen is reached from a corridor, over a corporate NAT, or through the reverse proxy the
// deployment guide recommends — all of which collapse many callers into one source. A source-keyed
// bucket here would be one bucket for the whole internet that a single television could exhaust, which
// is a denial of service with extra steps. The key is the identifier the caller does not choose.
func TestUnlockAttemptsAreLimitedPerLinkRatherThanPerSource(t *testing.T) {
	h := newHarness(t)

	first := publishShare(t, h, "First", "the first corridor passphrase")
	second := publishShare(t, h, "Second", "the second corridor passphrase")

	// Spend the first link's bucket. Every attempt is wrong, so every one is a 404 until the limiter
	// answers instead.
	var limited bool
	for range 20 {
		status, _ := h.shareJSON(t, first, http.MethodPost, "/api/v1/wallboard/public/unlock",
			map[string]any{"passphrase": "not it"})
		if status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("twenty wrong passphrases on one link were never rate limited")
	}

	// The second link, from the same source, is unaffected — which is the whole point of the keying.
	status, body := h.shareJSON(t, second, http.MethodPost, "/api/v1/wallboard/public/unlock",
		map[string]any{"passphrase": "the second corridor passphrase"})
	if status != http.StatusNoContent {
		t.Fatalf("a second link from the same source answered %d; the limiter is keyed on the source "+
			"rather than on the link: %s", status, body)
	}
}

// TestAPublishedLinkIsRefusedWithoutAnOperatorCredential keeps the two halves of this feature apart.
//
// Publishing is a decision about a whole fleet, so it is behind requireOperator like every other write
// — which is also what keeps docs/SECURITY.md §9 true, because requireOperator refuses a platform
// credential and a platform administrator therefore cannot publish somebody else's fleet through the
// product.
func TestAPublishedLinkIsRefusedWithoutAnOperatorCredential(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		// name says which credential is being tried.
		name string

		// token is what is presented, empty for none at all.
		token string

		// want is the status it must come back with.
		want int
	}{
		{"no credential", "", http.StatusUnauthorized},
		{"a platform credential", h.platformToken, http.StatusForbidden},
		{"another fleet's operator", h.otherToken, http.StatusCreated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, body := h.adminJSON(t, c.token, http.MethodPost, "/api/v1/wallboard/shares",
				map[string]any{"label": "Trying"})
			if status != c.want {
				t.Fatalf("publishing with %s returned %d, want %d: %s", c.name, status, c.want, body)
			}
		})
	}
}

// TestALinkIsGivenADeadlineWhetherOrNotOneWasAskedFor is the absence of the "never" option, asserted.
//
// A shared credential that does not expire is the one docs/SECURITY.md §4.5 removed under a different
// name, so the default is a deadline rather than the lack of one, and a request for a longer life than
// this build will grant is refused rather than clamped — clamping would hand somebody a link they
// believe lasts five years.
func TestALinkIsGivenADeadlineWhetherOrNotOneWasAskedFor(t *testing.T) {
	h := newHarness(t)

	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/wallboard/shares",
		map[string]any{"label": "Default"})
	if status != http.StatusCreated {
		t.Fatalf("publishing returned %d: %s", status, body)
	}
	var created struct {
		// Share is the row as an operator sees it.
		Share struct {
			// ExpiresAt is the deadline the control plane chose.
			ExpiresAt time.Time `json:"expiresAt"`
		} `json:"share"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decoding the published link: %v (%s)", err, body)
	}
	want := time.Now().Add(server.DefaultWallboardDays * 24 * time.Hour)
	if created.Share.ExpiresAt.Sub(want).Abs() > time.Minute {
		t.Errorf("the default deadline is %s, want about %s", created.Share.ExpiresAt, want)
	}

	status, body = h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/wallboard/shares",
		map[string]any{"label": "Forever", "days": server.MaxWallboardDays + 1})
	if status != http.StatusBadRequest {
		t.Fatalf("asking for a longer life than this build grants returned %d: %s", status, body)
	}
}

// TestALinkIsShownOnceAndIsNotInTheList is the property that makes storing a digest worth anything.
//
// The key comes back in the response that created it and nowhere else, so a database dump is not a set
// of live wallboards and a listing is not a way to recover a link somebody lost.
func TestALinkIsShownOnceAndIsNotInTheList(t *testing.T) {
	h := newHarness(t)

	key := publishShare(t, h, "Once", "")
	if !strings.HasPrefix(key, "frb_") {
		t.Fatalf("a published key is %q, which a secret scanner cannot recognise", key)
	}

	_, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard/shares", nil)
	if bytes.Contains(body, []byte(key)) {
		t.Fatalf("the listing carries the key itself: %s", body)
	}
	secret := key[strings.Index(key, ".")+1:]
	if bytes.Contains(body, []byte(secret)) {
		t.Fatalf("the listing carries the secret half of the key: %s", body)
	}
}

// publishShare publishes one link and returns the key, failing the test if it cannot.
func publishShare(t *testing.T, h *harness, label, passphrase string) string {
	t.Helper()

	request := map[string]any{"label": label}
	if passphrase != "" {
		request["passphrase"] = passphrase
	}
	status, body := h.adminJSON(t, h.adminToken, http.MethodPost, "/api/v1/wallboard/shares", request)
	if status != http.StatusCreated {
		t.Fatalf("publishing a link returned %d: %s", status, body)
	}
	var created struct {
		// Key is the credential, shown exactly once.
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decoding the published link: %v (%s)", err, body)
	}
	if created.Key == "" {
		t.Fatalf("publishing a link returned no key: %s", body)
	}
	return created.Key
}

// listShares returns this fleet's published links as decoded documents.
func listShares(t *testing.T, h *harness) []map[string]any {
	t.Helper()

	status, body := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/wallboard/shares", nil)
	if status != http.StatusOK {
		t.Fatalf("listing links returned %d: %s", status, body)
	}
	var listing struct {
		// Shares is what the fleet has published.
		Shares []map[string]any `json:"shares"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("decoding the listing: %v (%s)", err, body)
	}
	return listing.Shares
}

// shareJSON makes one request as a screen holding a key, with no cookie jar.
//
// The key travels in the Authorization header rather than in the path, because it lives in the URL's
// fragment and a fragment is never transmitted. A test that put it in the path would be exercising a
// route this server does not have.
func (h *harness) shareJSON(t *testing.T, key, method, path string, body any) (int, []byte) {
	t.Helper()
	return h.shareRequest(t, nil, key, method, path, body)
}

// shareBrowser is a screen that keeps the cookie an unlock hands it.
type shareBrowser struct {
	// harness is the control plane it is talking to.
	harness *harness

	// cookies are what the last response set, replayed on the next request.
	//
	// A slice rather than net/http/cookiejar because the jar wants a URL policy and a persistent
	// client, and what is being tested is that one value comes back — not that the standard library
	// implements RFC 6265.
	cookies []*http.Cookie
}

// shareClient returns a screen that remembers cookies across requests.
func (h *harness) shareClient(t *testing.T) *shareBrowser {
	t.Helper()
	return &shareBrowser{harness: h}
}

// do makes one request, sending the cookies it holds and keeping any it is given.
func (b *shareBrowser) do(t *testing.T, key, method, path string, body any) (int, []byte) {
	t.Helper()
	return b.harness.shareRequest(t, b, key, method, path, body)
}

// shareRequest makes one request as a screen, optionally through a cookie-keeping browser.
func (h *harness) shareRequest(t *testing.T, browser *shareBrowser, key, method, path string,
	body any,
) (int, []byte) {
	t.Helper()

	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding a request body: %v", err)
		}
		payload = encoded
	}

	req, err := http.NewRequest(method, h.server.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	if browser != nil {
		for _, cookie := range browser.cookies {
			req.AddCookie(cookie)
		}
	}

	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()

	if browser != nil {
		browser.cookies = append(browser.cookies, res.Cookies()...)
	}
	decoded, err := readAll(res)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return res.StatusCode, decoded
}
