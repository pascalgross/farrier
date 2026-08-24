package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// failedFleetView is the fleet-wide "where is something failed" answer, as a client reads it.
//
// Declared as a type rather than decoded into a map because the three fields this file is about —
// the failed list, the truncation flag and the unknown flag — are exactly the ones a map would let a
// test read as a missing key without noticing.
type failedFleetView struct {
	// Hosts is one entry per host worth showing.
	Hosts []struct {
		// HostID identifies the host.
		HostID string `json:"hostId"`

		// Hostname is what the page displays.
		Hostname string `json:"hostname"`

		// Failed lists the units in the failed state.
		Failed []struct {
			// Name is the unit name.
			Name string `json:"name"`
		} `json:"failed"`

		// ServicesTruncated reports that this host's unit list was cut at the protocol's cap.
		ServicesTruncated bool `json:"servicesTruncated"`

		// FactsUnknown reports that nothing at all is known about this host's units.
		FactsUnknown bool `json:"factsUnknown"`
	} `json:"hosts"`

	// Total is the denominator the page renders beside the count.
	Total int `json:"total"`
}

// unitListFacts builds a facts document holding one unit, optionally flagged as a truncated list.
//
// The truncation flag is a parameter rather than a second builder because the whole point of the test
// below is that two documents differing only in that flag must not render the same way.
func unitListFacts(unit, activeState string, truncated bool) map[string]any {
	facts := map[string]any{
		"services": []map[string]any{
			{"name": unit, "loadState": "loaded", "activeState": activeState, "subState": activeState},
		},
	}
	if truncated {
		facts["servicesTruncated"] = true
	}
	return facts
}

// failedFleet asks the fleet view what it shows.
func (h *harness) failedFleet(t *testing.T) failedFleetView {
	t.Helper()
	status, raw := h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/services/failed", nil)
	if status != http.StatusOK {
		t.Fatalf("reading the fleet view: %d %s", status, raw)
	}
	var view failedFleetView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decoding the fleet view: %v", err)
	}
	return view
}

// entryFor returns the fleet view's row for one host, and whether it had one at all.
func (v failedFleetView) entryFor(hostID string) (int, bool) {
	for i, host := range v.Hosts {
		if host.HostID == hostID {
			return i, true
		}
	}
	return 0, false
}

// TestTheFleetViewTellsCleanFromTruncatedFromUnknown is the whole of what this page has to get right,
// and none of it was asserted.
//
// The page answers "where is something failed" across a fleet, and it is read as an exhaustive answer:
// a host that is not on it is a host somebody stops thinking about. So the two ways of knowing nothing
// have to look different from knowing there is nothing. A host whose unit list was cut at the
// protocol's cap may have a failed unit sorting after the cap, and a host whose facts cannot be read
// has never said anything at all — rendering either as "clean" is the page confidently answering a
// question it was not able to ask.
//
// One test for all three because they are one decision in one loop, and because the interesting part is
// the contrast: a clean host proves the view is not simply listing everybody, which is what a test of
// the truncated host alone would also have passed against.
func TestTheFleetViewTellsCleanFromTruncatedFromUnknown(t *testing.T) {
	h := newHarness(t)

	clean := h.enrolHost(t, "clean-01", h.issueToken(t, "web-prod"))
	heartbeatWithFacts(t, h, clean, unitListFacts("nginx.service", "active", false), nil)

	truncated := h.enrolHost(t, "truncated-01", h.issueToken(t, "web-prod"))
	heartbeatWithFacts(t, h, truncated, unitListFacts("apache2.service", "active", true), nil)

	failing := h.enrolHost(t, "failing-01", h.issueToken(t, "web-prod"))
	heartbeatWithFacts(t, h, failing, unitListFacts("postgresql.service", "failed", false), nil)

	// Enrolled and never heard from again: the host exists, and nothing is known about its units.
	unknown := h.enrolHost(t, "unknown-01", h.issueToken(t, "web-prod"))

	view := h.failedFleet(t)

	if _, listed := view.entryFor(clean.HostID); listed {
		t.Errorf("a host with a whole unit list and nothing failed is on the failed page: %+v", view)
	}

	i, listed := view.entryFor(truncated.HostID)
	switch {
	case !listed:
		t.Fatalf("a host whose unit list was truncated is missing from the page: %+v", view)
	case len(view.Hosts[i].Failed) != 0:
		t.Errorf("the truncated host reports failed units it never sent: %+v", view.Hosts[i])
	case !view.Hosts[i].ServicesTruncated:
		t.Errorf("the truncated host is listed without saying why: %+v", view.Hosts[i])
	case view.Hosts[i].FactsUnknown:
		t.Errorf("a host that reported a truncated list is not a host with no facts: %+v",
			view.Hosts[i])
	}

	i, listed = view.entryFor(unknown.HostID)
	switch {
	case !listed:
		t.Fatalf("a host whose facts cannot be read is missing from the page: %+v", view)
	case !view.Hosts[i].FactsUnknown:
		t.Errorf("a host with no facts is rendered as one with nothing failed: %+v", view.Hosts[i])
	case len(view.Hosts[i].Failed) != 0:
		t.Errorf("a host with no facts reports failed units: %+v", view.Hosts[i])
	}

	i, listed = view.entryFor(failing.HostID)
	if !listed {
		t.Fatalf("the failing host is missing from the failed page: %+v", view)
	}
	if len(view.Hosts[i].Failed) != 1 || view.Hosts[i].Failed[0].Name != "postgresql.service" {
		t.Errorf("the failing host's units: %+v", view.Hosts[i])
	}

	if view.Total != 4 {
		t.Errorf("the page counts %d hosts, expected the four that are enrolled", view.Total)
	}
}

// TestUnreadableFactsAreUnknownRatherThanClean is the other half of "cannot be read".
//
// A host that never reported is the easy case. The one that matters is a host whose stored document is
// there and does not parse — a schema that moved, a restore that half worked — because that host looks
// like a fully reporting machine everywhere else on the page. The handler answers from the parse
// failing, not from the column being empty, and only a stored document that is present and unreadable
// tells the two apart.
func TestUnreadableFactsAreUnknownRatherThanClean(t *testing.T) {
	h := newHarness(t)
	broken := h.enrolHost(t, "broken-01", h.issueToken(t, "web-prod"))

	// Written past the API on purpose: the agent endpoints will not store this, which is exactly why
	// it is the case nothing else covers.
	if err := h.scoped().StoreFacts(context.Background(), broken.HostID, "sha256:corrupt",
		[]byte("{not json at all")); err != nil {
		t.Fatalf("storing an unreadable facts document: %v", err)
	}

	view := h.failedFleet(t)
	i, listed := view.entryFor(broken.HostID)
	if !listed {
		t.Fatalf("a host with unreadable facts is missing from the page: %+v", view)
	}
	if !view.Hosts[i].FactsUnknown {
		t.Fatalf("unreadable facts rendered as a clean host: %+v", view.Hosts[i])
	}
}

// TestARevokedHostIsNeitherListedNorCounted keeps the denominator honest.
//
// "3 of 300 hosts have something failed" is read as a proportion of the fleet, and a fleet does not
// include the machines somebody deliberately removed from it. Counting them made the denominator
// disagree with the numerator silently — the page still rendered, the number was just wrong, and it
// drifted further every time somebody decommissioned a host.
func TestARevokedHostIsNeitherListedNorCounted(t *testing.T) {
	h := newHarness(t)

	kept := h.enrolHost(t, "kept-01", h.issueToken(t, "web-prod"))
	heartbeatWithFacts(t, h, kept, unitListFacts("nginx.service", "failed", false), nil)

	gone := h.enrolHost(t, "gone-01", h.issueToken(t, "web-prod"))
	heartbeatWithFacts(t, h, gone, unitListFacts("nginx.service", "failed", false), nil)

	if before := h.failedFleet(t); before.Total != 2 {
		t.Fatalf("two enrolled hosts counted as %d", before.Total)
	}

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/hosts/"+gone.HostID+"/revoke", nil)
	if status != http.StatusOK {
		t.Fatalf("revoking: %d %s", status, raw)
	}

	view := h.failedFleet(t)
	if _, listed := view.entryFor(gone.HostID); listed {
		t.Errorf("a revoked host is still on the fleet page: %+v", view)
	}
	if _, listed := view.entryFor(kept.HostID); !listed {
		t.Errorf("revoking one host removed another from the page: %+v", view)
	}
	if view.Total != 1 {
		t.Errorf("the page counts %d hosts after a revocation, expected 1", view.Total)
	}
}
