package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"path"
	"time"

	"github.com/pascalgross/farrier/internal/notify"
	"github.com/pascalgross/farrier/internal/store"
)

// policyProbe is the slice of a host's reported policy the server reads for unit monitoring.
type policyProbe struct {
	// Services carries the watch list.
	Services struct {
		// Watched is the list of unit globs the host's owner considers interesting.
		Watched []string `json:"watched"`
	} `json:"services"`
}

// watchedMatcher answers whether a unit's changes are worth an event, from one host's own policy.
//
// The list comes from the host — `[services] watched` in policy.toml, reported on the heartbeat —
// because which units matter is a per-host question: the machine's owner knows that nginx.service
// matters and motd-news.timer does not, and the control plane can at most read what they wrote down.
// An empty list watches everything: the shipped default should surface a failed unit, and a fleet
// that wants quiet writes down what it cares about.
type watchedMatcher []string

// parseWatched reads the watch list out of a host's stored policy document.
func parseWatched(policyDoc []byte) watchedMatcher {
	var probe policyProbe
	if len(policyDoc) == 0 || json.Unmarshal(policyDoc, &probe) != nil {
		return nil
	}
	return probe.Services.Watched
}

// matches reports whether a unit is on the watch list, with an empty list matching everything.
func (w watchedMatcher) matches(unit string) bool {
	if len(w) == 0 {
		return true
	}
	for _, pattern := range w {
		// The same shell-style globbing the restartable list uses, so an operator learns one syntax.
		// A pattern that does not compile matches nothing, exactly as policy.RestartableAllows treats
		// it on the host.
		if ok, err := path.Match(pattern, unit); err == nil && ok {
			return true
		}
	}
	return false
}

// detectUnitTransitions compares a host's previous and newly stored facts and turns unit-state
// changes into history rows and events.
//
// It runs where the full facts report arrives, because that is the only place a "before" exists. The
// resolution is the heartbeat interval by construction: a unit that fails and recovers between two
// beats is invisible here, which is a stated property rather than a bug — see the UnitTransition doc.
//
// The first report a host ever sends produces no transitions: the units did not change, the server's
// knowledge did, and a newly enrolled machine with a long-failed unit is the fleet view's job to show
// rather than a page-worthy incident that "just happened".
func (s *Server) detectUnitTransitions(ctx context.Context, who caller, previous, current []byte) {
	if len(previous) == 0 {
		return
	}
	before, okBefore := parseFactsProbe(previous)
	after, okAfter := parseFactsProbe(current)
	if !okBefore || !okAfter {
		return
	}

	prior := make(map[string]unitProbe, len(before.Services))
	for _, unit := range before.Services {
		prior[unit.Name] = unit
	}

	watched := parseWatched(who.Host.Policy)
	now := time.Now().UTC()
	var transitions []store.UnitTransition

	for _, unit := range after.Services {
		was, known := prior[unit.Name]
		if !known || was.ActiveState == unit.ActiveState {
			continue
		}
		transitions = append(transitions, store.UnitTransition{
			Unit: unit.Name, From: was.ActiveState, To: unit.ActiveState, At: now,
		})

		if !watched.matches(unit.Name) {
			continue
		}
		switch {
		case unit.ActiveState == "failed":
			s.emit(ctx, who.Store.Tenant(), notify.Event{
				Kind: string(notify.KindServiceFailed), HostID: who.Host.ID,
				Hostname: who.Host.Hostname, At: now,
				Summary: who.Host.Hostname + ": " + unit.Name + " failed (" + unit.SubState + ")",
				Detail: map[string]any{
					"unit": unit.Name, "from": was.ActiveState, "to": unit.ActiveState,
					"subState": unit.SubState,
				},
			})
		case was.ActiveState == "failed" && unit.ActiveState == "active":
			s.emit(ctx, who.Store.Tenant(), notify.Event{
				Kind: string(notify.KindServiceRecovered), HostID: who.Host.ID,
				Hostname: who.Host.Hostname, At: now,
				Summary: who.Host.Hostname + ": " + unit.Name + " is running again",
				Detail:  map[string]any{"unit": unit.Name, "from": was.ActiveState},
			})
		}
	}

	if len(transitions) == 0 {
		return
	}
	if err := who.Store.RecordUnitTransitions(ctx, who.Host.ID, transitions); err != nil {
		slog.Error("could not record unit transitions",
			"host", who.Host.ID, "count", len(transitions), "error", err)
	}
}

// failedServiceView is one host's failed units as the fleet view renders them.
type failedServiceView struct {
	// HostID identifies the host.
	HostID string `json:"hostId"`

	// Hostname is for display.
	Hostname string `json:"hostname"`

	// Online reports whether the host has been heard from recently.
	Online bool `json:"online"`

	// Failed lists the units in the failed active state, with load and sub state preserved — a
	// masked unit and a crashed unit are different problems, and a view that paints both red
	// teaches operators to ignore it.
	Failed []unitProbe `json:"failed"`

	// ServicesTruncated reports that this host's unit list was cut at the protocol's cap, so "no
	// failed units here" and "the failed unit sorts after the cap" do not render identically.
	ServicesTruncated bool `json:"servicesTruncated"`
}

// handleFailedServices answers "where is something failed" across the fleet, without opening hosts
// one at a time.
func (s *Server) handleFailedServices(w http.ResponseWriter, r *http.Request, who operator) {
	hosts, err := who.Store.ListHosts(r.Context())
	if err != nil {
		slog.Error("could not list hosts", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the fleet")
		return
	}

	now := time.Now()
	views := make([]failedServiceView, 0)
	for _, host := range hosts {
		if host.Revoked {
			continue
		}
		probe, ok := parseFactsProbe(host.Facts)
		if !ok {
			continue
		}
		view := failedServiceView{
			HostID:            host.ID,
			Hostname:          host.Hostname,
			Online:            host.Online(now, s.cfg.HeartbeatSeconds),
			Failed:            []unitProbe{},
			ServicesTruncated: probe.ServicesTruncated,
		}
		for _, unit := range probe.Services {
			if unit.ActiveState == "failed" {
				view.Failed = append(view.Failed, unit)
			}
		}
		if len(view.Failed) > 0 || view.ServicesTruncated {
			views = append(views, view)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts":      views,
		"total":      len(hosts),
		"serverTime": now.UTC(),
	})
}

// unitTransitionView is one history row as the API renders it.
type unitTransitionView struct {
	// Unit is the systemd unit name.
	Unit string `json:"unit"`

	// From is the previous active state.
	From string `json:"from"`

	// To is the active state it moved to.
	To string `json:"to"`

	// At is when the control plane observed the change.
	At time.Time `json:"at"`
}

// handleServiceHistory returns one host's unit-state transitions, newest first.
//
// This is what makes "this has been flapping since Tuesday" visible rather than inferred: the fleet
// view answers now, and this answers since when.
func (s *Server) handleServiceHistory(w http.ResponseWriter, r *http.Request, who operator) {
	hostID := r.PathValue("id")
	if _, err := who.Store.GetHost(r.Context(), hostID); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such host")
		return
	}
	transitions, err := who.Store.ListUnitTransitions(r.Context(), hostID, 0)
	if err != nil {
		slog.Error("could not list unit transitions", "error", err, "host", hostID)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the history")
		return
	}
	views := make([]unitTransitionView, 0, len(transitions))
	for _, tr := range transitions {
		views = append(views, unitTransitionView{Unit: tr.Unit, From: tr.From, To: tr.To, At: tr.At})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"transitions": views,
		// Stated rather than discovered: the history's resolution is the heartbeat, and a unit that
		// failed and recovered between two beats is not in it.
		"resolutionSeconds": s.cfg.HeartbeatSeconds,
		"serverTime":        time.Now().UTC(),
	})
}
