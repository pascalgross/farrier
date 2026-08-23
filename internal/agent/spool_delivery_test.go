package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/protocol"
)

// TestGuaranteeAResultTheControlPlaneWillNeverAcceptDoesNotStayForEver is the regression test for a
// spool that only ever grew.
//
// The spool is what makes host.reboot reportable at all, so leaving a result on disk after a failed
// delivery is right for every failure the spool exists for — a control plane that is down, a network
// that is gone, a machine that lost power. It is wrong for the one class docs/PROTOCOL.md §11 calls
// out: a refusal the control plane understood and will repeat identically. Retrying that on every pass
// for the life of the machine costs a request and a warning line each time, and it puts a file that can
// never leave into the directory the next reboot's result has to be written to.
func TestGuaranteeAResultTheControlPlaneWillNeverAcceptDoesNotStayForEver(t *testing.T) {
	for _, c := range []struct {
		// name says what the control plane answered with.
		name string

		// status is that answer, and kept says whether the spool file must survive it.
		status int
		kept   bool
	}{
		{"a body it cannot parse", http.StatusBadRequest, false},
		{"a job that is not this host's", http.StatusNotFound, false},
		{"a state already taken", http.StatusConflict, false},
		{"an outage", http.StatusServiceUnavailable, true},
		{"a credential it rejected", http.StatusUnauthorized, true},
		{"a body it found too large", http.StatusRequestEntityTooLarge, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			result := protocol.ResultRequest{
				JobID: "01JREBOOT", Status: protocol.StatusSucceeded,
				StartedAt: time.Now(), FinishedAt: time.Now(),
			}
			if err := SpoolResult(dir, result); err != nil {
				t.Fatalf("spooling: %v", err)
			}

			var calls int
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(`{"error":"refused","message":"no"}`))
			}))
			defer control.Close()

			client := &Client{baseURL: control.URL, http: control.Client()}
			DeliverPending(context.Background(), client, dir)

			if calls != 1 {
				t.Fatalf("the agent made %d delivery attempts, want exactly 1", calls)
			}
			_, err := os.Stat(filepath.Join(dir, PendingResultsDir, "01JREBOOT.json"))
			switch {
			case c.kept && err != nil:
				t.Errorf("a result refused with %d was discarded; it is the spool's whole job to "+
					"outlive that", c.status)
			case !c.kept && err == nil:
				t.Errorf("a result refused with %d is still spooled and will be retried for ever",
					c.status)
			}
		})
	}
}

// TestADeliveredResultLeavesTheSpool is the ordinary path, asserted alongside the one above so that a
// change which discarded everything would not look like a pass.
func TestADeliveredResultLeavesTheSpool(t *testing.T) {
	dir := t.TempDir()
	if err := SpoolResult(dir, protocol.ResultRequest{
		JobID: "01JREBOOT", Status: protocol.StatusSucceeded,
		StartedAt: time.Now(), FinishedAt: time.Now(),
	}); err != nil {
		t.Fatalf("spooling: %v", err)
	}

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"recorded"}`))
	}))
	defer control.Close()

	DeliverPending(context.Background(), &Client{baseURL: control.URL, http: control.Client()}, dir)

	if _, err := os.Stat(filepath.Join(dir, PendingResultsDir, "01JREBOOT.json")); err == nil {
		t.Error("a delivered result is still spooled, so it will be delivered again on the next pass")
	}
}

// TestAnUndeliverableResultIsNotMistakenForARefusedOne is the distinction the discard depends on.
//
// A transport failure — the control plane's name does not resolve, the connection is refused, the TLS
// handshake fails — is precisely the case the spool exists for. Reading one as a refusal would throw
// away the result of work that had actually run, which is the failure this whole mechanism is built to
// prevent.
func TestAnUndeliverableResultIsNotMistakenForARefusedOne(t *testing.T) {
	dir := t.TempDir()
	if err := SpoolResult(dir, protocol.ResultRequest{
		JobID: "01JREBOOT", Status: protocol.StatusSucceeded,
		StartedAt: time.Now(), FinishedAt: time.Now(),
	}); err != nil {
		t.Fatalf("spooling: %v", err)
	}

	// A server that is closed before the call, so the connection is refused outright.
	control := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := control.URL
	control.Close()

	DeliverPending(context.Background(), &Client{baseURL: url, http: http.DefaultClient}, dir)

	if _, err := os.Stat(filepath.Join(dir, PendingResultsDir, "01JREBOOT.json")); err != nil {
		t.Errorf("a result that could not be delivered was discarded: %v", err)
	}
}
