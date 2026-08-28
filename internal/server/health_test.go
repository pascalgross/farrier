package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestTheHealthProbeAnswersLivenessAndNothingElse pins what an unauthenticated caller gets.
//
// Both halves are about the endpoint being unauthenticated, which makes both its cost and its
// disclosure things somebody else chooses. It used to list every tenant on every hit, so anybody who
// could reach the port could pick load for the shared database; and it returned the exact version and
// commit, which is the first half of the work of matching a deployment against a published advisory.
//
// A test rather than a comment because nothing else would notice either coming back. A handler that
// reintroduced the listing would still answer 200, and one that put the version back would look like an
// improvement to whoever wrote it.
func TestTheHealthProbeAnswersLivenessAndNothingElse(t *testing.T) {
	h := newHarness(t)
	client := h.browser(t)

	res, err := client.Get(h.server.URL + "/healthz")
	if err != nil {
		t.Fatalf("probing: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}

	var answer map[string]any
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}
	if answer["status"] != "ok" {
		t.Errorf("the probe answered %q, want status ok", body)
	}

	// Named rather than counted, so the failure says which field came back and a field added for some
	// other reason does not fail a test about these two.
	for _, disclosed := range []string{"version", "commit"} {
		if _, present := answer[disclosed]; present {
			t.Errorf("the unauthenticated probe returned %q; the build belongs on /api/v1/whoami, "+
				"which knows who is asking", disclosed)
		}
	}
}
