package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/pascalgross/hostseal/internal/protocol"
)

// TestGuaranteeAMistypedAPICallIsNotAnsweredWithSuccess is the regression test for a fallback that
// answered for the API.
//
// The single-page application is served from a "/" pattern, and in Go's ServeMux that pattern matches
// every path no other one does — including every path under /api and /agent. A wrong verb or a typo
// therefore came back 200 with an HTML page, and the sharpest edge was not the operator's: an agent
// posting a result to a path that does not route saw 2xx, concluded the result was delivered and
// dropped its spool file, turning at-least-once delivery into at-most-once for exactly the requests
// that had already gone wrong once.
func TestGuaranteeAMistypedAPICallIsNotAnsweredWithSuccess(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		// name says what the request gets wrong.
		name string

		// method and path are the request.
		method string
		path   string

		// want is the status it must come back with.
		want int

		// allow is the Allow header a 405 must carry, empty when none is expected.
		allow string
	}{
		{"a known path with the wrong verb", http.MethodGet, "/api/v1/jobs/abc/approve", http.StatusMethodNotAllowed, "POST"},
		{"a verb the API has no handler for", http.MethodDelete, "/api/v1/jobs/abc", http.StatusMethodNotAllowed, "GET"},
		{"a path that accepts two verbs", http.MethodPatch, "/api/v1/hosts/abc", http.StatusMethodNotAllowed, "DELETE, GET"},
		{"a path that does not exist", http.MethodGet, "/api/v1/nope", http.StatusNotFound, ""},
		{"a collection with a trailing slash", http.MethodGet, "/api/v1/jobs/", http.StatusNotFound, ""},
		{"an agent endpoint with the wrong verb", http.MethodGet, "/agent/v1/heartbeat", http.StatusMethodNotAllowed, "POST"},
		{"a result path the job id broke", http.MethodPost, "/agent/v1/jobs/west/reboot/result", http.StatusNotFound, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, body := h.adminJSON(t, h.adminToken, c.method, c.path, nil)
			if status != c.want {
				t.Fatalf("%s %s returned %d, want %d: %s", c.method, c.path, status, c.want, body)
			}

			var problem protocol.ErrorBody
			if err := json.Unmarshal(body, &problem); err != nil || problem.Error == "" {
				t.Fatalf("%s %s answered with %s, want a JSON problem document", c.method, c.path, body)
			}
		})
	}
}

// TestAMethodNotAllowedSaysWhichMethodsThePathTakes checks the half of the answer that saves a round
// trip: an operator who is told only "405" goes looking through the documentation, and one who is told
// "it accepts POST" has already been told the fix.
func TestAMethodNotAllowedSaysWhichMethodsThePathTakes(t *testing.T) {
	h := newHarness(t)

	req, err := http.NewRequest(http.MethodPatch, h.server.URL+"/api/v1/hosts/abc", nil)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.adminToken)

	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("PATCH /api/v1/hosts/abc: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH on a GET/DELETE path returned %d", res.StatusCode)
	}
	if got := res.Header.Get("Allow"); got != "DELETE, GET" {
		t.Errorf("Allow is %q, want %q", got, "DELETE, GET")
	}
	body, err := readAll(res)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	if !strings.Contains(string(body), "DELETE, GET") {
		t.Errorf("the problem document does not name the methods: %s", body)
	}
}

// TestTheApplicationIsStillServedFromEveryOtherPath guards the fix from over-reaching.
//
// The fallback exists because the application routes client-side: a browser opening /jobs directly must
// get index.html rather than a 404. Narrowing it to exclude the API prefixes must not narrow it to
// exclude that.
func TestTheApplicationIsStillServedFromEveryOtherPath(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/", "/jobs", "/hosts/01J9ABC", "/catalogue"} {
		res, err := h.server.Client().Get(h.server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s returned %d, want the application", path, res.StatusCode)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s returned %s, want text/html", path, ct)
		}
	}
}
