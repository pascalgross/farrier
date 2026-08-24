package server_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// logCapture collects everything the process logs for the length of one test.
//
// There was no way to assert anything about this package's logging before, which is why the one
// property that is *about* logging — that a credential never reaches a log line — was unenforced. A
// buffer behind the default logger is the smallest thing that fixes that: the handlers under test call
// the package-level slog functions, so the default logger is the only seam there is.
type logCapture struct {
	// mu guards buffer.
	//
	// Deliveries detached by earlier tests can still be running and logging while this one asserts, so
	// the buffer is written from more than one goroutine whether this test wants it to be or not. An
	// unguarded bytes.Buffer here is a data race that -race reports against whichever test is unlucky.
	mu sync.Mutex

	// buffer holds every line written since the capture began.
	buffer bytes.Buffer
}

// Write records one log line.
func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.Write(p)
}

// text returns everything logged so far.
func (c *logCapture) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.String()
}

// captureLogs redirects the default logger into a buffer for the length of one test.
//
// At debug level deliberately. The property being asserted is that a secret reaches *no* log line, and
// a capture that only saw Info would pass against a build that had put the rendered body behind
// slog.Debug — which is precisely the shape a well-meaning "let's make this debuggable" change takes.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()

	capture := &logCapture{}
	held := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	t.Cleanup(func() { slog.SetDefault(held) })
	return capture
}

// marker builds a value these tests can search the logs for.
//
// Assembled rather than written out, and deliberately low-entropy, for the reason .gitleaksignore
// states at length: `passwd: <high-entropy string>` is a credential everywhere else in the world, and
// a scanner that reads it as one is right to. The repository's rule is that the tree never carries
// such a literal at all — the ignore file covers commits that are already published and is explicitly
// not somewhere new entries go — so a fixture needing the shape builds it, as harnessCredential and
// pemShape already do.
//
// Distinctive without being random: it has to be a string that cannot turn up in a log by accident,
// which "farrier-test-…-not-a-real-credential" manages without looking like key material.
func marker(what string) string {
	return "farrier-test-" + what + "-not-a-real-credential"
}

// secretBody is a template whose contents are recognisable anywhere they turn up.
//
// Every part of it is a distinct marker: the body has one, the parameter substituted into it has
// another, and the token is minted at render time. A single marker would not tell "the body leaked"
// from "the substituted value leaked", and those are different bugs with different fixes.
var secretBody = "#cloud-config\nhostname: {{hostname}}\n" +
	"write_files:\n  - path: /etc/secret\n    content: " + marker("stored-body") + "\n" +
	"runcmd:\n  - farrier enroll --token {{enrollmentToken}}\n"

// TestARenderedTemplateNeverReachesALogLine is issue #16's first consequence, and it was unasserted.
//
// The render endpoint's output is a credential: it carries an enrolment token minted for that render,
// and it carries whatever the operator put in the body — break-glass passwords, keys, the things the
// secret-shape warnings exist to talk them out of. The response is authorised, shown once and marked
// no-store, and every one of those precautions is undone by one log line, because a log is copied to
// places the database never goes and kept for longer than the token lives.
//
// The test asserts the negative and the positive together on purpose. "The body is not in the logs" is
// satisfied completely by a build that logs nothing at all, which would lose the audit trail that says
// who rendered what — so the template's name and version have to be there in the same breath.
func TestARenderedTemplateNeverReachesALogLine(t *testing.T) {
	h := newHarness(t)
	capture := captureLogs(t)

	h.saveTemplate(t, h.adminToken, map[string]any{"name": "standard-server", "body": secretBody})

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/standard-server/render", map[string]any{
			"params": map[string]string{"hostname": marker("parameter")},
		})
	if status != http.StatusOK {
		t.Fatalf("rendering: %d %s", status, raw)
	}
	var rendered struct {
		// UserData is the credential this test is about.
		UserData string `json:"userData"`
	}
	if err := json.Unmarshal(raw, &rendered); err != nil {
		t.Fatalf("decoding the render: %v", err)
	}
	token := strings.TrimSpace(strings.Split(strings.Split(rendered.UserData, "--token ")[1], "\n")[0])
	if token == "" || !strings.Contains(rendered.UserData, marker("stored-body")) {
		t.Fatalf("the fixture did not render what this test asserts about: %q", rendered.UserData)
	}

	logged := capture.text()
	for _, secret := range []struct {
		// what names the leak in the failure message.
		what string

		// value is the string that must not appear.
		value string
	}{
		{"the stored body", marker("stored-body")},
		{"the substituted parameter", marker("parameter")},
		{"the minted enrolment token", token},
	} {
		if strings.Contains(logged, secret.value) {
			t.Errorf("%s reached a log line:\n%s", secret.what, logged)
		}
	}

	// And the render is still recorded, or the assertion above would be satisfied by silence.
	for _, want := range []string{"template rendered", "standard-server", "template version stored"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the logs do not carry %q, so this test would pass against a build that logged "+
				"nothing:\n%s", want, logged)
		}
	}
}

// TestAStoredTemplateBodyNeverReachesALogLineEither closes the other half of the same door.
//
// A save is where the body arrives in plaintext for the only time it ever does, and the body is what
// the warnings on that same response are about — an operator who has just been told "this contains a
// private-key block, and user-data is readable by anything with metadata access" has been told the
// wrong thing if the control plane has already copied it into a log.
//
// It asserts against a body that refuses to render, so the save is the only handler that ever saw it:
// a leak found here cannot have come from the render path.
func TestAStoredTemplateBodyNeverReachesALogLineEither(t *testing.T) {
	h := newHarness(t)
	capture := captureLogs(t)

	h.saveTemplate(t, h.adminToken, map[string]any{
		"name": "breakglass",
		"body": "#cloud-config\nusers:\n  - name: ops\n    passwd: " + marker("saved-body") + "\n",
	})

	logged := capture.text()
	if strings.Contains(logged, marker("saved-body")) {
		t.Errorf("a stored template body reached a log line:\n%s", logged)
	}
	if !strings.Contains(logged, "breakglass") {
		t.Errorf("the save was not recorded at all, so this test asserts nothing:\n%s", logged)
	}
}
