package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// cleanTemplateBody carries no secret shape of its own and one hole where a credential goes.
//
// It is the shape of the real mistake: nobody writes a key into a template body, because a body is a
// document that gets reviewed and reused. They write a placeholder, and the key arrives at render time
// from whoever is provisioning the machine that afternoon.
const cleanTemplateBody = "#cloud-config\nruncmd:\n" +
	"  - aws configure set aws_access_key_id {{awsKeyId}}\n"

// renderResponse is the slice of a render these tests read back.
type renderResponse struct {
	// UserData is the rendered document.
	UserData string `json:"userData"`

	// Warnings are the secret shapes found in that document.
	Warnings []string `json:"warnings"`
}

// TestTheRenderWarnsAboutWhatTheParametersPutInIt is issue #17's render half, through the API.
//
// The save endpoint's warnings are already covered, and they are the easy half: the body is right there
// in the request. What nothing asserted is that the warnings are computed over the *output*, which is
// the only place a substituted credential exists — a handler that warned about the stored body instead
// would pass every save-side test, return an empty warnings list on this render, and be wrong in
// exactly the case an operator most needs to be told about.
//
// The stored template's own warnings are asserted to stay empty in the same test, because that contrast
// is the property: same template, two answers, and the difference is the parameters.
func TestTheRenderWarnsAboutWhatTheParametersPutInIt(t *testing.T) {
	h := newHarness(t)

	saved := h.saveTemplate(t, h.adminToken, map[string]any{
		"name": "with-credentials", "body": cleanTemplateBody,
	})
	if warnings, ok := saved["warnings"].([]any); !ok || len(warnings) != 0 {
		t.Fatalf("the template this test calls clean warned on save: %v", saved["warnings"])
	}

	status, raw := h.adminJSON(t, h.adminToken, http.MethodPost,
		"/api/v1/templates/with-credentials/render", map[string]any{
			// AWS's own documentation example, which is what makes it safe to write here and still
			// exactly the shape the detector is looking for.
			"params": map[string]string{"awsKeyId": "AKIAIOSFODNN7EXAMPLE"},
		})
	if status != http.StatusOK {
		t.Fatalf("rendering: %d %s", status, raw)
	}
	var rendered renderResponse
	if err := json.Unmarshal(raw, &rendered); err != nil {
		t.Fatalf("decoding the render: %v", err)
	}

	if len(rendered.Warnings) != 1 {
		t.Fatalf("a credential substituted into a clean template produced %d warnings: %v",
			len(rendered.Warnings), rendered.Warnings)
	}
	if !strings.Contains(rendered.Warnings[0], "AWS access key id") {
		t.Errorf("the warning does not name what it found: %q", rendered.Warnings[0])
	}
	if !strings.Contains(rendered.Warnings[0], "/var/lib/cloud/instance/user-data.txt") {
		t.Errorf("the warning does not name the consequence: %q", rendered.Warnings[0])
	}

	// It warns and never blocks. A refusal here would be routed around — by pasting the key into a
	// provider's console instead, where nothing warns at all — and a control that gets routed around
	// teaches people to ignore the next one too.
	if !strings.Contains(rendered.UserData, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("the render was censored rather than flagged: %q", rendered.UserData)
	}

	// And the stored version is still clean, which is what makes the warning above about the render.
	status, raw = h.adminJSON(t, h.adminToken, http.MethodGet, "/api/v1/templates/with-credentials", nil)
	if status != http.StatusOK {
		t.Fatalf("reading the template back: %d %s", status, raw)
	}
	var stored struct {
		// Warnings are the shapes found in the stored body.
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("decoding the template: %v", err)
	}
	if len(stored.Warnings) != 0 {
		t.Fatalf("the stored body warns too, so the render's warning proves nothing: %v",
			stored.Warnings)
	}
}
