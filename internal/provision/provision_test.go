package provision

import (
	"strings"
	"testing"
)

// TestRenderSubstitutes proves the whole of what rendering does: values into placeholders.
func TestRenderSubstitutes(t *testing.T) {
	body := "#cloud-config\nhostname: {{hostname}}\nruncmd:\n" +
		"  - farrier enroll --token {{ enrollmentToken }} --server {{server}}\n"
	out, err := Render(body, map[string]string{
		"hostname":        "web-01",
		"enrollmentToken": "tok-123",
		"server":          "https://farrier.example.org",
	})
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	want := "#cloud-config\nhostname: web-01\nruncmd:\n" +
		"  - farrier enroll --token tok-123 --server https://farrier.example.org\n"
	if out != want {
		t.Fatalf("rendered:\n%q\nwant:\n%q", out, want)
	}
}

// TestRenderIsStrictInBothDirections proves a missing value and a typo are both errors that name names.
func TestRenderIsStrictInBothDirections(t *testing.T) {
	body := "hostname: {{hostname}}\ngroup: {{group}}\nagain: {{hostname}}\n"

	_, err := Render(body, map[string]string{"hostname": "web-01"})
	if err == nil || !strings.Contains(err.Error(), "group") {
		t.Fatalf("a missing parameter was not named: %v", err)
	}
	if err != nil && strings.Count(err.Error(), "hostname") > 0 {
		t.Fatalf("a supplied parameter was reported missing: %v", err)
	}

	_, err = Render(body, map[string]string{
		"hostname": "web-01", "group": "web", "hostnme": "typo",
	})
	if err == nil || !strings.Contains(err.Error(), "hostnme") {
		t.Fatalf("an unused parameter was not named: %v", err)
	}
}

// TestRenderRefusesExpressions proves the placeholder syntax cannot smuggle anything but a name.
//
// This is the mechanical half of "the renderer never grows into a template language": a brace pair
// holding anything other than an identifier is not a placeholder, so it substitutes nothing, takes no
// parameter, and reaches the output verbatim for cloud-init to reject.
func TestRenderRefusesExpressions(t *testing.T) {
	for _, body := range []string{
		"{{ exec \"rm -rf /\" }}",
		"{{ if .Debug }}",
		"{{hostname | upper}}",
		"{{ range .Items }}",
	} {
		if names := Placeholders(body); len(names) != 0 {
			t.Errorf("%q parsed as placeholders %v; expressions must not be placeholders", body, names)
		}
		out, err := Render(body, map[string]string{})
		if err != nil || out != body {
			t.Errorf("%q did not pass through verbatim: %q, %v", body, out, err)
		}
	}
}

// TestPlaceholdersAreReported proves a client can ask what a template needs.
func TestPlaceholdersAreReported(t *testing.T) {
	got := Placeholders("a: {{beta}}\nb: {{alpha}}\nc: {{beta}}\n")
	if len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("placeholders: %v", got)
	}
}

// pemShape assembles a PEM block for the detector to find.
//
// Assembled rather than written out, for the reason .gitleaksignore states at length: a literal key
// block in the tree is a finding somebody has to judge, and then a line in an ignore file that has to
// be trusted for ever. The detector under test matches the header, so it sees exactly the same string
// either way — this only keeps the secret scanner's answer about this repository honest.
//
// An empty body produces a bare header, which is its own case: a truncated paste is still a paste.
func pemShape(label, body string) string {
	block := "-----BEGIN " + label + "-----"
	if body == "" {
		return block
	}
	return block + "\n" + body + "\n-----END " + label + "-----"
}

// TestWarningsFireOnHighSignalShapes proves each shape is caught and each warning carries the
// consequence, which is the half that makes it actionable.
func TestWarningsFireOnHighSignalShapes(t *testing.T) {
	for _, body := range []string{
		pemShape("OPENSSH PRIVATE KEY", "b3BlbnNzaA=="),
		pemShape("RSA PRIVATE KEY", ""),
		"users:\n  - name: breakglass\n    passwd: $6$rounds=4096$salt$hash\n",
		"password: hunter2\n",
		"aws_access_key_id: AKIAIOSFODNN7EXAMPLE\n",
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
		"token: github_pat_11ABCDEFG0123456789_abcdef\n",
		"slack: xoxb-1234567890-abcdefghij\n",
	} {
		warnings := Warnings(body)
		if len(warnings) == 0 {
			t.Errorf("no warning for %q", body)
			continue
		}
		for _, w := range warnings {
			if !strings.Contains(w, "/var/lib/cloud/instance/user-data.txt") {
				t.Errorf("the warning does not spell out the consequence: %q", w)
			}
		}
	}
}

// TestWarningsStayQuietOnLegitimateUserData proves the false-positive discipline.
//
// These are the documents operators actually write, and a detector that flagged them would teach
// people to ignore it — which is the failure mode issue #17 names as the one that matters.
func TestWarningsStayQuietOnLegitimateUserData(t *testing.T) {
	for _, body := range []string{
		// Public keys are the thing user-data is for.
		"ssh_authorized_keys:\n  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3 ops@example\n",
		// A chpasswd structure with no inline value: the stanza is legitimate scaffolding.
		"chpasswd:\n  expire: true\n  users:\n    - {name: breakglass}\npassword:\n",
		// A 32-character hex string is not a token shape worth crying wolf over.
		"digest: 9e107d9d372bb6826bd81d3542a419d6a1b2c3d4\n",
		// An enrolment command with its token placeholder still unsubstituted.
		"runcmd:\n  - farrier enroll --token {{enrollmentToken}}\n",
	} {
		if warnings := Warnings(body); len(warnings) != 0 {
			t.Errorf("false positive on %q: %v", body, warnings)
		}
	}
}
