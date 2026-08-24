package provision

import (
	"strings"
	"testing"
)

// TestRenderingCanMakeACleanTemplateDirty is the case the warnings run on render for.
//
// A template body is reviewed once, when somebody saves it, and after that it is a document with holes
// in it. The holes are where the secrets go: a deploy key, a registry password, a break-glass hash —
// none of which are in the body anybody looked at, and all of which are in the user-data that leaves
// the control plane. Warning only at save time would therefore warn about exactly the templates that
// have nothing wrong with them, and stay quiet on every one that does.
//
// The two halves are asserted together because the property is a difference: the same document warns
// about nothing before substitution and about a private key after it, and a detector that warned on
// both would be the false-positive failure the shape list is written to avoid.
func TestRenderingCanMakeACleanTemplateDirty(t *testing.T) {
	body := "#cloud-config\nwrite_files:\n  - path: /root/.ssh/deploy\n    permissions: '0600'\n" +
		"    content: |\n      {{deployKey}}\n"

	if warnings := Warnings(body); len(warnings) != 0 {
		t.Fatalf("the template this test calls clean is not: %v", warnings)
	}

	rendered, err := Render(body, map[string]string{
		"deployKey": pemShape("OPENSSH PRIVATE KEY", "b3BlbnNzaA=="),
	})
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}

	warnings := Warnings(rendered)
	if len(warnings) != 1 {
		t.Fatalf("substituting a private key produced %d warnings: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "private-key block") {
		t.Errorf("the warning does not say what was found: %q", warnings[0])
	}
	// The consequence is the half that makes it a decision rather than a scold: an operator weighing
	// "should this key be in user-data" needs to know where user-data ends up, and "possible secret
	// detected" tells them nothing they can act on.
	if !strings.Contains(warnings[0], "/var/lib/cloud/instance/user-data.txt") {
		t.Errorf("the warning does not spell out the consequence: %q", warnings[0])
	}
	if !strings.Contains(warnings[0], "metadata") {
		t.Errorf("the warning does not name the metadata service: %q", warnings[0])
	}
}

// TestAnOrdinaryParameterStillRendersQuietly is the discipline half, on the render path.
//
// Substituting a value is the ordinary case and must stay silent, or the warning that matters arrives
// in a stream of ones that did not. A public key is the exact value most often substituted into
// user-data, which makes it the one a careless shape would catch first.
func TestAnOrdinaryParameterStillRendersQuietly(t *testing.T) {
	body := "#cloud-config\nusers:\n  - name: ops\n    ssh_authorized_keys:\n      - {{opsKey}}\n"
	rendered, err := Render(body, map[string]string{
		"opsKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3 ops@example",
	})
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if warnings := Warnings(rendered); len(warnings) != 0 {
		t.Fatalf("substituting a public key warned: %v", warnings)
	}
}
