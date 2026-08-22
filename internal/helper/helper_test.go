package helper

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pegasusnetworks/farrier/internal/intent"
	"github.com/pegasusnetworks/farrier/internal/policy"
)

// writePolicy writes a policy file into a temporary directory and returns its path.
//
// The helpers read the policy from disk on every invocation by design, so the tests exercise that
// rather than handing them a parsed value: the thing being asserted is what happens when the file on
// disk is wrong, which an in-memory fixture cannot express.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing policy fixture: %v", err)
	}
	return path
}

// permissive is a policy that permits everything the tests below might ask for.
//
// Starting from "everything permitted" and breaking exactly one thing per test is what makes each case
// prove what it claims to, rather than passing because of an unrelated refusal.
const permissive = `
[updates]
allow = "all"
reboot = "window"
# Open every hour of every day, written out. An empty window no longer combines with reboot = "window",
# because "always open" was not what anybody writing that meant.
window = "daily 00:00-00:00"
timezone = "UTC"

[services]
restartable = ["nginx.service"]

[limits]
max_job_age_seconds = 900
`

// restartRequest builds a service.restart request for a unit.
func restartRequest(unit string) Request {
	return Request{
		JobID:    "01JTEST",
		Intent:   intent.ServiceRestart,
		Params:   []byte(`{"unit":"` + unit + `"}`),
		IssuedAt: time.Now(),
	}
}

// TestGuaranteeHelperRefusesWhenThePolicyCannotBeRead is the fail-closed case that matters most.
//
// A host whose policy file does not parse must refuse privileged work rather than fall back to a
// default, because the alternative is that a syntax error in a hand-edited file silently widens what
// the host accepts. The distinct refusal code matters too: an operator told "not permitted" goes
// looking for the setting that forbade it, which is the wrong place when the cause is a stray bracket.
func TestGuaranteeHelperRefusesWhenThePolicyCannotBeRead(t *testing.T) {
	path := writePolicy(t, "this is not toml ][\n")
	decision, _, err := Authorise(restartRequest("nginx.service"), path, time.Now())
	if err != nil {
		t.Fatalf("Authorise returned an error rather than a refusal: %v", err)
	}
	if decision.Allowed {
		t.Fatal("an unparseable policy file permitted a privileged operation")
	}
	if decision.Code != policy.CodePolicyUnreadable {
		t.Errorf("code %q, want %q", decision.Code, policy.CodePolicyUnreadable)
	}
}

// TestAuthoriseUsesTheBuiltInDefaultWhenNoPolicyFileExists covers the unconfigured host.
//
// A missing file and an unparseable file mean opposite things. The first is a host nobody has
// configured yet, which takes the conservative default — and the conservative default still refuses a
// restart, because nothing is on services.restartable until somebody puts it there.
func TestAuthoriseUsesTheBuiltInDefaultWhenNoPolicyFileExists(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent.toml")
	decision, _, err := Authorise(restartRequest("nginx.service"), absent, time.Now())
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	if decision.Allowed {
		t.Fatal("the built-in default permitted a service restart; nothing should be restartable")
	}
	if decision.Code != policy.CodeUnitNotRestartable {
		t.Errorf("code %q, want %q", decision.Code, policy.CodeUnitNotRestartable)
	}
}

// TestAuthoriseRunsTheCatalogueDecoderOnItsOwnSideOfThePrivilegeBoundary is the point of the design.
//
// The helper decodes the raw parameter bytes itself rather than accepting a decoding somebody else
// performed. A unit name that the catalogue's pattern rejects must be refused here, in the root
// process, even though the agent already rejected it before calling.
func TestAuthoriseRunsTheCatalogueDecoderOnItsOwnSideOfThePrivilegeBoundary(t *testing.T) {
	path := writePolicy(t, permissive)
	for _, unit := range []string{
		"nginx.service; rm -rf /",
		"../../etc/systemd/system/evil.service",
		"-nginx.service",
		"",
	} {
		decision, _, err := Authorise(restartRequest(unit), path, time.Now())
		if err == nil {
			t.Errorf("unit %q did not produce a decoding error", unit)
		}
		if decision.Allowed {
			t.Errorf("unit %q was permitted", unit)
		}
	}
}

// TestAuthorisePermitsWhatThePolicyPermits is the counterweight to every refusal test above.
//
// A helper that refused everything would satisfy all of them, so this asserts the permitted case
// reaches a decision with the validated parameters attached — which is what the caller builds its argv
// from.
func TestAuthorisePermitsWhatThePolicyPermits(t *testing.T) {
	path := writePolicy(t, permissive)
	decision, params, err := Authorise(restartRequest("nginx.service"), path, time.Now())
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("a permitted restart was refused: %s", decision.Reason)
	}
	unit, ok := params.(intent.UnitParams)
	if !ok {
		t.Fatalf("params are %T, want intent.UnitParams", params)
	}
	if unit.Unit != "nginx.service" {
		t.Errorf("params carry unit %q, want nginx.service", unit.Unit)
	}
}

// TestAuthoriseRefusesIntentsOutsideTheCatalogue asserts the helper cannot be pointed at anything else.
//
// The helpers take an intent name on their command line, and the only caller is the agent through a
// fixed sudoers entry — but the check belongs here anyway, because "the only caller is trusted" is the
// assumption this whole layer exists to avoid making.
func TestAuthoriseRefusesIntentsOutsideTheCatalogue(t *testing.T) {
	path := writePolicy(t, permissive)
	for _, name := range append([]intent.Name{"", "service.enable"}, intent.Refused...) {
		req := Request{JobID: "01JTEST", Intent: name, Params: []byte(`{}`), IssuedAt: time.Now()}
		decision, _, err := Authorise(req, path, time.Now())
		if err == nil {
			t.Errorf("intent %q was accepted", name)
		}
		if decision.Allowed {
			t.Errorf("intent %q was permitted", name)
		}
	}
}

// TestAuthoriseEnforcesTheLocalJobAgeLimit covers limits.max_job_age_seconds in its real position.
//
// The agent checks this too, but the agent is the process that might be compromised. The limit only
// means anything because it is re-checked here, against the clock this process read, using the value
// from the root-owned file.
func TestAuthoriseEnforcesTheLocalJobAgeLimit(t *testing.T) {
	path := writePolicy(t, permissive)
	req := restartRequest("nginx.service")
	req.IssuedAt = time.Now().Add(-time.Hour)

	decision, _, err := Authorise(req, path, time.Now())
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	if decision.Allowed {
		t.Fatal("an hour-old job was permitted with a 900-second limit")
	}
	if decision.Code != policy.CodeExpired {
		t.Errorf("code %q, want %q", decision.Code, policy.CodeExpired)
	}
}
