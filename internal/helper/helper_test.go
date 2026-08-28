package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/policy"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/protocol"
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

// closed is the shipped policy's answer to a restart: a list with nothing on it.
//
// It is spelled out rather than derived from packaging/policy.toml because the property being asserted
// is what an empty restartable list does, not what today's package happens to contain. It is otherwise
// permissive, so a test using it fails only for the reason it names.
const closed = `
[services]
restartable = []

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

// TestAHelperRunByHandNeedsNoIssueTime holds the diagnostic path open through the whole sequence.
//
// The command-line path is what an administrator uses to diagnose a host, and it has no job behind it,
// so it sends no issue time: ParseIssuedAt documents the empty value as exactly that case,
// docs/SECURITY.md §6 describes the path, testfleet's 080-write-capability drives every helper this way,
// and the packaging job installs the .deb and runs restart-unit by hand to prove the shipped policy
// refuses a restart. All of those need the *policy* to be what answers.
//
// A version of this branch once refused a zero issue time before the policy was consulted, on the theory
// that only a buggy agent sends one. Both by-hand callers then failed on a request local policy would
// have decided, and the packaging job read exit 2 where it asserts exit 3 — a refusal that says
// "malformed" where the product's whole claim is "the host said no". The assertion therefore runs
// performWith rather than Authorise: Main and Serve both reach the policy through it, and a precondition
// added anywhere in that sequence turns this red rather than the fleet.
func TestAHelperRunByHandNeedsNoIssueTime(t *testing.T) {
	req := restartRequest("nginx.service")
	req.IssuedAt = time.Time{}

	ran := false
	helper := Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute: func(context.Context, Job) (string, error) {
			ran = true
			return "restarted", nil
		},
	}
	resp := helper.performWith(context.Background(), req, writePolicy(t, permissive))
	if resp.ExitCode != ExitOK {
		t.Fatalf("a by-hand run of a permitted operation exited %d: %s", resp.ExitCode, resp.Error)
	}
	if !ran {
		t.Error("the operation was reported as done without the executor being called")
	}
}

// TestAPolicyRefusalOutranksAMissingIssueTime is the packaging job's assertion, one layer down.
//
// The check that ships in CI installs the package and runs restart-unit by hand against the packaged
// policy, whose restartable list is empty, and requires exit 3. Exit 3 means local policy declined;
// exit 2 means the request never reached it. Those are different claims about the product, and the one
// the guarantee rests on is the first. This pins the ordering in the unit tests, where the fix is cheap,
// instead of only in a job that needs a built .deb to say so.
func TestAPolicyRefusalOutranksAMissingIssueTime(t *testing.T) {
	req := restartRequest("nginx.service")
	req.IssuedAt = time.Time{}

	helper := Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute: func(context.Context, Job) (string, error) {
			t.Error("the executor ran for an operation local policy forbids")
			return "", nil
		},
	}
	resp := helper.performWith(context.Background(), req, writePolicy(t, closed))
	if resp.ExitCode != ExitRefused {
		t.Fatalf("exit %d, want %d: a request the policy forbids must be told so by the policy",
			resp.ExitCode, ExitRefused)
	}
}

// TestGuaranteeAHelperRefusesAnIntentItDoesNotServe is the check that replaces sudoers' fixed argv.
//
// systemd routes a connection to exactly one helper, but the request arriving on it still names an
// intent, and nothing about the socket stops a compromised agent from sending host.reboot to the one
// that restarts units. Without this check the reboot helper would be one request away from the update
// socket, which is the whole privilege separation undone by a routing mistake rather than by an
// exploit.
func TestGuaranteeAHelperRefusesAnIntentItDoesNotServe(t *testing.T) {
	restartUnit := Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute: func(context.Context, Job) (string, error) {
			t.Error("the executor ran for an intent this helper does not serve")
			return "", nil
		},
	}
	path := writePolicy(t, permissive)

	misrouted := []intent.Name{
		intent.HostReboot,
		intent.PackagesApplyAll,
		intent.PackagesApplySecurity,
		intent.FactsCollect,
		"shell.exec",
	}
	for _, name := range misrouted {
		resp := restartUnit.performWith(context.Background(), Request{
			JobID: "01JTEST", Intent: name, Params: []byte(`{}`),
		}, path)
		if resp.ExitCode != ExitUsage {
			t.Errorf("%s reached restart-unit and exited %d, expected %d", name, resp.ExitCode, ExitUsage)
		}
	}
}

// TestPerformRefusesWhatThePolicyRefuses asserts the refusal reaches the reply rather than the log.
//
// The exit code is the same one an administrator sees running the helper by hand and the same one the
// control plane is shown, so an operator reading "exit 3" in a journal and "exitCode: 3" in the UI is
// reading the same thing.
func TestPerformRefusesWhatThePolicyRefuses(t *testing.T) {
	h := Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute: func(context.Context, Job) (string, error) {
			t.Error("the executor ran on a request local policy refused")
			return "", nil
		},
	}

	resp := h.performWith(context.Background(), restartRequest("sshd.service"), writePolicy(t, permissive))
	if resp.ExitCode != ExitRefused {
		t.Fatalf("exit %d, expected %d (refused by local policy)", resp.ExitCode, ExitRefused)
	}
	if !strings.Contains(resp.Error, policy.CodeUnitNotRestartable) {
		t.Errorf("the reply does not name the refusal code: %q", resp.Error)
	}
}

// TestPerformHandsTheExecutorValidatedParametersAndReportsItsOutput is the permitted path.
//
// The executor is handed the decoded intent.Params rather than the request's bytes, because that is
// what makes "the value reaching systemd is the one the catalogue accepted" true by construction
// instead of by everyone remembering.
func TestPerformHandsTheExecutorValidatedParametersAndReportsItsOutput(t *testing.T) {
	var seen Job
	h := Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute: func(_ context.Context, job Job) (string, error) {
			seen = job
			return "restart nginx.service: done", nil
		},
	}

	resp := h.performWith(context.Background(), restartRequest("nginx.service"), writePolicy(t, permissive))
	if resp.ExitCode != ExitOK {
		t.Fatalf("exit %d (%s), expected 0", resp.ExitCode, resp.Error)
	}
	if resp.Output != "restart nginx.service: done" {
		t.Errorf("output %q", resp.Output)
	}
	unit, ok := seen.Params.(intent.UnitParams)
	if !ok {
		t.Fatalf("the executor was handed %T, want intent.UnitParams", seen.Params)
	}
	if unit.Unit != "nginx.service" {
		t.Errorf("the executor was handed unit %q", unit.Unit)
	}
	if seen.ID != "01JTEST" || seen.Intent != intent.ServiceRestart {
		t.Errorf("the executor was handed job %+v", seen)
	}
}

// TestPerformReportsAFailingExecutorWithItsOutput asserts a failure keeps what the operation printed.
//
// An update that got half way and then failed is diagnosed from what apt printed before it stopped, so
// the output has to survive the error rather than being replaced by it.
func TestPerformReportsAFailingExecutorWithItsOutput(t *testing.T) {
	h := Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute: func(context.Context, Job) (string, error) {
			return "systemd reported \"failed\"", errors.New("systemd could not restart nginx.service")
		},
	}

	resp := h.performWith(context.Background(), restartRequest("nginx.service"), writePolicy(t, permissive))
	if resp.ExitCode != ExitFailed {
		t.Fatalf("exit %d, expected %d (attempted and did not succeed)", resp.ExitCode, ExitFailed)
	}
	if !strings.Contains(resp.Output, "failed") {
		t.Errorf("the operation's output was lost: %q", resp.Output)
	}
	if !strings.Contains(resp.Error, "could not restart") {
		t.Errorf("the error is %q", resp.Error)
	}
}

// TestPerformReportsAnAbsentExecutorDistinctly asserts the older-package case stays distinguishable.
//
// A fleet is upgraded host by host, so an agent from this release will talk to a helper from the last
// one. "Your package is behind" and "the operation did not work" are fixed by different people, and
// folding them together would send an operator to read apt logs on a host that never ran apt.
func TestPerformReportsAnAbsentExecutorDistinctly(t *testing.T) {
	h := Helper{Component: "restart-unit", Socket: privsep.RestartUnitSocket}

	resp := h.performWith(context.Background(), restartRequest("nginx.service"), writePolicy(t, permissive))
	if resp.ExitCode != ExitNotImplemented {
		t.Fatalf("exit %d, expected %d (no executor in this build)", resp.ExitCode, ExitNotImplemented)
	}
	if !strings.Contains(resp.Error, "nothing was changed") {
		t.Errorf("the reply does not say that nothing happened: %q", resp.Error)
	}
}

// TestPerformTruncatesOutputToWhatTheProtocolCarries asserts the bound is applied on this side.
//
// A full dist-upgrade prints far more than the protocol carries, and the tail is what matters because
// the failure is at the end. Truncating here rather than in the agent means the socket never carries a
// megabyte the control plane would immediately discard.
func TestPerformTruncatesOutputToWhatTheProtocolCarries(t *testing.T) {
	h := Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute: func(context.Context, Job) (string, error) {
			return strings.Repeat("x", protocol.MaxJobOutputBytes+4096) + "TAIL", nil
		},
	}

	resp := h.performWith(context.Background(), restartRequest("nginx.service"), writePolicy(t, permissive))
	if !resp.OutputTruncated {
		t.Error("over-size output was not flagged as truncated")
	}
	if len(resp.Output) != protocol.MaxJobOutputBytes {
		t.Errorf("output is %d bytes, expected %d", len(resp.Output), protocol.MaxJobOutputBytes)
	}
	if !strings.HasSuffix(resp.Output, "TAIL") {
		t.Error("the head was kept rather than the tail; the failure is at the end")
	}
}

// TestGuaranteeAnUnsignedRequestIsBoundedByPolicyRatherThanRefused pins where the two controls divide.
//
// Nothing crossing the socket carries a signature, and no helper checks for one. An attacker holding
// the agent's account is in the farrier group, can therefore reach these sockets, and can invoke any
// routed intent with no signature at all — which is the scenario this asserts, in both directions.
//
// The point is that it changes nothing about what happens. A request the policy permits is performed,
// signature or not; a request it forbids is refused, signature or not. Local policy is what stands
// between a taken-over agent and a destructive operation, and the offline signature is what stands
// between a taken-over control plane and one. Two controls, two adversaries, and neither is the
// other's backstop.
//
// A test asserting the absence of a check is unusual, and it is here because the alternative is a
// future refactor quietly relying on one. If somebody later makes a helper verify a signature, this
// test should be deleted in the same commit as docs/SECURITY.md §6 and the package comment — which is
// the friction that ought to exist around changing which process holds this boundary.
func TestGuaranteeAnUnsignedRequestIsBoundedByPolicyRatherThanRefused(t *testing.T) {
	// A unit the policy names, from a request carrying nothing that could authorise it.
	permitted := writePolicy(t, permissive)
	decision, _, err := Authorise(restartRequest("nginx.service"), permitted, time.Now())
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("an unsigned request for a permitted unit was refused (%s: %s).\n"+
			"The helper does not check signatures, by design: a caller who can reach this socket has "+
			"the agent's account already. What bounds them is the policy file, and this one permits it.",
			decision.Code, decision.Reason)
	}

	// And the same request, unchanged, against a policy that does not name the unit.
	forbidden := writePolicy(t, `
[updates]
allow = "all"

[services]
restartable = ["postgresql.service"]

[limits]
max_job_age_seconds = 900
`)
	decision, _, err = Authorise(restartRequest("nginx.service"), forbidden, time.Now())
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	if decision.Allowed {
		t.Fatal("a unit outside services.restartable was permitted; local policy is what bounds a " +
			"caller the signature check cannot see")
	}
	if decision.Code != policy.CodeUnitNotRestartable {
		t.Errorf("code %q, want %q", decision.Code, policy.CodeUnitNotRestartable)
	}
}
