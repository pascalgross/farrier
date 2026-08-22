// Package helper is the shared spine of the three root helpers in helpers/.
//
// It exists so that /usr/libexec/farrier/apply-updates, restart-unit and reboot-host are each small
// enough to review line by line — which is a stated requirement for code that runs as root on every
// managed host — while the part that must be identical in all three lives in one place.
//
// The part that must be identical is the authorisation sequence: become root only if genuinely root,
// re-read the root-owned policy file from disk, decode and re-validate the parameters, evaluate the
// policy, and refuse on any failure. The agent has already done a version of this before invoking the
// helper. That earlier check exists to save a round trip and to produce a good error message; this one
// is the check the guarantee depends on, because it runs as root against the root-owned file and does
// not trust its caller. Duplicating it is the entire point.
package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/pegasusnetworks/farrier/internal/buildinfo"
	"github.com/pegasusnetworks/farrier/internal/intent"
	"github.com/pegasusnetworks/farrier/internal/policy"
)

// Exit codes. They are part of the interface between the agent and the helpers, so they are named
// constants rather than literals scattered through three programs.
const (
	// ExitOK means the operation completed.
	ExitOK = 0

	// ExitUsage means the command line was malformed. It never means the operation was attempted.
	ExitUsage = 2

	// ExitRefused means local policy declined the operation.
	ExitRefused = 3

	// ExitNotImplemented means this build has no executor for the operation.
	//
	// Phase 0 ships no write capability at all, so every privileged path ends here after a full,
	// genuine policy evaluation. Keeping the evaluation and stopping short of the execve is deliberate:
	// the enforcement code is exercised in the real place from the first release rather than written
	// later against a path that has never run.
	ExitNotImplemented = 4

	// ExitFailed means the operation was attempted and did not succeed.
	ExitFailed = 5
)

// Request is a helper invocation reduced to what an authorisation decision needs.
//
// Params is carried as raw JSON rather than a decoded value because the helper must run the same
// decoder the agent ran, on the same bytes, rather than trusting a decoding somebody else performed.
// A helper that accepted pre-parsed parameters would be trusting its caller, which is the one thing
// this package exists not to do.
type Request struct {
	// JobID identifies the job in the control plane, for the audit log.
	JobID string

	// Intent is the catalogue member being requested.
	Intent intent.Name

	// Params is the raw JSON parameter object.
	Params []byte

	// IssuedAt is when the control plane created the job, for the age check.
	IssuedAt time.Time
}

// Authorise re-reads the root-owned policy and evaluates a request against it.
//
// It is the function every helper calls before doing anything, and it fails closed at every step: an
// unknown intent, unparseable parameters, an unreadable policy file and a closed policy all lead to a
// refusal rather than to a default. The decoded parameters are returned alongside the decision so the
// caller can build its argv from validated values, never from its own command line.
func Authorise(req Request, policyPath string, now time.Time) (policy.Decision, intent.Params, error) {
	spec, params, err := intent.Decode(req.Intent, req.Params)
	if err != nil {
		return policy.Decision{Code: policy.CodeUnknownIntent, Reason: err.Error()}, nil, err
	}

	// A missing file is an unconfigured host and takes the conservative built-in default. Anything
	// else is a host whose administrator meant something this code could not read, and that refuses
	// with its own code: an operator told "not permitted" goes looking for the setting that forbade
	// it, which is the wrong place when the real cause is a stray bracket on line 79.
	p, err := policy.LoadFrom(policyPath)
	switch {
	case errors.Is(err, policy.ErrNoPolicyFile):
		slog.Warn("no policy file; using the built-in default", "path", policyPath, "using", p.Source())
	case err != nil:
		slog.Error("policy could not be read; refusing all privileged work",
			"path", policyPath, "error", err)
		return policy.Decision{
			Code:   policy.CodePolicyUnreadable,
			Reason: err.Error(),
		}, params, nil
	}

	decision := policy.Decide(p, policy.Request{
		Intent:   spec.Name,
		Params:   params,
		IssuedAt: req.IssuedAt,
	}, policy.Env{
		Now:    now,
		Paused: policy.Paused(),
	})

	slog.Info("policy decision",
		"job", req.JobID,
		"intent", spec.Name,
		"params", params.Describe(),
		"allowed", decision.Allowed,
		"code", decision.Code,
		"reason", decision.Reason,
		"policy", p.Source(),
	)
	return decision, params, nil
}

// RequireRoot exits unless the process is genuinely running as root.
//
// A helper invoked without privilege cannot enforce anything: it would read a policy file it could
// also have been tricked about and then fail at the operation anyway, having logged a decision that
// looked authoritative. Refusing early keeps the audit log honest.
func RequireRoot() {
	if os.Geteuid() != 0 {
		Fatalf(ExitUsage, "must run as root; it is invoked through sudo from the farrier agent")
	}
}

// Fatalf prints a message to stderr and exits with the given code.
//
// It exists so the three helpers report failures identically. The agent parses nothing from this
// output — it uses the exit code — but a human reading the journal after an incident reads exactly
// this, and three slightly different formats is three times the work at the worst moment.
func Fatalf(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "farrier-helper: "+format+"\n", args...)
	os.Exit(code)
}

// SetupLogging configures structured logging to stderr, which systemd routes to the journal.
//
// Helpers log as JSON because their output is read by machines more often than by people: the audit
// trail of who authorised what, on which host, against which policy, is the thing an operator needs
// six months later, and grepping it out of prose does not work.
func SetupLogging(component string) {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", component,
		"version", buildinfo.Version,
	))
}

// ParamsJSON encodes a helper's own flags as the parameter object the intent decoder expects.
//
// Round-tripping the helper's command line through the catalogue's decoder, rather than using the flag
// values directly, is what makes the helper's validation identical to the agent's rather than merely
// similar. It also means a helper cannot accidentally act on a value the catalogue would have
// rejected.
func ParamsJSON(fields map[string]any) []byte {
	raw, err := json.Marshal(fields)
	if err != nil {
		Fatalf(ExitUsage, "encoding parameters: %v", err)
	}
	return raw
}

// ParseIssuedAt parses the job's issue time from the command line.
//
// An empty value is accepted and disables the age check, because a helper run by hand for diagnosis
// has no job behind it. A malformed value is rejected rather than treated as empty: silently ignoring
// a timestamp the agent meant to enforce would turn the age limit off exactly when it was needed.
func ParseIssuedAt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		Fatalf(ExitUsage, "--issued-at %q is not an RFC 3339 timestamp: %v", s, err)
	}
	return t
}

// Dispatch runs the standard helper sequence and returns the validated parameters, or exits.
//
// Every helper's main function is this call followed by the operation itself, so that the operation
// cannot be reached without the decision having been made. Structuring it that way — rather than
// having each helper call Authorise and then check the result — removes the possibility of a helper
// that logs a refusal and carries on regardless, which is a mistake that reviews miss because the
// refusal is right there in the journal.
//
// **The policy path is not a parameter.** It is the packaged constant, always. A helper that accepted
// a path from its command line would be a helper a compromised agent could point at a file it wrote
// itself: the agent can write /var/lib/farrier, the sudoers entry pins the program and not its
// arguments, and local policy sovereignty would end there. Authorise takes a path because tests and
// `farrier-agent policy check` need one; nothing reachable through sudo does.
//
// The clock is read here and nowhere else in a helper. A job's validity window is checked against it,
// and accepting a caller-supplied time would let whoever invoked the helper extend that window.
//
// In dryRun the same decision is evaluated and printed, and the process exits without acting. It is a
// diagnostic path, not a privilege path: it never runs the operation, so it does not require root —
// and it reads the same packaged policy file, so it cannot be used to preview a different one.
func Dispatch(req Request, dryRun bool) intent.Params {
	const policyPath = policy.Path
	if !dryRun {
		RequireRoot()
	}

	decision, params, err := Authorise(req, policyPath, time.Now())
	if err != nil {
		Fatalf(ExitUsage, "%v", err)
	}

	if dryRun {
		verdict := "refused"
		if decision.Allowed {
			verdict = "permitted"
		}
		fmt.Printf("%s: %s (%s)\n", verdict, decision.Reason, decision.Code)
		if !decision.Allowed {
			os.Exit(ExitRefused)
		}
		os.Exit(ExitOK)
	}

	if !decision.Allowed {
		Fatalf(ExitRefused, "%v", decision.Error())
	}
	return params
}
