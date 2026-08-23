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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/policy"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/protocol"
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
	// It was every privileged path's ending in phase 0, which shipped no write capability at all. It is
	// kept, and the agent still maps it to unsupported_intent, because a fleet is upgraded host by host:
	// an agent from this release talking to a helper from the last one gets exactly this, and "your
	// package is behind" needs to stay distinguishable from "the operation did not work".
	ExitNotImplemented = 4

	// ExitFailed means the operation was attempted and did not succeed.
	ExitFailed = 5
)

// Request is a helper invocation reduced to what an authorisation decision needs.
//
// It is an alias for the type that crosses the socket rather than a second struct beside it, and that
// is the point: a helper reached over its socket by the agent and a helper run by hand by an
// administrator are answering the same request, through the same authorisation sequence, against the
// same packaged policy file. Two structurally identical types would let the two paths drift, and the
// command-line path is only useful as a diagnostic while it cannot.
//
// Params is carried as raw JSON rather than a decoded value because the helper must run the same
// decoder the agent ran, on the same bytes, rather than trusting a decoding somebody else performed.
// A helper that accepted pre-parsed parameters would be trusting its caller, which is the one thing
// this package exists not to do.
type Request = privsep.Request

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
		Fatalf(ExitUsage, "must run as root; it is started by its .socket unit, "+
			"or run directly by an administrator")
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

// Job is what an executor is handed once local policy has permitted the work.
//
// It carries the decoded parameters rather than the raw bytes, and carries them as the sealed
// intent.Params interface, so an executor builds its argument vector from values a catalogue validator
// has already accepted. An executor that reached back to the request's bytes, or to its own command
// line, would be acting on input the policy decision was not made about.
type Job struct {
	// ID identifies the job in the control plane, for the audit log.
	ID string

	// Intent is the catalogue member being performed.
	Intent intent.Name

	// Params are the decoded, validated parameters.
	Params intent.Params
}

// Executor performs the operation a helper exists for, after policy has permitted it.
//
// It returns the operation's combined output and an error if it did not succeed. It deliberately does
// not return an exit code: the mapping from "this failed" to a number is one decision, made once in
// Perform, rather than three helpers each choosing their own and drifting.
type Executor func(ctx context.Context, job Job) (string, error)

// Helper is one root helper: the socket it answers on and the operation behind it.
//
// Socket is the identity that matters. systemd routes a connection to exactly one helper, but the
// request arriving on it still names an intent, and nothing stops a compromised agent from sending
// host.reboot to the socket that restarts units. Perform therefore checks that the intent's endpoint in
// internal/privsep *is* this helper's socket, which makes the routing table and the helpers agree by
// construction rather than by convention.
type Helper struct {
	// Component is the name this helper logs under, such as "apply-updates".
	Component string

	// Socket is the privsep endpoint systemd activates this helper on.
	Socket string

	// Execute performs the operation. A nil executor answers ExitNotImplemented.
	Execute Executor
}

// Perform authorises one request and runs the operation, returning what to report.
//
// This is the whole helper sequence in one function, and every step fails closed: an intent this helper
// does not serve, unparseable parameters, an unreadable policy file and a closed policy all produce a
// refusal rather than a default. It never returns an error, because every outcome — including a crash
// in the operation — has to become a reply. A helper that failed without answering would leave the job
// sitting in the queue looking like a host that had gone quiet.
//
// **The policy path is not a parameter.** It is the packaged constant, always. A helper that accepted a
// path from its caller would be one a compromised agent could point at a file it had just written: the
// agent can write /var/lib/farrier, and local policy sovereignty would end there. performWith takes a
// path because this package's tests need one; nothing reachable over the socket does.
func (h Helper) Perform(ctx context.Context, req Request) privsep.Response {
	return h.performWith(ctx, req, policy.Path)
}

// performWith is Perform against an explicit policy file, for this package's tests.
func (h Helper) performWith(ctx context.Context, req Request, policyPath string) privsep.Response {
	// Whose work is this? Asked before anything is decoded, because the cheapest refusal is the one
	// that happens before the parser runs.
	endpoint, routed := privsep.Endpoint(req.Intent)
	switch {
	case !routed:
		return privsep.Response{
			ExitCode: ExitUsage,
			Error: fmt.Sprintf("%s does not perform %q, and no helper does: it is not a privileged "+
				"member of the intent catalogue", h.Component, req.Intent),
		}
	case endpoint != h.Socket:
		return privsep.Response{
			ExitCode: ExitUsage,
			Error: fmt.Sprintf("%s does not perform %q; that intent is served by %s",
				h.Component, req.Intent, endpoint),
		}
	}

	decision, params, err := Authorise(req, policyPath, time.Now())
	if err != nil {
		return privsep.Response{ExitCode: ExitUsage, Error: err.Error()}
	}
	if !decision.Allowed {
		return privsep.Response{ExitCode: ExitRefused, Error: decision.Error().Error()}
	}

	if h.Execute == nil {
		// Unreachable in a complete build. It is kept as a distinct code rather than folded into a
		// failure because an agent talking to a helper from an older package — a fleet mid-upgrade —
		// gets exactly this, and "your package is behind" is a different problem from "the operation
		// did not work".
		return privsep.Response{
			ExitCode: ExitNotImplemented,
			Error: fmt.Sprintf("this build of %s has no executor for %q; local policy permitted %q "+
				"and nothing was changed", h.Component, req.Intent, params.Describe()),
		}
	}

	slog.Info("performing", "job", req.JobID, "intent", req.Intent, "params", params.Describe())
	output, execErr := h.Execute(ctx, Job{ID: req.JobID, Intent: req.Intent, Params: params})
	truncated, wasCut := protocol.TruncateOutput(output)
	resp := privsep.Response{ExitCode: ExitOK, Output: truncated, OutputTruncated: wasCut}
	if execErr != nil {
		resp.ExitCode = ExitFailed
		resp.Error = execErr.Error()
		slog.Error("the operation failed", "job", req.JobID, "intent", req.Intent, "error", execErr)
		return resp
	}
	slog.Info("the operation completed", "job", req.JobID, "intent", req.Intent)
	return resp
}

// Serve answers the one request systemd's socket activation handed this process, then exits.
//
// The helper units are Accept=yes, so this process *is* one connection: there is no listening socket
// here, no accept loop, and no long-running root daemon. It exists for as long as the operation does
// and no longer, which is a smaller thing to get wrong than a resident privileged service.
//
// The exit status reports whether the mechanism worked, not whether the operation was permitted. A
// policy refusal is a successful answer — the refusal is in the reply — and marking the unit failed for
// one would fill an operator's journal with red for the system working exactly as designed.
func (h Helper) Serve() {
	RequireRoot()

	agentUID, err := privsep.AccountUID(privsep.AgentAccount)
	if err != nil {
		Fatalf(ExitUsage, "%v", err)
	}
	conn, err := privsep.ConnFromSystemd()
	if err != nil {
		Fatalf(ExitUsage, "%v", err)
	}

	// SIGTERM cancels the operation's context rather than killing the process outright, so that a
	// helper stopped mid-upgrade still writes a reply. The agent hearing "interrupted" can report that;
	// the agent hearing nothing reports a host that went quiet.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := privsep.ServeConn(ctx, conn, agentUID, h.Perform); err != nil {
		slog.Error("the request could not be answered", "component", h.Component, "error", err)
		os.Exit(ExitUsage)
	}
	os.Exit(ExitOK)
}

// Main runs the helper's command-line path, then exits.
//
// It is the path an administrator uses to diagnose a host by hand, and it runs the same Perform the
// socket does against the same packaged policy file — which is what makes it evidence about production
// rather than a separate program that agrees today.
//
// In dryRun the decision is evaluated and printed and nothing is done, so it does not require root. It
// still reads the packaged policy file and cannot be pointed at another one.
func (h Helper) Main(req Request, dryRun bool) {
	if dryRun {
		decision, _, err := Authorise(req, policy.Path, time.Now())
		if err != nil {
			Fatalf(ExitUsage, "%v", err)
		}
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

	RequireRoot()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	resp := h.Perform(ctx, req)
	if out := strings.TrimRight(resp.Output, "\n"); out != "" {
		fmt.Println(out)
	}
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "farrier-helper: %s\n", resp.Error)
	}
	stop()
	os.Exit(resp.ExitCode)
}
