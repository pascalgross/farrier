package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/collect"
	"github.com/pascalgross/farrier/internal/collect/collector"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/policy"
	"github.com/pascalgross/farrier/internal/privsep"
	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/signing"
)

// acceptance is the outcome of checking whether a job may run.
//
// It carries a protocol status rather than a boolean, because every refusal reason is reported back to
// the control plane distinctly: an operator debugging a job that did not run needs to know whether it
// was the policy, the signature, the clock or the catalogue.
type acceptance struct {
	// spec is the catalogue entry, valid only when the job was accepted.
	spec intent.Spec

	// params are the decoded, validated parameters.
	params intent.Params

	// raw is the parameter object as JSON, for a privileged job to forward to the helper.
	//
	// It is a re-encoding of job.Params, not the bytes off the wire — the agent decodes a response
	// body once, into protocol.Job, and there is no arrived-bytes copy of this field to keep. Saying
	// otherwise here would describe a property the helper's decode does not have.
	//
	// What forwarding JSON rather than the decoded intent.Params buys is real and is the reason the
	// field exists: the helper runs intent.Decode itself, as root, over this object. It therefore
	// validates the same shape the agent validated rather than a Go struct the agent produced, so a
	// field the agent's own round trip dropped or coerced cannot become the thing root acts on. The
	// helper trusts its caller for none of it — see docs/SECURITY.md §6.
	raw []byte

	// status is the protocol status to report when the job is refused.
	status string

	// reason explains the refusal in words.
	reason string
}

// accepted reports whether the job may run.
func (a acceptance) accepted() bool { return a.status == "" }

// accept runs the agent-side acceptance sequence from docs/PROTOCOL.md §5.1.
//
// The order is the specification's order and each step fails closed. It is worth being explicit about
// what this function is and is not: for a privileged intent it is an optimisation and a better error
// message, because the check that actually holds runs as root inside the helper against the root-owned
// policy file. For a read-only intent, which never reaches a helper, it is the only check there is.
//
// The class is taken from this agent's own compiled-in catalogue and never from the job. A control
// plane that could label host.reboot as "read" would defeat the signature requirement without touching
// the signature code.
func accept(job protocol.Job, hostID string, p policy.Policy, signers, online *signing.SignerSet,
	nonces *NonceStore, clockOffset time.Duration, now time.Time) acceptance {

	// 1. Recognise the intent, and decode and validate its parameters, against the catalogue.
	rawParams, err := json.Marshal(job.Params)
	if err != nil {
		return acceptance{status: protocol.StatusFailed, reason: "parameters could not be re-encoded"}
	}
	spec, params, err := intent.Decode(intent.Name(job.Intent), rawParams)
	if err != nil {
		return acceptance{
			status: protocol.StatusUnsupportedIntent,
			reason: fmt.Sprintf("%s: %v", job.Intent, err),
		}
	}
	if !spec.Implemented {
		// The catalogue is complete, so nothing should reach here in a released build. It stays because
		// an agent talking to a newer control plane can be asked for an intent it does not have, and
		// because internal/intent's `unimplemented` map exists for a member that is deliberately
		// withheld — reporting unsupported_intent is how both cases stay safe rather than guessed at.
		return acceptance{
			status: protocol.StatusUnsupportedIntent,
			reason: fmt.Sprintf("%s has no executor in this build", spec.Name),
		}
	}

	// 2. Refuse privileged work when the clock is too far out to reason about a validity window.
	//    Before the window check, not after: a host whose clock is an hour wrong would otherwise
	//    report every privileged job as "expired", which sends an operator looking at the control
	//    plane's scheduling rather than at the host's clock. The refusal should name the cause.
	//    Read-only intents still run: blinding an operator to the state of a host with a wrong clock
	//    would help nobody.
	if spec.Class.Privileged() && absDuration(clockOffset) > protocol.MaxClockSkewSeconds*time.Second {
		return acceptance{
			status: protocol.StatusRefusedClockSkew,
			reason: fmt.Sprintf("the local clock is %s from the control plane's; privileged intents "+
				"fail closed beyond %ds", clockOffset.Round(time.Second), protocol.MaxClockSkewSeconds),
		}
	}

	// 3. Check the validity window against the local clock. Never against server-supplied time: a
	//    compromised control plane could otherwise extend a signature's window by lying about now.
	if !job.NotBefore.IsZero() && now.Before(job.NotBefore) {
		return acceptance{status: protocol.StatusExpired, reason: "the job's validity window has not opened"}
	}
	if !job.NotAfter.IsZero() && now.After(job.NotAfter) {
		return acceptance{status: protocol.StatusExpired, reason: "the job's validity window has closed"}
	}

	// 4. Verify the signature the class requires, against the anchor that class is verified against.
	//
	//    Two anchors, never interchangeable. A destructive intent verifies against
	//    /etc/farrier/trusted-signers, which the control plane cannot write — that is what
	//    docs/SECURITY.md §1 rests on. A routine intent verifies against the online key the control
	//    plane sent, which is a weaker authority and bounded by the local policy rather than by the
	//    key. Asking the catalogue twice, rather than branching on one boolean, is what keeps a
	//    control plane from ever authorising the destructive tier with its own key.
	switch {
	case spec.Class.RequiresOfflineSignature():
		if err := verifyOfflineSignature(job, hostID, signers); err != nil {
			return acceptance{status: protocol.StatusRefusedUnsigned, reason: err.Error()}
		}
	case spec.Class.RequiresOnlineSignature():
		if err := verifyOnlineSignature(job, hostID, online); err != nil {
			return acceptance{status: protocol.StatusRefusedUnsigned, reason: err.Error()}
		}
	}

	// 4a. Refuse a signed privileged job whose window is not a window.
	//
	//     Three separate replay defences each degrade to "no bound" on a zero time, and they degrade
	//     together: step 3 treats a zero notAfter as open forever, effectiveIssueTime falls back to the
	//     *unsigned* issuedAt when notBefore is zero so max_job_age_seconds measures from a number the
	//     control plane chooses, and the nonce record would expire on a schedule of its own. A
	//     compromised control plane holding one such job could then redeliver it indefinitely, and it
	//     would be a validly signed destructive job every time — without ever holding the offline key.
	//
	//     Nothing shipped produces one: `farrier sign` sets both edges and refuses --valid-for ≤ 0. That
	//     is the point of checking here rather than trusting it. The agent is the side that has to
	//     survive a signer it did not write, and this is the one check that closes all three at once.
	//
	//     After the signature rather than before it, so that an unsigned job is refused for being
	//     unsigned — the message an operator can act on — rather than for a window it was never going
	//     to have.
	if job.Signature != "" && spec.Class.Privileged() {
		switch {
		case job.NotBefore.IsZero():
			return acceptance{status: protocol.StatusRefusedUnsigned,
				reason: "the signature covers no start time, so nothing bounds how old this job may be"}
		case job.NotAfter.IsZero():
			return acceptance{status: protocol.StatusRefusedUnsigned,
				reason: "the signature covers no expiry, so the authorisation would never lapse"}
		}
	}

	// 5. Refuse a replayed nonce — but only for a job whose signature has already verified above.
	//    Recording it first would let anyone who can reach the agent burn a nonce with a job carrying a
	//    garbage signature, and the nonce store is persistent, so the genuine job bearing that nonce
	//    would be refused as a replay for as long as its signature remained valid.
	//
	//    Both privileged tiers, not just the destructive one: a routine job is signed, so it can be
	//    replayed, and a control plane that could re-deliver yesterday's applySecurity indefinitely
	//    would be re-running an operation whose window the signature was supposed to bound.
	if job.Signature != "" && spec.Class.Privileged() {
		seen, err := nonces.Check(job.Nonce, job.NotAfter)
		if err != nil {
			return acceptance{status: protocol.StatusFailed, reason: "the replay store is unusable: " + err.Error()}
		}
		if seen {
			return acceptance{status: protocol.StatusRefusedUnsigned, reason: "this job's nonce has already been used"}
		}
	}

	// 6. Apply the local policy, including the job age limit.
	decision := policy.Decide(p, policy.Request{
		Intent:   spec.Name,
		Params:   params,
		IssuedAt: effectiveIssueTime(job),
	}, policy.Env{Now: now, Paused: policy.Paused()})
	if !decision.Allowed {
		status := protocol.StatusRefusedByPolicy
		if decision.Code == policy.CodeExpired {
			status = protocol.StatusExpired
		}
		return acceptance{status: status, reason: decision.Reason}
	}

	return acceptance{spec: spec, params: params, raw: rawParams}
}

// verifyOfflineSignature checks a destructive job against the host's own trusted-signers.
//
// A signature by the control plane's online key is not acceptable here, and there is no code path by
// which it could be: the only key set consulted is the one read from /etc/farrier/trusted-signers, which
// the control plane cannot write.
func verifyOfflineSignature(job protocol.Job, hostID string, signers *signing.SignerSet) error {
	if signers.Empty() {
		return fmt.Errorf("%s requires a signature from a key in %s, and this host has none",
			job.Intent, signing.TrustedSignersPath)
	}
	signature, err := decodeSignature(job.Signature)
	if err != nil {
		return err
	}
	payload, err := canonical.Marshal(job.SignedPayload(hostID))
	if err != nil {
		return fmt.Errorf("could not canonicalise the signed payload: %w", err)
	}
	key, err := signers.Verify(payload, signature)
	if err != nil {
		return fmt.Errorf("no key in %s produced this signature: %w", signing.TrustedSignersPath, err)
	}
	if job.SignerKeyID != "" && job.SignerKeyID != key.KeyID {
		// Not fatal by itself — the signature verified against a trusted key, which is what matters —
		// but a mismatch means the control plane's record of who authorised the job disagrees with the
		// host's, and the audit trail should not quietly take the server's word for it.
		return fmt.Errorf("the job names signer %q but verified against %q", job.SignerKeyID, key.KeyID)
	}
	return nil
}

// verifyOnlineSignature checks a routine job against the control plane's own key.
//
// It is a separate function from verifyOfflineSignature holding almost the same code, and the
// duplication is deliberate. The two verify different authorities against different anchors, and the
// obvious refactor — one function taking whichever key set applies — is exactly the shape in which a
// caller eventually passes the wrong one. There is no argument here that could make this accept a
// destructive job, because it never sees the trusted-signers set at all.
//
// What it means when this succeeds is narrower than the offline case, and worth remembering when
// reading it: the control plane authorised this, and the control plane is inside the threat model. The
// bound on a routine intent is the host's local policy, which the root helper re-reads for itself. See
// docs/SECURITY.md §3.
func verifyOnlineSignature(job protocol.Job, hostID string, online *signing.SignerSet) error {
	if online.Empty() {
		return fmt.Errorf("%s requires a signature by the control plane's online key, and this host "+
			"has not been given one", job.Intent)
	}
	signature, err := decodeSignature(job.Signature)
	if err != nil {
		return err
	}
	payload, err := canonical.Marshal(job.SignedPayload(hostID))
	if err != nil {
		return fmt.Errorf("could not canonicalise the signed payload: %w", err)
	}
	key, err := online.Verify(payload, signature)
	if err != nil {
		return fmt.Errorf("the control plane's online key did not produce this signature: %w", err)
	}
	if job.SignerKeyID != "" && job.SignerKeyID != key.KeyID {
		return fmt.Errorf("the job names signer %q but verified against %q", job.SignerKeyID, key.KeyID)
	}
	return nil
}

// effectiveIssueTime returns the instant the local age limit is measured from.
//
// issuedAt is not covered by a job's signature — the signed payload is fixed by docs/PROTOCOL.md §8 and
// does not include it — so for a signed job it is a number the control plane chooses freely. A control
// plane that had been taken over could defeat limits.max_job_age_seconds entirely by setting issuedAt
// to the current time, which is the one thing that limit exists to prevent: a restart signed on Tuesday
// executing on Friday because the agent was offline in between.
//
// notBefore *is* signed, and is when the signer said the job became valid. Measuring from it means the
// age limit binds whoever holds the key rather than whoever holds the control plane. An unsigned job —
// a read intent — has nothing to defend, so its issuedAt is taken at face value.
func effectiveIssueTime(job protocol.Job) time.Time {
	if job.Signature != "" && !job.NotBefore.IsZero() {
		return job.NotBefore
	}
	return job.IssuedAt
}

// absDuration returns the magnitude of a duration.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Execute runs an accepted read-only intent in this process and produces its typed result.
//
// Only read-only intents reach here, and that is the design rather than an accident of what is
// implemented: every privileged operation happens in a root helper on the other side of a socket, so
// there is no branch of this function a future change could fill in to make the agent itself act on a
// host. Runner.elevate is the whole of the other path, and it names an intent rather than an operation.
//
// The local policy arrives as a parameter for the same reason the platform does, and it is the one the
// job was accepted under. A read intent needs no permission, but some sections of a fact report are a
// disclosure the host may refuse, and facts.collect must give the same answer as the heartbeat does —
// a control plane that could get a section by asking for it that the host had switched off in its
// heartbeat would make the switch decorative.
func Execute(ctx context.Context, spec intent.Spec, params intent.Params, plat collect.Platform,
	local policy.Policy) (any, error) {

	switch spec.Name {
	case intent.FactsCollect:
		return collect.Gather(ctx, plat, local, collector.All()...)

	case intent.PackagesListUpgradable:
		packages, err := plat.UpgradablePackages(ctx)
		if err != nil {
			return nil, err
		}
		return collect.Summarise(packages), nil

	case intent.ServicesList:
		units, truncated, err := collect.ListUnits(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"services": units, "truncated": truncated}, nil

	case intent.RebootCheckRequired:
		return plat.RebootRequired(ctx)

	default:
		// Unreachable while Accept refuses unimplemented intents, and kept as a hard failure rather
		// than a silent success so that adding a catalogue member without an executor is a visible
		// error rather than a job that reports success having done nothing.
		return nil, fmt.Errorf("agent: %s has no executor", spec.Name)
	}
}

// Runner holds everything one job needs to be accepted, executed and reported.
//
// It is a struct rather than a longer parameter list because two of its fields are now interfaces, and
// a call site that passes eight positional values of which two are seams is one where a test can wire
// the wrong seam without the compiler noticing. Named fields also make the one rule that cannot be
// expressed in a signature visible at every call site: Spool is not optional for an operation that may
// take the host away.
type Runner struct {
	// HostID is this host's control-plane identifier, which is part of every signed payload.
	HostID string

	// Policy is the local policy as the agent last read it.
	Policy policy.Policy

	// Signers is the host's own trust anchor, read from /etc/farrier/trusted-signers.
	//
	// The authority for every destructive intent, and the one the control plane cannot write.
	Signers *signing.SignerSet

	// Online is the control plane's own key, as this host last cached it.
	//
	// A separate field rather than another entry in Signers, and that separation is the mechanism
	// rather than tidiness: merging them would make a control plane's own key acceptable for the
	// destructive tier, which is the single thing docs/SECURITY.md §1 promises cannot happen. Empty
	// when no control plane has sent one, in which case routine intents are refused.
	Online *signing.SignerSet

	// Nonces refuses a replayed signature across restarts.
	Nonces *NonceStore

	// Platform is the distribution-family implementation, used only by read-only intents.
	Platform collect.Platform

	// Elevate is the route to the root helpers. A nil value means this build has none.
	//
	// It is an interface so that the job path can be tested without a root helper and without systemd —
	// the same reason the platform is an interface. It is not an extension point: a second
	// implementation outside a test would be a second privileged route, and internal/privsep is
	// arranged so that there is exactly one.
	Elevate privsep.Invoker

	// ClockOffset is the agent's own measurement of its offset from the control plane.
	ClockOffset time.Duration

	// Spool writes a result to disk and fsyncs it, before the operation it describes has run.
	//
	// It is required for any operation that may not return, and Run refuses rather than proceeding
	// without it. See the refusal in Run for why that is not merely defensive.
	Spool func(protocol.ResultRequest) error
}

// Run executes a job end to end and returns the result to report.
//
// It never returns an error: every outcome, including a refusal and a crash in collection, becomes a
// result the control plane is told about. A job that produced no result at all would sit in the queue
// looking like a host that had gone quiet, which is the least useful thing a fleet tool can do.
func (r Runner) Run(ctx context.Context, job protocol.Job) protocol.ResultRequest {
	started := time.Now()
	result := protocol.ResultRequest{JobID: job.ID, StartedAt: started}

	decision := accept(job, r.HostID, r.Policy, r.Signers, r.Online, r.Nonces, r.ClockOffset, started)
	if !decision.accepted() {
		result.Status = decision.status
		result.Error = decision.reason
		result.FinishedAt = time.Now()
		return result
	}

	// An operation that can complete by the host disappearing needs its result on disk *before* it
	// starts. host.reboot is the obvious case, and an update job carrying rebootIfRequired is the one
	// that is easy to miss — which is why the question is asked of the parameters and not only of the
	// catalogue entry. An agent that wrote the result afterwards would write nothing at all, and the
	// job would sit in the queue looking like a host that had gone quiet. The provisional record is
	// replaced by the real one below if this process is still here to write it.
	if intent.MayNotReturn(decision.spec, decision.params) {
		if r.Spool == nil {
			// A refusal rather than a shrug. An operation that may take the host away, whose result
			// cannot be recorded first, is one whose outcome nobody would ever learn — and a Runner
			// assembled without a Spool is a programming error, not a host condition, so it must be
			// loud where it happens rather than silent until the one reboot that is never reported.
			result.Status = protocol.StatusFailed
			result.Error = "refusing to start an operation that may not return: this agent has no way " +
				"to record a result before it begins"
			result.FinishedAt = time.Now()
			return result
		}
		provisional := result
		provisional.Status = protocol.StatusSucceeded
		provisional.FinishedAt = started
		provisional.Output = "This result was written and fsynced before the operation began, because " +
			decision.spec.Name.String() + " can complete by the host disappearing. If the host came " +
			"back and the operation had failed, a later result replaced this one."
		if err := r.Spool(provisional); err != nil {
			result.Status = protocol.StatusFailed
			result.Error = "refusing to start an operation that may not return, because its result " +
				"could not be recorded first: " + err.Error()
			result.FinishedAt = time.Now()
			return result
		}
	}

	if decision.spec.Class.Privileged() {
		return r.elevate(ctx, job, decision, result)
	}

	output, err := Execute(ctx, decision.spec, decision.params, r.Platform, r.Policy)
	result.FinishedAt = time.Now()
	if err != nil {
		result.Status = protocol.StatusFailed
		result.Error = err.Error()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			result.Error = "the job was interrupted: " + err.Error()
		}
		return result
	}
	result.Status = protocol.StatusSucceeded
	result.Result = output
	return result
}

// elevate hands a privileged job to the root helper that serves it and maps the reply onto a result.
//
// The agent does not perform the operation and does not learn how it was performed. It names an intent,
// forwards the parameter bytes it received, and reports what came back — which is the whole of its
// involvement in every privileged thing Farrier does.
func (r Runner) elevate(ctx context.Context, job protocol.Job, decision acceptance,
	result protocol.ResultRequest) protocol.ResultRequest {

	if r.Elevate == nil {
		result.Status = protocol.StatusFailed
		result.Error = "this agent has no route to the root helpers"
		result.FinishedAt = time.Now()
		return result
	}

	ctx, cancel := context.WithTimeout(ctx, privsep.InvokeFor(decision.spec.Name))
	defer cancel()

	resp, err := r.Elevate.Invoke(ctx, privsep.Request{
		JobID:  job.ID,
		Intent: decision.spec.Name,
		Params: decision.raw,
		// The *effective* issue time, which for a signed job is the signed notBefore. The helper runs
		// the age check again against whatever it is given, so handing it the unsigned issuedAt would
		// reopen the limits.max_job_age_seconds bypass on the root side of the boundary — where it
		// matters most, and where nothing else would catch it.
		IssuedAt: effectiveIssueTime(job),
	})
	result.FinishedAt = time.Now()
	if err != nil {
		result.Status = protocol.StatusFailed
		result.Error = err.Error()
		return result
	}

	result.ExitCode = resp.ExitCode
	result.Error = resp.Error
	result.Status = statusForExit(resp.ExitCode)

	// Truncated again on this side even though the helper already did it. A helper from an older
	// package might not have, and an over-size result is not merely untidy: the server rejects a body
	// past its limit, DeliverPending only removes a spool file after a 2xx, and the host would then
	// retry the same over-size body for ever.
	output, truncated := protocol.TruncateOutput(resp.Output)
	result.Output = output
	result.OutputTruncated = truncated || resp.OutputTruncated
	return result
}

// statusForExit maps a helper's exit code onto the protocol status the control plane is told.
//
// The mapping is made once, here, rather than at each call site, because the distinction that matters
// most is easy to lose: a refusal is not a failure. An operator who is told "failed" for every job local
// policy declined learns to ignore failures, which is precisely the wrong lesson from the mechanism
// working exactly as designed.
func statusForExit(code int) string {
	switch code {
	case privsep.ExitOK:
		return protocol.StatusSucceeded
	case privsep.ExitRefused:
		return protocol.StatusRefusedByPolicy
	case privsep.ExitNotImplemented:
		// The helper is from an older package than this agent. Reporting it as the same
		// "unsupported_intent" an unknown intent gets is right: in both cases this host cannot do the
		// thing, and in neither was anything attempted.
		return protocol.StatusUnsupportedIntent
	default:
		// ExitUsage and ExitFailed and anything unrecognised. Usage is an agent bug rather than a host
		// condition and should read as a failure so that somebody looks at it.
		return protocol.StatusFailed
	}
}
