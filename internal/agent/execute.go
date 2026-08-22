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
func accept(job protocol.Job, hostID string, p policy.Policy, signers *signing.SignerSet,
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
		return acceptance{
			status: protocol.StatusUnsupportedIntent,
			reason: fmt.Sprintf("%s has no executor in this build: phase 0 ships no write capability", spec.Name),
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

	// 4. Verify the signature the class requires, against this host's own trust anchor.
	if spec.Class.RequiresOfflineSignature() {
		if err := verifyOfflineSignature(job, hostID, signers); err != nil {
			return acceptance{status: protocol.StatusRefusedUnsigned, reason: err.Error()}
		}
	}

	// 5. Refuse a replayed nonce — but only for a job whose signature has already verified above.
	//    Recording it first would let anyone who can reach the agent burn a nonce with a job carrying a
	//    garbage signature, and the nonce store is persistent, so the genuine job bearing that nonce
	//    would be refused as a replay for as long as its signature remained valid.
	if job.Signature != "" && spec.Class.RequiresOfflineSignature() {
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

	return acceptance{spec: spec, params: params}
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

// Execute runs an accepted job and produces its result.
//
// Only read-only intents reach here in phase 0, because Accept refuses anything without an executor.
// The privileged branch is deliberately absent rather than stubbed: an empty case that a future change
// could fill in without touching the acceptance sequence is exactly the shape of the mistake this
// design is meant to prevent.
func Execute(ctx context.Context, spec intent.Spec, params intent.Params, plat collect.Platform) (any, error) {
	switch spec.Name {
	case intent.FactsCollect:
		return collect.Gather(ctx, plat, collector.All()...)

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

// Run executes a job end to end and returns the result to report.
//
// It never returns an error: every outcome, including a refusal and a crash in collection, becomes a
// result the control plane is told about. A job that produced no result at all would sit in the queue
// looking like a host that had gone quiet, which is the least useful thing a fleet tool can do.
func Run(ctx context.Context, job protocol.Job, hostID string, p policy.Policy,
	signers *signing.SignerSet, nonces *NonceStore, plat collect.Platform,
	clockOffset time.Duration, beforeExecute func(protocol.ResultRequest) error) protocol.ResultRequest {

	started := time.Now()
	result := protocol.ResultRequest{JobID: job.ID, StartedAt: started}

	decision := accept(job, hostID, p, signers, nonces, clockOffset, started)
	if !decision.accepted() {
		result.Status = decision.status
		result.Error = decision.reason
		result.FinishedAt = time.Now()
		return result
	}

	// An operation that can complete by the host disappearing needs its result on disk *before* it
	// starts. host.reboot is the case: an agent that wrote the result afterwards would write nothing at
	// all, and the job would sit in the queue looking like a host that had gone quiet. The provisional
	// record is replaced by the real one below if this process is still here to write it.
	if decision.spec.MayNotReturn && beforeExecute != nil {
		provisional := result
		provisional.Status = protocol.StatusSucceeded
		provisional.FinishedAt = started
		provisional.Output = "This result was written and fsynced before the operation began, because " +
			decision.spec.Name.String() + " can complete by the host disappearing. If the host came " +
			"back and the operation had failed, a later result replaced this one."
		if err := beforeExecute(provisional); err != nil {
			// Refused rather than attempted. An operation that may take the host away, whose result
			// cannot be written down first, is one whose outcome nobody would ever learn.
			result.Status = protocol.StatusFailed
			result.Error = "refusing to start an operation that may not return, because its result " +
				"could not be recorded first: " + err.Error()
			result.FinishedAt = time.Now()
			return result
		}
	}

	output, err := Execute(ctx, decision.spec, decision.params, plat)
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
