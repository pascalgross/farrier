package policy

import (
	"fmt"
	"time"

	"github.com/pascalgross/farrier/internal/intent"
)

// Request is what the control plane asked a host to do.
//
// It carries the decoded intent and parameters rather than the raw job so that this package has no
// opinion about the wire format and no reason to parse anything. The helpers construct one of these
// from their own command line, which is what lets the agent and the root helper reach the same
// decision through the same code without sharing a transport.
type Request struct {
	// Intent is the catalogue member the control plane asked for.
	Intent intent.Name

	// Params are the decoded, already-validated parameters.
	Params intent.Params

	// IssuedAt is when the control plane created the job.
	IssuedAt time.Time
}

// Env is the local state a decision depends on, other than the policy itself.
//
// Passing it in rather than reading the clock and the filesystem inside Decide is what makes
// maintenance-window behaviour testable without waiting for Sunday, and what keeps the decision
// function free of anything that could fail.
type Env struct {
	// Now is the local clock reading. It is never server-supplied; see docs/SECURITY.md §4.3.
	Now time.Time

	// Paused reports whether /etc/farrier/paused exists.
	Paused bool
}

// Decision is the outcome of evaluating a request against a policy.
//
// It carries a reason even when allowed, because the audit log records why a job was permitted as well
// as that it was, and reconstructing that after the fact from the policy file as it stands today is
// exactly the thing you cannot do during an incident.
type Decision struct {
	// Allowed reports whether the host will carry out the request.
	Allowed bool

	// Code is a stable machine-readable reason, suitable for a job result status.
	Code string

	// Reason is a human-readable explanation naming the policy setting responsible.
	Reason string

	// EffectiveAllow is min(requested, local) for update intents, and AllowNone otherwise.
	EffectiveAllow Allow
}

// Error returns the decision as an error when it refuses, and nil when it permits.
//
// It exists so callers can write `if err := policy.Decide(...).Error(); err != nil` in the common case
// while still having the structured Decision available where the audit log needs it.
func (d Decision) Error() error {
	if d.Allowed {
		return nil
	}
	return fmt.Errorf("refused by local policy (%s): %s", d.Code, d.Reason)
}

// Refusal codes. They are stable strings because they end up in job results, in the UI and in
// operators' alerting rules, and renaming one silently breaks somebody's dashboard.
const (
	// CodePaused means /etc/farrier/paused exists.
	CodePaused = "paused"

	// CodeExpired means the job is older than limits.max_job_age_seconds.
	CodeExpired = "expired"

	// CodeUpdatesNotAllowed means updates.allow is lower than the request needs.
	CodeUpdatesNotAllowed = "updates_not_allowed"

	// CodeUnitNotRestartable means the unit is not on services.restartable.
	CodeUnitNotRestartable = "unit_not_restartable"

	// CodeRebootNotAllowed means updates.reboot is never.
	CodeRebootNotAllowed = "reboot_not_allowed"

	// CodeOutsideWindow means the maintenance window is closed.
	CodeOutsideWindow = "outside_window"

	// CodeUnknownIntent means the request named something not in the catalogue.
	CodeUnknownIntent = "unknown_intent"

	// CodePolicyUnreadable means the policy file exists but could not be parsed.
	//
	// It is distinct from every other refusal because it is the only one an operator fixes by editing
	// a file rather than by changing what they asked for. Folding it into "not permitted" produces a
	// refusal that reads as a deliberate policy decision, which is the wrong thing to be told when the
	// real cause is a stray bracket on line 79.
	CodePolicyUnreadable = "policy_unreadable"

	// CodeAllowed is the code recorded for a permitted request.
	CodeAllowed = "allowed"
)

// requestedAllow maps an update intent to the permission level it asks for.
//
// Deriving the central request from the intent, rather than taking it as a separate field, is what
// makes the min() rule of docs/SECURITY.md §2.2 literally the implementation: there is no way to send
// a request for packages.applyAll that claims to only need security permission.
func requestedAllow(name intent.Name) (Allow, bool) {
	switch name {
	case intent.PackagesApplySecurity:
		return AllowSecurity, true
	case intent.PackagesApplyAll:
		return AllowAll, true
	default:
		return AllowNone, false
	}
}

// Decide evaluates a request against a policy and the local environment.
//
// This function is the whole of local policy sovereignty. It runs twice for every privileged job: once
// in the agent, where it saves a round trip and produces a good error message, and once inside the root
// helper, where it is the check that actually holds. The second call is the one the guarantee depends
// on, because it runs as root against the root-owned file and does not trust its caller.
//
// It refuses anything it does not understand. A future intent that reaches this function without a case
// below is refused rather than permitted, so forgetting to add a case fails closed.
func Decide(p Policy, req Request, env Env) Decision {
	if env.Paused {
		return Decision{
			Code:   CodePaused,
			Reason: "the host is paused; " + PausedPath + " exists",
		}
	}

	spec, ok := intent.Lookup(req.Intent)
	if !ok {
		return Decision{
			Code:   CodeUnknownIntent,
			Reason: fmt.Sprintf("%q is not in the intent catalogue", req.Intent),
		}
	}

	// Read-only intents are unprivileged and are not gated by policy. They run as the farrier user
	// with no capabilities and read nothing an unprivileged local user could not read; refusing them
	// would blind the operator to the state of a host without protecting anything.
	if !spec.Class.Privileged() {
		return Decision{Allowed: true, Code: CodeAllowed, Reason: "read-only intent"}
	}

	if !req.IssuedAt.IsZero() {
		age := env.Now.Sub(req.IssuedAt)
		maxAge := time.Duration(p.Limits.MaxJobAgeSeconds) * time.Second
		if age > maxAge {
			return Decision{
				Code: CodeExpired,
				Reason: fmt.Sprintf("job is %s old, limits.max_job_age_seconds is %d",
					age.Round(time.Second), p.Limits.MaxJobAgeSeconds),
			}
		}
	}

	switch req.Intent {
	case intent.PackagesApplySecurity, intent.PackagesApplyAll:
		return decideUpdate(p, req, env)

	case intent.ServiceStart, intent.ServiceStop, intent.ServiceRestart:
		unit, ok := req.Params.(intent.UnitParams)
		if !ok {
			return Decision{
				Code:   CodeUnitNotRestartable,
				Reason: fmt.Sprintf("%s requires unit parameters", req.Intent),
			}
		}
		if !p.RestartableAllows(unit.Unit) {
			return Decision{
				Code: CodeUnitNotRestartable,
				Reason: fmt.Sprintf("%q is not matched by services.restartable %v",
					unit.Unit, p.Services.Restartable),
			}
		}
		return Decision{Allowed: true, Code: CodeAllowed,
			Reason: fmt.Sprintf("%q is matched by services.restartable", unit.Unit)}

	case intent.HostReboot:
		return decideReboot(p, env)

	default:
		return Decision{
			Code: CodeUnknownIntent,
			Reason: fmt.Sprintf("%q is privileged but this policy build has no rule for it; "+
				"refusing", req.Intent),
		}
	}
}

// decideUpdate applies the min(central request, local policy) rule to an update intent.
func decideUpdate(p Policy, req Request, env Env) Decision {
	wanted, ok := requestedAllow(req.Intent)
	if !ok {
		return Decision{Code: CodeUnknownIntent, Reason: fmt.Sprintf("%q is not an update intent", req.Intent)}
	}
	effective := Min(wanted, p.Updates.Allow)
	if effective != wanted {
		return Decision{
			Code: CodeUpdatesNotAllowed,
			Reason: fmt.Sprintf("%s needs updates.allow >= %q, this host allows %q",
				req.Intent, wanted, p.Updates.Allow),
			EffectiveAllow: effective,
		}
	}

	// A request to reboot afterwards is evaluated as a reboot, because that is what it is. Letting it
	// through on the strength of the update permission alone would make "reboot = never" mean "never,
	// unless the update job asked nicely".
	if apply, ok := req.Params.(intent.ApplyParams); ok && apply.RebootIfRequired {
		if d := decideReboot(p, env); !d.Allowed {
			d.EffectiveAllow = effective
			d.Reason = "updates are permitted but the requested follow-up reboot is not: " + d.Reason
			return d
		}
	}

	return Decision{
		Allowed:        true,
		Code:           CodeAllowed,
		Reason:         fmt.Sprintf("updates.allow is %q", p.Updates.Allow),
		EffectiveAllow: effective,
	}
}

// decideReboot evaluates whether the host will reboot now.
func decideReboot(p Policy, env Env) Decision {
	if p.Updates.Reboot != RebootWindow {
		return Decision{
			Code:   CodeRebootNotAllowed,
			Reason: fmt.Sprintf("updates.reboot is %q", p.Updates.Reboot),
		}
	}
	if !p.window.Contains(env.Now) {
		next := p.window.NextOpen(env.Now)
		reason := fmt.Sprintf("outside the maintenance window %q (%s)", p.window, p.Updates.Timezone)
		if !next.IsZero() {
			reason += "; next opens " + next.Format(time.RFC3339)
		}
		return Decision{Code: CodeOutsideWindow, Reason: reason}
	}
	return Decision{
		Allowed: true,
		Code:    CodeAllowed,
		Reason:  fmt.Sprintf("inside the maintenance window %q (%s)", p.window, p.Updates.Timezone),
	}
}
