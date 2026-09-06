//go:build linux

package policy

// Path is where the policy file lives on a managed host.
//
// It is a constant rather than a configurable path because a policy file whose location the agent
// chooses is a policy file the agent can point somewhere it controls. The helpers hard-code this same
// constant, which is the point.
const Path = "/etc/hostseal/policy.toml"

// PausedPath is the kill-switch marker a local administrator can create.
//
// Together with `systemctl stop hostseal-agent` it is a stop the control plane cannot override, which is
// why there is deliberately no agent.resume intent: an off switch that something else can flip back on
// is not an off switch.
const PausedPath = "/etc/hostseal/paused"
