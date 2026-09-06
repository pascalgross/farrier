//go:build windows

package policy

// Path is where the policy file lives on a managed Windows host.
//
// A constant, for the same reason the Linux path is one: a policy file whose location the agent chooses
// is a policy file the agent can point somewhere it controls.
//
// Program Files rather than ProgramData, and that is the whole security argument on this platform. The
// Linux file is protected by ownership — root:root, and the agent runs as a different user — and Windows
// has no equivalent that comes for free. %ProgramData% looks like the natural home for machine-wide
// configuration and is exactly wrong here: its inherited ACL grants CREATOR OWNER full control on new
// files and lets ordinary accounts create them, so a file the agent's own service account could rewrite
// would be a policy the agent enforces against itself. %ProgramFiles% inherits an ACL that grants
// ordinary accounts read and execute only, which is the property that makes local policy sovereign.
//
// The installer sets the ACL explicitly rather than relying on that inheritance, because an inherited
// permission is one somebody can change without meaning to. See packaging/windows/Install-HostSealAgent.ps1.
const Path = `C:\Program Files\HostSeal\policy.toml`

// PausedPath is the kill-switch marker a local administrator can create.
//
// Together with `Stop-Service hostseal-agent` it is a stop the control plane cannot override, which is
// why there is deliberately no agent.resume intent: an off switch that something else can flip back on
// is not an off switch.
const PausedPath = `C:\Program Files\HostSeal\paused`
