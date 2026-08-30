//go:build windows

package agent

// DefaultStateDir is where the agent keeps everything it writes.
//
// %ProgramData% rather than %ProgramFiles%, and the split from the policy file is the point. This
// directory holds what the *agent* owns and rewrites — the credential, the CA bundle, the salt, the
// result spool — so the agent's own service account must be able to write it. The policy file and the
// trust anchor are the opposite: they bound the agent, so they live under Program Files where its
// account has read and execute only. A single directory holding both would be either a policy the agent
// could rewrite or a spool it could not.
//
// The installer sets this directory's ACL explicitly and does not rely on what ProgramData inherits.
// The inherited ACL grants CREATOR OWNER full control on new files and lets ordinary accounts create
// them, which is fine for the agent's own state and would be a hole for anything else.
const DefaultStateDir = `C:\ProgramData\Farrier`

// DefaultServerCABundle is where an administrator puts the control plane's CA before enrolling.
//
// Under Program Files with the policy file, for the same reason: it is administrator-supplied
// configuration chosen before the agent exists, and an agent that could rewrite the authority it
// verifies its control plane against would be verifying against one it chose.
const DefaultServerCABundle = `C:\Program Files\Farrier\server-ca.crt`

// MachineIDPath is unused on Windows and is the empty string.
//
// Windows has no /etc/machine-id. The stable identity is the Cryptography\MachineGuid registry value,
// read through internal/winapi and hashed with the same per-host salt, so nothing downstream changes.
// The constant is kept so that code shared with the Linux agent still compiles, and is empty rather than
// pointing at a plausible file so that a caller that used it by mistake fails immediately rather than
// reading something that happened to exist.
//
// It carries the same warning MachineGUID does, and it is worse here: the value is cloned with a disk
// image. A fleet built by copying one prepared virtual machine without running Sysprep has many hosts
// claiming one identity.
const MachineIDPath = ""
