// Package privsep carries one privileged request from the unprivileged agent to a root helper.
//
// It exists because the design's original answer — the agent calls the helpers through sudo(8) — cannot
// work, and phase 0 shipped with that written down as unresolved in packaging/README.md and in the unit
// file. With NoNewPrivileges=yes in force, execve silently drops the setuid bit, so sudo fails with
// "effective uid is not 0"; and systemd *implies* NoNewPrivileges from ProtectKernelTunables,
// ProtectKernelModules, ProtectClock, RestrictNamespaces, RestrictSUIDSGID, MemoryDenyWriteExecute,
// LockPersonality and SystemCallFilter, every one of which the agent's unit sets. Making sudo work
// would have meant dropping most of the sandbox.
//
// So the privilege boundary is a socket instead. Each root helper is socket-activated by systemd:
// /run/hostseal/<helper>.sock is owned root:hostseal and mode 0660, and a connection to it starts a fresh
// root instance of that one helper with the connection as its standard input. Nothing is setuid,
// nothing about the agent's sandbox is relaxed, and no long-running root process is added — the helper
// exists only for as long as the operation does.
//
// Three properties of the old sudoers entry are kept deliberately, because they are what made it safe:
//
//   - The set of reachable programs is closed and visible in one place. It is the endpoints map below,
//     and the guarantee suite pins it against the catalogue exactly as it pinned the sudoers file.
//   - A caller names an intent, never a program. There is no field in Request that can hold a path, a
//     command or a shell fragment, and the helper on the other side re-decodes the parameters through
//     the catalogue and re-evaluates the root-owned policy file before acting.
//   - Authorisation is by identity rather than by anything the caller says about itself. sudoers named
//     the hostseal user; the socket's mode names the hostseal group, and the helper additionally reads
//     the peer's credentials from the kernel, which is the one claim about a caller that a caller
//     cannot forge.
package privsep

import (
	"encoding/json"
	"time"

	"github.com/pascalgross/hostseal/internal/intent"
)

// SocketDir is the runtime directory holding the helper sockets.
//
// It is under /run rather than /var/run because /var/run is a compatibility symlink, and because the
// directory must be recreated empty on every boot: a stale socket file surviving a crash would be a
// path the agent connects to and nothing answers on.
const SocketDir = "/run/hostseal"

// The three helper sockets, one per root helper.
//
// They are separate sockets rather than one multiplexed endpoint so that the mapping from an intent to
// the program that serves it is made by systemd, from unit files a reviewer can read, rather than by a
// dispatcher process deciding at run time. There is deliberately no fourth socket, and no socket that
// serves more than the one helper named in its unit.
const (
	// ApplyUpdatesSocket reaches /usr/libexec/hostseal/apply-updates.
	ApplyUpdatesSocket = SocketDir + "/apply-updates.sock"

	// RestartUnitSocket reaches /usr/libexec/hostseal/restart-unit.
	RestartUnitSocket = SocketDir + "/restart-unit.sock"

	// RebootHostSocket reaches /usr/libexec/hostseal/reboot-host.
	RebootHostSocket = SocketDir + "/reboot-host.sock"
)

// endpoints is the complete set of privileged operations the agent can reach, and the only one.
//
// This map is the successor to /etc/sudoers.d/hostseal and carries the same weight: an intent that is
// not in it has no route from the agent to root at all, whatever the policy file says and however well
// the job was signed. It is a compile-time map with no mutating accessor for the same reason the intent
// catalogue is — a registry would make the set of privileged operations a property of what was linked
// in rather than of what is written here — and TestGuaranteeEveryPrivilegedIntentHasExactlyOneEndpoint
// checks it against the catalogue so that adding a privileged intent without deciding which helper
// serves it fails CI rather than failing on a host.
var endpoints = map[intent.Name]string{
	intent.PackagesApplySecurity: ApplyUpdatesSocket,
	intent.PackagesApplyAll:      ApplyUpdatesSocket,

	intent.ServiceStart:   RestartUnitSocket,
	intent.ServiceStop:    RestartUnitSocket,
	intent.ServiceRestart: RestartUnitSocket,

	intent.HostReboot: RebootHostSocket,
}

// Endpoint returns the socket serving an intent, and whether one exists.
//
// It is a total function with a boolean rather than one that returns an empty path, because a caller
// that ignored the second result would otherwise dial the empty string — which fails, but fails with an
// error about a missing file rather than about an intent that has no privileged route by design.
func Endpoint(n intent.Name) (string, bool) {
	path, ok := endpoints[n]
	return path, ok
}

// Endpoints returns every distinct helper socket, for the guarantee suite and for diagnostics.
//
// An operator auditing what the agent can reach on their host should be able to ask the binary rather
// than read the source, which is the same reason internal/run exports its allowlist.
func Endpoints() []string {
	seen := map[string]bool{}
	out := make([]string, 0, 3)
	for _, path := range []string{ApplyUpdatesSocket, RestartUnitSocket, RebootHostSocket} {
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}

// MaxRequestBytes bounds the request a helper will read from the socket.
//
// The catalogue already bounds a parameter object to 8 KiB, so this is generous by two orders of
// magnitude; the point is that a helper running as root never reads without a limit, whatever is on the
// other end of the connection.
const MaxRequestBytes = 64 << 10

// MaxResponseBytes bounds the reply the agent will read from a helper.
//
// It is larger than protocol.MaxJobOutputBytes because the helper truncates the operation's output to
// that before replying and the envelope costs a little more. The bound exists so that a helper which
// has gone wrong cannot exhaust the agent's memory from the privileged side of the boundary.
const MaxResponseBytes = 1 << 20

// RequestTimeout bounds how long a helper waits for its caller to say what it wants.
//
// A connection that is opened and then held says nothing and occupies a root process. Ten seconds is
// far longer than a local write of a few hundred bytes needs and short enough that a stuck caller is
// not a resource an attacker can accumulate.
const RequestTimeout = 10 * time.Second

// Exit codes. They are the interface between the agent and the helpers, and they are defined here — at
// the boundary itself — rather than in either of the two packages that use them, so that neither side
// owns the vocabulary the other has to speak.
//
// The same numbers reach an administrator running a helper by hand, so "exit 3" in a journal and
// "exitCode: 3" in the control plane's UI are the same statement about the same event.
const (
	// ExitOK means the operation completed.
	ExitOK = 0

	// ExitUsage means the request was malformed. It never means the operation was attempted.
	ExitUsage = 2

	// ExitRefused means local policy declined the operation.
	ExitRefused = 3

	// ExitNotImplemented means this build has no executor for the operation.
	//
	// It was every privileged path's ending in phase 0, which shipped no write capability at all. It is
	// kept, and the agent still maps it to unsupported_intent, because a fleet is upgraded host by host:
	// an agent from a later release talking to a helper from an earlier one gets exactly this, and "your
	// package is behind" needs to stay distinguishable from "the operation did not work".
	ExitNotImplemented = 4

	// ExitFailed means the operation was attempted and did not succeed.
	ExitFailed = 5
)

// ReplyTimeout bounds how long a helper spends handing its answer back.
//
// A reply is at most a little over protocol.MaxJobOutputBytes and a unix socket's send buffer is larger
// than that, so a caller that is still there never comes close to this. It exists for the caller that is
// not: an agent killed mid-operation leaves a root process blocked on a write to nobody, and a bound is
// cheaper than reasoning about whether that can happen.
const ReplyTimeout = 30 * time.Second

// Request is one privileged operation, as the agent asks for it.
//
// Note what is absent, because the absence is the design: there is no program, no path, no argument
// vector and no free-form option. The intent names a catalogue member and the parameters are the same
// bytes the control plane sent, which the helper decodes with the same decoder on its own side of the
// privilege boundary. A helper that accepted pre-parsed parameters would be trusting its caller.
type Request struct {
	// JobID identifies the job in the control plane, for the audit log.
	JobID string `json:"jobId"`

	// Intent is the catalogue member being requested.
	Intent intent.Name `json:"intent"`

	// Params is the raw JSON parameter object, exactly as it arrived on the wire.
	//
	// It crosses the boundary as bytes rather than as a decoded value so that the helper runs the
	// catalogue's decoder itself, as root, on the same input. Phase 0's helpers reconstructed this
	// from their own command-line flags because a socket did not exist yet; carrying the original
	// bytes removes that round trip and the chance of the two disagreeing.
	Params json.RawMessage `json:"params"`

	// IssuedAt is when the job's authorisation began, for the local age check.
	//
	// It is chosen by the caller and the helper cannot check it, so be exact about what the age limit
	// is worth here. A lying caller can move it in *either* direction: `now` makes an arbitrarily old
	// job look fresh, and a zero value used to skip the check altogether. So this field does not
	// defend against a compromised agent — nothing at this boundary could, since such an agent can
	// simply mint an equivalent request with a fresh time.
	//
	// What it does defend against is the case the limit was written for, and the reason it is worth
	// forwarding at all: an honest agent talking to a control plane that has been taken over. The
	// agent sends the *signed* notBefore for a signed job — see effectiveIssueTime in
	// internal/agent/execute.go — so the age is measured from something the control plane cannot
	// choose, and a restart signed on Tuesday cannot execute on Friday because the host was offline
	// in between.
	//
	// A zero value means the age check measures nothing, and that is left as it is here rather than
	// refused, because the refusal would have to live in the sequence a helper run by hand shares —
	// and by hand there is no job to be old relative to, which is the case ParseIssuedAt and
	// docs/SECURITY.md §6 both describe. The case worth catching is the signed one, and it is caught
	// where the job still exists: internal/agent/execute.go refuses a signed privileged job whose
	// window is unbounded, so effectiveIssueTime cannot return zero for one. An unsigned job's issue
	// time is chosen by the control plane in any case, so refusing its absence here would turn away a
	// caller who omitted a field while admitting the same caller sending `now`.
	IssuedAt time.Time `json:"issuedAt"`
}

// Response is what the helper reports back.
//
// The exit code is carried rather than only a status because it is the interface the phase 0 helpers
// already had, it is what an administrator running a helper by hand sees, and it is what
// protocol.ResultRequest reports to the control plane.
type Response struct {
	// ExitCode is one of the Exit constants above.
	ExitCode int `json:"exitCode"`

	// Output is the operation's combined output, already truncated by the helper.
	Output string `json:"output,omitempty"`

	// OutputTruncated reports that the output was cut, so a reader knows it is partial by design.
	OutputTruncated bool `json:"outputTruncated,omitempty"`

	// Error is a human-readable failure or refusal reason, empty on success.
	Error string `json:"error,omitempty"`
}
