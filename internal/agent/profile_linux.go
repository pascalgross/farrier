//go:build linux

package agent

import "github.com/pascalgross/farrier/internal/intent"

// hostProfile is the set of catalogue members this build will execute.
//
// A const in a build-tagged file, and both halves of that are the design. Const, so that nothing can
// assign to it: a var would be one line of a future refactor away from being set from configuration, and
// a profile chosen at run time is a profile an attacker who reaches the process can widen. Build-tagged,
// so that the answer is decided by which binary was produced rather than by a check the binary performs
// on itself — a Linux agent does not contain the Windows answer at all.
//
// It is deliberately not on the wire in the direction that would matter. The agent reports its profile
// so that the control plane can refuse a job at creation with a useful message, and the control plane's
// copy is used for that and for greying out buttons — never as permission. The enforcement is here,
// against this constant, so a lying host can only make the control plane offer it more, and a lying
// control plane cannot make this host accept more.
const hostProfile = intent.ProfileLinux
