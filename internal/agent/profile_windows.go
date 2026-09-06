//go:build windows

package agent

import "github.com/pascalgross/hostseal/internal/intent"

// hostProfile is the set of catalogue members this build will execute.
//
// The read tier only. See profile_linux.go for why this is a const in a build-tagged file rather than a
// variable, and docs/SECURITY.md §12.3 for why a Windows host executes no privileged intent: without a
// fresh, socket-activated root helper re-reading the host's own policy, a privileged operation would
// rest on the agent process alone, and §1's second and third clauses would rest on it with them.
const hostProfile = intent.ProfileWindowsReadOnly
