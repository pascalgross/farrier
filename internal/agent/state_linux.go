//go:build linux

package agent

import (
	"os"
	"syscall"
)

// directoryOwner returns the uid and gid the kernel recorded for a directory.
//
// It is the one part of AdoptStateDir that cannot be written portably: os.FileInfo carries no owner in
// its portable half, so the answer has to come out of the platform's own stat structure. Keeping it
// behind a build tag rather than inline is what lets the rest of the package compile for a platform
// Farrier does not yet ship an agent for — see state_other.go, which is the same argument
// internal/privsep's peer_other.go makes for the same reason.
func directoryOwner(info os.FileInfo) (ownership, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ownership{}, false
	}
	return ownership{uid: int(st.Uid), gid: int(st.Gid)}, true
}
