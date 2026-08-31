//go:build !linux

package agent

import "os"

// directoryOwner reports that this platform has no owner to read, so nothing is adopted.
//
// It exists for the reason internal/privsep's peer_other.go exists: so that `go build ./...` and an
// editor's language server work off Linux, not so that the agent runs there. Farrier ships no Windows
// or macOS agent, and cmd/farrier-agent carries a build constraint that says so — this file only keeps
// the library half compiling, which is what a Windows agent would have to start from.
//
// Returning false rather than a zero-valued ownership is the whole point. AdoptStateDir's caller reads
// the boolean as "there is nobody here to be locked out of this directory" and does nothing; a zero
// value would read as "root owns it" and chown the credential to uid 0 on a platform where that means
// nothing at all.
func directoryOwner(os.FileInfo) (ownership, bool) {
	return ownership{}, false
}
