//go:build !linux

package privsep

import (
	"errors"
	"net"
)

// PeerOf reports that peer credentials are unavailable on this platform.
//
// Farrier manages Ubuntu and Debian hosts and its helpers only ever run on Linux, so this file exists
// so that `go build ./...` and an editor's language server work on a maintainer's laptop — not so that
// the helpers can run elsewhere. It fails closed rather than returning a permissive zero value: a build
// that reached this would be one where nothing could be authorised, which is the correct outcome for a
// privilege check that cannot be performed.
func PeerOf(_ *net.UnixConn) (Peer, error) {
	return Peer{}, errors.New("privsep: peer credentials are only available on Linux, " +
		"and the root helpers only ever run there")
}
