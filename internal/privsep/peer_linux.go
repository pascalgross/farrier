//go:build linux

package privsep

import (
	"fmt"
	"net"
	"syscall"
)

// PeerOf returns the credentials the kernel recorded for the other end of a unix connection.
//
// SO_PEERCRED is read from the socket rather than taken from anything in the request, because it is the
// one statement about a caller that the caller does not get to make: the kernel copies the connecting
// process's uid, gid and pid at connect time. Everything else a helper knows about who is asking
// arrives over the same channel as the request, and would be worth exactly as much as the request.
func PeerOf(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("privsep: reaching the connection's file descriptor: %w", err)
	}

	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, fmt.Errorf("privsep: reading the peer's credentials: %w", err)
	}
	if credErr != nil {
		return Peer{}, fmt.Errorf("privsep: reading the peer's credentials: %w", credErr)
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}
