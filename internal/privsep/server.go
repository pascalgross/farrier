package privsep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"
)

// AgentAccount is the system account the agent runs as.
//
// It is the name the package's maintainer scripts create and the name the socket units give the helper
// sockets as their group. Resolving it to a uid at run time rather than compiling one in is what makes
// the check work on a host whose adduser picked a different number, which is every host.
const AgentAccount = "farrier"

// Peer is the kernel's account of who is on the other end of a helper socket.
//
// It is read with SO_PEERCRED, which is the one claim about a caller that a caller cannot make: the
// values are recorded by the kernel at connect time from the connecting process's own credentials, so
// nothing in the request has to be believed in order to know who sent it. That is the property the
// sudoers entry had, and it is why the socket's file mode is a second line of defence rather than the
// only one.
type Peer struct {
	// UID is the connecting process's effective user id.
	UID uint32

	// GID is its effective group id.
	GID uint32

	// PID is its process id, recorded for the audit log rather than for any decision.
	//
	// A pid is not an identity — it is reused, and the process behind it may have exited between the
	// connect and the read — so it is logged and never checked. Deciding on it would be a
	// time-of-check-to-time-of-use bug with a long history.
	PID int32
}

// String renders the peer for a log line.
func (p Peer) String() string {
	return "uid=" + strconv.FormatUint(uint64(p.UID), 10) +
		" gid=" + strconv.FormatUint(uint64(p.GID), 10) +
		" pid=" + strconv.FormatInt(int64(p.PID), 10)
}

// ErrPeerRefused reports a connection from a process that may not ask for privileged work.
var ErrPeerRefused = errors.New("privsep: the connecting process may not request privileged work")

// AccountUID returns the numeric uid of a system account by name.
//
// It is separate from the check below so that a helper can resolve the agent's uid once, at start, and
// report a clear failure when the account is missing — which means a broken installation rather than an
// attack, and should read as one in the journal.
func AccountUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("privsep: looking up the %q account: %w", name, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("privsep: the %q account has a non-numeric uid %q: %w", name, u.Uid, err)
	}
	return uint32(uid), nil
}

// CheckPeer reports whether a peer may request privileged work.
//
// Two uids are accepted and no more. The agent's own account is the point of the socket. Root is
// accepted because root can already run the helper directly, by hand, from an administrator's shell —
// refusing it here would deny nothing and would only make the diagnostic path behave differently from
// the real one, which is how a diagnostic stops being evidence about production.
func CheckPeer(p Peer, agentUID uint32) error {
	if p.UID == 0 || p.UID == agentUID {
		return nil
	}
	return fmt.Errorf("%w: %s, expected uid 0 or %d", ErrPeerRefused, p, agentUID)
}

// ConnFromSystemd returns the connection systemd passed as this process's standard input.
//
// The helper units are socket-activated with Accept=yes, which is the inetd arrangement: systemd
// accepts the connection and starts one instance of the service per connection with the connection
// itself as file descriptor 0. There is therefore no listening socket in this process, no accept loop
// and no long-running root daemon — the helper exists for exactly as long as the operation does.
//
// A helper started any other way — by hand from a shell, by a test, by a misconfigured unit — fails
// here rather than reading a request from a terminal, because the failure should name the cause.
func ConnFromSystemd() (*net.UnixConn, error) {
	raw, err := net.FileConn(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("privsep: standard input is not the socket systemd should have "+
			"passed; this program is started by its .socket unit, not from a shell: %w", err)
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("privsep: standard input is a %T rather than a unix socket", raw)
	}
	return conn, nil
}

// Handler answers one request. It never returns an error: every outcome is a Response.
//
// That shape is deliberate. A helper that could fail without producing a reply would leave the agent
// waiting for a job result that never arrives, and the job would sit in the queue looking like a host
// that had gone quiet — which is the least useful thing a fleet tool can do.
type Handler func(ctx context.Context, req Request) Response

// ServeConn reads one request, checks the peer, answers it, and closes the connection.
//
// The order matters and is the same order the sudoers entry enforced: establish who is calling before
// reading what they want. A request read first and authorised afterwards is a request that has already
// been parsed by root on behalf of a stranger, and the parser is the part most worth not exposing.
func ServeConn(ctx context.Context, conn *net.UnixConn, agentUID uint32, h Handler) error {
	defer func() { _ = conn.Close() }()

	peer, err := PeerOf(conn)
	if err != nil {
		return err
	}
	if err := CheckPeer(peer, agentUID); err != nil {
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(RequestTimeout)); err != nil {
		return fmt.Errorf("privsep: setting a read deadline: %w", err)
	}
	req, err := readRequest(conn)
	if err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("privsep: clearing the read deadline: %w", err)
	}

	resp := h(ctx, req)
	return writeResponse(conn, resp)
}

// readRequest reads a bounded request from a connection.
func readRequest(conn net.Conn) (Request, error) {
	raw, err := io.ReadAll(io.LimitReader(conn, MaxRequestBytes+1))
	if err != nil {
		return Request{}, fmt.Errorf("privsep: reading the request: %w", err)
	}
	if len(raw) > MaxRequestBytes {
		return Request{}, fmt.Errorf("privsep: request exceeds %d bytes", MaxRequestBytes)
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("privsep: the request could not be decoded: %w", err)
	}
	if dec.More() {
		return Request{}, errors.New("privsep: trailing data after the request")
	}
	return req, nil
}

// writeResponse encodes a reply and finishes the connection.
//
// The write is bounded as well as the read. A reply is at most a little over
// protocol.MaxJobOutputBytes and a unix socket's buffer is larger than that, so this deadline should
// never fire against a caller that is still there — which is the point of setting it. A helper blocked
// writing to an agent that died mid-operation would be a root process held open by a process that no
// longer exists.
func writeResponse(conn *net.UnixConn, resp Response) error {
	raw, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("privsep: encoding the reply: %w", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(ReplyTimeout)); err != nil {
		return fmt.Errorf("privsep: setting a write deadline: %w", err)
	}
	if _, err := conn.Write(raw); err != nil {
		return fmt.Errorf("privsep: sending the reply: %w", err)
	}
	return conn.CloseWrite()
}
