package privsep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pascalgross/farrier/internal/intent"
)

// ErrNoEndpoint reports an intent with no privileged route from the agent.
//
// It is distinguished from a dial failure because the two mean opposite things to whoever reads the
// job result: no endpoint is a catalogue member nobody wired up, which is a bug in this build, while a
// dial failure is a host whose helper sockets are not running, which is a bug on that machine.
var ErrNoEndpoint = errors.New("privsep: no helper serves this intent")

// ErrUnreachable reports that the helper socket could not be reached.
//
// The agent turns it into a job result rather than a crash: a host whose helper units are masked or
// whose package was half-installed should say so on the dashboard, not go quiet.
var ErrUnreachable = errors.New("privsep: the helper socket could not be reached")

// Invoker is the agent's view of the privilege boundary.
//
// It is an interface with exactly one implementation so that the agent's job path can be tested
// without a root helper and without systemd. That is the whole reason it exists; it is not an
// extension point, and a second implementation outside a test would be a second privileged route,
// which is the thing this package is arranged to prevent.
type Invoker interface {
	// Invoke sends a request to the helper serving its intent and returns the reply.
	Invoke(ctx context.Context, req Request) (Response, error)
}

// Client is the real Invoker, dialling the socket systemd activates the helper on.
//
// It holds no connection between calls. A helper exists for the length of one operation, so there is
// nothing to keep open, and a pooled connection to a process that has already exited is a class of bug
// this design does not need to have.
type Client struct {
	// dialer is how the unix socket is reached, overridden only by this package's tests.
	dialer func(ctx context.Context, path string) (net.Conn, error)
}

// NewClient returns a Client that dials the packaged socket paths.
func NewClient() *Client { return &Client{} }

// Invoke sends one request across the privilege boundary and returns the helper's reply.
//
// The context's deadline is the caller's bound on the whole operation, and it must be generous:
// applying updates on a slow host with a full mirror behind it is minutes of work, and a deadline that
// expired mid-upgrade would leave the host patched half way with the job reported as failed. The
// helper has its own bounds on the parts it controls; this one bounds the agent's patience.
func (c *Client) Invoke(ctx context.Context, req Request) (Response, error) {
	path, ok := Endpoint(req.Intent)
	if !ok {
		return Response{}, fmt.Errorf("%w: %s", ErrNoEndpoint, req.Intent)
	}

	dial := c.dialer
	if dial == nil {
		dial = dialUnix
	}
	conn, err := dial(ctx, path)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %s: %w", ErrUnreachable, path, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		// Best effort: a connection that does not support deadlines still works, it simply relies on
		// the context cancellation below rather than on the socket timing out by itself.
		_ = conn.SetDeadline(deadline)
	}

	// A goroutine rather than only a deadline, because a helper that has stopped reading leaves the
	// write blocked and no deadline was set when the caller passed a context without one. Closing the
	// connection is what unblocks both directions.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if err := writeRequest(conn, req); err != nil {
		return Response{}, err
	}
	return readResponse(conn)
}

// dialUnix opens a stream connection to a helper socket.
func dialUnix(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// writeRequest encodes a request and half-closes the connection.
//
// The half-close is what tells the helper the request is complete. Framing by end-of-input rather than
// by a length prefix means the helper's read is bounded by MaxRequestBytes and nothing else: there is
// no declared length for a caller to lie about, and a caller that writes for ever hits the limit rather
// than a mismatch the helper has to decide what to do about.
func writeRequest(conn net.Conn, req Request) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("privsep: encoding the request: %w", err)
	}
	if len(raw) > MaxRequestBytes {
		return fmt.Errorf("privsep: request is %d bytes, limit %d", len(raw), MaxRequestBytes)
	}
	if _, err := conn.Write(raw); err != nil {
		return fmt.Errorf("privsep: sending the request: %w", err)
	}
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := half.CloseWrite(); err != nil {
			return fmt.Errorf("privsep: finishing the request: %w", err)
		}
	}
	return nil
}

// readResponse reads a bounded reply from a helper.
func readResponse(conn net.Conn) (Response, error) {
	raw, err := io.ReadAll(io.LimitReader(conn, MaxResponseBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("privsep: reading the reply: %w", err)
	}
	if len(raw) > MaxResponseBytes {
		return Response{}, fmt.Errorf("privsep: reply exceeds %d bytes", MaxResponseBytes)
	}
	if len(raw) == 0 {
		return Response{}, errors.New("privsep: the helper closed the connection without replying")
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Response{}, fmt.Errorf("privsep: the helper's reply could not be decoded: %w", err)
	}
	return resp, nil
}

// InvokeTimeout is the agent's default bound on one privileged operation.
//
// Forty-five minutes is chosen for the worst realistic case rather than the common one: a small host
// with a slow mirror applying a release's worth of accumulated updates, where dpkg is genuinely working
// the whole time. Every shorter bound this project considered would have expired during a real upgrade
// on somebody's machine, and an update interrupted part way is worse than one that took too long.
const InvokeTimeout = 45 * time.Minute

// InvokeFor returns the bound to place on one intent's invocation.
//
// Restarting a unit and scheduling a reboot are near-instant and get the ordinary bound, so that a
// helper wedged on either is noticed in a minute rather than in three quarters of an hour. Only the
// update intents get InvokeTimeout, because only they are legitimately slow.
func InvokeFor(n intent.Name) time.Duration {
	switch n {
	case intent.PackagesApplySecurity, intent.PackagesApplyAll:
		return InvokeTimeout
	default:
		return 2 * time.Minute
	}
}
