package privsep

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/intent"
)

// TestGuaranteeEveryPrivilegedIntentHasExactlyOneEndpoint pins the successor to the sudoers file.
//
// The endpoints map is now the complete statement of what the agent can reach as root, which is the
// role /etc/sudoers.d/farrier used to play. The failure this defends against is a privileged intent
// added to the catalogue without anyone deciding which helper serves it: the agent would refuse it at
// run time, which looks like a bug on a host rather than an omission in a commit.
func TestGuaranteeEveryPrivilegedIntentHasExactlyOneEndpoint(t *testing.T) {
	for _, s := range intent.All() {
		path, ok := Endpoint(s.Name)
		switch {
		case s.Class.Privileged() && !ok:
			t.Errorf("intent %q is privileged but no helper socket serves it.\n"+
				"Add it to the endpoints map in privsep.go, naming the one helper that performs it, "+
				"and expect a careful review: this map is what the sudoers entry used to be.", s.Name)
		case !s.Class.Privileged() && ok:
			t.Errorf("read-only intent %q has a privileged endpoint %q. Read intents run in the agent "+
				"itself, unprivileged; giving one a route to root would be a privilege escalation with "+
				"no operation behind it.", s.Name, path)
		}
	}
}

// TestGuaranteeEndpointsAreThreeSocketsUnderTheRuntimeDirectory asserts the shape of the whole set.
//
// There are three root helpers and therefore three sockets. A fourth would mean a fourth privileged
// program, which docs/SECURITY.md §3 says will never exist, and this is where that becomes mechanical
// rather than a sentence in a document.
func TestGuaranteeEndpointsAreThreeSocketsUnderTheRuntimeDirectory(t *testing.T) {
	list := Endpoints()
	if len(list) != 3 {
		t.Fatalf("there are %d helper sockets, expected exactly 3: %v", len(list), list)
	}
	seen := map[string]bool{}
	for _, path := range list {
		if seen[path] {
			t.Errorf("%q is listed twice", path)
		}
		seen[path] = true
		if filepath.Dir(path) != SocketDir {
			t.Errorf("%q is not directly under %s; the runtime directory is recreated empty on every "+
				"boot, which is what stops a stale socket outliving the helper that served it",
				path, SocketDir)
		}
		if !strings.HasSuffix(path, ".sock") {
			t.Errorf("%q does not look like a socket", path)
		}
	}
	for _, name := range intent.Names() {
		if path, ok := Endpoint(name); ok && !seen[path] {
			t.Errorf("intent %q names socket %q, which is not one of the three", name, path)
		}
	}
}

// TestGuaranteeARequestCannotNameAProgram asserts the request type has no field a path could hide in.
//
// The sudoers entry's safety came from naming three programs and no arguments. The socket's comes from
// the request carrying an intent and a parameter object, both of which the helper re-validates against
// the closed catalogue. A field added here that carried a path, a command or an argument list would
// quietly reintroduce the thing the whole design exists to not have, and it would look innocuous in a
// diff — so the field set is asserted rather than reviewed for.
func TestGuaranteeARequestCannotNameAProgram(t *testing.T) {
	raw, err := json.Marshal(Request{Intent: intent.ServiceRestart})
	if err != nil {
		t.Fatalf("encoding a request: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decoding a request: %v", err)
	}

	allowed := map[string]bool{"jobId": true, "intent": true, "params": true, "issuedAt": true}
	for name := range fields {
		if !allowed[name] {
			t.Errorf("privsep.Request carries the field %q. The request names an operation, never a "+
				"program: add a field here and the helper is taking instructions from its caller.", name)
		}
	}
	for name := range allowed {
		if _, ok := fields[name]; !ok {
			t.Errorf("privsep.Request no longer carries %q", name)
		}
	}
}

// listenerFor starts a one-connection helper on a temporary socket and returns its path.
//
// The socket is real rather than a net.Pipe because the peer-credential check is the thing most worth
// testing here, and it is a property of an actual unix socket that a pipe cannot have.
func listenerFor(t *testing.T, h Handler) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listening on %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			return
		}
		_ = ServeConn(context.Background(), unixConn, uint32(os.Getuid()), h)
	}()
	return path
}

// clientFor returns a Client that dials an explicit path rather than a packaged one.
func clientFor(path string) *Client {
	return &Client{dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
}

// TestARequestCrossesTheBoundaryAndTheReplyComesBack is the round trip, over a real unix socket.
func TestARequestCrossesTheBoundaryAndTheReplyComesBack(t *testing.T) {
	var got Request
	path := listenerFor(t, func(_ context.Context, req Request) Response {
		got = req
		return Response{ExitCode: 0, Output: "nginx.service restarted"}
	})

	issued := time.Now().UTC().Truncate(time.Second)
	resp, err := clientFor(path).Invoke(context.Background(), Request{
		JobID:    "01JTEST",
		Intent:   intent.ServiceRestart,
		Params:   json.RawMessage(`{"unit":"nginx.service"}`),
		IssuedAt: issued,
	})
	if err != nil {
		t.Fatalf("invoking: %v", err)
	}
	if resp.ExitCode != 0 || resp.Output != "nginx.service restarted" {
		t.Errorf("reply is %+v", resp)
	}

	if got.JobID != "01JTEST" || got.Intent != intent.ServiceRestart {
		t.Errorf("the helper saw %+v", got)
	}
	if string(got.Params) != `{"unit":"nginx.service"}` {
		t.Errorf("the helper saw parameters %s; they must cross as the bytes that arrived on the wire, "+
			"so that the helper runs the catalogue's decoder on the same input the agent did", got.Params)
	}
	if !got.IssuedAt.Equal(issued) {
		t.Errorf("the helper saw issuedAt %s, sent %s", got.IssuedAt, issued)
	}
}

// TestARefusalCrossesTheBoundaryUnchanged asserts a policy refusal survives the round trip.
//
// The exit code is the same one an administrator sees running the helper by hand and the same one the
// control plane is shown. One set of codes across the socket, the command line and the wire means "exit
// 3" means one thing everywhere it appears.
func TestARefusalCrossesTheBoundaryUnchanged(t *testing.T) {
	path := listenerFor(t, func(_ context.Context, _ Request) Response {
		return Response{ExitCode: 3, Error: "refused by local policy (unit_not_restartable): nope"}
	})

	resp, err := clientFor(path).Invoke(context.Background(), Request{
		JobID: "01JTEST", Intent: intent.ServiceStop, Params: json.RawMessage(`{"unit":"sshd.service"}`),
	})
	if err != nil {
		t.Fatalf("invoking: %v", err)
	}
	if resp.ExitCode != 3 || !strings.Contains(resp.Error, "unit_not_restartable") {
		t.Errorf("reply is %+v", resp)
	}
}

// TestServeConnRefusesAPeerThatIsNotTheAgent is the check that replaces the sudoers entry's user field.
//
// The uid is read from the kernel rather than from the request, so this is a test that an impostor
// cannot be served even though it can reach the socket — which is exactly the case the file mode alone
// would not cover if the mode were ever loosened by an edit nobody noticed.
func TestServeConnRefusesAPeerThatIsNotTheAgent(t *testing.T) {
	if os.Getuid() == 0 {
		// Root is accepted deliberately — see CheckPeer — so a test running as root cannot be the
		// impostor. The uid table in TestCheckPeerAcceptsOnlyTheAgentAndRoot covers the decision
		// itself; this test covers what the connection does about it, and needs an ordinary user.
		t.Skip("running as root, which CheckPeer accepts on purpose")
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer func() { _ = ln.Close() }()

	served := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			served <- acceptErr
			return
		}
		// An impossible uid, so that whatever the test process runs as it is not this.
		served <- ServeConn(context.Background(), conn.(*net.UnixConn), 4294967294,
			func(context.Context, Request) Response {
				t.Error("the handler ran for a peer that should have been refused")
				return Response{}
			})
	}()

	_, err = clientFor(path).Invoke(context.Background(), Request{
		JobID: "01JTEST", Intent: intent.HostReboot, Params: json.RawMessage(`{}`),
	})
	if err == nil {
		t.Error("the caller got a reply; a refused peer must be answered with nothing at all")
	}
	if serveErr := <-served; !errors.Is(serveErr, ErrPeerRefused) {
		t.Errorf("ServeConn returned %v, want ErrPeerRefused", serveErr)
	}
}

// TestCheckPeerAcceptsOnlyTheAgentAndRoot pins the two uids that may ask for privileged work.
func TestCheckPeerAcceptsOnlyTheAgentAndRoot(t *testing.T) {
	const agent = 998
	for _, uid := range []uint32{0, agent} {
		if err := CheckPeer(Peer{UID: uid}, agent); err != nil {
			t.Errorf("uid %d was refused: %v", uid, err)
		}
	}
	for _, uid := range []uint32{1, 1000, agent + 1} {
		if err := CheckPeer(Peer{UID: uid}, agent); err == nil {
			t.Errorf("uid %d was accepted and must not be", uid)
		}
	}
}

// TestAnUnknownRequestFieldIsRejected asserts the helper's decode is strict.
//
// It is the same reasoning as the catalogue's strict parameter decoding, one layer out: a caller able
// to attach unrecognised fields to a request would have a channel for smuggling values past a validator
// into whatever later code decided to be helpful about them.
func TestAnUnknownRequestFieldIsRejected(t *testing.T) {
	path := listenerFor(t, func(context.Context, Request) Response {
		t.Error("the handler ran on a request that should not have decoded")
		return Response{}
	})

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(`{"intent":"host.reboot","program":"/bin/sh"}`)); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("half-closing: %v", err)
	}

	buf := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting a deadline: %v", err)
	}
	if n, err := conn.Read(buf); err == nil && n > 0 {
		t.Errorf("a request carrying an unknown field was answered with %q", buf[:n])
	}
}

// TestAnOversizeRequestIsRefused asserts the helper never reads without a bound.
func TestAnOversizeRequestIsRefused(t *testing.T) {
	path := listenerFor(t, func(context.Context, Request) Response {
		t.Error("the handler ran on an over-size request")
		return Response{}
	})

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Written in chunks: the helper stops reading at the limit and closes, so a single huge write
	// would fail with a broken pipe on this side rather than exercising the bound on the other.
	chunk := make([]byte, 8<<10)
	for i := range chunk {
		chunk[i] = 'a'
	}
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting a deadline: %v", err)
	}
	for range (MaxRequestBytes / len(chunk)) + 4 {
		if _, err := conn.Write(chunk); err != nil {
			break
		}
	}

	buf := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting a deadline: %v", err)
	}
	if n, err := conn.Read(buf); err == nil && n > 0 {
		t.Errorf("an over-size request was answered with %q", buf[:n])
	}
}

// TestInvokeNamesAnIntentWithNoPrivilegedRoute asserts the failure is distinguishable.
//
// "This build has no helper for that" and "this host's helper socket is not running" are fixed by
// different people in different places, so they are different errors rather than one message.
func TestInvokeNamesAnIntentWithNoPrivilegedRoute(t *testing.T) {
	_, err := NewClient().Invoke(context.Background(), Request{Intent: intent.FactsCollect})
	if !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("invoking a read intent returned %v, want ErrNoEndpoint", err)
	}
}

// TestInvokeReportsAnUnreachableHelperSocket asserts a missing socket is reported, not fatal.
//
// A host whose helper units are masked, or whose package was half installed, must say so on the
// dashboard. An agent that crashed instead would take the host's reporting down with the capability it
// had lost, which is the wrong way round.
func TestInvokeReportsAnUnreachableHelperSocket(t *testing.T) {
	client := clientFor(filepath.Join(t.TempDir(), "absent.sock"))
	_, err := client.Invoke(context.Background(), Request{
		JobID: "01JTEST", Intent: intent.ServiceRestart, Params: json.RawMessage(`{"unit":"a.service"}`),
	})
	if !errors.Is(err, ErrUnreachable) {
		t.Errorf("invoking against a missing socket returned %v, want ErrUnreachable", err)
	}
}

// TestInvokeTimeoutsMatchWhatTheOperationsActuallyCost pins the two bounds.
//
// Applying updates is legitimately minutes of work and must not be interrupted part way; restarting a
// unit is not, and a helper wedged on one should be noticed in a minute rather than in three quarters
// of an hour. Giving both the generous bound would hide the second failure completely.
func TestInvokeTimeoutsMatchWhatTheOperationsActuallyCost(t *testing.T) {
	for _, slow := range []intent.Name{intent.PackagesApplySecurity, intent.PackagesApplyAll} {
		if InvokeFor(slow) != InvokeTimeout {
			t.Errorf("%s has bound %s, expected the update bound %s", slow, InvokeFor(slow), InvokeTimeout)
		}
	}
	for _, quick := range []intent.Name{
		intent.ServiceStart, intent.ServiceStop, intent.ServiceRestart, intent.HostReboot,
	} {
		if d := InvokeFor(quick); d >= InvokeTimeout {
			t.Errorf("%s has bound %s, which is the update bound; a wedged helper would go unnoticed "+
				"for that long", quick, d)
		}
	}
}
