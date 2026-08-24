package notify

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testEvent is the event these tests render and deliver.
//
// A real one: the summary is the sentence an alert rule actually produces, because the subject line is
// the whole of what an operator sees before deciding whether to open the mail, and a fixture reading
// "test" would let a subject that said "test" pass.
var testEvent = Event{
	Kind:     string(KindUpdatesPending),
	HostID:   "01JHOST",
	Hostname: "web-01",
	Summary:  "web-01: 3 security updates pending, 14 days old",
	At:       time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC),
	Detail:   map[string]any{"pending": 3, "days": 14},
}

// headerBlock returns the part of a rendered message before the blank line that ends the headers.
//
// Every injection assertion below is about that boundary and nothing else: a header the sender did not
// write is only a header if it is above the blank line, and text that landed below it is body. Splitting
// once, here, is what keeps each test from re-deriving the rule it is asserting.
func headerBlock(t *testing.T, message []byte) string {
	t.Helper()
	head, _, found := strings.Cut(string(message), "\r\n\r\n")
	if !found {
		t.Fatalf("the message has no header/body boundary at all:\n%s", message)
	}
	return head
}

// headerNamed returns the value of one header line, and whether it was there.
//
// Case-sensitive and prefix-matched on purpose: these tests are about the exact bytes renderMail wrote,
// not about what a tolerant parser could be persuaded to read back.
func headerNamed(block, name string) (string, bool) {
	for _, line := range strings.Split(block, "\r\n") {
		if value, ok := strings.CutPrefix(line, name+": "); ok {
			return value, true
		}
	}
	return "", false
}

// TestTheSubjectLineIsTheEventsSummary is what decides whether the mail is read at all.
//
// "Farrier notification" is a subject somebody writes a folder rule for inside a week, and after that
// the alert has been delivered to a place nobody looks — which is indistinguishable from not having
// been sent. The summary is the one line that says what happened, so it is the subject.
func TestTheSubjectLineIsTheEventsSummary(t *testing.T) {
	message := renderMail("farrier@example.org", []string{"oncall@example.org"}, testEvent)
	block := headerBlock(t, message)

	subject, ok := headerNamed(block, "Subject")
	if !ok {
		t.Fatalf("the message carries no subject at all:\n%s", block)
	}
	if subject != testEvent.Summary {
		t.Fatalf("the subject is %q, want the event's summary %q", subject, testEvent.Summary)
	}

	// The envelope around it has to be there too, or the relay rejects a message no test noticed was
	// malformed: a sender, a recipient list, and a content type that says the body is UTF-8 text.
	if from, ok := headerNamed(block, "From"); !ok || from != "farrier@example.org" {
		t.Errorf("From: %q", from)
	}
	if to, ok := headerNamed(block, "To"); !ok || to != "oncall@example.org" {
		t.Errorf("To: %q", to)
	}
	if !strings.Contains(block, "Content-Type: text/plain; charset=utf-8") {
		t.Errorf("the message does not declare its own encoding:\n%s", block)
	}

	// And the body says the rest, because a subject is one line and an incident is not: the kind, the
	// host under both its names, and the detail fields the rule carried.
	body := string(message[len(block)+4:])
	for _, want := range []string{testEvent.Summary, testEvent.Kind, "web-01", "01JHOST", "days: 14"} {
		if !strings.Contains(body, want) {
			t.Errorf("the body does not carry %q:\n%s", want, body)
		}
	}
}

// TestASummaryCannotInjectMailHeaders is the one security property in this file.
//
// A summary is built from a hostname and from whatever a helper printed, so it is attacker-influenced
// text placed directly into a header. A CR or an LF in it would end the Subject line and let everything
// after it be read as further headers — a Bcc to somewhere else, or a blank line and a body of the
// sender's choosing, sent under the control plane's own From.
//
// Both mechanisms that close it are asserted, because they close it independently and a reader has to
// know which one is load-bearing: sanitizeHeader replaces the line breaks, and the Q-encoder would
// escape them if it ever saw any. Removing sanitizeHeader alone therefore keeps the injection shut and
// silently makes every summary with a newline in it arrive as encoded gibberish — which is why the
// substitution is asserted directly below rather than only through its effect here.
func TestASummaryCannotInjectMailHeaders(t *testing.T) {
	hostile := Event{
		Kind:     string(KindJobFailed),
		Hostname: "web-01",
		Summary: "web-01: unattended-upgrade failed\r\nBcc: attacker@example.net\r\n" +
			"\r\nPay this invoice immediately.",
		At: testEvent.At,
	}
	message := renderMail("farrier@example.org", []string{"oncall@example.org"}, hostile)
	block := headerBlock(t, message)

	for _, line := range strings.Split(block, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("a summary added a header of its own:\n%s", block)
		}
	}
	subject, ok := headerNamed(block, "Subject")
	if !ok {
		t.Fatalf("the hostile summary displaced the subject entirely:\n%s", block)
	}
	// The whole hostile string stays inside the one header it was written into. Truncating it instead
	// would be the other defensible answer, and it is not the one this code makes: an operator reading
	// the subject sees what the helper printed, on one line.
	if !strings.Contains(subject, "attacker@example.net") {
		t.Errorf("the summary was not carried into the subject at all: %q", subject)
	}
	if strings.ContainsAny(subject, "\r\n") {
		t.Errorf("the subject still holds a line break: %q", subject)
	}
}

// TestSanitizeHeaderReplacesEveryLineBreak pins the substitution the injection defence is made of.
//
// Directly rather than through renderMail, because the Q-encoder would hide its removal: the end-to-end
// test above would still pass against a build with no sanitizing at all, and a property that two
// mechanisms hold up needs the weaker one asserted where it can actually be seen to fail.
func TestSanitizeHeaderReplacesEveryLineBreak(t *testing.T) {
	for _, c := range []struct {
		// in is the hostile summary.
		in string

		// want is what may reach a header.
		want string
	}{
		{"a\rb", "a b"},
		{"a\nb", "a b"},
		{"a\r\nb", "a  b"},
		{"a\n\nb\r\rc", "a  b  c"},
		{"ordinary text", "ordinary text"},
	} {
		if got := sanitizeHeader(c.in); got != c.want {
			t.Errorf("sanitizeHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestANonASCIISubjectIsEncodedRatherThanSentRaw keeps hostnames and helper output legible.
//
// Summaries are built from both, and both are routinely not ASCII. A raw high byte in a header is
// rejected by some relays and mangled by others, and the failure arrives as "the alert mail stopped
// working" long after whoever renamed the host has forgotten doing it.
func TestANonASCIISubjectIsEncodedRatherThanSentRaw(t *testing.T) {
	summary := "wörter-01: Dienst fehlgeschlagen — Größe überschritten"
	message := renderMail("farrier@example.org", []string{"oncall@example.org"},
		Event{Kind: string(KindServiceFailed), Summary: summary, At: testEvent.At})
	block := headerBlock(t, message)

	subject, ok := headerNamed(block, "Subject")
	if !ok {
		t.Fatalf("no subject:\n%s", block)
	}
	if !strings.HasPrefix(subject, "=?utf-8?") {
		t.Fatalf("a non-ASCII subject was not encoded: %q", subject)
	}
	for i := 0; i < len(block); i++ {
		if block[i] > 0x7e {
			t.Fatalf("a raw high byte survived into the headers at %d:\n%s", i, block)
		}
	}
	// Encoded, not lost: a mail client decodes it back to what the rule said.
	decoded, err := new(mime.WordDecoder).DecodeHeader(subject)
	if err != nil {
		t.Fatalf("the encoded subject does not decode: %v", err)
	}
	if decoded != summary {
		t.Fatalf("the subject decodes to %q, want %q", decoded, summary)
	}

	// And an ASCII subject is left alone, which is the half that keeps a mail readable in a log or a
	// packet capture. mime encodes only when it must, and this asserts that it is being let to.
	ascii := renderMail("farrier@example.org", []string{"oncall@example.org"}, testEvent)
	if subject, _ := headerNamed(headerBlock(t, ascii), "Subject"); strings.HasPrefix(subject, "=?") {
		t.Errorf("an ASCII subject was encoded anyway: %q", subject)
	}
}

// transcript records the plaintext lines a relay received, for the tests that assert what never went
// out in the clear.
//
// Guarded, because the conversation runs in the accept goroutine while the test asserts on the main
// one; an unguarded slice here is a data race that -race would report as a failure in whichever test
// happened to be running.
type transcript struct {
	// mu guards lines.
	mu sync.Mutex

	// lines is every command the relay read, in order.
	lines []string
}

// add records one line the relay received.
func (tr *transcript) add(line string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.lines = append(tr.lines, line)
}

// all returns a copy of what was received.
func (tr *transcript) all() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]string(nil), tr.lines...)
}

// sawCommand reports whether any recorded line began with a command word, case-insensitively.
//
// It exists for the assertion that matters most in this file: that no MAIL FROM, and therefore no
// hostname and no failure text, was written to a connection that never got a TLS handshake.
func (tr *transcript) sawCommand(word string) bool {
	for _, line := range tr.all() {
		if strings.HasPrefix(strings.ToUpper(line), strings.ToUpper(word)) {
			return true
		}
	}
	return false
}

// relay is a listener a test drives one SMTP conversation against.
//
// A stand-in rather than a working mail server, deliberately: every property below is about which of
// the two transports was chosen and what was said before TLS started, and all of that is decided in the
// first three exchanges. A relay that could actually accept a message would only add ways for these
// tests to fail for reasons that are not the property.
type relay struct {
	// host is what SMTPConfig.Host must be set to in order to reach it.
	host string

	// port is the port it listens on.
	port int

	// received is the plaintext side of the conversation.
	received *transcript

	// hello captures the TLS ClientHello, when one arrived, so a test can assert on what the client
	// offered rather than only that something happened.
	hello chan tls.ClientHelloInfo

	// closed reports that the conversation goroutine has finished.
	closed chan struct{}
}

// startRelay listens on a loopback port and runs one conversation against the first connection.
//
// The conversation is the test's, because each of these tests is a different script — a relay that
// offers STARTTLS, one that does not, one that says nothing at all. What is shared is the listening,
// the recording and the shutdown, which is the part that is identical every time and easy to get
// subtly wrong.
func startRelay(t *testing.T, converse func(r *relay, conn net.Conn, in *bufio.Reader)) *relay {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("the listener is not on TCP: %T", listener.Addr())
	}
	r := &relay{
		host:     "127.0.0.1",
		port:     addr.Port,
		received: &transcript{},
		hello:    make(chan tls.ClientHelloInfo, 1),
		closed:   make(chan struct{}),
	}

	go func() {
		defer close(r.closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// A bound on the fake, not on the code under test: a script that misjudges what the client
		// sends must fail this test in a second rather than hang the package for ten minutes.
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		converse(r, conn, bufio.NewReader(conn))
	}()
	return r
}

// config points an SMTPConfig at this relay.
func (r *relay) config() SMTPConfig {
	return SMTPConfig{Host: r.host, Port: r.port, From: "farrier@example.org"}
}

// readLine reads one command line and records it.
func (r *relay) readLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	if line != "" {
		r.received.add(strings.TrimRight(line, "\r\n"))
	}
	return strings.TrimRight(line, "\r\n"), err
}

// capturingTLS wraps an accepted connection in a TLS server that records what the client offered.
//
// The ClientHello is the evidence: it says which protocol versions the client was willing to speak and
// therefore whether MinVersion is doing anything, and it arrives before any certificate is chosen — so
// it is observable even though the handshake below it is going to fail against a certificate this test
// never persuaded the client to trust.
func (r *relay) capturingTLS(conn net.Conn, cert tls.Certificate) *tls.Conn {
	return tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.0 and 1.1 are offered by the *server* here on purpose: the assertion is about what the
		// client was prepared to accept, and a server that refused them itself would make the client's
		// own floor unobservable.
		MinVersion: tls.VersionTLS10,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case r.hello <- *info:
			default:
			}
			return nil, nil
		},
	})
}

// awaitHello returns the ClientHello the relay captured, or fails the test.
func (r *relay) awaitHello(t *testing.T) tls.ClientHelloInfo {
	t.Helper()
	select {
	case info := <-r.hello:
		return info
	case <-time.After(10 * time.Second):
		t.Fatalf("the client never started a TLS handshake; it sent %v", r.received.all())
		return tls.ClientHelloInfo{}
	}
}

// selfSignedCert mints a certificate the fake relay presents.
//
// Self-signed and trusted by nobody, which is the point: the client must refuse it. A test that handed
// the client a certificate it trusted would pass just as well against a delivery path that had
// InsecureSkipVerify set, and verifying the relay is half of what the TLS requirement is for.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, public, private)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

// assertModernTLS fails unless the client offered TLS 1.2 at the oldest.
//
// Written against the offered versions rather than the negotiated one because the negotiated version is
// whatever the server picked: a client with MinVersion unset would still negotiate TLS 1.3 against a
// modern server and look identical, right up until it meets one that offers TLS 1.0 and takes it.
func assertModernTLS(t *testing.T, info tls.ClientHelloInfo) {
	t.Helper()
	for _, version := range info.SupportedVersions {
		if version < tls.VersionTLS12 {
			t.Errorf("the client offered %#04x, below TLS 1.2: %#04x", version, info.SupportedVersions)
		}
	}
	if len(info.SupportedVersions) == 0 {
		t.Error("the ClientHello offered no versions at all")
	}
}

// TestGuaranteeAlertMailIsRefusedRatherThanSentInPlaintext is the promise docs/SECURITY.md §8.3 makes
// about mail, asserted against a relay that does not offer STARTTLS.
//
// It carries the guarantee prefix because §8.3 states it as a property of the product rather than as an
// implementation detail — "mail leaves over STARTTLS on 587 or implicit TLS on 465 and never in
// plaintext" — and because of what the failure looks like: an alert legitimately carries hostnames and
// failure text, so a build that fell back to plaintext would keep working, keep delivering, and publish
// a fleet's inventory to every hop on the way for as long as nobody looked. There is no error state to
// notice, which is exactly the shape of property that belongs inside a check nobody can skip.
//
// The relay is on an ephemeral port rather than 587, because 587 is privileged and unreachable to an
// unprivileged test process. The code branches on "is the port 465", so every other port takes the one
// path being asserted here and the substitution costs the test nothing.
func TestGuaranteeAlertMailIsRefusedRatherThanSentInPlaintext(t *testing.T) {
	r := startRelay(t, func(r *relay, conn net.Conn, in *bufio.Reader) {
		// Nothing is written for a moment first. A client doing implicit TLS speaks before the server
		// does, so silence here is what makes the next assertion — that this port got no ClientHello —
		// mean "the client waited for a greeting" rather than "the client had not got there yet".
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if early, err := in.Peek(1); err == nil && len(early) > 0 {
			r.received.add("EARLY:" + string(early))
		}
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

		_, _ = conn.Write([]byte("220 relay.invalid ESMTP\r\n"))
		if _, err := r.readLine(in); err != nil {
			return
		}
		// A perfectly ordinary relay, with one extension missing.
		_, _ = conn.Write([]byte("250-relay.invalid\r\n250 SIZE 10240000\r\n"))
		for {
			if _, err := r.readLine(in); err != nil {
				return
			}
		}
	})

	err := NewSMTP(r.config(), []string{"oncall@example.org"}).Deliver(context.Background(), testEvent)
	if err == nil {
		t.Fatal("a relay with no STARTTLS accepted an alert; the mail went out in the clear")
	}
	if !strings.Contains(err.Error(), "refusing to send in plaintext") {
		t.Fatalf("the refusal does not say why: %v", err)
	}

	<-r.closed
	for _, line := range r.received.all() {
		if strings.HasPrefix(line, "EARLY:") {
			t.Errorf("the client spoke before the greeting on a non-465 port: %q", line)
		}
	}
	if !r.received.sawCommand("EHLO") {
		t.Fatalf("the client never greeted the relay at all: %v", r.received.all())
	}
	// The assertion the whole test is for: the refusal came before anything worth protecting was
	// written. A build that refused *after* MAIL FROM would pass a test that only read the error.
	for _, command := range []string{"MAIL FROM", "RCPT TO", "DATA"} {
		if r.received.sawCommand(command) {
			t.Errorf("%s was sent to a relay with no TLS: %v", command, r.received.all())
		}
	}
	for _, line := range r.received.all() {
		if strings.Contains(line, testEvent.Hostname) || strings.Contains(line, "security updates") {
			t.Errorf("the event's contents reached the wire in the clear: %q", line)
		}
	}
}

// TestSTARTTLSIsTakenAndTheRelayIsVerified is the other half: the upgrade actually happens, it happens
// before any of the message, and the relay's certificate is checked when it does.
//
// Verification is asserted through a refusal rather than a success. The relay presents a certificate
// nothing trusts, so a client that verifies must fail — and a client that had InsecureSkipVerify set
// would sail past, deliver the mail, and pass every test that only asserted "TLS was started".
func TestSTARTTLSIsTakenAndTheRelayIsVerified(t *testing.T) {
	cert := selfSignedCert(t)
	r := startRelay(t, func(r *relay, conn net.Conn, in *bufio.Reader) {
		_, _ = conn.Write([]byte("220 relay.invalid ESMTP\r\n"))
		if _, err := r.readLine(in); err != nil {
			return
		}
		_, _ = conn.Write([]byte("250-relay.invalid\r\n250 STARTTLS\r\n"))
		line, err := r.readLine(in)
		if err != nil || !strings.EqualFold(line, "STARTTLS") {
			return
		}
		_, _ = conn.Write([]byte("220 2.0.0 Ready to start TLS\r\n"))
		_ = r.capturingTLS(conn, cert).Handshake()
	})

	err := NewSMTP(r.config(), []string{"oncall@example.org"}).Deliver(context.Background(), testEvent)
	if err == nil {
		t.Fatal("a relay presenting an untrusted certificate was accepted")
	}
	if !strings.Contains(err.Error(), "starting TLS") {
		t.Fatalf("the failure did not come from the upgrade: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("the relay's certificate was not verified: %v", err)
	}

	assertModernTLS(t, r.awaitHello(t))
	<-r.closed
	if !r.received.sawCommand("STARTTLS") {
		t.Fatalf("the client never asked to upgrade: %v", r.received.all())
	}
	for _, command := range []string{"MAIL FROM", "RCPT TO", "DATA"} {
		if r.received.sawCommand(command) {
			t.Errorf("%s was sent before the upgrade: %v", command, r.received.all())
		}
	}
}

// privilegedPortsEnv turns the skip below into a failure.
//
// CI sets it after arranging for an unprivileged process to bind 465. It is the shape
// TestGuaranteeRowLevelSecurityIsTheRuleNotThePredicate uses for the same reason: a check that opts
// itself out reports exactly what a passing one does, so where the environment is supposed to support
// it, not running is a failure.
const privilegedPortsEnv = "FARRIER_TEST_PRIVILEGED_PORTS"

// implicitTLSPort is the port that selects implicit TLS, and the reason the test below can be skipped.
//
// It is a constant here rather than a literal in one place because the skip message has to name it: a
// reader looking at a skipped test needs to know that the requirement is the privileged port and not
// something about their machine.
const implicitTLSPort = 465

// TestPortFourSixFiveSpeaksTLSFromTheFirstByte pins the other transport.
//
// 465 is implicit TLS: the client must open the handshake itself rather than waiting for a greeting and
// upgrading, because there is no greeting to wait for and a client that waited would hang until its
// deadline. The two transports share every line of code after the connection exists, so this is the
// whole of what distinguishes them.
//
// It needs a listener on 465 itself — the branch is an exact port comparison — and 465 is a privileged
// port. Where the test process cannot bind it the test skips rather than pretending, and says so: this
// is the one property in this file that an ordinary CI runner cannot observe. The complementary half is
// asserted unconditionally in the plaintext test above, which fails if a non-465 port ever starts
// speaking first.
func TestPortFourSixFiveSpeaksTLSFromTheFirstByte(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(implicitTLSPort))
	if err != nil {
		// A skip is the right answer on a laptop and the wrong one in CI, so the environment decides
		// which it gets. Without the variable this is the one property here an unprivileged process
		// cannot observe, and skipping says so. With it, the runner has been arranged to make the bind
		// possible, and a skip would then be a check that quietly stopped running — the failure this
		// repository already refuses to accept from the store tests and the PKCS#11 ones. Same shape:
		// a test that opts itself out is worse than no test, because the summary reads the same.
		if os.Getenv(privilegedPortsEnv) != "" {
			t.Fatalf("%s is set, so this runner is meant to be able to bind %d, and it could not: %v. "+
				"Either the setup step that lowers ip_unprivileged_port_start did not run, or something "+
				"else holds the port — do not paper over it by unsetting the variable",
				privilegedPortsEnv, implicitTLSPort, err)
		}
		t.Skipf("this test needs a listener on the privileged port %d, which this process may not "+
			"bind (%v); it is the one assertion here that an unprivileged runner cannot make. CI sets "+
			"%s so that this is a failure there rather than a silent skip",
			implicitTLSPort, err, privilegedPortsEnv)
	}
	t.Cleanup(func() { _ = listener.Close() })

	cert := selfSignedCert(t)
	r := &relay{
		host: "127.0.0.1", port: implicitTLSPort, received: &transcript{},
		hello: make(chan tls.ClientHelloInfo, 1), closed: make(chan struct{}),
	}
	go func() {
		defer close(r.closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		// No greeting is written, ever. If the client waited for one this would time out, which is
		// precisely the failure a build that treated 465 as STARTTLS would produce.
		_ = r.capturingTLS(conn, cert).Handshake()
	}()

	err = NewSMTP(r.config(), []string{"oncall@example.org"}).Deliver(context.Background(), testEvent)
	if err == nil {
		t.Fatal("a relay presenting an untrusted certificate was accepted")
	}
	if !strings.Contains(err.Error(), "dialling") {
		t.Fatalf("the failure did not come from the implicit-TLS dial: %v", err)
	}

	assertModernTLS(t, r.awaitHello(t))
	<-r.closed
	if lines := r.received.all(); len(lines) != 0 {
		t.Fatalf("the client sent plaintext on an implicit-TLS port: %v", lines)
	}
}

// TestTheDeadlineCoversTheConnectionAndNotOnlyTheDial is the failure the Sink contract exists to
// prevent, in its most literal form.
//
// A relay that accepts the connection and then says nothing is not a hypothetical: it is what a mail
// server looks like while it is being restarted, and what a stateful firewall looks like after it has
// dropped the flow. The dial succeeds, so a bound that applied only to dialling leaves the caller
// parked for ever — and the caller here is a detached delivery holding one of a bounded number of
// outbound slots, so "for ever" means the control plane stops delivering anything at all.
func TestTheDeadlineCoversTheConnectionAndNotOnlyTheDial(t *testing.T) {
	r := startRelay(t, func(_ *relay, conn net.Conn, _ *bufio.Reader) {
		// Accepted, and then nothing. Held open until the test is done with it.
		<-time.After(10 * time.Second)
		_ = conn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := NewSMTP(r.config(), []string{"oncall@example.org"}).Deliver(ctx, testEvent)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a relay that never spoke reported a delivered mail")
	}
	if !strings.Contains(err.Error(), "greeting") {
		t.Fatalf("the failure did not come from waiting on the greeting: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the caller waited %s on a connection that was never going to speak", elapsed)
	}
}

// TestASlowRelayIsBoundedEvenWhenTheCallerIsPatient is the same property with the caller's deadline
// removed from under it, which is the case production actually takes.
//
// mailRule gives a delivery a sixty-second budget so that three retries against a restarting relay fit
// inside it. That budget is deliberately longer than one attempt is allowed to take, so the sink's own
// fifteen seconds is what has to bound this — and if it did not, one unresponsive relay would consume
// the whole retry budget in a single silent attempt and the retry that exists for exactly this case
// would never happen.
//
// It costs the sink's full deadline in wall-clock time and is therefore skipped under -short. There is
// no seam to shorten: smtpDeadline is a constant, deliberately, because a mail deadline that a caller
// could widen is a mail deadline.
func TestASlowRelayIsBoundedEvenWhenTheCallerIsPatient(t *testing.T) {
	if testing.Short() {
		t.Skip("this test waits out smtpDeadline; it is the only way to observe a constant")
	}
	r := startRelay(t, func(_ *relay, conn net.Conn, _ *bufio.Reader) {
		<-time.After(smtpDeadline + 15*time.Second)
		_ = conn.Close()
	})

	patient, cancel := context.WithTimeout(context.Background(), smtpDeadline+45*time.Second)
	defer cancel()

	start := time.Now()
	err := NewSMTP(r.config(), []string{"oncall@example.org"}).Deliver(patient, testEvent)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a relay that never spoke reported a delivered mail")
	}
	if elapsed > smtpDeadline+10*time.Second {
		t.Fatalf("a delivery took %s against a sink whose deadline is %s", elapsed, smtpDeadline)
	}
	if deadline, ok := patient.Deadline(); ok && time.Now().After(deadline) {
		t.Fatal("the delivery ran until the caller's deadline rather than its own")
	}
}

// TestAnUnconfiguredRelayAndAnEmptyRecipientListAreRefusedBeforeAnySocket keeps the two arrangements
// that produce no mail from producing a connection attempt instead.
//
// Both are ordinary operator states rather than bugs — an installation with no --smtp-host, a rule
// whose recipients were cleared during an incident — and both have to fail with a sentence that names
// the arrangement, because the caller stamps that sentence on the rule as the record of why no mail
// went out.
func TestAnUnconfiguredRelayAndAnEmptyRecipientListAreRefusedBeforeAnySocket(t *testing.T) {
	err := NewSMTP(SMTPConfig{}, []string{"oncall@example.org"}).Deliver(context.Background(), testEvent)
	if err == nil || !strings.Contains(err.Error(), "SMTP") {
		t.Fatalf("an unconfigured relay: %v", err)
	}

	// The recipient half gets a live relay to not connect to, because this is the arrangement where a
	// socket is actually possible: the host, the port and the sender are all valid, and only the list
	// of people to tell is empty. Reading the error text alone would pass against a build that dialled,
	// greeted, negotiated TLS and only then noticed it had nobody to send to — which is a connection to
	// a mail server on every event, from an installation that mails nothing.
	connected := make(chan struct{})
	r := startRelay(t, func(_ *relay, _ net.Conn, _ *bufio.Reader) { close(connected) })

	err = NewSMTP(r.config(), nil).Deliver(context.Background(), testEvent)
	if err == nil || !strings.Contains(err.Error(), "recipients") {
		t.Fatalf("an empty recipient list: %v", err)
	}
	select {
	case <-connected:
		t.Fatal("a delivery with no recipients opened a connection to the relay anyway")
	case <-time.After(250 * time.Millisecond):
	}
}

// TestImplicitTLSIsSelectedByThePortAndNothingElse covers the half of the transport decision that a
// runner unable to bind 465 can still observe.
//
// The decision is made twice — once to choose the dialer, once to decide whether STARTTLS is still
// owed — and a build where the two disagreed would dial TLS and then write the word STARTTLS into a
// stream the relay is already reading as TLS records. That is why it is one predicate rather than two
// comparisons, and asserting the predicate directly is what keeps the classification covered on every
// runner, whatever the port bind does.
//
// 587 and 25 are here because they are the ports operators actually configure, and both must take the
// STARTTLS path; 0 is the unconfigured zero value, which must not accidentally mean implicit TLS.
func TestImplicitTLSIsSelectedByThePortAndNothingElse(t *testing.T) {
	for _, c := range []struct {
		// port is the configured relay port.
		port int

		// want is whether TLS is expected from the first byte.
		want bool
	}{
		{465, true},
		{587, false},
		{25, false},
		{2525, false},
		{0, false},
		{4650, false},
	} {
		if got := (SMTPConfig{Host: "relay.invalid", Port: c.port}).implicitTLS(); got != c.want {
			t.Errorf("port %d: implicitTLS() = %v, want %v", c.port, got, c.want)
		}
	}
}

// TestNetSMTPRefusesALineBreakInAnAddress pins the mechanism that closes the two headers
// sanitizeHeader does not touch.
//
// Only the Subject is sanitized. From and To are interpolated into the message verbatim, and one of
// them is operator-supplied — a rule's recipient list. internal/server refuses a recipient containing
// a line break, but that is a validation two packages away, and this package's own correctness should
// not depend on a row having come through that handler: a migration, a restore, or a future writer
// that forgets would each produce a recipient nobody checked.
//
// What actually closes it is the standard library. Client.Mail and Client.Rcpt each run the address
// through validateLine, which refuses CR and LF, and Deliver calls both of them *before* it renders
// the message — so a poisoned address ends the conversation with an error rather than becoming a Bcc
// header. That is a dependency on somebody else's implementation detail, which is exactly the kind of
// thing worth an assertion: if a future Go release stopped validating, this package would silently
// lose its only defence for those two headers, and nothing else here would notice.
//
// Driven against net/smtp directly rather than through Deliver, deliberately. Deliver verifies the
// relay's certificate before it reaches Mail or Rcpt, so an end-to-end version would be refused at the
// handshake and would pass without ever exercising the property it names.
func TestNetSMTPRefusesALineBreakInAnAddress(t *testing.T) {
	poisoned := []string{
		"oncall@example.org>\r\nBcc: attacker@example.net",
		"oncall@example.org\nBcc: attacker@example.net",
		"oncall@example.org\rBcc: attacker@example.net",
	}

	for _, address := range poisoned {
		r, client := conversingRelay(t)

		if err := client.Mail(address); err == nil {
			t.Errorf("Mail(%q) was accepted", address)
		}
		if err := client.Rcpt(address); err == nil {
			t.Errorf("Rcpt(%q) was accepted", address)
		}
		_ = client.Close()

		<-r.closed
		for _, line := range r.received.all() {
			if strings.Contains(strings.ToLower(line), "bcc:") {
				t.Errorf("%q: an injected header reached the relay: %q", address, line)
			}
		}
		if r.received.sawCommand("DATA") {
			t.Errorf("%q: the conversation reached DATA", address)
		}
	}

	// And a clean address is accepted by the same relay, or every assertion above would be satisfied
	// by a client that could not send anything at all.
	r, client := conversingRelay(t)
	if err := client.Mail("farrier@example.org"); err != nil {
		t.Fatalf("a clean sender was refused, so this test proves nothing: %v", err)
	}
	if err := client.Rcpt("oncall@example.org"); err != nil {
		t.Fatalf("a clean recipient was refused, so this test proves nothing: %v", err)
	}
	_ = client.Close()
	<-r.closed
	if !r.received.sawCommand("MAIL FROM") || !r.received.sawCommand("RCPT TO") {
		t.Fatalf("the clean pair never reached the relay: %v", r.received.all())
	}
}

// conversingRelay starts a plaintext relay that answers every command, and returns a client on it.
//
// Plaintext because this is about address validation rather than transport: the client here is
// net/smtp's, driven directly, and the point is what it refuses to put on the wire at all. Deliver's
// own refusal to speak to a relay like this one is asserted separately, and unconditionally, by
// TestGuaranteeAlertMailIsRefusedRatherThanSentInPlaintext.
func conversingRelay(t *testing.T) (*relay, *smtp.Client) {
	t.Helper()

	r := startRelay(t, func(r *relay, conn net.Conn, in *bufio.Reader) {
		_, _ = conn.Write([]byte("220 relay.invalid ESMTP\r\n"))
		for {
			line, err := r.readLine(in)
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(strings.ToUpper(line), "EHLO"):
				_, _ = conn.Write([]byte("250-relay.invalid\r\n250 SIZE 10240000\r\n"))
			case strings.HasPrefix(strings.ToUpper(line), "QUIT"):
				_, _ = conn.Write([]byte("221 2.0.0 Bye\r\n"))
				return
			default:
				_, _ = conn.Write([]byte("250 2.0.0 Ok\r\n"))
			}
		}
	})

	conn, err := net.Dial("tcp", net.JoinHostPort(r.host, strconv.Itoa(r.port)))
	if err != nil {
		t.Fatalf("dialling the relay: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client, err := smtp.NewClient(conn, r.host)
	if err != nil {
		t.Fatalf("greeting the relay: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return r, client
}
