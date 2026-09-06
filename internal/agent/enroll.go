package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
)

// EnrollOptions are the inputs to enrolling a host.
type EnrollOptions struct {
	// ServerURL is the control plane to enrol with.
	ServerURL string

	// Token is the single-use bootstrap token.
	Token string

	// StateDir is where the agent keeps its key, certificate and state.
	StateDir string

	// CABundle is a path to the control plane's CA, for a private server certificate.
	CABundle string

	// SignersFile is a local trusted-signers file to install before anything is fetched.
	//
	// This is what solves the chicken-and-egg problem in docs/SECURITY.md §7: the trust anchor is
	// established from a local, administrator-chosen file *before* a bootstrap template is requested,
	// so the template can be verified against a key the server never supplied.
	SignersFile string

	// PolicyFile is a local policy.toml to install.
	PolicyFile string

	// Bootstrap names a provisioning template to apply, exactly once, during enrolment.
	//
	// It is per-invocation and never a server default or a group setting. Without signers present it
	// refuses rather than falling back to trusting the server.
	Bootstrap string

	// Hostname overrides the reported hostname, for testing.
	Hostname string

	// seedDir overrides where the verified user-data is written, for tests. Empty means
	// CloudInitSeedDir, which is root-owned and therefore unreachable from a unit test.
	seedDir string

	// applyUserData overrides how the seeded user-data is applied, for tests. Nil means cloud-init's
	// own stages via internal/run; a unit test must not reinitialise cloud-init on the machine
	// running it.
	applyUserData func(ctx context.Context) error
}

// ErrNoTrustAnchor reports that --bootstrap was requested with no trusted signers present.
//
// It is a named error because it is the one refusal in enrolment that is a security property rather
// than a validation failure, and the message a user sees for it needs to explain the whole design.
var ErrNoTrustAnchor = errors.New("agent: no trusted signers")

// Enroll registers this host with a control plane and writes its credentials.
//
// The private key is generated here and never leaves the host: only a certificate signing request is
// sent. The certificate that comes back is written atomically alongside it, so that an interrupted
// enrolment leaves a host that is not enrolled rather than one that is half enrolled.
func Enroll(ctx context.Context, opts EnrollOptions) (*State, error) {
	if opts.ServerURL == "" || opts.Token == "" {
		return nil, errors.New("agent: a server URL and a token are required")
	}
	if err := os.MkdirAll(opts.StateDir, 0o750); err != nil {
		return nil, fmt.Errorf("agent: creating %s: %w", opts.StateDir, err)
	}

	// The trust anchor and the policy are installed first, from local files the administrator chose,
	// before anything is fetched. Ordering is the whole mechanism: a bootstrap template verified
	// against signers the same server supplied would be verified against nothing.
	if opts.SignersFile != "" {
		if err := installLocalFile(opts.SignersFile, signing.TrustedSignersPath); err != nil {
			return nil, err
		}
	}
	if opts.PolicyFile != "" {
		if err := installLocalFile(opts.PolicyFile, "/etc/hostseal/policy.toml"); err != nil {
			return nil, err
		}
	}

	var signers *signing.SignerSet
	if opts.Bootstrap != "" {
		var err error
		if signers, err = signing.LoadTrustedSigners(); err != nil {
			return nil, fmt.Errorf("agent: reading the trust anchor: %w", err)
		}
		if signers.Empty() {
			return nil, fmt.Errorf("%w: --bootstrap needs a key in %s to verify the template against, "+
				"and there is none. Pass --signers with a local file first. HostSeal will not fall back "+
				"to trusting the server: a template verified against a key the server supplied is a "+
				"template verified against nothing",
				ErrNoTrustAnchor, signing.TrustedSignersPath)
		}
		// The interlock is read here, before the token is spent, and again in verifyBootstrap. It
		// needs nothing from the network — it is one local file — and asking it late is expensive in a
		// way that is invisible until it happens: the control plane consumes the single-use token,
		// issues a certificate and records the machine id before the agent refuses, so the operator is
		// left with a phantom host they must delete before the machine can be enrolled at all. Asking
		// the local question locally costs one stat and wedges nobody.
		if err := checkBootstrapInterlock(opts.StateDir); err != nil {
			return nil, err
		}
	}

	key, csrPEM, err := generateKeyAndCSR()
	if err != nil {
		return nil, err
	}

	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	machineID, err := MachineIDHash(opts.StateDir)
	if err != nil {
		// Not fatal. A container or a minimal image may have no machine-id, and refusing to enrol it
		// would exclude exactly the hosts most likely to be forgotten. Duplicate detection is weaker
		// without it, which is worth a warning and not worth a refusal.
		slog.Warn("could not hash the machine id; duplicate detection will be weaker", "error", err)
	}

	client, err := NewUnauthenticatedClient(opts.ServerURL, opts.CABundle)
	if err != nil {
		return nil, err
	}

	res, err := client.Enroll(ctx, protocol.EnrollRequest{
		Token:              opts.Token,
		CSR:                string(csrPEM),
		Hostname:           hostname,
		MachineIDHash:      machineID,
		AgentVersion:       buildinfo.Version,
		RequestedBootstrap: opts.Bootstrap,
	})
	if err != nil {
		return nil, fmt.Errorf("agent: enrolling: %w", err)
	}
	if res.HostID == "" || res.Certificate == "" {
		return nil, errors.New("agent: the control plane returned an incomplete enrolment response")
	}
	// Checked rather than assumed, because this value becomes content in a document something else
	// parses: the agent writes it into cloud-init's meta-data as `instance-id`, and a control plane
	// that returned an id containing a newline could add keys to that YAML — `public-keys`, which
	// cloud-init installs into authorized_keys — beside a template the operator did approve. See
	// protocol.ValidHostID.
	if !protocol.ValidHostID(res.HostID) {
		return nil, fmt.Errorf("agent: the control plane assigned the host id %q, which is not %s; "+
			"refusing to enrol", res.HostID, protocol.HostIDShape)
	}

	var bootstrapKey signing.PublicKey
	if opts.Bootstrap != "" {
		if res.Bootstrap == nil {
			return nil, enrolledButRefused(res.HostID, fmt.Errorf(
				"agent: --bootstrap %q was requested and the control plane returned no template; "+
					"refusing to continue as though one had been applied", opts.Bootstrap))
		}
		// The name the operator typed must be the name that came back. The signature covers the name,
		// so a mismatch is a control plane returning a genuinely signed template for something else —
		// and "--bootstrap standard-server applied database-wipe" is not a sentence anybody should be
		// able to write.
		if res.Bootstrap.Name != opts.Bootstrap {
			return nil, enrolledButRefused(res.HostID, fmt.Errorf(
				"agent: --bootstrap %q but the control plane returned a template named %q; refusing",
				opts.Bootstrap, res.Bootstrap.Name))
		}
		// Verified — interlock, signature against this host's own trusted-signers, full text printed —
		// before any credential is written, so a template that fails verification leaves nothing
		// behind. Application waits until the host is enrolled locally, further down: a template may
		// legitimately end in a reboot, and an operation that may not return must find the credential
		// already durable, the same ordering the agent uses for a result before host.reboot.
		key, err := verifyBootstrap(opts.StateDir, signers, *res.Bootstrap)
		if err != nil {
			return nil, enrolledButRefused(res.HostID, err)
		}
		bootstrapKey = key
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("agent: encoding the private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := WriteCredential(opts.StateDir, []byte(res.Certificate), keyPEM); err != nil {
		return nil, err
	}
	if res.CABundle != "" {
		if err := WriteFileAtomic(filepath.Join(opts.StateDir, CABundleFile), []byte(res.CABundle), 0o644); err != nil {
			return nil, err
		}
	}
	// Cached now as well as on every heartbeat, so that a host enrolled and immediately handed a
	// routine job can verify it without waiting for a beat. A failure here is logged rather than
	// fatal: enrolment has already succeeded on the server, the host has a working credential, and
	// the next heartbeat will supply the key again. Failing the whole enrolment over the key that
	// governs one intent would be the wrong trade.
	if err := StoreOnlineKey(opts.StateDir, res.OnlineKey); err != nil {
		slog.Warn("could not cache the control plane's online key at enrolment; "+
			"routine jobs are refused until a heartbeat supplies it", "error", err)
	}

	state := &State{ServerURL: trimSlash(opts.ServerURL), HostID: res.HostID, EnrolledAt: time.Now()}
	if err := state.Save(opts.StateDir); err != nil {
		return nil, err
	}

	// Before the bootstrap rather than after it, because a template may legitimately end in a reboot
	// and the machine has to come back with a credential its service account can open.
	if err := AdoptStateDir(opts.StateDir); err != nil {
		return nil, enrolledButUnreadable(res.HostID, opts.StateDir, err)
	}

	if opts.Bootstrap != "" {
		// Applied last, after the credential and the state are durable: a bootstrap template may
		// legitimately end in a reboot, and a machine that comes back must come back enrolled. A
		// failure here does not undo the enrolment — the error says so, because "your host is fine
		// and your template is not" and "start over" are very different afternoons.
		if err := applyBootstrap(ctx, opts, *res.Bootstrap, bootstrapKey, res.HostID); err != nil {
			return nil, fmt.Errorf("agent: enrolled as %s, and the bootstrap did not complete: %w",
				res.HostID, err)
		}
	}

	// Again, for the interlock record the bootstrap writes into the same directory as root.
	if err := AdoptStateDir(opts.StateDir); err != nil {
		return nil, enrolledButUnreadable(res.HostID, opts.StateDir, err)
	}

	slog.Info("enrolled", "host", res.HostID, "server", state.ServerURL, "hostname", hostname)
	return state, nil
}

// generateKeyAndCSR creates the host's key pair and a certificate signing request.
//
// ECDSA P-256 for the same reason the CA uses it: the agent's connection may pass through a proxy or a
// load balancer, and the whole reason the transport is ordinary HTTPS is that it survives those.
//
// The CSR's subject is deliberately minimal. The control plane overwrites it with the host id it
// assigns, because a CSR is an untrusted document and honouring its subject would let a host enrol
// under any name it liked.
func generateKeyAndCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: generating a key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "hostseal-agent"},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: creating a certificate request: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// installLocalFile copies an administrator-chosen file into place before anything is fetched.
//
// It refuses to overwrite an existing file. Silently replacing a host's trust anchor or its policy
// during a re-enrolment would undo decisions somebody made deliberately, and the recovery is noticing
// that a host started accepting things it used not to.
func installLocalFile(source, destination string) error {
	body, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("agent: reading %s: %w", source, err)
	}
	if existing, err := os.ReadFile(destination); err == nil && len(existing) > 0 {
		if string(existing) == string(body) {
			return nil
		}
		return fmt.Errorf("agent: %s already exists and differs from %s; refusing to replace it. "+
			"Edit it in place if the change is intended", destination, source)
	}
	// 0755, not 0750. /etc/hostseal holds root-owned, world-readable configuration that the
	// unprivileged hostseal user must be able to read: the agent reads policy.toml and trusted-signers
	// on every cycle, and a directory it cannot traverse would make the host refuse everything.
	//nolint:gosec // G301: deliberate, and the files inside are individually 0644 root:root.
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("agent: creating %s: %w", filepath.Dir(destination), err)
	}
	slog.Info("installing local file", "source", source, "destination", destination)
	return WriteFileAtomic(destination, body, 0o644)
}

// checkBootstrapInterlock reports whether a template has already been applied on this host.
//
// The interlock is one file — the same file that is the permanent record, so the two cannot disagree —
// and this is the whole of guardrail 4 in docs/SECURITY.md §7 on the reading side. It is deliberately
// a question about the local disk and nothing else, so that it can be asked before a single-use
// enrolment token is spent as well as immediately before a template is verified.
//
// Anything other than "there is no such file" refuses. A permission error, an I/O error or a directory
// where the record should be leaves the question unanswered, and treating an unanswered question as
// "no template has been applied" is exactly how a template gets applied twice.
func checkBootstrapInterlock(stateDir string) error {
	recordPath := filepath.Join(stateDir, BootstrapRecordFile)
	raw, err := os.ReadFile(recordPath)
	switch {
	case err == nil:
		// Named in the refusal where the record is readable. "A template was already applied" sends an
		// operator looking through a file; "standard-server was applied on the 4th" usually ends the
		// question.
		var applied bootstrapRecord
		if json.Unmarshal(raw, &applied) == nil && applied.Name != "" {
			return fmt.Errorf("agent: the template %q was already applied on this host at %s (see %s); "+
				"templates are applied at most once",
				applied.Name, applied.AppliedAt.Format(time.RFC3339), recordPath)
		}
		return fmt.Errorf("agent: a bootstrap template has already been applied on this host (see %s); "+
			"templates are applied at most once", recordPath)

	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("agent: cannot read the bootstrap record at %s, so whether a template has "+
			"already been applied here is unknown; refusing rather than risking a second application: %w",
			recordPath, err)
	}
	return nil
}

// enrolledButRefused says what a bootstrap refusal after a successful enrolment has left behind.
//
// Verification needs the template, and the template arrives in the enrolment response, so these
// refusals unavoidably happen after the control plane has consumed the single-use token and recorded
// this machine. Saying so turns a confusing second attempt — "a host with this machine id is already
// enrolled" — into one sentence naming what to do. The refusal itself does not change: nothing has been
// written locally, and this host applies no template.
func enrolledButRefused(hostID string, err error) error {
	return fmt.Errorf("%w\n\nThe control plane has already recorded this machine as %s and the "+
		"enrolment token is spent. Nothing was written on this host and no template was applied; "+
		"delete or revoke that host before enrolling this machine again", err, hostID)
}

// enrolledButUnreadable reports an enrolment the service account cannot use.
//
// A distinct error from enrolledButRefused, and the difference is what the operator should do next.
// That one means nothing was written and the machine has to be released on the control plane first;
// this one means the enrolment worked, the credential is on disk, and the only problem is which user
// owns it. Telling somebody to start over here would spend a second token to reproduce the same files.
//
// It names the command, because the alternative is the failure this whole function exists to prevent:
// an agent that starts, cannot read its own credential, reports "not enrolled", and leaves an operator
// looking at a control plane that shows the host and a host that sends nothing.
func enrolledButUnreadable(hostID, stateDir string, err error) error {
	return fmt.Errorf("%w\n\nThis host enrolled as %s and the credential is on disk, but it is owned "+
		"by the wrong user, so the agent will report \"not enrolled\" and send nothing. Do not enrol "+
		"again — that spends another token for the same files. Fix the ownership instead:\n\n"+
		"    sudo chown -R hostseal:hostseal %s\n    sudo systemctl restart hostseal-agent",
		err, hostID, stateDir)
}

// verifyBootstrap checks a provisioning template against this host's own trust anchor, and shows it.
//
// This is the exception named in the second paragraph of the guarantee, and the guardrails in
// docs/SECURITY.md §7 that constrain *authorising* a template are enforced here: the apply-once
// interlock is checked first, the signature is verified against a key already in this host's own
// trusted-signers, and the full text is printed before anything could happen.
//
// It stops there, and returns the key that authorised it. Applying — and writing the permanent record
// that consumes the interlock — belongs to applyBootstrap, which runs only after the enrolment
// credential is durable. Keeping verification and application apart is what lets a failed verification
// leave nothing behind: no record, no spent interlock, and a host that can still be enrolled for the
// template it was meant to have.
func verifyBootstrap(stateDir string, signers *signing.SignerSet,
	bootstrap protocol.Bootstrap) (signing.PublicKey, error) {

	if err := checkBootstrapInterlock(stateDir); err != nil {
		return signing.PublicKey{}, err
	}

	if signers == nil || signers.Empty() {
		return signing.PublicKey{}, fmt.Errorf(
			"%w: refusing to apply a template with no trust anchor", ErrNoTrustAnchor)
	}

	signature, err := decodeSignature(bootstrap.Signature)
	if err != nil {
		return signing.PublicKey{}, err
	}
	payload, err := canonical.Marshal(bootstrap.SignedPayload())
	if err != nil {
		return signing.PublicKey{}, fmt.Errorf("agent: canonicalising the bootstrap template: %w", err)
	}
	key, err := signers.Verify(payload, signature)
	if err != nil {
		return signing.PublicKey{}, fmt.Errorf(
			"agent: the bootstrap template is not signed by any key in %s: %w",
			signing.TrustedSignersPath, err)
	}

	// Printed in full, to the terminal and to the journal, before anything could act on it. An operator
	// must be able to see exactly what is about to run on their machine.
	//
	// Quoted with %q rather than printed raw. The body comes from the control plane, and a raw body can
	// contain terminal control sequences that scroll the real content away, or a line that looks exactly
	// like the end-of-template marker followed by something else — so the operator reads a template and
	// approves a different one. %q escapes both, at the cost of a less pretty display of a document
	// nobody should be approving casually anyway.
	fmt.Printf("\n--- bootstrap template %q, signed by %s ---\n%q\n--- end of template ---\n\n",
		bootstrap.Name, key, bootstrap.Body)

	// Identity and a digest, not the body.
	//
	// A template legitimately carries credentials — a break-glass account's hashed password, a static
	// deploy key; provision.Warnings flags exactly those shapes — and slog.Info here wrote the whole of
	// it into journald, structured and indexed, on every host enrolled from that template, where it
	// persists for as long as the journal does. internal/provision's own doc says rendered output is a
	// credential and is "never written to a log line or an audit entry", and this was the line that
	// made that untrue.
	//
	// Nothing is lost that the audit needs. The verbatim body is fsynced into the bootstrap record
	// before anything runs, and that record — not a log line — is what docs/SECURITY.md §7 guardrail 2
	// names as the durable statement of what was applied. The digest is what ties the two together: an
	// operator with a journal and a record can prove they are the same document without the journal
	// holding a second copy of it.
	slog.Info("bootstrap template verified",
		"name", bootstrap.Name, "version", bootstrap.Version, "signer", key.String(),
		"bytes", len(bootstrap.Body), "digest", canonical.DigestBytes([]byte(bootstrap.Body)))

	return key, nil
}
