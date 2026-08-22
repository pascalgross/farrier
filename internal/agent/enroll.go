package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pegasusnetworks/farrier/internal/buildinfo"
	"github.com/pegasusnetworks/farrier/internal/protocol"
	"github.com/pegasusnetworks/farrier/internal/signing"
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
	// This is what solves the chicken-and-egg problem in docs/SECURITY.md §6: the trust anchor is
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
		if err := installLocalFile(opts.PolicyFile, "/etc/farrier/policy.toml"); err != nil {
			return nil, err
		}
	}

	if opts.Bootstrap != "" {
		signers, err := signing.LoadTrustedSigners()
		if err != nil {
			return nil, fmt.Errorf("agent: reading the trust anchor: %w", err)
		}
		if signers.Empty() {
			return nil, fmt.Errorf("%w: --bootstrap needs a key in %s to verify the template against, "+
				"and there is none. Pass --signers with a local file first. Farrier will not fall back "+
				"to trusting the server: a template verified against a key the server supplied is a "+
				"template verified against nothing",
				ErrNoTrustAnchor, signing.TrustedSignersPath)
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

	if opts.Bootstrap != "" {
		if res.Bootstrap == nil {
			return nil, fmt.Errorf("agent: --bootstrap %q was requested and the control plane returned "+
				"no template; refusing to continue as though one had been applied", opts.Bootstrap)
		}
		if err := applyBootstrap(opts.StateDir, *res.Bootstrap); err != nil {
			return nil, err
		}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("agent: encoding the private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := WriteFileAtomic(filepath.Join(opts.StateDir, KeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(filepath.Join(opts.StateDir, CertFile), []byte(res.Certificate), 0o644); err != nil {
		return nil, err
	}
	if res.CABundle != "" {
		if err := WriteFileAtomic(filepath.Join(opts.StateDir, CABundleFile), []byte(res.CABundle), 0o644); err != nil {
			return nil, err
		}
	}

	state := &State{ServerURL: trimSlash(opts.ServerURL), HostID: res.HostID, EnrolledAt: time.Now()}
	if err := state.Save(opts.StateDir); err != nil {
		return nil, err
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
		Subject: pkix.Name{CommonName: "farrier-agent"},
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
	// 0755, not 0750. /etc/farrier holds root-owned, world-readable configuration that the
	// unprivileged farrier user must be able to read: the agent reads policy.toml and trusted-signers
	// on every cycle, and a directory it cannot traverse would make the host refuse everything.
	//nolint:gosec // G301: deliberate, and the files inside are individually 0644 root:root.
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("agent: creating %s: %w", filepath.Dir(destination), err)
	}
	slog.Info("installing local file", "source", source, "destination", destination)
	return WriteFileAtomic(destination, body, 0o644)
}

// BootstrapRecordFile is where an applied provisioning template is recorded permanently.
const BootstrapRecordFile = "bootstrap-applied.json"

// bootstrapRecord is what is written to the host before a template is executed.
type bootstrapRecord struct {
	// Name is the template as the operator named it.
	Name string `json:"name"`

	// Body is the full text, recorded so that what ran is knowable afterwards.
	Body string `json:"body"`

	// SignerKeyID names the key from this host's own trusted-signers that authorised it.
	SignerKeyID string `json:"signerKeyId"`

	// AppliedAt is when it was applied.
	AppliedAt time.Time `json:"appliedAt"`
}

// applyBootstrap verifies, records and would apply a provisioning template.
//
// This is the exception named in the second paragraph of the guarantee, and every guardrail in
// docs/SECURITY.md §6 is enforced here: the signature is checked against a key already in this host's
// own trusted-signers, the full text is printed and recorded *before* anything happens, and an on-disk
// interlock makes it exactly once.
//
// Phase 0 stops before applying: Tier 2 provisioning arrives in phase 3, and cloud-init will do the
// applying then. Farrier will never ship a hand-written YAML-to-shell engine, which would be the exec
// channel wearing a hat.
func applyBootstrap(stateDir string, bootstrap protocol.Bootstrap) error {
	recordPath := filepath.Join(stateDir, BootstrapRecordFile)
	if _, err := os.Stat(recordPath); err == nil {
		return fmt.Errorf("agent: a bootstrap template has already been applied on this host "+
			"(see %s); templates are applied at most once", recordPath)
	}

	signers, err := signing.LoadTrustedSigners()
	if err != nil {
		return fmt.Errorf("agent: reading the trust anchor: %w", err)
	}
	if signers.Empty() {
		return fmt.Errorf("%w: refusing to apply a template with no trust anchor", ErrNoTrustAnchor)
	}

	signature, err := decodeSignature(bootstrap.Signature)
	if err != nil {
		return err
	}
	key, err := signers.Verify([]byte(bootstrap.Body), signature)
	if err != nil {
		return fmt.Errorf("agent: the bootstrap template is not signed by any key in %s: %w",
			signing.TrustedSignersPath, err)
	}

	// Printed in full, to the terminal and to the journal, and written to disk — all before execution.
	// An operator must be able to see exactly what is about to run on their machine, and afterwards
	// anybody auditing the host must be able to see exactly what did.
	fmt.Printf("\n--- bootstrap template %q, signed by %s ---\n%s\n--- end of template ---\n\n",
		bootstrap.Name, key, bootstrap.Body)
	slog.Info("applying bootstrap template", "name", bootstrap.Name, "signer", key.String(),
		"body", bootstrap.Body)

	record, err := jsonRecord(bootstrapRecord{
		Name:        bootstrap.Name,
		Body:        bootstrap.Body,
		SignerKeyID: key.KeyID,
		AppliedAt:   time.Now(),
	})
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(recordPath, record, 0o644); err != nil {
		return err
	}

	return fmt.Errorf("agent: this build applies no bootstrap templates. The template was verified "+
		"against %s and recorded in %s; nothing was executed. Tier 2 provisioning arrives in phase 3 "+
		"and cloud-init will do the applying", key, recordPath)
}
