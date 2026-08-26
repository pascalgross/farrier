// Package ca is the control plane's private certificate authority.
//
// Farrier issues its own agent certificates rather than using a public CA because the certificates
// identify hosts to one control plane, not services to the internet. A private CA means enrolment needs
// no external dependency, no rate limit and no DNS name per host, and it means the control plane can
// revoke a host instantly by forgetting its fingerprint.
//
// Revocation is deliberately a database fingerprint check on every request rather than a CRL or OCSP.
// The check has to happen anyway to find the host, so it costs nothing; it takes effect immediately
// rather than at the next distribution interval; and there is no stapling infrastructure to
// misconfigure. See docs/PROTOCOL.md §2.2.
//
// What compromising this key does and does not buy is worth being precise about: it lets an attacker
// impersonate *hosts to the server*. It does not let them run code on a host, because an agent
// authorises a job by its intent class and its signature, not by who asked. That asymmetry is why the
// CA key and the database are worth backing up separately.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// File names inside the CA directory.
const (
	// CertFile is the CA certificate, world-readable because it is public.
	CertFile = "ca.crt"

	// KeyFile is the CA private key, 0600 and never transmitted.
	KeyFile = "ca.key"
)

// Lifetimes.
const (
	// CALifetime is how long the authority itself is valid.
	//
	// Ten years, because rotating a private CA means re-enrolling every host, and an authority that
	// expires unexpectedly takes an entire fleet offline at once. It is long on purpose and the
	// expiry is surfaced in the UI so it is not a surprise.
	CALifetime = 10 * 365 * 24 * time.Hour

	// AgentCertLifetime is how long an issued agent certificate is valid.
	//
	// Ninety days, renewed automatically at two thirds of that. Short enough that a leaked certificate
	// stops working on its own, long enough that a host offline for a fortnight comes back and
	// re-keys rather than needing to be re-enrolled by hand.
	AgentCertLifetime = 90 * 24 * time.Hour

	// RenewAfterFraction is the point in a certificate's life at which the agent renews.
	//
	// Two thirds leaves a full third of the lifetime — thirty days — in which a failing renewal can be
	// retried, noticed and fixed before the certificate actually expires.
	RenewAfterFraction = 2.0 / 3.0
)

// ErrNotInitialised reports that no CA exists at the given directory.
var ErrNotInitialised = errors.New("ca: not initialised")

// Authority is a loaded certificate authority.
type Authority struct {
	// cert is the CA certificate.
	cert *x509.Certificate

	// key is the CA private key.
	key *ecdsa.PrivateKey

	// certPEM is the encoded certificate, cached because it is returned on every enrolment.
	certPEM []byte
}

// Init creates a new authority in dir and returns it.
//
// It refuses to overwrite an existing one. Silently replacing a CA would invalidate every certificate
// in a fleet at once, and the recovery is re-enrolling every host by hand — so this is one of the very
// few places where refusing and making somebody move a file is the kind behaviour.
func Init(dir, commonName string) (*Authority, error) {
	if _, err := os.Stat(filepath.Join(dir, KeyFile)); err == nil {
		return nil, fmt.Errorf("ca: %s already holds a certificate authority; refusing to replace it, "+
			"because doing so would invalidate every agent certificate in the fleet", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca: creating %s: %w", dir, err)
	}

	// ECDSA P-256 rather than Ed25519. Go's TLS stack handles Ed25519 certificates, but the agent's
	// connection may pass through a corporate proxy or a load balancer that does not, and the whole
	// reason the transport is ordinary HTTPS is that it survives those. P-256 is universally
	// supported and the difference matters to nobody's threat model.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generating key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Farrier"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(CALifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: creating certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: encoding key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// 0644 for the certificate and 0600 for the key. A CA certificate is a public document that every
	// agent is given a copy of; restricting it would protect nothing and would break any process
	// running as something other than the server's own user that needs to read it.
	//nolint:gosec // G306: a public certificate is meant to be readable.
	if err := os.WriteFile(filepath.Join(dir, CertFile), certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("ca: writing %s: %w", CertFile, err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("ca: writing %s: %w", KeyFile, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: reparsing the certificate just created: %w", err)
	}
	return &Authority{cert: cert, key: key, certPEM: certPEM}, nil
}

// Load opens an existing authority.
func Load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s; run `farrier-server ca init`", ErrNotInitialised, dir)
	}
	if err != nil {
		return nil, fmt.Errorf("ca: reading %s: %w", CertFile, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, fmt.Errorf("ca: reading %s: %w", KeyFile, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("ca: ca.crt does not contain a PEM certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing ca.crt: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("ca: ca.key does not contain a PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing ca.key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: ca.key holds a %T, expected an ECDSA key", parsed)
	}
	return &Authority{cert: cert, key: key, certPEM: certPEM}, nil
}

// CertificatePEM returns the CA certificate, for agents to pin.
func (a *Authority) CertificatePEM() []byte { return a.certPEM }

// Certificate returns the parsed CA certificate, for building a TLS client pool.
func (a *Authority) Certificate() *x509.Certificate { return a.cert }

// NotAfter reports when the authority itself expires.
//
// It is surfaced in the UI because a private CA quietly expiring takes an entire fleet offline at once,
// and ten years from now nobody will remember that it was going to.
func (a *Authority) NotAfter() time.Time { return a.cert.NotAfter }

// Issue signs a certificate for one host from its CSR.
//
// The subject is overwritten with the host id the caller supplies rather than taken from the request.
// A CSR is an untrusted document: honouring the subject in it would let a host enrol under any name it
// liked, and let a renewal re-key a certificate for a different host entirely.
func (a *Authority) Issue(csrPEM []byte, hostID string) ([]byte, *x509.Certificate, error) {
	if hostID == "" {
		return nil, nil, errors.New("ca: a host id is required")
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("ca: body does not contain a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parsing certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("ca: certificate request signature: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		// Only the common name is taken from Farrier, and everything else in the CSR's subject is
		// discarded. The host id is the identity the server will look up on every request.
		Subject:     pkix.Name{CommonName: hostID, Organization: []string{"Farrier Agents"}},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(AgentCertLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// No DNS names and no IP addresses. An agent certificate authenticates a client and is never
		// presented as a server identity, so any SAN here would only be a way to use it as one.
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: reparsing the certificate just signed: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// ClientCAPool returns a pool containing only this authority, for verifying agent certificates.
//
// It contains only this CA on purpose. Using the system roots would mean any publicly trusted
// certificate could authenticate as an agent, which is a spectacular way to lose a fleet.
func (a *Authority) ClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return pool
}

// randomSerial returns a 128-bit random certificate serial number.
//
// Random rather than sequential: a sequential serial leaks how many hosts a control plane has issued
// to, which is business information a customer's own certificate should not carry.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: generating serial: %w", err)
	}
	return serial, nil
}

// RenewAt reports when a certificate should be renewed.
//
// The agent adds jitter to this so that a fleet enrolled on the same afternoon does not renew in the
// same minute three months later — which is a stampede that arrives exactly once and is therefore
// never load-tested.
func RenewAt(cert *x509.Certificate) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotBefore.Add(time.Duration(float64(lifetime) * RenewAfterFraction))
}

// Server certificate file names inside the CA directory.
const (
	// ServerCertFile is the control plane's own HTTPS certificate, when Farrier issued it.
	ServerCertFile = "server.crt"

	// ServerKeyFile is the key for it.
	ServerKeyFile = "server.key"
)

// EnsureServerCertificate issues a server certificate for the control plane, if one does not exist.
//
// It exists because client certificates require TLS. Serving the agent protocol over plain HTTP is not
// merely insecure — it does not work at all, since there is no client certificate to present — so a
// control plane started without one needs *something*, and an unusable process that logs a warning is
// worse than one that works.
//
// The certificate is signed by the same private CA that issues agent certificates, which has a
// pleasant consequence: an agent is handed the CA bundle at enrolment and writes it to disk, so from
// its second request onwards it verifies the control plane with no extra configuration. Only the first
// call, enrolment itself, needs the operator to pass --ca.
//
// It is deliberately not a substitute for a real certificate. An operator's browser will not trust this
// one, and telling people to click through a warning to reach their fleet management console is how
// clicking through warnings becomes a habit. Production deployments should pass --tls-cert and
// --tls-key from whatever issues their public certificates.
func (a *Authority) EnsureServerCertificate(dir string, dnsNames []string, ips []net.IP) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, ServerCertFile)
	keyPath = filepath.Join(dir, ServerKeyFile)

	// localhost and the loopback addresses are always included, because the most common first use of a
	// freshly initialised control plane is somebody curling it from the machine it runs on.
	dnsNames = append([]string{"localhost"}, dnsNames...)
	ips = append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, ips...)

	if reusable(certPath, keyPath, dnsNames, ips) {
		return certPath, keyPath, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("ca: generating a server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Farrier control plane", Organization: []string{"Farrier"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(AgentCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return "", "", fmt.Errorf("ca: signing the server certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("ca: encoding the server key: %w", err)
	}

	// 0644 for the certificate and 0600 for the key, as for the CA itself: a certificate is a public
	// document that every client is shown on every connection.
	//nolint:gosec // G306: a public certificate is meant to be readable.
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", fmt.Errorf("ca: writing %s: %w", ServerCertFile, err)
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", fmt.Errorf("ca: writing %s: %w", ServerKeyFile, err)
	}
	return certPath, keyPath, nil
}

// reusable reports whether an existing server certificate is still worth using.
//
// A certificate close to expiry is replaced rather than served: renewing on restart is free, and a
// control plane whose own certificate expires takes the whole fleet offline until somebody notices.
func reusable(certPath, keyPath string, dnsNames []string, ips []net.IP) bool {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if !time.Now().Before(RenewAt(cert)) {
		return false
	}
	for _, name := range dnsNames {
		if cert.VerifyHostname(name) != nil {
			return false
		}
	}
	for _, ip := range ips {
		if ip == nil || cert.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}
