package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// TestCSR builds a certificate signing request whose subject names a given common name.
//
// It is exported for tests in other packages, which need to construct the one attack that matters
// against certificate renewal: a CSR is an untrusted document, and the server must ignore its subject
// entirely rather than honouring a request to be re-keyed as somebody else. Producing that request
// needs the same key and encoding machinery enrolment uses, and a second implementation in a test
// package would be a second thing to keep correct.
func TestCSR(commonName string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("agent: generating a key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return "", fmt.Errorf("agent: creating a certificate request: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
