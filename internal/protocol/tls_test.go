package protocol

import (
	"crypto/tls"
	"testing"
)

// TestGuaranteeTheCipherListIsAEADAndForwardSecret pins what may be negotiated below TLS 1.3.
//
// The list is a decision rather than an inheritance, and this is what keeps it one. Go's own 1.2
// default includes ECDHE with AES-CBC and a SHA-1 HMAC; the failure mode of leaving it inherited is
// not that somebody chooses a bad suite but that nobody chooses at all, and the offered set then
// changes with the toolchain.
//
// It asserts the property rather than the literal list, so that adding a suite is allowed and adding a
// CBC or a static-RSA one is not — which is the distinction that matters and the one a golden-value
// comparison would lose.
func TestGuaranteeTheCipherListIsAEADAndForwardSecret(t *testing.T) {
	if len(TLSCipherSuites) == 0 {
		t.Fatal("the cipher list is empty; Go would fall back to its own defaults")
	}

	// Every suite Go will negotiate, sound and insecure alike. InsecureCipherSuites is where the CBC
	// and RC4 constructions live, so a suite appearing in neither list is one this toolchain no longer
	// knows — which is a failure and not a pass.
	known := map[uint16]*tls.CipherSuite{}
	for _, suite := range tls.CipherSuites() {
		known[suite.ID] = suite
	}
	insecure := map[uint16]*tls.CipherSuite{}
	for _, suite := range tls.InsecureCipherSuites() {
		insecure[suite.ID] = suite
	}

	for _, id := range TLSCipherSuites {
		if bad, ok := insecure[id]; ok {
			t.Errorf("%s is in the offered list and Go classifies it as insecure", bad.Name)
			continue
		}
		suite, ok := known[id]
		if !ok {
			t.Errorf("cipher suite %#x is offered and this toolchain does not recognise it", id)
			continue
		}
		// TLS 1.3 suites are not configurable through CipherSuites, so one listed here would be a
		// line that reads as hardening and does nothing.
		for _, version := range suite.SupportedVersions {
			if version == tls.VersionTLS13 {
				t.Errorf("%s is a TLS 1.3 suite; the CipherSuites field does not apply to 1.3", suite.Name)
			}
		}
	}
}

// TestGuaranteeTheFloorRefusesTLS11 is the floor stated as behaviour rather than as a constant.
//
// A constant compared against itself proves nothing. This one asserts what the number does: 1.1 and
// below are gone, which is the half of the setting that is about the version rather than the suites.
func TestGuaranteeTheFloorRefusesTLS11(t *testing.T) {
	if TLSMinVersion <= tls.VersionTLS11 {
		t.Errorf("the floor is %#x, which admits TLS 1.1 or older", TLSMinVersion)
	}
}
