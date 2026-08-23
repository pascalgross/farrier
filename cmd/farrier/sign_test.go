package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/signing"
	"github.com/pascalgross/farrier/internal/signing/backend/file"
)

// TestGuaranteeWhatIsShownIsWhatIsSigned is the property this command exists for.
//
// A control plane that handed the tool a digest to sign could render "restart nginx on web-01" while
// having "reboot every host" signed, and no care by the operator would catch it. So the display is
// derived from the payload rather than alongside it, and this asserts the two cannot drift: the bytes
// printed as "signed payload, verbatim" are the bytes the signature covers, and the human-readable
// summary is decoded from the same job.
func TestGuaranteeWhatIsShownIsWhatIsSigned(t *testing.T) {
	job, spec, decoded, err := buildSignableJob(
		"", "01JTESTHOST", "service.restart", `{"unit":"nginx.service"}`, "", time.Hour)
	if err != nil {
		t.Fatalf("building a signable job: %v", err)
	}

	payload, err := canonical.Marshal(job.SignedPayload("01JTESTHOST"))
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}

	// Everything the operator is shown has to appear in, or be derived from, the bytes being signed.
	for _, shown := range []string{job.ID, job.Nonce, "01JTESTHOST", "service.restart", "nginx.service"} {
		if !strings.Contains(string(payload), shown) {
			t.Errorf("the summary shows %q, which the signed payload does not contain", shown)
		}
	}
	if decoded.Describe() != "service.restart nginx.service" {
		t.Errorf("the operation is described as %q", decoded.Describe())
	}
	if spec.Class != intent.ClassDestructive {
		t.Errorf("class is %q; this test is about the tier that needs an offline signature", spec.Class)
	}

	// And the window is the one the summary reports, to the second the payload can carry. A signature
	// made over a time the payload cannot represent would verify against a different value than the one
	// displayed, and the failure would look like a broken key rather than a rounding decision.
	if !job.NotBefore.Equal(job.NotBefore.Truncate(time.Second)) {
		t.Error("notBefore carries sub-second precision the canonical payload discards")
	}
	if !job.NotAfter.Equal(job.NotAfter.Truncate(time.Second)) {
		t.Error("notAfter carries sub-second precision the canonical payload discards")
	}
}

// TestGuaranteeASignedJobVerifiesAgainstTheHostsOwnAnchor is the end of the chain this command starts.
//
// It signs with the file backend exactly as the command does, then verifies with signing.SignerSet
// exactly as the agent does — against a trusted-signers set built from the key's own public half. The
// two halves live in different packages and are written from different ends; the failure this catches
// is a signature that is correct in isolation and does not verify where it has to.
func TestGuaranteeASignedJobVerifiesAgainstTheHostsOwnAnchor(t *testing.T) {
	keyPath := t.TempDir() + "/ops.key"
	signer, err := file.Generate(keyPath, "ops-laptop", signing.Ed25519, []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })

	line, err := signing.TrustedSignerLine(signer)
	if err != nil {
		t.Fatalf("rendering the trusted-signers line: %v", err)
	}
	anchor, err := signing.ParseSigners(strings.NewReader(line), "test")
	if err != nil {
		t.Fatalf("parsing the anchor: %v", err)
	}

	const host = "01JTESTHOST"
	job, _, _, err := buildSignableJob("", host, "host.reboot", `{"delaySeconds":60}`, "", time.Hour)
	if err != nil {
		t.Fatalf("building a signable job: %v", err)
	}
	payload, err := canonical.Marshal(job.SignedPayload(host))
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	key, err := anchor.Verify(payload, signature)
	if err != nil {
		t.Fatalf("a job this command signed does not verify against the host's own anchor: %v", err)
	}
	if key.KeyID != "ops-laptop" {
		t.Errorf("verified against %q", key.KeyID)
	}

	// And the signature is over *that host*. Binding to a host id is what stops a signature authorising
	// the same operation everywhere, and it is a property of the payload rather than of the transport.
	elsewhere, err := canonical.Marshal(job.SignedPayload("01JOTHERHOST"))
	if err != nil {
		t.Fatalf("canonicalising for another host: %v", err)
	}
	if _, err := anchor.Verify(elsewhere, signature); err == nil {
		t.Fatal("a signature made for one host verified for another")
	}
}

// TestSignRefusesAnIntentItCannotAuthorise covers the two tiers this command has no business signing.
//
// A read intent is authorised by mTLS and a routine one by the control plane's own key. Producing an
// offline signature for either would create a job the control plane refuses to accept, and the operator
// would have entered a passphrase to find that out.
func TestSignRefusesAnIntentItCannotAuthorise(t *testing.T) {
	for _, name := range []string{"facts.collect", "packages.applySecurity"} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := buildSignableJob("", "01JTESTHOST", name, `{}`, "", time.Hour)
			if err == nil {
				t.Fatalf("%s was accepted for offline signing", name)
			}
			if !strings.Contains(err.Error(), "not signed offline") {
				t.Errorf("the refusal does not explain which tier signs it: %v", err)
			}
		})
	}
}

// TestSignRefusesAJobIdentifierAHostCannotReportAgainst keeps the operator-chosen id inside the shape
// the rest of the system can carry.
//
// The id becomes a path segment in the result endpoint and a filename in the agent's spool. Refused
// here rather than corrected, because the signature covers it: a normalised id would simply stop
// verifying, and the operator would be told their key was wrong.
func TestSignRefusesAJobIdentifierAHostCannotReportAgainst(t *testing.T) {
	for _, bad := range []string{"west/reboot", "reboot?now", "reboot-2026-08-23", strings.Repeat("A", 65)} {
		_, _, _, err := buildSignableJob(bad, "01JTESTHOST", "host.reboot", `{}`, "", time.Hour)
		if err == nil {
			t.Errorf("job id %q was accepted", bad)
		}
	}
}

// TestSignedRequestCarriesEverythingTheSignatureCovers checks the body this command prints is the body
// the control plane needs.
//
// A signed job's id, nonce and validity window all arrive from the signer, because all four are covered
// by the signature and a value chosen by the control plane would invalidate it. Omitting one from the
// request would produce a 400 that reads as a malformed request rather than as a missing field.
func TestSignedRequestCarriesEverythingTheSignatureCovers(t *testing.T) {
	const host = "01JTESTHOST"
	job, _, _, err := buildSignableJob("", host, "host.reboot", `{"delaySeconds":60}`, "", time.Hour)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	payload := job.SignedPayload(host)
	for _, field := range []string{"jobId", "hostId", "intent", "params", "notBefore", "notAfter", "nonce"} {
		if _, present := payload[field]; !present {
			t.Errorf("the signed payload has no %q; docs/PROTOCOL.md §8 fixes the set", field)
		}
	}
	if len(payload) != 7 {
		t.Errorf("the signed payload has %d fields, want the 7 docs/PROTOCOL.md §8 fixes: %v",
			len(payload), payload)
	}

	// issuedAt is deliberately not among them: it is not signed, so an agent measures a signed job's
	// age from notBefore instead. A payload that gained it would let a control plane defeat the local
	// age limit by restating when it issued the job.
	if _, present := payload["issuedAt"]; present {
		t.Error("the signed payload carries issuedAt, which docs/PROTOCOL.md §8 excludes on purpose")
	}
}
