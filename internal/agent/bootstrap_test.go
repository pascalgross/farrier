package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/signing"
)

// testBootstrap is the template these tests apply.
var testBootstrap = protocol.Bootstrap{
	Name:    "standard-server",
	Version: 3,
	Body:    "#cloud-config\nhostname: bootstrapped\n",
}

// testKey is the trusted-signers entry the fixture pretends verified the template.
//
// applyBootstrap takes the key verifyBootstrap returned; these tests hand it one directly, because
// verification's own behaviour — the anchor at a fixed root-owned path — is asserted where it runs and
// cannot be exercised from a unit test's privileges.
var testKey = signing.PublicKey{Algorithm: signing.Ed25519, KeyID: "ops-laptop", Backend: "file"}

// TestApplyBootstrapRecordsBeforeItRuns is guardrail 2 of docs/SECURITY.md §7 as an ordering assertion.
//
// The record must exist, durably and in full, at the moment the executor starts: it is the only thing
// that survives a template that crashes the machine halfway, and "what was attempted" is the question
// an incident asks. The fake executor does the asserting, because it runs at exactly the instant the
// ordering is about.
func TestApplyBootstrapRecordsBeforeItRuns(t *testing.T) {
	stateDir, seedDir := t.TempDir(), t.TempDir()
	recordPath := filepath.Join(stateDir, BootstrapRecordFile)

	var sawRecord bootstrapRecord
	opts := EnrollOptions{
		StateDir: stateDir,
		seedDir:  seedDir,
		applyUserData: func(_ context.Context) error {
			raw, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatalf("the executor started with no record on disk: %v", err)
			}
			if err := json.Unmarshal(raw, &sawRecord); err != nil {
				t.Fatalf("the record is not readable JSON: %v", err)
			}
			return nil
		},
	}

	if err := applyBootstrap(context.Background(), opts, testBootstrap, testKey, "01JHOST"); err != nil {
		t.Fatalf("applying: %v", err)
	}

	if sawRecord.Name != "standard-server" || sawRecord.Version != 3 {
		t.Errorf("the record names %q v%d", sawRecord.Name, sawRecord.Version)
	}
	if sawRecord.Body != testBootstrap.Body {
		t.Errorf("the record does not carry the body verbatim: %q", sawRecord.Body)
	}
	if sawRecord.SignerKeyID != "ops-laptop" {
		t.Errorf("the record names signer %q", sawRecord.SignerKeyID)
	}
	if sawRecord.VerifiedAgainst != signing.TrustedSignersPath {
		t.Errorf("the record claims verification against %q", sawRecord.VerifiedAgainst)
	}
	if sawRecord.AppliedAt.IsZero() {
		t.Error("the record carries no timestamp")
	}
}

// TestApplyBootstrapSeedsCloudInit proves the body becomes a file where cloud-init reads it, and never
// an argument.
func TestApplyBootstrapSeedsCloudInit(t *testing.T) {
	stateDir, seedDir := t.TempDir(), t.TempDir()

	ran := false
	opts := EnrollOptions{
		StateDir: stateDir,
		seedDir:  seedDir,
		applyUserData: func(_ context.Context) error {
			ran = true
			userData, err := os.ReadFile(filepath.Join(seedDir, "user-data"))
			if err != nil || string(userData) != testBootstrap.Body {
				t.Fatalf("the seed user-data is %q, %v", userData, err)
			}
			meta, err := os.ReadFile(filepath.Join(seedDir, "meta-data"))
			if err != nil || !strings.Contains(string(meta), "farrier-bootstrap-01JHOST") {
				t.Fatalf("the seed meta-data is %q, %v", meta, err)
			}
			return nil
		},
	}
	if err := applyBootstrap(context.Background(), opts, testBootstrap, testKey, "01JHOST"); err != nil {
		t.Fatalf("applying: %v", err)
	}
	if !ran {
		t.Fatal("the executor never ran")
	}
}

// TestApplyBootstrapIsOnceOnly proves the interlock: a written record refuses the next attempt, at the
// same check every build honours.
//
// The second attempt goes through verifyBootstrap, which is where re-enrolment lands, and the interlock
// is its first check — before the trust anchor is even read, which is what makes this assertable from a
// unit test that cannot write /etc/farrier.
func TestApplyBootstrapIsOnceOnly(t *testing.T) {
	stateDir, seedDir := t.TempDir(), t.TempDir()
	opts := EnrollOptions{
		StateDir:      stateDir,
		seedDir:       seedDir,
		applyUserData: func(_ context.Context) error { return nil },
	}
	if err := applyBootstrap(context.Background(), opts, testBootstrap, testKey, "01JHOST"); err != nil {
		t.Fatalf("applying: %v", err)
	}

	_, err := verifyBootstrap(stateDir, testBootstrap)
	if err == nil {
		t.Fatal("a second application was permitted")
	}
	if !strings.Contains(err.Error(), "standard-server") || !strings.Contains(err.Error(), "applied") {
		t.Fatalf("the refusal does not name what was applied: %v", err)
	}
}

// TestApplyBootstrapFailureLeavesTheRecordStanding proves a failed application still consumed the
// interlock and still tells the truth.
//
// This is the deliberate direction of the trade: a crash between deciding and applying costs a manual
// re-run at worst, and never permits a second automatic attempt — because "the template ran twice" is
// the lie the record exists to make impossible.
func TestApplyBootstrapFailureLeavesTheRecordStanding(t *testing.T) {
	stateDir, seedDir := t.TempDir(), t.TempDir()
	opts := EnrollOptions{
		StateDir:      stateDir,
		seedDir:       seedDir,
		applyUserData: func(_ context.Context) error { return errors.New("stage exploded") },
	}

	err := applyBootstrap(context.Background(), opts, testBootstrap, testKey, "01JHOST")
	if err == nil {
		t.Fatal("a failed executor reported success")
	}
	recordPath := filepath.Join(stateDir, BootstrapRecordFile)
	if !strings.Contains(err.Error(), recordPath) {
		t.Errorf("the error does not point at the record: %v", err)
	}
	if _, statErr := os.Stat(recordPath); statErr != nil {
		t.Fatalf("the record did not survive the failure: %v", statErr)
	}
	if _, verifyErr := verifyBootstrap(stateDir, testBootstrap); verifyErr == nil {
		t.Fatal("a failed application left the interlock open")
	}
}
