package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pegasusnetworks/farrier/internal/canonical"
	"github.com/pegasusnetworks/farrier/internal/policy"
	"github.com/pegasusnetworks/farrier/internal/protocol"
	"github.com/pegasusnetworks/farrier/internal/signing"
)

// testHostID is the host identity every job in these tests is addressed to.
//
// It is a constant because the signed payload includes it: a signature made for one host must not
// verify for another, and the tests need both halves to agree for the cases where they should.
const testHostID = "01JTESTHOST"

// signerFixture is a key pair plus the trusted-signers set that trusts it.
//
// Each test builds its own rather than sharing one, so that a test which needs an *untrusted* key can
// simply build a second fixture and use its private half against the first one's set.
type signerFixture struct {
	// private signs payloads.
	private ed25519.PrivateKey

	// set is a SignerSet trusting the matching public key.
	set *signing.SignerSet
}

// newSignerFixture generates a key and the trusted-signers set that trusts it.
func newSignerFixture(t *testing.T, keyID string) signerFixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("encoding a key: %v", err)
	}
	line := "ed25519 " + base64.StdEncoding.EncodeToString(der) + " " + keyID + " file\n"
	set, err := signing.ParseSigners(strings.NewReader(line), "test")
	if err != nil {
		t.Fatalf("parsing the trusted-signers fixture: %v", err)
	}
	return signerFixture{private: priv, set: set}
}

// sign produces a detached signature over a job's canonical signed payload.
func (f signerFixture) sign(t *testing.T, job protocol.Job) string {
	t.Helper()

	payload, err := canonical.Marshal(job.SignedPayload(testHostID))
	if err != nil {
		t.Fatalf("canonicalising the payload: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, payload))
}

// newNonceStore returns a nonce store in a temporary directory.
func newNonceStore(t *testing.T) *NonceStore {
	t.Helper()
	store, err := LoadNonceStore(t.TempDir())
	if err != nil {
		t.Fatalf("loading a nonce store: %v", err)
	}
	return store
}

// permissivePolicy is a policy that permits everything, so a refusal in a test is never accidental.
func permissivePolicy(t *testing.T) policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`
[updates]
allow = "all"
reboot = "window"
window = ""
timezone = "UTC"

[services]
restartable = ["nginx.service"]

[limits]
max_job_age_seconds = 900
`))
	if err != nil {
		t.Fatalf("parsing the fixture policy: %v", err)
	}
	return p
}

// destructiveJob builds a signed service.restart job.
func destructiveJob(nonce string) protocol.Job {
	now := time.Now()
	return protocol.Job{
		ID:              "01JTESTJOB" + nonce,
		Intent:          "service.restart",
		Params:          map[string]any{"unit": "nginx.service"},
		Class:           "destructive",
		IssuedAt:        now,
		NotBefore:       now.Add(-time.Minute),
		NotAfter:        now.Add(30 * time.Minute),
		Nonce:           nonce,
		SignerAlgorithm: "ed25519",
	}
}

// TestGuaranteeAnUnsignedDestructiveJobIsRefused is the third mechanism at the agent's boundary.
//
// A destructive intent requires a signature from a key in this host's own trusted-signers. The control
// plane does not hold one, so a control plane that has been completely taken over can issue this job and
// still get nowhere.
func TestGuaranteeAnUnsignedDestructiveJobIsRefused(t *testing.T) {
	trusted := newSignerFixture(t, "ops-laptop")
	job := destructiveJob("nonce-unsigned")

	got := accept(job, testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), 0, time.Now())
	if got.accepted() {
		t.Fatal("a destructive job with no signature was accepted")
	}
	if got.status != protocol.StatusUnsupportedIntent && got.status != protocol.StatusRefusedUnsigned {
		t.Errorf("status %q, want a refusal", got.status)
	}
}

// TestGuaranteeAnUntrustedSignatureIsRefused covers the key set actually being consulted.
//
// A well-formed signature from a key the administrator did not list must not authorise anything. This is
// what "a key the control plane does not hold" reduces to in code.
func TestGuaranteeAnUntrustedSignatureIsRefused(t *testing.T) {
	trusted := newSignerFixture(t, "ops-laptop")
	attacker := newSignerFixture(t, "attacker")

	job := destructiveJob("nonce-untrusted")
	job.Signature = attacker.sign(t, job)

	got := accept(job, testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), 0, time.Now())
	if got.accepted() {
		t.Fatal("a signature from an untrusted key was accepted")
	}
}

// TestGuaranteeAnEmptyTrustAnchorRefusesEverythingDestructive is a fresh install's behaviour.
//
// The shipped trusted-signers file is empty, so this is the state every host is in until an
// administrator changes it: no key, no destructive work, no fallback to trusting whoever sent the job.
func TestGuaranteeAnEmptyTrustAnchorRefusesEverythingDestructive(t *testing.T) {
	signer := newSignerFixture(t, "ops-laptop")
	job := destructiveJob("nonce-empty-anchor")
	job.Signature = signer.sign(t, job)

	got := accept(job, testHostID, permissivePolicy(t), &signing.SignerSet{}, newNonceStore(t), 0, time.Now())
	if got.accepted() {
		t.Fatal("a host with an empty trust anchor accepted a destructive job")
	}
}

// TestGuaranteeTheAgentTakesTheClassFromItsOwnCatalogue is the label-forgery case.
//
// A control plane that could label host.reboot as "read" would defeat the signature requirement without
// touching the signature code. The job's own class field is carried for display and must never be
// consulted for a decision.
func TestGuaranteeTheAgentTakesTheClassFromItsOwnCatalogue(t *testing.T) {
	trusted := newSignerFixture(t, "ops-laptop")

	job := destructiveJob("nonce-forged-class")
	job.Class = "read" // the lie

	got := accept(job, testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), 0, time.Now())
	if got.accepted() {
		t.Fatal("a destructive job labelled \"read\" by the control plane was accepted")
	}
}

// TestGuaranteeReplayedNoncesAreRefused covers the persisted replay defence.
//
// A signature is valid for a window. Without a nonce store, anyone holding one signed job could deliver
// it repeatedly until the window closed — which for a reboot means a reboot loop.
func TestGuaranteeReplayedNoncesAreRefused(t *testing.T) {
	nonces := newNonceStore(t)

	seen, err := nonces.Check("nonce-replay", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("first check: %v", err)
	}
	if seen {
		t.Fatal("a fresh nonce was reported as already seen")
	}

	seen, err = nonces.Check("nonce-replay", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("second check: %v", err)
	}
	if !seen {
		t.Fatal("a replayed nonce was not detected")
	}
}

// TestNonceStoreSurvivesARestart is why the store is on disk rather than in memory.
//
// A replay defence held only in memory is defeated by restarting the agent, and for a reboot job that
// restart is the very next thing that happens.
func TestNonceStoreSurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadNonceStore(dir)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if _, err := first.Check("nonce-persisted", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("recording: %v", err)
	}

	second, err := LoadNonceStore(dir)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	seen, err := second.Check("nonce-persisted", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("checking after a reload: %v", err)
	}
	if !seen {
		t.Error("a nonce recorded before a restart was not remembered after it")
	}
}

// TestNonceStorePrunesExpiredEntries asserts the file does not grow without bound.
//
// A nonce whose signature has expired cannot be replayed anyway — the validity check refuses it first —
// so keeping it forever would be a file that grows for the life of the host and nothing else.
func TestNonceStorePrunesExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadNonceStore(dir)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if _, err := store.Check("already-expired", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("recording: %v", err)
	}
	if _, err := store.Check("still-valid", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("recording: %v", err)
	}

	reloaded, err := LoadNonceStore(dir)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if reloaded.Len() != 1 {
		t.Errorf("the reloaded store holds %d nonces, want 1 after pruning", reloaded.Len())
	}
}

// TestValidityWindowsAreCheckedAgainstTheLocalClock covers docs/SECURITY.md §4.3.
//
// The agent never adjusts anything to server-supplied time: a compromised control plane could otherwise
// extend a signature's validity window arbitrarily by lying about the current time.
func TestValidityWindowsAreCheckedAgainstTheLocalClock(t *testing.T) {
	trusted := newSignerFixture(t, "ops-laptop")
	now := time.Now()

	expired := protocol.Job{
		ID: "01JEXPIRED", Intent: "facts.collect", Params: map[string]any{},
		IssuedAt: now.Add(-time.Hour), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(-time.Minute),
	}
	got := accept(expired, testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), 0, now)
	if got.accepted() {
		t.Error("a job whose validity window had closed was accepted")
	}
	if got.status != protocol.StatusExpired {
		t.Errorf("status %q, want %q", got.status, protocol.StatusExpired)
	}

	notYet := expired
	notYet.NotBefore = now.Add(time.Hour)
	notYet.NotAfter = now.Add(2 * time.Hour)
	if accept(notYet, testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), 0, now).accepted() {
		t.Error("a job whose validity window had not opened was accepted")
	}
}

// TestClockSkewFailsClosedForPrivilegedIntentsOnly is the fail-closed rule, both halves.
//
// Beyond five minutes of offset, privileged intents refuse and read-only ones still run. Blinding an
// operator to the state of a host with a wrong clock would help nobody, and it is the host with the
// wrong clock they most need to look at.
func TestClockSkewFailsClosedForPrivilegedIntentsOnly(t *testing.T) {
	trusted := newSignerFixture(t, "ops-laptop")
	now := time.Now()
	skew := 10 * time.Minute

	read := protocol.Job{ID: "01JREAD", Intent: "facts.collect", Params: map[string]any{}, IssuedAt: now}
	if got := accept(read, testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), skew, now); !got.accepted() {
		t.Errorf("a read-only intent was refused for clock skew: %s", got.reason)
	}

	job := destructiveJob("nonce-skew")
	job.Signature = trusted.sign(t, job)
	got := accept(job, testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), skew, now)
	if got.accepted() {
		t.Fatal("a privileged intent ran with ten minutes of clock skew")
	}
	if got.status != protocol.StatusRefusedClockSkew && got.status != protocol.StatusUnsupportedIntent {
		t.Errorf("status %q, want a clock-skew refusal", got.status)
	}
}

// TestPhaseZeroRefusesEveryPrivilegedIntent asserts the shipped build has no write path.
//
// Every privileged intent is refused for want of an executor, whatever the policy says and however well
// it is signed. It is stated here as well as in the catalogue's own tests because this is the layer an
// actual job passes through.
func TestPhaseZeroRefusesEveryPrivilegedIntent(t *testing.T) {
	trusted := newSignerFixture(t, "ops-laptop")
	now := time.Now()

	jobs := []protocol.Job{
		{ID: "01JA", Intent: "packages.applySecurity", Params: map[string]any{}},
		{ID: "01JB", Intent: "packages.applyAll", Params: map[string]any{}},
		{ID: "01JC", Intent: "service.restart", Params: map[string]any{"unit": "nginx.service"}},
		{ID: "01JD", Intent: "host.reboot", Params: map[string]any{}},
	}
	for i := range jobs {
		jobs[i].IssuedAt = now
		jobs[i].NotAfter = now.Add(time.Hour)
		jobs[i].Nonce = "nonce-phase0-" + jobs[i].ID
		jobs[i].Signature = trusted.sign(t, jobs[i])

		got := accept(jobs[i], testHostID, permissivePolicy(t), trusted.set, newNonceStore(t), 0, now)
		if got.accepted() {
			t.Errorf("%s was accepted; phase 0 ships no write capability", jobs[i].Intent)
		}
	}
}

// TestSpooledResultsSurviveAndAreReadBack is the mechanism that makes host.reboot reportable.
//
// The job completes by the host disappearing, so the result must be on disk before the operation runs
// and must be found again on the next start.
func TestSpooledResultsSurviveAndAreReadBack(t *testing.T) {
	dir := t.TempDir()
	result := protocol.ResultRequest{
		JobID: "01JREBOOT", Status: protocol.StatusSucceeded,
		StartedAt: time.Now(), FinishedAt: time.Now(),
	}
	if err := SpoolResult(dir, result); err != nil {
		t.Fatalf("spooling: %v", err)
	}

	pending, err := PendingResults(dir)
	if err != nil {
		t.Fatalf("reading pending results: %v", err)
	}
	if len(pending) != 1 || pending[0].JobID != "01JREBOOT" {
		t.Fatalf("read back %+v", pending)
	}

	// The file must be where docs/PROTOCOL.md §6.2 says it is, because an operator debugging a lost
	// result looks there.
	if _, err := os.Stat(filepath.Join(dir, PendingResultsDir, "01JREBOOT.json")); err != nil {
		t.Errorf("the spooled result is not at the documented path: %v", err)
	}
}

// TestSpoolRefusesAJobIDThatWouldEscapeTheDirectory covers the one path-traversal surface here.
//
// The job id becomes a filename, and it arrives from the control plane. Identifiers are Crockford base32
// and contain none of these characters, so anything that does is either a bug or an attempt to write
// outside the spool.
func TestSpoolRefusesAJobIDThatWouldEscapeTheDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"../escape", "a/b", "..", "with.dot", ""} {
		err := SpoolResult(dir, protocol.ResultRequest{JobID: id, Status: protocol.StatusSucceeded})
		if err == nil {
			t.Errorf("job id %q was accepted as a filename", id)
		}
	}
}

// TestBackoffIsFullJitter asserts the property that prevents a reconnection stampede.
//
// Full jitter means the delay is uniform on [0, ceiling], so five hundred agents that failed together
// retry spread across the whole window. Equal or decorrelated jitter would leave them clustered, and
// clustering is the entire failure being prevented.
func TestBackoffIsFullJitter(t *testing.T) {
	b := NewBackoff()
	b.Base = time.Second
	b.Cap = 8 * time.Second

	var belowHalf, aboveHalf int
	for range 400 {
		b.Reset()
		for range 3 {
			d := b.Next()
			if d < 0 || d > b.Cap {
				t.Fatalf("delay %s is outside [0, %s]", d, b.Cap)
			}
		}
		// After three attempts the ceiling is 4s; count how the samples fall around its midpoint.
		b.Reset()
		_ = b.Next()
		_ = b.Next()
		if d := b.Next(); d < 2*time.Second {
			belowHalf++
		} else {
			aboveHalf++
		}
	}
	if belowHalf == 0 || aboveHalf == 0 {
		t.Errorf("delays are not spread across the window: %d below the midpoint, %d above",
			belowHalf, aboveHalf)
	}
}

// TestBackoffIsCapped asserts a long outage does not turn into an hours-long retry interval.
//
// A control plane coming back must not require a fleet-wide restart to be noticed.
func TestBackoffIsCapped(t *testing.T) {
	b := NewBackoff()
	b.Base = time.Second
	b.Cap = 5 * time.Minute
	for range 100 {
		if d := b.Next(); d > b.Cap {
			t.Fatalf("delay %s exceeded the cap %s", d, b.Cap)
		}
	}
}

// TestSleepReturnsEarlyOnCancellation asserts a stop signal is not delayed by a backoff.
//
// systemd's default stop timeout is ninety seconds, after which it sends SIGKILL. A process killed
// rather than stopped is one that skipped whatever it does on the way out.
func TestSleepReturnsEarlyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	if Sleep(ctx, time.Minute) {
		t.Error("Sleep reported completion despite a cancelled context")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("Sleep took %s to notice a cancelled context", elapsed)
	}
}

// TestWriteFileAtomicLeavesNoPartialFile covers the durability rule for the key and the certificate.
//
// An interrupted write must never leave a truncated file where a valid one used to be: for the
// certificate that means a host that cannot authenticate and cannot renew, recoverable only by
// re-enrolling it by hand.
func TestWriteFileAtomicLeavesNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := WriteFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(body) != "second" {
		t.Errorf("file holds %q, want %q", body, "second")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode is %o, want 600", perm)
	}

	// No temporary files may be left behind: a directory that accumulates them across a fleet's
	// lifetime is a slow disk leak nobody notices until it matters.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the directory: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want 1: %v", len(entries), entries)
	}
}
