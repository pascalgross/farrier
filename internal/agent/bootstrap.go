package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/run"
	"github.com/pascalgross/farrier/internal/signing"
)

// BootstrapRecordFile is where an applied provisioning template is recorded permanently.
const BootstrapRecordFile = "bootstrap-applied.json"

// CloudInitSeedDir is where the verified user-data is written for cloud-init to read.
//
// The NoCloud seed directory is cloud-init's own documented file-based datasource. Writing here is
// what "Farrier writes the user-data where cloud-init reads it" means concretely, and it is the whole
// of Farrier's involvement in applying: the body becomes a file, cloud-init interprets the file, and
// no byte of it ever appears on a command line.
const CloudInitSeedDir = "/var/lib/cloud/seed/nocloud"

// cloudInitStageTimeout bounds one cloud-init stage.
//
// Generous, because the final stage legitimately installs packages; bounded, because an unbounded
// stage blocked on a prompt would leave the operator's enrolment hanging forever with no explanation.
const cloudInitStageTimeout = 15 * time.Minute

// bootstrapRecord is the permanent record of a template that was applied.
//
// It is written durably **before** execution, and that ordering is the design: the record is the only
// thing that survives a failure, and a template that ran halfway has still changed the machine. A
// record written on success answers "what worked"; this one answers "what was attempted", which is the
// question an incident asks. It is also the apply-once interlock — one file, so the record and the
// interlock cannot disagree — and it lives on the host because an audit trail that exists only in the
// database of the system whose compromise you are worried about is not an audit trail.
type bootstrapRecord struct {
	// Name is the template as the operator named it.
	Name string `json:"name"`

	// Version is the stored revision the control plane reported, zero when it reported none.
	//
	// Informational: the body below is the authoritative answer to "what ran", knowable from this
	// host alone even if a control plane relabelled its version numbers afterwards.
	Version int `json:"version,omitempty"`

	// Body is the full text, recorded so that what ran is knowable afterwards.
	Body string `json:"body"`

	// SignerKeyID names the key from this host's own trusted-signers that authorised it.
	SignerKeyID string `json:"signerKeyId"`

	// VerifiedAgainst records which trust anchor the signature was checked against.
	//
	// It is always the packaged constant; it is written down anyway so the record answers the
	// question by itself, without the reader having to know which build wrote it.
	VerifiedAgainst string `json:"verifiedAgainst"`

	// AppliedAt is when application was decided — written before execution, so on a machine that
	// crashed mid-apply it reads as "attempted at" rather than lying about completion.
	AppliedAt time.Time `json:"appliedAt"`
}

// applyBootstrap applies a verified template through cloud-init, exactly once.
//
// The caller has already verified the signature and shown the operator the full text; everything here
// is the ordering that makes "exactly once" true across crashes:
//
//  1. The record — which is also the interlock — is written and fsynced first. A crash between
//     "decided to apply" and "applied" therefore refuses a second attempt rather than permitting one,
//     which errs on the side the guarantee needs: at worst an operator re-runs cloud-init by hand,
//     and never discovers a template ran twice.
//  2. The user-data lands in cloud-init's seed directory, under a fresh instance-id, so cloud-init
//     treats the enrolment as a new instance and processes the seed once.
//  3. cloud-init runs its own stages, with argument vectors fixed here. Farrier never interprets the
//     body: a hand-written YAML-to-shell engine is the exec channel wearing a hat, and it is refused
//     by name in docs/SECURITY.md §7.
//
// A failure after step 1 leaves the record standing and application blocked, and the error says so:
// the record is the honest statement of what was attempted on this machine.
func applyBootstrap(ctx context.Context, opts EnrollOptions, b protocol.Bootstrap,
	key signing.PublicKey, hostID string) error {

	record := bootstrapRecord{
		Name:            b.Name,
		Version:         b.Version,
		Body:            b.Body,
		SignerKeyID:     key.KeyID,
		VerifiedAgainst: signing.TrustedSignersPath,
		AppliedAt:       time.Now().UTC(),
	}
	recordPath := filepath.Join(opts.StateDir, BootstrapRecordFile)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encoding the bootstrap record: %w", err)
	}
	// WriteFileAtomic syncs the file and its directory: a rename is not durable until the directory
	// entry is, and an interlock that a power cut could un-write is not an interlock.
	if err := WriteFileAtomic(recordPath, encoded, 0o600); err != nil {
		return fmt.Errorf("agent: recording the bootstrap before applying it: %w", err)
	}
	fmt.Printf("Recorded the template in %s; applying it via cloud-init now.\n", recordPath)
	slog.Info("bootstrap recorded before execution",
		"template", b.Name, "version", b.Version, "record", recordPath)

	seedDir := opts.seedDir
	if seedDir == "" {
		seedDir = CloudInitSeedDir
	}
	if err := writeSeed(seedDir, hostID, b.Body); err != nil {
		return fmt.Errorf("%w\nThe record at %s stands: nothing has executed, and this host will not "+
			"accept another bootstrap", err, recordPath)
	}

	apply := opts.applyUserData
	if apply == nil {
		apply = runCloudInit
	}
	if err := apply(ctx); err != nil {
		return fmt.Errorf("agent: cloud-init did not complete: %w\nThe record at %s is the statement "+
			"of what was attempted; the machine may be partially configured, and this host will not "+
			"accept another bootstrap", err, recordPath)
	}

	fmt.Printf("Bootstrap template %q applied.\n", b.Name)
	slog.Info("bootstrap applied", "template", b.Name, "version", b.Version)
	return nil
}

// writeSeed places the user-data and its meta-data where cloud-init's NoCloud datasource reads them.
//
// The instance-id is derived from the host id this enrolment was assigned, which is what makes the
// application once-per-enrolment from cloud-init's own point of view: per-instance modules run when
// the instance-id changes, and no later boot changes it back.
func writeSeed(seedDir, hostID, body string) error {
	// 0700, not 0755. The only reader is cloud-init, which is root, and what is in here is the
	// rendered user-data — a credential everywhere else in Farrier, and no different for sitting in a
	// seed directory. A mode that let every local account list it would be the one place that
	// treatment lapsed.
	if err := os.MkdirAll(seedDir, 0o700); err != nil {
		return fmt.Errorf("agent: creating %s: %w", seedDir, err)
	}
	// 0600: rendered user-data is treated as a credential everywhere else in Farrier, and the seed
	// copy is no different. Anything that needs it — cloud-init — is root.
	if err := WriteFileAtomic(filepath.Join(seedDir, "user-data"), []byte(body), 0o600); err != nil {
		return err
	}
	meta := "instance-id: farrier-bootstrap-" + hostID + "\n"
	return WriteFileAtomic(filepath.Join(seedDir, "meta-data"), []byte(meta), 0o600)
}

// runCloudInit drives cloud-init through its four stages against the seeded user-data.
//
// The stages are the ones cloud-init itself runs at boot, in boot order, each with an argument vector
// fixed here. Exit code 2 is accepted alongside 0: cloud-init documents it as "completed with
// recoverable errors", and a template whose one optional module degraded should not read as a machine
// that was never configured — the operator sees cloud-init's own output either way, because it is
// relayed to the terminal below.
func runCloudInit(ctx context.Context) error {
	for _, args := range [][]string{
		{"init", "--local"},
		{"init"},
		{"modules", "--mode=config"},
		{"modules", "--mode=final"},
	} {
		res, err := run.CommandWith(ctx, run.Options{Timeout: cloudInitStageTimeout}, run.CloudInit, args...)
		if res != nil {
			// cloud-init's own output goes to the operator running the enrolment: they are being
			// asked to trust what just ran, and a silent success is less trustworthy than a noisy one.
			//
			// The write errors are dropped deliberately, which is rare enough here to say why: the
			// only way they fail is a closed terminal, cloud-init has already run by this point, and
			// abandoning a bootstrap because its transcript could not be printed would turn a
			// cosmetic problem into a half-provisioned machine.
			_, _ = os.Stdout.Write(res.Stdout)
			_, _ = os.Stderr.Write(res.Stderr)
		}
		if err != nil {
			if res != nil && res.ExitCode == 2 {
				slog.Warn("cloud-init reported recoverable errors", "stage", args[0])
				continue
			}
			return fmt.Errorf("cloud-init %v: %w", args, err)
		}
	}
	return nil
}
