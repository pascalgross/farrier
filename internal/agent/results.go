package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/pegasusnetworks/farrier/internal/protocol"
)

// SpoolResult writes a job result to disk durably, before it is sent.
//
// This ordering is what makes host.reboot reportable at all: the job completes by the host
// disappearing, so an agent that sent the result after invoking the helper would send nothing. The file
// and its directory are both fsynced, because a rename is not durable until its parent is, and a crash
// between the two loses the result just as completely as never writing it.
//
// It is also what makes results idempotent in practice. The spooled file is removed only after the
// control plane returns 2xx, so a lost response means a redelivery rather than a re-execution. Work
// that succeeded but whose result was lost must never re-execute: that is how a retry turns one reboot
// into a reboot loop.
func SpoolResult(stateDir string, result protocol.ResultRequest) error {
	dir := filepath.Join(stateDir, PendingResultsDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("agent: creating %s: %w", dir, err)
	}
	if result.JobID == "" {
		return errors.New("agent: a result needs a job id; results are keyed by it")
	}
	if strings.ContainsAny(result.JobID, "/\\.") {
		// The job id becomes a filename. Identifiers are Crockford base32 and contain none of these,
		// so anything that does is either a bug or a control plane trying to write outside the spool.
		return fmt.Errorf("agent: job id %q contains characters that may not appear in one", result.JobID)
	}

	raw, err := jsonRecord(result)
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, result.JobID+".json"), raw, 0o640)
}

// PendingResults reads every spooled result.
//
// A file that cannot be parsed is logged and skipped rather than failing the whole delivery pass: one
// corrupt result must not be able to block every other host result behind it forever.
func PendingResults(stateDir string) ([]protocol.ResultRequest, error) {
	dir := filepath.Join(stateDir, PendingResultsDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: reading %s: %w", dir, err)
	}

	var out []protocol.ResultRequest
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("could not read a pending result", "path", path, "error", err)
			continue
		}
		var result protocol.ResultRequest
		if err := json.Unmarshal(raw, &result); err != nil {
			slog.Warn("a pending result is unreadable and will be discarded", "path", path, "error", err)
			if removeErr := os.Remove(path); removeErr != nil {
				slog.Warn("could not remove an unreadable pending result", "path", path, "error", removeErr)
			}
			continue
		}
		out = append(out, result)
	}
	return out, nil
}

// DeliverPending sends every spooled result and removes the ones that were accepted.
//
// It runs before anything else on start, which is how a result written just before a reboot reaches the
// control plane after it. A delivery that fails is left on disk for the next pass, so the only way to
// lose a result is to lose the disk.
func DeliverPending(ctx context.Context, client *Client, stateDir string) {
	pending, err := PendingResults(stateDir)
	if err != nil {
		slog.Error("could not read pending job results", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}
	slog.Info("delivering job results held from an earlier run", "count", len(pending))

	dir := filepath.Join(stateDir, PendingResultsDir)
	for _, result := range pending {
		if ctx.Err() != nil {
			return
		}
		if err := client.ReportResult(ctx, result); err != nil {
			slog.Warn("a pending job result could not be delivered; it stays on disk",
				"job", result.JobID, "error", err)
			continue
		}
		path := filepath.Join(dir, result.JobID+".json")
		if err := os.Remove(path); err != nil {
			slog.Warn("delivered a result but could not remove its spool file",
				"job", result.JobID, "path", path, "error", err)
			continue
		}
		if err := SyncDir(dir); err != nil {
			slog.Warn("could not sync the spool directory after a delivery", "error", err)
		}
		slog.Info("delivered a held job result", "job", result.JobID, "status", result.Status)
	}
}
