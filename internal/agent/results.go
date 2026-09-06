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

	"github.com/pascalgross/hostseal/internal/protocol"
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
	path, err := SpoolPath(stateDir, result.JobID)
	if err != nil {
		return err
	}
	raw, err := jsonRecord(result)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, raw, 0o640)
}

// SpoolPath returns the file a job's result is spooled to, rejecting an id that is not one.
//
// The job id arrives from the control plane and becomes a filename, so it is validated in exactly one
// place and every path that builds one goes through here. The shape itself is protocol.ValidJobID,
// shared with the control plane that issues the id, so the two cannot disagree about what an id is. Identifiers are Crockford base32 and contain
// none of these characters, so anything that does is either a bug or a control plane trying to reach
// outside the spool — and the delete path matters as much as the write path, because the agent can
// write /var/lib/hostseal and an unvalidated id there is a way to remove the host's certificate.
func SpoolPath(stateDir, jobID string) (string, error) {
	if jobID == "" {
		return "", errors.New("agent: a result needs a job id; results are keyed by it")
	}
	if !protocol.ValidJobID(jobID) {
		return "", fmt.Errorf("agent: job id %q is not an identifier: %s", jobID, protocol.JobIDShape)
	}
	return filepath.Join(stateDir, PendingResultsDir, jobID+".json"), nil
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
			if !permanentlyRefused(err) {
				slog.Warn("a pending job result could not be delivered; it stays on disk",
					"job", result.JobID, "error", err)
				continue
			}
			// The control plane understood it and refused it, and will refuse it identically for
			// ever — the job is not this host's, or the body is one this build cannot produce.
			// docs/PROTOCOL.md §11 says drop it, and the alternative is a file retried on every pass
			// for the life of the machine, in the directory a reboot's result has to be written to.
			// Logged at error rather than warn because a result that never arrives is exactly the
			// kind of nothing nobody notices.
			slog.Error("a pending job result was refused permanently and has been discarded",
				"job", result.JobID, "status", result.Status, "error", err)
		}
		path, pathErr := SpoolPath(stateDir, result.JobID)
		if pathErr != nil {
			slog.Warn("a spooled result has an unusable job id and will be left alone",
				"job", result.JobID, "error", pathErr)
			continue
		}
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

// permanentlyRefused reports whether the control plane will refuse this result however often it is
// resent.
//
// Only an HTTPError can say so. A transport failure, a TLS failure or a context deadline is exactly the
// case the spool exists for, and reading one of those as permanent would throw away the result of work
// that had actually run.
func permanentlyRefused(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.Permanent()
}
