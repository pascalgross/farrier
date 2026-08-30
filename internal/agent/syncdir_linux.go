//go:build linux

package agent

import (
	"fmt"
	"os"
)

// SyncDir fsyncs a directory, making a rename inside it durable.
//
// Without this, a crash immediately after writing a pending job result can lose the rename even though
// the file's own contents were synced — and a lost result for host.reboot is a job that completes by
// the host disappearing and is never reported at all.
func SyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("agent: opening %s to sync: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("agent: syncing %s: %w", dir, err)
	}
	return nil
}
