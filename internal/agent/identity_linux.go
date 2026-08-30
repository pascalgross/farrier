//go:build linux

package agent

import (
	"fmt"
	"os"
)

// machineIdentity returns the host's stable identifier, before hashing.
//
// systemd's machine-id, which is documented as confidential — which is why the caller hashes it with a
// per-host salt and the raw value never leaves the machine.
func machineIdentity() (string, error) {
	id, err := os.ReadFile(MachineIDPath)
	if err != nil {
		return "", fmt.Errorf("agent: reading %s: %w", MachineIDPath, err)
	}
	return string(id), nil
}
