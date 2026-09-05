//go:build windows

package agent

import "github.com/pascalgross/hostseal/internal/winapi"

// machineIdentity returns the host's stable identifier, before hashing.
//
// The Cryptography\MachineGuid registry value, which is Windows' nearest equivalent to systemd's
// machine-id: written once when the operating system is installed and stable for its lifetime. It is
// hashed with the same per-host salt for the same reason, because the raw value identifies a Windows
// installation to anybody who has seen it elsewhere.
//
// It carries a hazard the Linux value does not, and it is worth naming where the code is: MachineGuid is
// **cloned with a disk image**. A fleet built by copying one prepared virtual machine without running
// Sysprep has many hosts sharing an identity, and the symptom is hosts intermittently overwriting each
// other's facts rather than anything that reads as a duplicate. Enrolment is where that has to be
// caught, because it is the only moment the control plane sees two claims to one identity and can still
// refuse.
func machineIdentity() (string, error) {
	return winapi.MachineGUID()
}
