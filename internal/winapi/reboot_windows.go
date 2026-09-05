//go:build windows

package winapi

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RebootSignal is one reason Windows believes a restart is outstanding.
//
// It is a named value rather than a bare string so that the reasons HostSeal reports are a closed set a
// reviewer can read, in the same spirit as the intent catalogue: an operator seeing "a reboot is
// pending" should be able to find out which of the four mechanisms said so, because they are not
// equally urgent and two of them are routinely stale.
type RebootSignal struct {
	// Reason is the short phrase reported to the control plane.
	Reason string

	// Stale reports that this signal is known to survive the reboot that should have cleared it.
	//
	// It exists because PendingFileRenameOperations is genuinely unreliable in this direction: an entry
	// whose source file no longer exists is never removed, so a host can carry one for months. HostSeal
	// reports the signal and marks it rather than hiding it, because suppressing it would be HostSeal
	// deciding an operator's business, and presenting it unqualified would train them to ignore the
	// field.
	Stale bool
}

// pendingKeys are the registry keys whose mere existence means a restart is outstanding.
//
// Component Based Servicing is the authoritative one: it is set by the servicing stack when a package
// has been staged and cleared when the reboot completes. Windows Update's own marker is second, and the
// two disagree often enough that reporting either alone would be wrong on some host.
var pendingKeys = []struct {
	path   string
	reason string
}{
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
		"servicing stack has a package staged"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending`,
		"servicing stack has packages pending"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
		"Windows Update requires a restart"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting`,
		"Windows Update has post-restart reporting outstanding"},
}

// RebootPending reports whether Windows believes a restart is outstanding, and why.
//
// Four independent mechanisms are consulted because no one of them is complete, and the third of this
// platform's silent-wrong-answer traps is that each of them looks complete on the host where it happens
// to be right. Component Based Servicing misses a rename queued by an installer that did not use the
// servicing stack; PendingFileRenameOperations misses a staged package; the computer-name comparison
// catches only a rename. A host is reported as needing a restart if any of them says so.
//
// The result is always conclusive, which is the honest difference from the Linux answer. On Linux the
// question can genuinely fail — needrestart may be absent, the marker file unreadable — and
// RebootReport.Conclusive exists to say so. Here every source is a registry read the agent's own
// account can perform, and an absent key is a real answer rather than a failure to look.
func RebootPending() ([]RebootSignal, error) {
	var signals []RebootSignal

	for _, k := range pendingKeys {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, k.path, registry.QUERY_VALUE)
		if err != nil {
			// Absent is the ordinary case and means "no". Anything else is also treated as no: this
			// account can read every one of these keys on a stock host, so a failure here is a host
			// whose registry permissions somebody has changed, and inventing a pending reboot from
			// that would be a worse answer than reporting the three signals that did work.
			continue
		}
		_ = key.Close()
		signals = append(signals, RebootSignal{Reason: k.reason})
	}

	if pending, err := pendingFileRenames(); err != nil {
		return signals, err
	} else if pending {
		signals = append(signals, RebootSignal{
			Reason: "files are queued to be replaced at the next restart",
			Stale:  true,
		})
	}

	if renamed, err := computerNameChanged(); err != nil {
		return signals, err
	} else if renamed {
		signals = append(signals, RebootSignal{Reason: "the computer has been renamed"})
	}

	return signals, nil
}

// pendingFileRenames reports whether the session manager has files queued for replacement at boot.
//
// This is the mechanism that makes needrestart's question unanswerable on Windows, and it is worth
// stating where the code is: Windows cannot replace a file that a running process has mapped, so an
// installer calls MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT and the swap happens before anything
// opens it. The state needrestart looks for on Linux — a process still holding a library that has
// already been replaced on disk — therefore cannot arise. What this value says is what *will* change at
// the next restart, which is a strictly weaker statement than what is already stale in memory.
func pendingFileRenames() (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		return false, nil
	}
	defer func() { _ = key.Close() }()

	values, _, err := key.GetStringsValue("PendingFileRenameOperations")
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, nil
	}
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return true, nil
		}
	}
	return false, nil
}

// computerNameChanged reports whether a rename is waiting for a restart to take effect.
//
// The active name is what the machine answers to now; the other is what it will answer to after a
// restart. They differ only between a rename and the reboot that completes it, which makes this the one
// signal here with no false positives at all — and the one an operator is most likely to have forgotten
// about, because nothing else on the machine looks wrong.
func computerNameChanged() (bool, error) {
	read := func(path string) (string, bool) {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return "", false
		}
		defer func() { _ = key.Close() }()
		name, _, err := key.GetStringValue("ComputerName")
		if err != nil {
			return "", false
		}
		return name, true
	}

	active, okActive := read(`SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`)
	configured, okConfigured := read(`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`)
	if !okActive || !okConfigured {
		return false, nil
	}
	// Case-insensitively: Windows computer names are not case-sensitive, and a comparison that said
	// otherwise would report a pending rename on a host where somebody had merely changed the casing.
	return !strings.EqualFold(active, configured), nil
}
