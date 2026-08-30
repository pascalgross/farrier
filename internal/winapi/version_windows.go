//go:build windows

package winapi

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// currentVersionKey is where Windows records what release it is.
//
// It is read alongside RtlGetVersion rather than instead of it, because neither is sufficient alone:
// the kernel call gives major, minor and build as numbers that cannot be edited by an administrator,
// and this key gives the display version ("22H2"), the edition and the update-build revision, none of
// which the kernel call carries.
const currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// Version is what Farrier reports about a Windows host's operating system.
//
// It exists as a struct rather than a handful of return values because the fields are read from two
// different sources and a caller has no way to combine them correctly on its own — DisplayVersion is
// meaningless without Build, and Build is what decides whether the host is supported.
type Version struct {
	// Major, Minor and Build are what the kernel reports. Build is the number that identifies a
	// release: every Server release since 2016 reports major 10 and minor 0.
	Major, Minor, Build uint32

	// UBR is the update build revision, the fourth component of "10.0.20348.4648".
	//
	// It is the only part of the version that moves when a host is patched, which makes it the useful
	// half for an operator comparing two machines that both say "Server 2022".
	UBR uint32

	// DisplayVersion is the marketing release, such as "22H2". It is empty where the key is absent.
	DisplayVersion string

	// EditionID is the SKU, such as "ServerDatacenter".
	EditionID string

	// ProductName is the full name Windows gives itself, such as "Windows Server 2022 Datacenter".
	ProductName string

	// ServerCore reports whether this is an installation without the desktop shell.
	//
	// It matters for a fleet agent because Server Core is where an agent is most useful and least
	// likely to be checked by hand, and because it changes what an operator can do on the host if the
	// agent goes wrong.
	ServerCore bool
}

// Release returns the Windows Server release name, such as "2022", and whether Farrier supports it.
//
// The name comes from the build number rather than from ProductName, because ProductName is a string an
// administrator can edit in the registry and the build number is not. A host Farrier does not support
// gets its build number as its name — "build 14393" — rather than an empty string, so that the fleet
// list says what the machine is instead of leaving a gap somebody has to go and look up.
func (v Version) Release() (string, bool) {
	if name, ok := SupportedBuilds[v.Build]; ok {
		return name, true
	}
	return fmt.Sprintf("build %d", v.Build), false
}

// String renders the version the way an operator writes it down.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Build, v.UBR)
}

// OSVersion reads what release of Windows this is.
//
// RtlGetVersion is used rather than GetVersionEx, and that is the first of this platform's
// silent-wrong-answer traps. GetVersionEx is subject to compatibility shimming: an executable without
// the right entries in its application manifest is told it is running on Windows 8 — version 6.2 —
// whatever it is really running on. The answer is plausible, stable, and wrong, so no test that did not
// already know the right answer would catch it. RtlGetVersion is not shimmed.
//
// The registry half is read separately and its failure is not fatal. A host whose CurrentVersion key
// cannot be read still reports a correct build number, which is what decides support; losing "22H2"
// costs a display string.
func OSVersion() (Version, error) {
	info := windows.RtlGetVersion()
	if info == nil {
		return Version{}, fmt.Errorf("winapi: RtlGetVersion returned nothing")
	}
	v := Version{
		Major: info.MajorVersion,
		Minor: info.MinorVersion,
		Build: info.BuildNumber,
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE)
	if err != nil {
		// Not an error for the caller. Everything that decides behaviour is already in v.
		return v, nil
	}
	defer func() { _ = key.Close() }()

	if s, _, err := key.GetStringValue("DisplayVersion"); err == nil {
		v.DisplayVersion = s
	}
	if s, _, err := key.GetStringValue("EditionID"); err == nil {
		v.EditionID = s
	}
	if s, _, err := key.GetStringValue("ProductName"); err == nil {
		v.ProductName = s
	}
	if n, _, err := key.GetIntegerValue("UBR"); err == nil {
		v.UBR = uint32(n)
	}
	if s, _, err := key.GetStringValue("InstallationType"); err == nil {
		// "Server Core" on a core install, "Server" on one with the desktop experience.
		v.ServerCore = s == "Server Core"
	}
	return v, nil
}

// PrettyName renders the operating system the way Facts.Distribution.PrettyName is rendered on Linux.
//
// It is built here rather than left to the caller because Distribution.String falls back to
// "${id} ${version} (${codename})" when PrettyName is empty, and a Windows host has no codename — so a
// host that did not fill this in would appear in the fleet list as "windows 2022 ()". That is the sort
// of defect that survives review because it is only visible in a rendered UI.
func (v Version) PrettyName() string {
	name := v.ProductName
	if name == "" {
		release, _ := v.Release()
		name = "Windows Server " + release
	}
	if v.ServerCore {
		name += " (Server Core)"
	}
	if v.DisplayVersion != "" {
		name += " " + v.DisplayVersion
	}
	return name + " " + v.String()
}

// MachineGUID returns the host's Cryptography\MachineGuid, which Farrier uses as a stable identity.
//
// It is the Windows counterpart of /etc/machine-id and carries the same warning, which the caller must
// honour: it is *cloned with a disk image*. A fleet built by copying one prepared virtual machine
// without running Sysprep has many hosts claiming one identity, and the failure looks like hosts
// intermittently overwriting each other's facts rather than like a duplicate id. Enrolment is where
// that has to be refused, with an error that names image cloning, because that is the only moment the
// control plane can see two claims to the same identity and still do something about it.
//
// It is hashed with the per-host salt before it leaves the machine, exactly as the machine-id is on
// Linux: the raw value identifies a Windows installation to anybody who has seen it elsewhere.
func MachineGUID() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("winapi: opening the Cryptography key: %w", err)
	}
	defer func() { _ = key.Close() }()

	guid, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("winapi: reading MachineGuid: %w", err)
	}
	if guid == "" {
		return "", fmt.Errorf("winapi: MachineGuid is empty")
	}
	return guid, nil
}

// KernelRelease returns the operating-system build as the string Facts.Kernel carries.
//
// Windows has no kernel release string of the shape /proc/sys/kernel/osrelease produces, and inventing
// one would be worse than reporting the version everybody actually uses to identify a Windows build. It
// never fails, for the reason the Linux reader never fails: a heartbeat carrying "unknown" is worth
// more than no heartbeat.
func KernelRelease() string {
	v, err := OSVersion()
	if err != nil {
		return "unknown"
	}
	return v.String()
}
