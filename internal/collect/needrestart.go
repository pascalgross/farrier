package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/pegasusnetworks/farrier/internal/run"
)

// UbuntuRebootMarker is update-notifier's reboot-required file.
//
// It is an Ubuntu convention rather than a standard. Debian only has it when update-notifier-common
// happens to be installed, which on a minimal image it is not — so this is treated as one input and
// never as the answer. A collector that stopped here would report that Debian hosts never need a
// reboot, and would do so silently.
const UbuntuRebootMarker = "/var/run/reboot-required"

// UbuntuRebootMarkerPackages names the packages that set the marker.
const UbuntuRebootMarkerPackages = "/var/run/reboot-required.pkgs"

// Kernel status values reported by needrestart in NEEDRESTART-KSTA.
const (
	// KernelStatusUnknown means needrestart could not determine the kernel situation.
	KernelStatusUnknown = 0

	// KernelStatusCurrent means the running kernel is the expected one.
	KernelStatusCurrent = 1

	// KernelStatusABICompatible means a kernel upgrade is pending but ABI-compatible.
	//
	// It is treated as requiring a reboot. Livepatch may make that untrue on a particular host, but
	// the honest default is to say a newer kernel is installed and not running, and let the operator
	// decide — the alternative reports a patched host that is still running the old code.
	KernelStatusABICompatible = 2

	// KernelStatusUpgradePending means a kernel version upgrade is pending and a reboot is required.
	KernelStatusUpgradePending = 3
)

// NeedrestartReport is what needrestart -b said.
type NeedrestartReport struct {
	// KernelStatus is the NEEDRESTART-KSTA value.
	KernelStatus int

	// CurrentKernel is NEEDRESTART-KCUR, the running kernel.
	CurrentKernel string

	// ExpectedKernel is NEEDRESTART-KEXP, the kernel that would run after a reboot.
	ExpectedKernel string

	// Services are the NEEDRESTART-SVC units that still hold replaced libraries.
	Services []string

	// Available reports whether needrestart could be run at all.
	Available bool

	// ScanComplete reports whether the scan could see every process.
	//
	// needrestart can only inspect processes the calling user owns, and the Farrier agent is
	// deliberately unprivileged. An incomplete scan must be reported as incomplete rather than
	// presented as a clean bill of health: "no services need restarting" and "I could not see the
	// services that do" must never look the same in a dashboard.
	ScanComplete bool
}

// RunNeedrestart runs needrestart in batch mode and parses the result.
//
// needrestart -b answers "which running services still hold the old OpenSSL", which is more actionable
// than reboot-required and is what most update dashboards skip. A missing binary is not an error: it is
// a recommended package rather than a dependency, and a host without it should report less rather than
// fail.
func RunNeedrestart(ctx context.Context) (NeedrestartReport, error) {
	if _, err := os.Stat(string(run.Needrestart)); errors.Is(err, os.ErrNotExist) {
		return NeedrestartReport{}, nil
	}

	// -b is batch mode; -r l lists rather than prompting or restarting. Farrier never lets needrestart
	// restart anything: that decision belongs to the intent catalogue and the local policy, not to a
	// helper program's default.
	res, err := run.Command(ctx, run.Needrestart, "-b", "-r", "l")
	if res == nil {
		return NeedrestartReport{}, err
	}
	report := ParseNeedrestart(res.Stdout)
	report.Available = true
	report.ScanComplete = os.Geteuid() == 0
	if err != nil && len(report.Services) == 0 && report.KernelStatus == KernelStatusUnknown {
		return report, err
	}
	return report, nil
}

// ParseNeedrestart reads needrestart's batch output.
//
// The format is one "NEEDRESTART-KEY: value" per line. Unknown keys are ignored so that a newer
// needrestart adding fields does not break a working agent.
func ParseNeedrestart(output []byte) NeedrestartReport {
	report := NeedrestartReport{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "NEEDRESTART-KSTA":
			if n, err := strconv.Atoi(value); err == nil {
				report.KernelStatus = n
			}
		case "NEEDRESTART-KCUR":
			report.CurrentKernel = value
		case "NEEDRESTART-KEXP":
			report.ExpectedKernel = value
		case "NEEDRESTART-SVC":
			if value != "" {
				report.Services = append(report.Services, value)
			}
		}
	}
	return report
}

// RebootMarker reads the update-notifier reboot marker and the packages that set it.
//
// It returns whether the marker exists and which packages are named. On a host without
// update-notifier-common the marker never appears, which is why callers must combine this with
// needrestart rather than trusting it alone.
func RebootMarker() (bool, []string) {
	if _, err := os.Stat(UbuntuRebootMarker); err != nil {
		return false, nil
	}
	raw, err := os.ReadFile(UbuntuRebootMarkerPackages)
	if err != nil {
		return true, nil
	}
	var reasons []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			reasons = append(reasons, line)
		}
	}
	if len(reasons) > MaxRebootReasons {
		reasons = reasons[:MaxRebootReasons]
	}
	return true, reasons
}

// CombineRebootSignals merges the marker file and needrestart into one answer.
//
// Both families use this, which is the point: the difference between them is which signal is present,
// not how the two should be combined. Either signal alone is enough to say a reboot is required, and
// the Source field records which one spoke so that a wrong answer can be traced to its input rather
// than argued about.
func CombineRebootSignals(markerPresent bool, markerReasons []string, nr NeedrestartReport) RebootReport {
	report := RebootReport{
		Reasons:             markerReasons,
		Services:            nr.Services,
		ServiceScanComplete: nr.ScanComplete,
	}

	var sources []string
	if markerPresent {
		report.Required = true
		sources = append(sources, UbuntuRebootMarker)
	}
	if nr.Available && nr.KernelStatus >= KernelStatusABICompatible {
		report.Required = true
		sources = append(sources, "needrestart (KSTA "+strconv.Itoa(nr.KernelStatus)+")")
		if nr.ExpectedKernel != "" && nr.ExpectedKernel != nr.CurrentKernel {
			report.Reasons = append(report.Reasons,
				"kernel "+nr.ExpectedKernel+" installed, "+nr.CurrentKernel+" running")
		}
	}
	switch {
	case len(sources) > 0:
		report.Source = strings.Join(sources, ", ")
	case nr.Available:
		report.Source = "needrestart reports no reboot needed"
	default:
		report.Source = "no reboot marker and needrestart is not installed"
	}

	if len(report.Reasons) > MaxRebootReasons {
		report.Reasons = report.Reasons[:MaxRebootReasons]
	}
	return report
}
