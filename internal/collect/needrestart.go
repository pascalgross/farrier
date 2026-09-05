package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/pascalgross/hostseal/internal/run"
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

	// Available reports whether needrestart is installed on this host.
	//
	// It says the binary is there, not that it answered — that is Failed's job. The two are separate
	// facts because they call for different responses: an absent needrestart is a package to install,
	// a failing one is a host to look at.
	Available bool

	// Failed reports that needrestart ran and produced no usable answer.
	//
	// It exists so that a needrestart which errored — a half-configured perl right after a
	// dist-upgrade, a timeout on a busy host — is never mistaken for one that said "no reboot
	// needed". CombineRebootSignals treats a failed run as inconclusive: the one case where the
	// mechanism genuinely could not tell must not be the one reported as a conclusive no.
	Failed bool

	// ScanComplete reports whether the scan could see every process.
	//
	// needrestart can only inspect processes the calling user owns, and the HostSeal agent is
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

	// -b is batch mode; -r l lists rather than prompting or restarting. HostSeal never lets needrestart
	// restart anything: that decision belongs to the intent catalogue and the local policy, not to a
	// helper program's default.
	res, err := run.Command(ctx, run.Needrestart, "-b", "-r", "l")
	if res == nil {
		// The binary exists — the Stat above proved it — so this is a run that failed, not a package
		// that is missing, and the report must say which: "install needrestart" is the wrong advice
		// for a host where it is installed and broken.
		return NeedrestartReport{Available: true, Failed: true}, err
	}
	return finishNeedrestart(res.Stdout, err)
}

// finishNeedrestart decides what a finished needrestart invocation actually said.
//
// It is separate from RunNeedrestart so the one security-relevant judgement here — when does a non-zero
// exit still count as an answer — can be tested without a needrestart binary on the test machine.
// A run that errored but still printed a kernel status or a service list answered the question; a run
// that errored with nothing parsable did not, and is marked Failed so that CombineRebootSignals reports
// "cannot tell" rather than a conclusive "no reboot needed".
func finishNeedrestart(stdout []byte, runErr error) (NeedrestartReport, error) {
	report := ParseNeedrestart(stdout)
	report.Available = true
	report.ScanComplete = os.Geteuid() == 0
	if runErr != nil && len(report.Services) == 0 && report.KernelStatus == KernelStatusUnknown {
		report.Failed = true
		return report, runErr
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
		// The flag is set by CombineRebootSignals, which is where the bound is applied to the merged
		// list; truncating here as well keeps a pathological marker file from being read into memory.
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
	// Conclusive means at least one mechanism actually spoke. A missing marker file and an absent
	// needrestart produce Required=false, and that false is an absence of evidence rather than
	// evidence of absence: nothing writes /var/run/reboot-required unless update-notifier-common is
	// installed, so its absence says nothing on its own. A needrestart that ran and failed spoke no
	// more than an absent one did — "installed" is not "answered" — so a failed run only counts when
	// the marker answered for it.
	report.Conclusive = markerPresent || (nr.Available && !nr.Failed)

	switch {
	case len(sources) > 0:
		report.Source = strings.Join(sources, ", ")
	case nr.Failed:
		report.Source = "needrestart failed"
	case nr.Available:
		report.Source = "needrestart reports no reboot needed"
	default:
		report.Source = "no reboot marker and needrestart is not installed"
	}

	if len(report.Reasons) > MaxRebootReasons {
		report.Reasons = report.Reasons[:MaxRebootReasons]
		report.ReasonsTruncated = true
	}
	return report
}
