package collect

import (
	"os"
	"path/filepath"
	"testing"
)

// fixture reads a captured command output from testdata.
//
// The fixtures are real output shapes from the supported releases rather than minimal invented ones,
// because every trap this package exists to avoid lives in the parts of the output a minimal fixture
// would omit — the multi-origin lines, the packages with no installed version, the ESM labels.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return raw
}

// ubuntuSecurity is Ubuntu's rule: the archive part of the release string ends in "-security".
//
// It is restated here rather than imported from the platform package to avoid an import cycle in the
// tests, and restating it is not a loss: the platform package tests the real one, and this exists so
// the parser can be tested independently of which family supplied the predicate.
func ubuntuSecurity(release string) bool {
	label, archive := splitReleaseForTest(release)
	_ = label
	return len(archive) > 9 && archive[len(archive)-9:] == "-security"
}

// splitReleaseForTest splits an apt release string the way the platform package does.
func splitReleaseForTest(release string) (label, archive string) {
	for i := range release {
		if release[i] == '/' {
			return release[:i], release[i+1:]
		}
	}
	for i := range release {
		if release[i] == ':' {
			return release[:i], release[i+1:]
		}
	}
	return release, ""
}

// TestParseSimulationReadsUbuntuOutput covers the line shapes apt-get actually prints.
//
// The important rows are openssh-client, which lists two origins on one line, and
// linux-image-6.8.0-51-generic, which is newly installed and therefore has no bracketed current
// version. A parser that handled only the simple row would produce numbers that look plausible.
func TestParseSimulationReadsUbuntuOutput(t *testing.T) {
	packages := ParseSimulation(fixture(t, "ubuntu-noble-dist-upgrade.txt"), ubuntuSecurity)

	if len(packages) != 4 {
		t.Fatalf("parsed %d packages, want 4: %+v", len(packages), packages)
	}
	byName := map[string]Package{}
	for _, p := range packages {
		byName[p.Name] = p
	}

	if got := byName["base-files"]; got.CurrentVersion != "13ubuntu10.1" ||
		got.CandidateVersion != "13ubuntu10.2" || got.Security || got.Architecture != "amd64" {
		t.Errorf("base-files parsed as %+v", got)
	}
	if got := byName["libssl3t64"]; !got.Security {
		t.Errorf("libssl3t64 came from noble-security and was not marked as security: %+v", got)
	}
	if got := byName["openssh-client"]; !got.Security || len(got.Origins) != 2 {
		t.Errorf("a package with two origins, one of them security, parsed as %+v", got)
	}
	newPkg := byName["linux-image-6.8.0-51-generic"]
	if newPkg.CurrentVersion != "" || newPkg.CandidateVersion != "6.8.0-51.52" {
		t.Errorf("a newly installed package parsed as %+v", newPkg)
	}

	report := Summarise(packages)
	if report.UpgradableTotal != 4 || report.UpgradableSecurity != 2 {
		t.Errorf("summary is %d security of %d total, want 2 of 4",
			report.UpgradableSecurity, report.UpgradableTotal)
	}
}

// TestParseSimulationHandlesReleasesWithNoVersionField covers the Ubuntu ESM shape.
//
// Some repositories publish a Release file with no Version, and apt then prints "Label:Archive" with no
// slash. On an ESM host the security marker lives entirely in that archive name, so a splitter that
// gave up without a slash would classify every ESM security update as an ordinary one — on precisely
// the hosts whose owners are paying for those updates.
func TestParseSimulationHandlesReleasesWithNoVersionField(t *testing.T) {
	packages := ParseSimulation(fixture(t, "ubuntu-jammy-esm-dist-upgrade.txt"), ubuntuSecurity)
	byName := map[string]Package{}
	for _, p := range packages {
		byName[p.Name] = p
	}
	if !byName["libxml2"].Security {
		t.Errorf("an ESM Apps security update was not marked as security: %+v", byName["libxml2"])
	}
	if !byName["libsystemd0"].Security {
		t.Errorf("an ESM Infra update with no version field was not marked as security: %+v",
			byName["libsystemd0"])
	}
	if byName["tzdata"].Security {
		t.Errorf("an ordinary update was marked as security: %+v", byName["tzdata"])
	}
}

// TestSummariseCountsBeforeTruncating asserts the counts and the list may disagree on purpose.
//
// A host with six hundred pending updates must report six hundred and say the list was cut short.
// Reporting five hundred would be a quietly wrong answer to the one question this product exists to
// answer.
func TestSummariseCountsBeforeTruncating(t *testing.T) {
	var packages []Package
	for i := range MaxPackages + 100 {
		p := Package{Name: "pkg", CandidateVersion: "1"}
		if i%2 == 0 {
			p.Security = true
		}
		packages = append(packages, p)
	}

	report := Summarise(packages)
	if report.UpgradableTotal != MaxPackages+100 {
		t.Errorf("total is %d, want %d", report.UpgradableTotal, MaxPackages+100)
	}
	if report.UpgradableSecurity != (MaxPackages+100)/2 {
		t.Errorf("security count is %d, want %d", report.UpgradableSecurity, (MaxPackages+100)/2)
	}
	if len(report.Packages) != MaxPackages || !report.Truncated {
		t.Errorf("list has %d entries, truncated=%v", len(report.Packages), report.Truncated)
	}
}

// TestParseNeedrestartReadsBatchOutput covers the format and the field that matters.
//
// NEEDRESTART-SVC is the actionable half — "which running services still hold the old OpenSSL" — and is
// what most update dashboards skip.
func TestParseNeedrestartReadsBatchOutput(t *testing.T) {
	report := ParseNeedrestart(fixture(t, "needrestart.txt"))
	if report.KernelStatus != KernelStatusUpgradePending {
		t.Errorf("kernel status is %d, want %d", report.KernelStatus, KernelStatusUpgradePending)
	}
	if report.CurrentKernel != "6.8.0-49-generic" || report.ExpectedKernel != "6.8.0-51-generic" {
		t.Errorf("kernels parsed as %q -> %q", report.CurrentKernel, report.ExpectedKernel)
	}
	if len(report.Services) != 3 {
		t.Errorf("parsed %d services, want 3: %v", len(report.Services), report.Services)
	}

	clean := ParseNeedrestart(fixture(t, "needrestart-clean.txt"))
	if clean.KernelStatus != KernelStatusCurrent || len(clean.Services) != 0 {
		t.Errorf("a clean host parsed as %+v", clean)
	}
}

// TestCombineRebootSignalsNeverTrustsTheMarkerAlone is the second silent-wrong-answer trap.
//
// /var/run/reboot-required is an Ubuntu update-notifier convention, not a standard. A collector that
// stopped at the marker would report that Debian hosts never need rebooting, quietly and forever.
func TestCombineRebootSignalsNeverTrustsTheMarkerAlone(t *testing.T) {
	kernelPending := NeedrestartReport{
		Available:      true,
		KernelStatus:   KernelStatusUpgradePending,
		CurrentKernel:  "6.1.0-27-amd64",
		ExpectedKernel: "6.1.0-28-amd64",
		Services:       []string{"ssh.service"},
	}

	// No marker — the Debian case — and needrestart says a reboot is pending.
	report := CombineRebootSignals(false, nil, kernelPending)
	if !report.Required {
		t.Error("needrestart reported a pending kernel upgrade and no reboot was required")
	}
	if len(report.Services) != 1 {
		t.Errorf("the service list was lost: %+v", report)
	}

	// Marker present, needrestart absent — a minimal Ubuntu image.
	report = CombineRebootSignals(true, []string{"linux-image-generic"}, NeedrestartReport{})
	if !report.Required || len(report.Reasons) != 1 {
		t.Errorf("the marker alone did not produce a required reboot: %+v", report)
	}

	// Neither signal. The source must say so rather than implying a clean bill of health.
	report = CombineRebootSignals(false, nil, NeedrestartReport{})
	if report.Required {
		t.Error("a reboot was required with no signal at all")
	}
	if report.Source == "" {
		t.Error("a negative answer carries no explanation of what it was based on")
	}
}

// TestCombineRebootSignalsReportsAnIncompleteScan is the honesty case.
//
// needrestart only sees processes the calling user owns, and the agent is deliberately unprivileged.
// "No services need restarting" and "I could not see the services that do" must never look the same.
func TestCombineRebootSignalsReportsAnIncompleteScan(t *testing.T) {
	partial := CombineRebootSignals(false, nil, NeedrestartReport{Available: true, KernelStatus: 1})
	if partial.ServiceScanComplete {
		t.Error("a scan run without privilege was reported as complete")
	}
	full := CombineRebootSignals(false, nil, NeedrestartReport{
		Available: true, KernelStatus: 1, ScanComplete: true,
	})
	if !full.ServiceScanComplete {
		t.Error("a complete scan was reported as incomplete")
	}
}

// TestDistributionFromOSReleaseClassifiesTheSupportedReleases covers the support rule.
//
// The rule is "the Ubuntu LTS releases in standard support, plus Debian stable and oldstable". Focal is
// the interesting row: it is an LTS, it is not supported, and the reason is that it is ESM-only.
func TestDistributionFromOSReleaseClassifiesTheSupportedReleases(t *testing.T) {
	cases := []struct {
		file      string
		family    Family
		codename  string
		supported bool
	}{
		{"os-release-noble", FamilyUbuntu, "noble", true},
		{"os-release-bookworm", FamilyDebian, "bookworm", true},
		{"os-release-focal", FamilyUbuntu, "focal", false},
	}
	for _, tc := range cases {
		fields, err := ParseOSRelease(filepath.Join("testdata", tc.file))
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		dist, err := DistributionFromOSRelease(fields)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if dist.Family != tc.family || dist.Codename != tc.codename || dist.Supported != tc.supported {
			t.Errorf("%s parsed as family=%s codename=%s supported=%v",
				tc.file, dist.Family, dist.Codename, dist.Supported)
		}
	}
}

// TestDistributionFromOSReleaseRefusesOtherDistributions asserts an honest failure.
//
// Farrier is for Ubuntu and Debian. Guessing at Fedora would produce a host whose update numbers are
// silently meaningless, which is worse than saying no.
func TestDistributionFromOSReleaseRefusesOtherDistributions(t *testing.T) {
	fields, err := ParseOSRelease(filepath.Join("testdata", "os-release-fedora"))
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	if _, err := DistributionFromOSRelease(fields); err == nil {
		t.Error("a Fedora host was accepted")
	}
}

// TestParseOSReleaseNeverEvaluatesItsInput asserts values are taken literally.
//
// The format is shell-like but is not shell. "source /etc/os-release" is a pattern this project will
// not adopt, and a parser that unquoted by evaluating would be the same mistake with extra steps.
func TestParseOSReleaseNeverEvaluatesItsInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	body := "ID=ubuntu\nPRETTY_NAME=\"Ubuntu $(reboot) `id`\"\nVERSION_CODENAME=noble\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	fields, err := ParseOSRelease(path)
	if err != nil {
		t.Fatalf("ParseOSRelease: %v", err)
	}
	if got := fields["PRETTY_NAME"]; got != "Ubuntu $(reboot) `id`" {
		t.Errorf("PRETTY_NAME is %q; the value must be taken literally", got)
	}
}
