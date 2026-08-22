package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pascalgross/farrier/internal/run"
)

// instLine matches one "Inst" line of an apt-get simulation.
//
// The shape apt-get prints is:
//
//	Inst coreutils [9.4-3ubuntu6.1] (9.4-3ubuntu6.2 Ubuntu:24.04/noble-updates [amd64])
//
// The current-version bracket is absent for a package being newly installed as a dependency, which is
// why that group is optional. The parenthesised group holds the candidate version, one or more release
// strings, and the architecture; on Debian there are commonly two releases, as in
// "Debian:12.8/stable, Debian-Security:12/stable-security".
var instLine = regexp.MustCompile(`^Inst\s+(\S+)(?:\s+\[([^\]]*)\])?\s+\(([^)]*)\)`)

// SimulateUpgrade asks apt-get what it would do, without doing it.
//
// This is the primary path for counting updates, and apt-check is only ever an optimisation on top of
// it. apt-check lives in update-notifier-common, which is absent from minimal images of both families:
// treating it as the source of truth means reporting zero pending updates on exactly the hosts most
// likely to have been forgotten, and reporting it confidently.
//
// The command is apt-get and never apt. apt 3.0, shipped in Ubuntu 25.04, reorganised apt's output into
// colourised columns; apt-get's format is machine-oriented and has been stable for two decades.
func SimulateUpgrade(ctx context.Context) ([]byte, error) {
	res, err := run.CommandWith(ctx, run.Options{
		// A simulation takes no locks and changes nothing, but it does read package lists, which on a
		// slow or busy host is not instant.
		Timeout: 3 * time.Minute,
		Env: []string{
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"LC_ALL=C.UTF-8",
			"DEBIAN_FRONTEND=noninteractive",
		},
	}, run.AptGet,
		"--just-print",
		"--quiet",
		"-o", "APT::Get::Show-User-Simulation-Note=false",
		"dist-upgrade",
	)
	if err != nil {
		return nil, fmt.Errorf("collect: simulating an upgrade: %w (stderr: %s)",
			err, truncateForError(res))
	}
	return res.Stdout, nil
}

// truncateForError renders a bounded slice of a failed command's stderr for an error message.
//
// A failing apt-get can print a great deal, and an error string that carries all of it ends up in a log
// line nobody can read. The first few hundred bytes always contain the reason.
func truncateForError(res *run.Result) string {
	if res == nil {
		return ""
	}
	s := strings.TrimSpace(string(res.Stderr))
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

// ParseSimulation extracts upgradable packages from apt-get simulation output.
//
// isSecurity decides whether a release string names a security origin. It is supplied by the platform
// rather than decided here, because Ubuntu and Debian express the same idea differently and getting it
// wrong produces a plausible-looking number rather than an error.
func ParseSimulation(output []byte, isSecurity func(release string) bool) []Package {
	var packages []Package

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		m := instLine.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		pkg := Package{Name: m[1], CurrentVersion: m[2]}

		// The parenthesised group is "<candidate> <release>[, <release>…] [<arch>]". Splitting the
		// architecture off first leaves a comma-separated release list with the candidate in front.
		body := m[3]
		if open := strings.LastIndex(body, "["); open != -1 && strings.HasSuffix(body, "]") {
			pkg.Architecture = strings.TrimSpace(body[open+1 : len(body)-1])
			body = strings.TrimSpace(body[:open])
		}
		candidate, releases, found := strings.Cut(body, " ")
		pkg.CandidateVersion = candidate
		if found {
			for _, r := range strings.Split(releases, ",") {
				r = strings.TrimSpace(r)
				if r == "" {
					continue
				}
				pkg.Origins = append(pkg.Origins, r)
				if isSecurity != nil && isSecurity(r) {
					pkg.Security = true
				}
			}
		}
		packages = append(packages, pkg)
	}
	return packages
}

// Summarise turns a package list into the bounded report the protocol carries.
//
// The counts are taken before truncation, so a host with six hundred pending updates reports six
// hundred and says the list was cut short — rather than reporting five hundred, which would be a
// quietly wrong answer to the one question this product exists to answer.
func Summarise(packages []Package) PackageReport {
	report := PackageReport{UpgradableTotal: len(packages)}
	for _, p := range packages {
		if p.Security {
			report.UpgradableSecurity++
		}
	}
	if len(packages) > MaxPackages {
		report.Packages = packages[:MaxPackages]
		report.Truncated = true
	} else {
		report.Packages = packages
	}
	return report
}
