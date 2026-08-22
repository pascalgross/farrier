// Package buildinfo carries the version stamped into a Farrier binary at link time.
//
// It exists as its own package, rather than a pair of variables in each main package, because all
// three binaries and the three root helpers need the same values and the agent reports them in every
// heartbeat. A control plane deciding what a host is capable of does so from this string, so it has to
// mean the same thing everywhere.
package buildinfo

import "runtime/debug"

// Version is the release version, stamped by the linker.
//
// The default is deliberately not "unknown": a binary built with plain `go build` is a development
// build, and saying so in a heartbeat is more useful to whoever is reading a fleet list at three in
// the morning than an empty field.
var Version = "0.0.0-dev"

// Commit is the short git revision, stamped by the linker.
var Commit = "unknown"

// String renders the version and commit as one line for logs, the User-Agent header and heartbeats.
//
// It exists so that every place reporting the build agrees on the format. Two slightly different
// renderings of the same thing is how a fleet list ends up with what looks like two versions deployed.
func String() string {
	return Version + " (" + Commit + ")"
}

// UserAgent returns the HTTP User-Agent a Farrier component identifies itself with.
//
// Agents are identifiable in a control plane's access log on purpose. When a fleet misbehaves — a
// backoff bug, a heartbeat storm — the first question is which agent version is doing it, and the
// answer should not require correlating against the database.
func UserAgent(component string) string {
	return "farrier-" + component + "/" + Version
}

// Revision returns the VCS revision the Go toolchain recorded, when the linker did not stamp one.
//
// It exists for `go install`-style builds, which skip the Makefile and therefore skip the ldflags.
// Those builds are common for the CLI, and a version string of "0.0.0-dev (unknown)" on an operator's
// signing machine is exactly where a reproducibility question is hardest to answer later.
func Revision() string {
	if Commit != "unknown" {
		return Commit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Commit
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return s.Value[:7]
		}
	}
	return Commit
}
