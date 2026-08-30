// Package winapi is the only place in Farrier that calls the Windows API.
//
// It is the Windows counterpart of internal/run's role rather than of its mechanism. internal/run
// concentrates process execution so that "no code path leads from a network message to a shell" can be
// proved by reading one file; this package concentrates the platform surface so that the same reviewer
// can see, in one directory, everything a Windows agent is able to ask the operating system for. The
// two are different in the way that matters: internal/run needs a run-time allowlist because the thing
// it starts is named by a variable, and nothing here is. Every call below names a fixed function at
// compile time, and the argument that could be dangerous — a program path — does not exist in this
// package at all.
//
// **Nothing here starts a process.** No CreateProcess, no ShellExecute, no WinExec, no
// CreateProcessAsUser, and no COM: `TestGuaranteeWinapiStartsNoProcess` asserts it over the AST, and
// the agent's one process start on Windows goes through internal/run to the update-scan binary exactly
// as it goes through internal/run to apt-get on Linux. COM lives in internal/wua, behind its own
// chokepoint and its own tests, and is reachable only from cmd/farrier-update-scan.
//
// Everything is read-only. There is no function here that changes the host: no StartService, no
// ControlService, no InitiateSystemShutdown, no registry write. That is not an omission to be filled in
// later — it is docs/SECURITY.md §12.3 expressed as a package boundary. A Windows host has no root
// helper, so there is nothing to re-read its policy as a privileged process and nothing to bound a
// privileged operation; adding a write here would put one in the agent's own address space.
//
// The build tags are the usual pattern and not a portability claim: this file carries none so that the
// package documents itself on every platform and `go vet ./...` has something to look at, and every
// file holding an actual call carries //go:build windows.
package winapi

// SupportedBuilds are the Windows Server builds a Farrier agent supports.
//
// The rule is the one README.md already states for Ubuntu and Debian — the releases in standard support
// — applied to a different vendor's calendar: Server 2019 (17763), 2022 (20348) and 2025 (26100).
// Server 2016 (14393) is excluded for the reason Ubuntu 20.04 is: it is in extended support only, and a
// release nobody tests against is one this project would be claiming rather than supporting.
//
// A build outside this map still reports. Refusing to look at a host would make the fleet list lie by
// omission, which is the same reasoning Distribution.Supported carries on Linux; the host says so
// instead, and wears the badge.
var SupportedBuilds = map[uint32]string{
	17763: "2019",
	20348: "2022",
	26100: "2025",
}
