//go:build linux

package platform

import "github.com/pascalgross/hostseal/internal/collect"

// Detect identifies the host and returns the matching platform implementation.
//
// It reads the real /etc/os-release. DetectFrom takes a path, for tests and for inspecting a chroot.
//
// It is build-tagged rather than switching on runtime.GOOS because the two answers have nothing in
// common: a Linux host is identified by parsing a file and choosing a distribution family, and a Windows
// host is identified by asking the kernel. A runtime switch would compile the os-release reader into the
// Windows agent and the registry reader into the Linux one, each unreachable, each still a path a
// reviewer has to account for.
func Detect() (collect.Platform, collect.Distribution, error) {
	return DetectFrom(collect.OSReleasePath)
}
