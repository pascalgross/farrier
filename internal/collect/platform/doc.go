// Package platform holds one HostSeal collect.Platform implementation per operating-system family.
//
// On Linux, Detect chooses between them from /etc/os-release. Adding a distribution family means adding
// a file here and a case in newFor; nothing else in the codebase learns about it, which is the property
// docs/EXTENDING.md promises about this seam.
//
// Every implementation must state in its own doc comment what it does about each of the four
// silent-wrong-answer traps listed in the collect package documentation. All four produce a plausible
// number rather than an error, so a reviewer cannot check them by reading the code for correctness —
// only by reading what the author says they thought about.
//
// Since a Windows agent exists, the seam spans operating systems rather than only distribution families,
// and the shape of the split changed with it. Detect is build-tagged: on Linux it parses os-release and
// chooses between Ubuntu and Debian through newFor, and on Windows it asks the kernel and returns the one
// implementation there is. A runtime switch on GOOS would have compiled the os-release reader into the
// Windows agent and the registry reader into the Linux one — each unreachable, each still a path a
// reviewer has to account for.
package platform
