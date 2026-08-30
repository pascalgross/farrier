//go:build windows

// Command farrier-update-scan reports the updates pending on a Windows host, and does nothing else.
//
// It exists to keep one sentence of docs/SECURITY.md §3 literally true on Windows: there is no runtime
// plugin loader in the agent, ever. Enumerating updates means loading wuapi.dll and calling COM, and the
// agent process holds the host's mTLS private key — so the loading happens here instead, in a process
// that holds no credential, opens no socket, listens on nothing, and exits as soon as it has written one
// JSON document to its standard output.
//
// This is the same shape the Linux agent already uses. It does not parse apt's internal state either: it
// runs apt-get through internal/run with a fixed argument vector and reads what comes back. The agent
// starts this binary the same way, from the same allowlist, with the same bound on how long it may take.
//
// It is deliberately not a service, not resident and not privileged. A scan needs no privilege —
// Microsoft grants IUpdateSearcher to the User group — and the update session belongs to one operating
// system thread, which is a discipline that is trivial in a single-purpose process and a defect waiting
// for a busy machine inside a long-running agent with a scheduler.
//
// It writes a result even when the scan fails, and exits zero for both outcomes. "The scan could not
// run" is a fact the control plane needs, and reporting it as a non-zero exit with nothing on stdout
// would leave a host looking as though it had nothing pending — which is the one wrong answer that
// costs an operator something.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/updatescan"
	"github.com/pascalgross/farrier/internal/wua"
)

// clientID is what this process calls itself to the Windows Update Agent.
//
// It is not decoration. An administrator reading the Windows Update log and asking why a scan started
// sees this string, and an unnamed client is one they cannot trace back to the software that caused it.
const clientID = "Farrier"

// main runs one scan and prints its result.
//
// It has no subcommands and takes no arguments beyond --version, because this program answers exactly
// one question. A scan binary that grew a second mode would be a second thing the agent could ask it to
// do, and the allowlist entry that permits it to run would then permit more than a reviewer read.
func main() {
	version := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *version {
		fmt.Println(buildinfo.String())
		return
	}

	// No arguments are accepted beyond the flag above. This process is started by the agent with a
	// fixed argument vector, and anything else arriving here means something is calling it that should
	// not be — better to refuse than to ignore.
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "farrier-update-scan takes no arguments")
		os.Exit(2)
	}

	result, err := wua.Scan(clientID)
	if err != nil {
		// Reserved for a failure to construct a result at all, which Scan does not currently produce.
		// It is still handled, because a future change that made it possible would otherwise print
		// nothing and exit zero.
		result = updatescan.ScanResult{Complete: false, Error: err.Error()}
	}

	raw, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier-update-scan: encoding the result: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(raw, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "farrier-update-scan: writing the result: %v\n", err)
		os.Exit(1)
	}
}
