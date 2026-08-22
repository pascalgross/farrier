// Command farrier is the operator's command-line tool.
//
// Its most important job is `farrier sign`, which decodes and renders a job request offline, without
// contacting the server, and then signs it with a key the control plane does not hold. That the
// rendering happens locally from the full signed payload is a requirement on the wire format rather
// than a nicety of this program: if the tool signed an opaque digest handed to it by the server, a
// compromised control plane could show one operation in the browser and have a different one signed.
//
// Phase 0 ships no write capability, so there is nothing to sign yet. The catalogue and enrolment
// commands are present because they are useful before that and because they exercise the same shared
// code the agent uses.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pegasusnetworks/farrier/internal/buildinfo"
	"github.com/pegasusnetworks/farrier/internal/intent"
)

// usage prints the command list.
func usage() {
	fmt.Fprintf(os.Stderr, `farrier %s

usage:
  farrier enroll     enrol this host with a control plane
  farrier sign       render a job request offline and sign it
  farrier catalogue  print the intent catalogue this build knows
  farrier version    print the version
`, buildinfo.String())
}

// main dispatches to a subcommand.
func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "catalogue":
		for _, s := range intent.All() {
			fmt.Printf("%-26s %-12s %s\n", s.Name, s.Class, s.Summary)
		}
	case "version":
		fmt.Println("farrier " + buildinfo.String())
	case "enroll", "sign":
		fmt.Fprintf(os.Stderr, "farrier: %q is not implemented in this build\n", args[0])
		os.Exit(4)
	default:
		fmt.Fprintf(os.Stderr, "farrier: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}
