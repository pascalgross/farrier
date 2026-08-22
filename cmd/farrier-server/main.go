// Command farrier-server is the Farrier control plane.
//
// It is a single binary with the Angular bundle embedded, plus PostgreSQL. That is a deliberate
// packaging decision rather than a limitation: open-source software is installed by strangers who
// close the tab on friction, and a four-service Compose stack is friction. Sharing Go with the agent
// also means the intent catalogue and signature verification are literally the same code on both
// sides, rather than two implementations that agree until they do not.
//
// The server can ask a host for work. It cannot make a host do anything the host's own
// /etc/farrier/policy.toml forbids, and it holds no key that authorises a destructive operation. See
// docs/SECURITY.md.
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
	fmt.Fprintf(os.Stderr, `farrier-server %s

usage:
  farrier-server serve       run the control plane
  farrier-server ca init     create the private CA that issues agent certificates
  farrier-server catalogue   print the intent catalogue this build knows
  farrier-server version     print the version
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
		printCatalogue()
	case "version":
		fmt.Println("farrier-server " + buildinfo.String())
	case "serve", "ca":
		fmt.Fprintf(os.Stderr, "farrier-server: %q is not implemented in this build\n", args[0])
		os.Exit(4)
	default:
		fmt.Fprintf(os.Stderr, "farrier-server: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

// printCatalogue writes the complete intent catalogue to stdout.
//
// It exists so that an operator evaluating Farrier can see the entire set of things the control plane
// is able to ask for, from the binary they are about to run, without reading the source or trusting a
// web page. The claim this project makes is about that set being small and closed, so it should be
// possible to check it in one command.
func printCatalogue() {
	fmt.Printf("%-26s %-12s %-6s %s\n", "INTENT", "CLASS", "EXEC", "SUMMARY")
	for _, s := range intent.All() {
		executor := "no"
		if s.Implemented {
			executor = "yes"
		}
		fmt.Printf("%-26s %-12s %-6s %s\n", s.Name, s.Class, executor, s.Summary)
	}
	fmt.Printf("\n%d intents. This set is closed: it is a compile-time map with no registry and no\n",
		len(intent.Names()))
	fmt.Println("configuration that adds to it. Permanently refused, with reasons in docs/SECURITY.md:")
	for _, n := range intent.Refused {
		fmt.Printf("  %s\n", n)
	}
}
