// Command farrier is the operator's command-line tool.
//
// Its most important job is `farrier sign`: decoding and rendering a job request offline, without
// contacting the server, and signing it with a key the control plane does not hold. That the rendering
// happens locally from the full signed payload is a requirement on the wire format rather than a nicety
// of this program — if the tool signed an opaque digest handed to it by the server, a compromised
// control plane could show one operation in the browser and have a different one signed.
//
// The rest of the path was built first and this closed it: the control plane accepts a signed job on
// POST /api/v1/jobs, holds a destructive one for release if the fleet asks for that, an agent verifies
// the signature against the host's own trusted-signers, and a root helper acts on it. What it adds is
// the end an operator stands at. The other commands are what made that end reachable: enrolling a host,
// and generating and inspecting signing keys so a trust anchor can be established in advance.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pascalgross/farrier/internal/agent"
	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/prompt"
	"github.com/pascalgross/farrier/internal/signing"
	"github.com/pascalgross/farrier/internal/signing/backend"
	"github.com/pascalgross/farrier/internal/signing/backend/file"

	// The backends this build ships, registered by their own init functions.
	//
	// Blank imports, in the shape database/sql uses, and they are the whole of what `farrier` knows
	// about any of them: the registry resolves a reference and this command never names a backend
	// again. They are imported here rather than in internal/signing because the agent and the control
	// plane import that package for the verifier and must link no backend at all — a property
	// TestGuaranteeNoManagedHostBinaryLoadsASigningBackend asserts rather than assumes.
	_ "github.com/pascalgross/farrier/internal/signing/backend/kms"
	_ "github.com/pascalgross/farrier/internal/signing/backend/pkcs11"
)

// usage prints the command list.
func usage() {
	fmt.Fprintf(os.Stderr, `farrier %s

usage:
  farrier enroll        enrol this host with a control plane
  farrier key generate  create a signing key and print its trusted-signers line
  farrier key show      print the trusted-signers line for an existing key
  farrier sign          render a job request offline and sign it
  farrier sign-template sign a provisioning template for the Tier 2 bootstrap
  farrier catalogue     print the intent catalogue this build knows
  farrier version       print the version

Run "farrier <command> --help" for a command's options.
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
	case "enroll", "enrol":
		os.Exit(enroll(args[1:]))
	case "key":
		os.Exit(keyCommand(args[1:]))
	case "catalogue":
		for _, s := range intent.All() {
			fmt.Printf("%-26s %-12s %s\n", s.Name, s.Class, s.Summary)
		}
	case "sign":
		os.Exit(signCommand(args[1:]))
	case "sign-template":
		os.Exit(signTemplateCommand(args[1:]))
	case "version":
		fmt.Println("farrier " + buildinfo.String())
	default:
		fmt.Fprintf(os.Stderr, "farrier: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

// enroll registers this host with a control plane.
func enroll(argv []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "control plane base URL, for example https://farrier.example.org")
	token := fs.String("token", "", "single-use bootstrap token")
	stateDir := fs.String("state-dir", agent.DefaultStateDir, "directory to keep enrolment state in")
	caBundle := fs.String("ca", "", "PEM file to verify the control plane's own certificate against")
	signers := fs.String("signers", "",
		"local trusted-signers file to install before anything is fetched")
	policyFile := fs.String("policy", "", "local policy.toml to install")
	bootstrap := fs.String("bootstrap", "",
		"provisioning template to apply once during enrolment; refuses without --signers")
	hostname := fs.String("hostname", "", "override the reported hostname")
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state, err := agent.Enroll(ctx, agent.EnrollOptions{
		ServerURL:   *server,
		Token:       *token,
		StateDir:    *stateDir,
		CABundle:    *caBundle,
		SignersFile: *signers,
		PolicyFile:  *policyFile,
		Bootstrap:   *bootstrap,
		Hostname:    *hostname,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		if errors.Is(err, agent.ErrNoTrustAnchor) {
			fmt.Fprintln(os.Stderr,
				"\nThe trust anchor is established from a local file you choose, before anything is\n"+
					"fetched, so that a bootstrap template can be verified against a key the server did\n"+
					"not supply. Without that ordering the verification would prove nothing.")
		}
		return 1
	}

	fmt.Printf("Enrolled as %s with %s.\n", state.HostID, state.ServerURL)
	fmt.Println("Start the agent with: systemctl start farrier-agent")
	return 0
}

// keyCommand implements `farrier key generate` and `farrier key show`.
func keyCommand(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: farrier key generate|show [options]")
		return 2
	}
	switch argv[0] {
	case "generate":
		return keyGenerate(argv[1:])
	case "show":
		return keyShow(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "farrier: unknown key command %q\n", argv[0])
		return 2
	}
}

// keyGenerate creates a signing key and prints the line to add to trusted-signers.
//
// The output is a line to paste rather than a file to copy, because trusted-signers is edited by hand
// on each host by an administrator who has decided that key should be able to reboot that machine.
// Making that a deliberate edit is the point; automating it would make the trust anchor something the
// tooling manages rather than something a person chose.
func keyGenerate(argv []string) int {
	fs := flag.NewFlagSet("key generate", flag.ExitOnError)
	out := fs.String("out", "", "path to write the encrypted key file to")
	keyID := fs.String("id", "", "identity recorded in the audit log, for example ops-laptop")
	algorithm := fs.String("algorithm", string(signing.Ed25519),
		"ed25519, or ecdsa-p256 where something in your chain cannot do Ed25519")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *out == "" || *keyID == "" {
		fmt.Fprintln(os.Stderr, "farrier: --out and --id are both required")
		return 2
	}

	passphrase, err := readPassphrase("Passphrase for the new key: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}
	confirm, err := readPassphrase("Confirm: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}
	if string(passphrase) != string(confirm) {
		fmt.Fprintln(os.Stderr, "farrier: the passphrases do not match")
		return 1
	}

	signer, err := file.Generate(*out, *keyID, signing.Algorithm(*algorithm), passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}
	defer func() { _ = signer.Close() }()

	line, err := signing.TrustedSignerLine(signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}

	fmt.Printf("\nWrote %s.\n\nAdd this line to /etc/farrier/trusted-signers on every host this key\n"+
		"should be able to authorise destructive operations on:\n\n%s\n\n", *out, line)
	fmt.Println("The file is empty by default and the control plane cannot write it, so a host will")
	fmt.Println("execute nothing destructive until somebody makes that edit deliberately.")
	return 0
}

// keyShow prints the trusted-signers line for an existing key.
//
// A file backend answers this without the passphrase, which is the situation somebody is in while
// setting up a host with the token at the office. A token or a key store may need its PIN or its cloud
// credential first, and says so rather than returning nothing.
func keyShow(argv []string) int {
	fs := flag.NewFlagSet("key show", flag.ExitOnError)
	in := fs.String("in", "", "path to the key file, or a backend reference: "+
		strings.Join(referenceExamples(), ", "))
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *in == "" {
		fmt.Fprintln(os.Stderr, "farrier: --in is required")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	showCtx, done := context.WithTimeout(ctx, DefaultSigningTimeout)
	defer done()

	pub, err := backend.Inspect(showCtx, *in, readPassphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}
	fmt.Printf("%s %s %s %s\n", pub.Algorithm, pub.Encoded, pub.KeyID, pub.Backend)
	return 0
}

// referenceExamples renders one example per registered backend, for the help text.
//
// Generated from the registry rather than written out, so a build without a backend does not advertise
// it and a build with a new one does not need this list edited. The examples themselves are the
// shortest reference each backend accepts.
func referenceExamples() []string {
	examples := map[string]string{
		"file":     "~/.config/farrier/ops.key",
		"pkcs11":   "pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so",
		"awskms":   "awskms:arn:aws:kms:eu-central-1:123456789012:key/abcd#ops-kms-1",
		"gcpkms":   "gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1#ops-kms-1",
		"azurekms": "azurekms:ops.vault.azure.net/keys/farrier-signing/9885aa55#ops-kms-1",
	}
	var out []string
	for _, scheme := range backend.Schemes() {
		if example, ok := examples[scheme]; ok {
			out = append(out, example)
		}
	}
	return out
}

// readPassphrase reads a passphrase without echoing it.
//
// A thin wrapper over internal/prompt so that it can be handed to the signing-backend registry as a
// backend.PassphraseFunc, which is the shape that keeps the rule travelling with the value: a
// passphrase or a PIN is never a command-line argument, where every user on the machine can read it
// from the process list.
func readPassphrase(message string) ([]byte, error) { return prompt.Secret(message) }
