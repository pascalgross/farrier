package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/prompt"
	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/provision"
	"github.com/pascalgross/farrier/internal/signing"
)

// signTemplateCommand implements `farrier sign-template`.
//
// It is `farrier sign` for the Tier 2 bootstrap: the signature is produced offline, by a key the
// control plane does not hold, over exactly the bytes an enrolling host will verify. The control plane
// stores the result and hands it over verbatim — it cannot produce one, which is what keeps the
// guarantee's second paragraph an exception rather than a hole.
//
// The whole body is printed before signing, the same way `farrier sign` prints the signed payload
// verbatim: what the operator authorises here will run as root, via cloud-init, on every host enrolled
// with `--bootstrap <name>` from now on, and a confirmation that showed a filename and not a body
// would be a confirmation of nothing.
func signTemplateCommand(argv []string) int {
	fs := flag.NewFlagSet("sign-template", flag.ExitOnError)
	keyPath := fs.String("key", "",
		"the signing key: a path from `farrier key generate`, or a backend reference")
	name := fs.String("name", "", "the template name operators will pass to --bootstrap")
	bodyPath := fs.String("body", "", "path to the cloud-init user-data to sign")
	assumeYes := fs.Bool("yes", false, "do not ask for confirmation; for scripting a known-good template")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *keyPath == "" || *name == "" || *bodyPath == "" {
		fmt.Fprintln(os.Stderr, "farrier: --key, --name and --body are all required")
		return 2
	}

	raw, err := os.ReadFile(*bodyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: reading the body: %v\n", err)
		return 2
	}
	if len(raw) == 0 || len(raw) > provision.MaxBodyBytes {
		fmt.Fprintf(os.Stderr, "farrier: the body must be between 1 byte and %d bytes\n",
			provision.MaxBodyBytes)
		return 2
	}

	bootstrap := protocol.Bootstrap{Name: *name, Body: string(raw)}

	// Canonicalised before anything is displayed, so that what is shown below and what is signed
	// further down are the same bytes rather than two renderings of the same intention. The payload
	// covers the name as well as the body: signing the body alone would let a compromised control
	// plane return a genuinely signed template the operator did not name.
	payload, err := canonical.Marshal(bootstrap.SignedPayload())
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: could not canonicalise the template: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	signer, err := openWithTimeout(ctx, *keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}
	defer func() { _ = signer.Close() }()

	fmt.Fprint(os.Stderr, describeTemplate(bootstrap, signer))
	if !*assumeYes {
		ok, err := prompt.Confirm("Sign this template? [y/N] ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
			return 1
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "farrier: not signed.")
			return 3
		}
	}

	// The context is honoured because backends block: a touch-required token waits for a finger and a
	// key store waits for a network. The deadline starts after the confirmation for the reason
	// `farrier sign` states: the prompt above is a person reading a template, and a timeout that
	// covered it would refuse to sign for anybody who read it carefully.
	signCtx, done := context.WithTimeout(ctx, DefaultSigningTimeout)
	defer done()
	signature, err := signer.Sign(signCtx, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: signing failed: %v\n", err)
		return 1
	}

	request := map[string]any{
		"name":            bootstrap.Name,
		"body":            bootstrap.Body,
		"signature":       base64.StdEncoding.EncodeToString(signature),
		"signerKeyId":     signer.KeyID(),
		"signerAlgorithm": string(signer.Algorithm()),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(request); err != nil {
		fmt.Fprintf(os.Stderr, "farrier: writing the request: %v\n", err)
		return 1
	}

	// To stderr, so that stdout is exactly the request body and can be piped into curl.
	fmt.Fprintf(os.Stderr, "\nSigned. Store it with:\n"+
		"  curl -X POST \"$FARRIER_URL/api/v1/templates\" \\\n"+
		"    -H \"Authorization: Bearer $FARRIER_ADMIN_TOKEN\" \\\n"+
		"    -H 'Content-Type: application/json' -d @-\n")
	return 0
}

// describeTemplate renders what is about to be signed, body verbatim.
//
// It returns the text rather than writing it, for the same reason describeJob does: the property worth
// pinning in a test is that what an operator is shown is what is signed. The secret-shape warnings run
// here too — the person about to authorise a template for every future enrolment is exactly the person
// who should hear that its password field will be world-readable on the instance.
func describeTemplate(b protocol.Bootstrap, signer signing.Signer) string {
	var out string
	out += fmt.Sprintf("\n  Template     %s (%d bytes)\n", b.Name, len(b.Body))
	out += fmt.Sprintf("  Signing key  %s (%s)\n", signer.KeyID(), signer.Backend())
	out += fmt.Sprintf("\n  A host enrolled with --bootstrap %s will apply this once, via cloud-init,\n"+
		"  if %s is listed in its own %s.\n",
		b.Name, signer.KeyID(), signing.TrustedSignersPath)
	for _, warning := range provision.Warnings(b.Body) {
		out += fmt.Sprintf("\n  WARNING: %s\n", warning)
	}
	out += fmt.Sprintf("\n  Body, verbatim:\n%s\n  --- end of template ---\n\n", indent(b.Body))
	return out
}

// indent prefixes every line of a body for display under the summary.
//
// Unlike verifyBootstrap's %q on the agent, the body here comes from a file the operator just wrote,
// not from a network peer — so it is shown as they wrote it, where a fully escaped rendering of their
// own YAML would only obscure what they are checking.
func indent(body string) string {
	out := "    "
	for _, r := range body {
		out += string(r)
		if r == '\n' {
			out += "    "
		}
	}
	return out
}
