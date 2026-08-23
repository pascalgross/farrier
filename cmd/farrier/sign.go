package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/id"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/signing"
	"github.com/pascalgross/farrier/internal/signing/backend/file"
)

// DefaultSignedValidity is how long a signed job stays valid when the operator does not say.
//
// An hour, because the window is the blast radius of a signature. A job signed this morning and
// delivered to a host that was offline until Friday is the failure the window exists to prevent, and
// the honest default is "long enough to reach a fleet that is mostly up, short enough that forgetting
// about it is not dangerous". An operator who needs longer says so and sees the value in the summary.
const DefaultSignedValidity = time.Hour

// signCommand implements `farrier sign`.
//
// This is the command the whole destructive tier is built around, and the reason it exists at all is
// what it refuses to do: it never contacts the control plane. Everything it shows an operator is
// derived locally, from the same canonical payload it is about to sign, and the signature covers
// exactly what was displayed.
//
// The alternative — a server that hands the tool a digest to sign — is the design this one exists to
// avoid. A compromised control plane could then render "restart nginx on web-01" in a browser while
// handing over the digest of "reboot every host", and no amount of care by the operator would catch
// it. That is why the signed payload is fixed by docs/PROTOCOL.md §8 as a structure rather than as an
// opaque blob: so that this program can reconstruct it, decode it against its own compiled-in
// catalogue, and print what it means.
func signCommand(argv []string) int {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to the signing key created by `farrier key generate`")
	host := fs.String("host", "", "the host id this job is for; a signature is bound to exactly one")
	name := fs.String("intent", "", "the catalogue member, for example service.restart")
	params := fs.String("params", "{}", "the parameter object as JSON")
	validFor := fs.Duration("valid-for", DefaultSignedValidity,
		"how long the signature stays valid, from now")
	notBefore := fs.String("not-before", "",
		"RFC3339 instant the job becomes valid; defaults to now, less a tolerance for clock skew")
	jobID := fs.String("id", "", "the job id; one is generated when omitted")
	assumeYes := fs.Bool("yes", false, "do not ask for confirmation; for scripting a known-good job")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *keyPath == "" || *host == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "farrier: --key, --host and --intent are all required")
		return 2
	}

	job, spec, decoded, err := buildSignableJob(*jobID, *host, *name, *params, *notBefore, *validFor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 2
	}

	// Canonicalised before anything is displayed, so that what is printed below and what is signed
	// further down are the same bytes rather than two renderings of the same intention.
	payload, err := canonical.Marshal(job.SignedPayload(*host))
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: could not canonicalise the payload: %v\n", err)
		return 1
	}

	signer, err := openSigningKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}
	defer func() { _ = signer.Close() }()

	fmt.Fprint(os.Stderr, describeJob(job, spec, decoded, *host, signer, payload))
	if !*assumeYes {
		ok, err := confirm("Sign this? [y/N] ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
			return 1
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "farrier: not signed.")
			return 3
		}
	}

	// The context is honoured because hardware backends block: a touch-required token waits for a
	// finger, and an operator who changes their mind at that moment should be able to press Ctrl-C.
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: signing failed: %v\n", err)
		return 1
	}

	request := map[string]any{
		"id":              job.ID,
		"hostId":          *host,
		"intent":          job.Intent,
		"params":          job.Params,
		"notBefore":       job.NotBefore.UTC().Format(time.RFC3339),
		"notAfter":        job.NotAfter.UTC().Format(time.RFC3339),
		"nonce":           job.Nonce,
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
	fmt.Fprintf(os.Stderr, "\nSigned. Send it with:\n"+
		"  curl -X POST \"$FARRIER_URL/api/v1/jobs\" \\\n"+
		"    -H \"Authorization: Bearer $FARRIER_ADMIN_TOKEN\" \\\n"+
		"    -H 'Content-Type: application/json' -d @-\n")
	return 0
}

// buildSignableJob assembles the job to be signed and decodes its parameters against the catalogue.
//
// Decoding here rather than only on the host is what lets this program describe the operation. It also
// means an operator who mistypes a unit name is told so before they enter a passphrase, rather than
// finding out when a host refuses the job.
func buildSignableJob(jobID, host, name, rawParams, notBefore string, validFor time.Duration) (
	protocol.Job, intent.Spec, intent.Params, error) {

	spec, decoded, err := intent.Decode(intent.Name(name), []byte(rawParams))
	if err != nil {
		return protocol.Job{}, intent.Spec{}, nil, err
	}
	if !spec.Class.RequiresOfflineSignature() {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf(
			"%s is a %s intent and is not signed offline. A read intent is authorised by mTLS alone "+
				"and a routine one by the control plane's own key; only the destructive tier needs a "+
				"key the control plane does not hold. See docs/SECURITY.md §3",
			spec.Name, spec.Class)
	}

	if jobID == "" {
		generated, genErr := id.New()
		if genErr != nil {
			return protocol.Job{}, intent.Spec{}, nil, genErr
		}
		jobID = generated
	}
	if !protocol.ValidJobID(jobID) {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf(
			"the job id must be %s: it is a path segment in the result endpoint and a filename in the "+
				"agent's spool", protocol.JobIDShape)
	}

	nonce, err := id.New()
	if err != nil {
		return protocol.Job{}, intent.Spec{}, nil, err
	}

	// The window opens a little before now by default, for the same reason the control plane backdates
	// the one it signs itself: the host checks it against its own clock, and a machine a second behind
	// would otherwise find a job whose window had not opened and report it expired. The tolerance is
	// the skew a host would still act on at all; beyond it the agent refuses on the clock, which is the
	// refusal that names the real problem.
	start := time.Now().UTC().Add(-protocol.MaxClockSkewSeconds * time.Second)
	if notBefore != "" {
		parsed, parseErr := time.Parse(time.RFC3339, notBefore)
		if parseErr != nil {
			return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf("--not-before is not RFC3339: %w", parseErr)
		}
		start = parsed.UTC()
	}
	if validFor <= 0 {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf("--valid-for must be positive")
	}

	// Truncated to the second because that is the resolution the canonical payload carries: a signature
	// made over a time the payload cannot represent would verify against a different value than the one
	// signed here, and the failure would look like a broken key.
	var reencoded map[string]any
	if err := json.Unmarshal([]byte(rawParams), &reencoded); err != nil {
		return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf("--params is not a JSON object: %w", err)
	}
	if reencoded == nil {
		reencoded = map[string]any{}
	}

	return protocol.Job{
		ID:        jobID,
		Intent:    spec.Name.String(),
		Params:    reencoded,
		Class:     string(spec.Class),
		IssuedAt:  time.Now().UTC().Truncate(time.Second),
		NotBefore: start.Truncate(time.Second),
		NotAfter:  start.Add(validFor).Truncate(time.Second),
		Nonce:     nonce,
	}, spec, decoded, nil
}

// openSigningKey opens a file-backed key, prompting for its passphrase.
//
// Only the file backend for now. docs/EXTENDING.md describes the PKCS#11 and KMS backends this seam
// exists for, and when one arrives it is selected here rather than by this command learning about it.
func openSigningKey(path string) (signing.Signer, error) {
	passphrase, err := readPassphrase("Passphrase for " + path + ": ")
	if err != nil {
		return nil, err
	}
	signer, err := file.Open(path, passphrase)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// describeJob renders what is about to be signed.
//
// Everything here is derived locally: the operation's description comes from decoding the parameters
// against this binary's own catalogue, and the payload at the end is the exact byte string the
// signature will cover. An operator who compares the two is checking the thing that matters, which is
// why both are shown rather than a summary alone.
//
// It returns the text rather than writing it, so that a test can assert what an operator is shown
// against what is signed. A function that printed would have to be tested by capturing a stream, and
// the property worth pinning here is the content.
func describeJob(job protocol.Job, spec intent.Spec, decoded intent.Params,
	host string, signer signing.Signer, payload []byte) string {

	var b strings.Builder
	fmt.Fprintf(&b, "\n  Operation   %s\n", decoded.Describe())
	fmt.Fprintf(&b, "  Class       %s — %s\n", spec.Class, spec.Summary)
	fmt.Fprintf(&b, "  Host        %s\n", host)
	fmt.Fprintf(&b, "  Job id      %s\n", job.ID)
	fmt.Fprintf(&b, "  Valid       %s to %s (%s)\n",
		job.NotBefore.Format(time.RFC3339), job.NotAfter.Format(time.RFC3339),
		job.NotAfter.Sub(job.NotBefore).Round(time.Second))
	fmt.Fprintf(&b, "  Signing key %s (%s)\n", signer.KeyID(), signer.Backend())
	fmt.Fprintf(&b, "\n  This host will act on it only if %s is listed in its own %s.\n",
		signer.KeyID(), signing.TrustedSignersPath)
	fmt.Fprintf(&b, "\n  Signed payload, verbatim:\n    %s\n\n", payload)
	return b.String()
}

// confirm asks a yes-or-no question on the terminal.
//
// Anything other than an explicit yes is a no, including an empty line and a closed input. A signature
// authorises a machine to be rebooted; defaulting to yes on a stray newline would be the wrong way for
// this to be wrong.
func confirm(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)

	// The shared reader, not a fresh one. A buffered reader created here would read past its own line
	// and take whatever followed with it — and the line before this one is a passphrase.
	answer, err := readPromptLine()
	if err != nil {
		return false, fmt.Errorf("reading the answer: %w", err)
	}
	// End of input is a no rather than an error: piping /dev/null at this command should decline
	// rather than authorise.
	return strings.EqualFold(strings.TrimSpace(answer), "y") ||
		strings.EqualFold(strings.TrimSpace(answer), "yes"), nil
}
