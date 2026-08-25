package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/id"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/prompt"
	"github.com/pascalgross/farrier/internal/protocol"
	"github.com/pascalgross/farrier/internal/signing"
	"github.com/pascalgross/farrier/internal/signing/backend"
)

// DefaultSignedValidity is how long a signed job stays valid when the operator does not say.
//
// An hour, because the window is the blast radius of a signature. A job signed this morning and
// delivered to a host that was offline until Friday is the failure the window exists to prevent, and
// the honest default is "long enough to reach a fleet that is mostly up, short enough that forgetting
// about it is not dangerous". An operator who needs longer says so and sees the value in the summary.
const DefaultSignedValidity = time.Hour

// DefaultSigningTimeout bounds one call into a signing backend.
//
// It exists for the backends that reach a network: a cloud key store having a bad afternoon must not
// leave this command hanging with no way out. Thirty seconds is far longer than a signature takes and
// short enough to be a failure rather than a hang.
//
// It is not a flag. Issue #11's point about this command is that it stops growing one per backend, and
// nobody has yet needed a different number. It deliberately does not cover the confirmation prompt —
// see where it is applied.
const DefaultSigningTimeout = 30 * time.Second

// openWithTimeout resolves a key reference under its own deadline.
//
// Separate from the signing deadline because the two bound different things: opening a token or
// fetching a cloud key's public half happens before the operator is shown anything, and a backend that
// cannot be reached should say so promptly rather than after the same wait twice.
func openWithTimeout(ctx context.Context, reference string) (signing.Signer, error) {
	openCtx, done := context.WithTimeout(ctx, DefaultSigningTimeout)
	defer done()
	return openSigningKey(openCtx, reference)
}

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
	keyPath := fs.String("key", "",
		"the signing key: a path from `farrier key generate`, or a backend reference such as\n"+
			"pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so")
	host := fs.String("host", "", "the host id this job is for; a signature is bound to exactly one")
	name := fs.String("intent", "", "the catalogue member, for example service.restart")
	params := fs.String("params", "{}", "the parameter object as JSON")
	validFor := fs.Duration("valid-for", DefaultSignedValidity,
		"how long the signature stays valid, from now or from --not-before")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	signer, err := openWithTimeout(ctx, *keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "farrier: %v\n", err)
		return 1
	}
	defer func() { _ = signer.Close() }()

	fmt.Fprint(os.Stderr, describeJob(job, spec, decoded, *host, signer, payload))
	if !*assumeYes {
		ok, err := prompt.Confirm("Sign this? [y/N] ")
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
	// key store waits for a network, and an operator who changes their mind at that moment should be
	// able to press Ctrl-C.
	//
	// The deadline starts here rather than around the whole command, and that ordering is the point:
	// the confirmation above is a person reading a payload, and a timeout that covered it would refuse
	// to sign for anyone who thought about it for half a minute.
	signCtx, done := context.WithTimeout(ctx, DefaultSigningTimeout)
	defer done()
	signature, err := signer.Sign(signCtx, payload)
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

	// One reading of the clock for all three instants below. Two calls to time.Now would put the
	// issue time and the window on different sides of a second boundary often enough to matter, and a
	// signature is the wrong place for a value that depends on how long the line above it took.
	now := time.Now().UTC()

	// The window opens a little before now by default, for the same reason the control plane backdates
	// the one it signs itself: the host checks it against its own clock, and a machine a second behind
	// would otherwise find a job whose window had not opened and report it expired. The tolerance is
	// the skew a host would still act on at all; beyond it the agent refuses on the clock, which is the
	// refusal that names the real problem.
	//
	// The backdating moves the opening edge only, which is why the expiry is measured from a separate
	// instant. Deriving it from the backdated start instead would silently turn --valid-for=1h into
	// fifty-five minutes, and the symptom — a job signed for an hour and refused as expired before the
	// hour was up — reads as a clock problem on the host rather than as arithmetic here.
	start, expireFrom := now.Add(-protocol.MaxClockSkewSeconds*time.Second), now
	if notBefore != "" {
		parsed, parseErr := time.Parse(time.RFC3339, notBefore)
		if parseErr != nil {
			return protocol.Job{}, intent.Spec{}, nil, fmt.Errorf("--not-before is not RFC3339: %w", parseErr)
		}
		// An operator who names the start has said what the duration runs from: there is no useful
		// "from now" for a window that opens next Tuesday, and no skew tolerance to add to an edge they
		// chose deliberately.
		start, expireFrom = parsed.UTC(), parsed.UTC()
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
		IssuedAt:  now.Truncate(time.Second),
		NotBefore: start.Truncate(time.Second),
		NotAfter:  expireFrom.Add(validFor).Truncate(time.Second),
		Nonce:     nonce,
	}, spec, decoded, nil
}

// openSigningKey resolves a key reference to a signer, whichever backend holds it.
//
// This command learns nothing about any backend: a reference names one, the registry in
// internal/signing/backend resolves it, and a path with no scheme is a file exactly as it always was.
// That is docs/EXTENDING.md's governing rule for this seam — extension means adding an implementation,
// never editing a switch — and it is why adding PKCS#11 and the three key stores changed one line
// here.
//
// The prompt is passed in rather than reached for, so the rule that matters travels with it: a
// passphrase or a PIN is never a command-line argument, where every user on the machine can read it
// from the process list.
func openSigningKey(ctx context.Context, reference string) (signing.Signer, error) {
	return backend.Open(ctx, reference, readPassphrase)
}

// referencer is a signer whose key is somewhere worth naming on the confirmation screen.
//
// A file's path is on the command line the operator just typed; a cloud key's resource name is not,
// and it is the thing this backend's caveat is entirely about — a key in the same account as the
// control plane is a key the control plane can use. So the confirmation shows it, and an operator
// about to reboot a fleet can see which account is about to authorise it.
type referencer interface {
	// Reference renders the key's location, for display.
	Reference() string
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
	if named, ok := signer.(referencer); ok {
		fmt.Fprintf(&b, "  Held in    %s\n", named.Reference())
	}
	fmt.Fprintf(&b, "\n  This host will act on it only if %s is listed in its own %s.\n",
		signer.KeyID(), signing.TrustedSignersPath)
	fmt.Fprintf(&b, "\n  Signed payload, verbatim:\n    %s\n\n", payload)
	return b.String()
}
