// Package backend is the registry of signing-key backends and the parser for the references that
// select them.
//
// It exists one directory below internal/signing on purpose. The agent and the control plane import
// internal/signing for the verifier, and the verifier is the half that must stay small: it sees a
// public key and a signature over a canonical payload and cannot learn — or care — which backend
// produced either. Keeping the registry down here means that neither of them links a backend at all,
// which is what turns "adding a backend cannot widen the agent's attack surface" from a claim about
// discipline into a property of the import graph. TestGuaranteeNoManagedHostBinaryLoadsASigningBackend
// asserts it.
//
// The shape is database/sql's: a backend registers itself from init, `farrier` blank-imports the ones
// it ships, and the command that opens a key learns nothing about any of them. docs/EXTENDING.md's
// governing rule is that extension means adding an implementation and never editing a switch, and this
// is that rule for the one seam it applies to.
package backend

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/pascalgross/farrier/internal/signing"
)

// PassphraseFunc supplies the secret that unlocks a key, when a backend needs one.
//
// It is a parameter rather than a call into a terminal package because this package is imported by
// tests and could one day be imported by something with no terminal at all, and because the one rule
// that matters here — a passphrase or a PIN is never taken from the command line, where every user on
// the machine can read it from the process list — belongs to the caller that owns the terminal.
type PassphraseFunc func(prompt string) ([]byte, error)

// Backend is one registered way of holding a signing key.
type Backend struct {
	// Scheme is the reference prefix that selects this backend, without its colon.
	Scheme string

	// Open returns a Signer for a reference with its scheme already stripped.
	Open func(ctx context.Context, ref string, prompt PassphraseFunc) (signing.Signer, error)

	// Inspect returns the trusted-signers entry for a key without unlocking or signing.
	//
	// It exists so `farrier key show` can print the line for a key the operator cannot currently
	// unlock — which is the situation somebody is in while setting up a host with the token at the
	// office. The file backend needs no secret for it and ignores the prompt; a token generally does,
	// because a good few modules will not read even a public object without a login, and a key show
	// that worked on one token and returned nothing on another would be worse than one that asks.
	Inspect func(ctx context.Context, ref string, prompt PassphraseFunc) (signing.PublicKey, error)
}

// registry holds the registered backends by scheme.
var registry = struct {
	// mu guards byScheme. Registration happens in init and reading happens from one command, but a
	// lock is cheaper than reasoning about whether that will always be true.
	mu sync.RWMutex

	// byScheme is the registered set.
	byScheme map[string]Backend
}{byScheme: map[string]Backend{}}

// Register adds a backend, panicking on a duplicate or an empty scheme.
//
// A panic rather than an error because this runs in init: two backends claiming one scheme means one
// of them silently never opens a key, and a signing tool that quietly used the wrong backend is worse
// than a binary that refuses to start.
func Register(b Backend) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if b.Scheme == "" || b.Open == nil {
		panic("backend: a backend needs a scheme and an Open function")
	}
	if _, exists := registry.byScheme[b.Scheme]; exists {
		panic("backend: two backends are registered as " + b.Scheme)
	}
	registry.byScheme[b.Scheme] = b
}

// Schemes returns the registered scheme names, sorted.
//
// It exists so that an unknown scheme can be refused with a message naming the ones that exist, which
// is the difference between an operator fixing a typo and an operator reading source code.
func Schemes() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	out := make([]string, 0, len(registry.byScheme))
	for scheme := range registry.byScheme {
		out = append(out, scheme)
	}
	sort.Strings(out)
	return out
}

// Open resolves a key reference and returns a signer for it.
func Open(ctx context.Context, reference string, prompt PassphraseFunc) (signing.Signer, error) {
	b, rest, err := resolve(reference)
	if err != nil {
		return nil, err
	}
	return b.Open(ctx, rest, prompt)
}

// Inspect resolves a key reference and returns its trusted-signers entry.
func Inspect(ctx context.Context, reference string, prompt PassphraseFunc) (signing.PublicKey, error) {
	b, rest, err := resolve(reference)
	if err != nil {
		return signing.PublicKey{}, err
	}
	if b.Inspect == nil {
		return signing.PublicKey{}, fmt.Errorf(
			"signing: the %s backend cannot show a public key without opening the key first", b.Scheme)
	}
	return b.Inspect(ctx, rest, prompt)
}

// resolve picks the backend a reference names and returns the remainder for it.
func resolve(reference string) (Backend, string, error) {
	ref, err := ParseReference(reference, Schemes())
	if err != nil {
		return Backend{}, "", err
	}

	registry.mu.RLock()
	b, ok := registry.byScheme[ref.Scheme]
	registry.mu.RUnlock()
	if !ok {
		// Unreachable while ParseReference is given the same set, and handled anyway: the two could
		// be given different sets by a future caller, and silently opening the wrong backend is not a
		// failure mode this package should be able to have.
		return Backend{}, "", fmt.Errorf("signing: no backend is registered for %q; the registered ones are %s",
			ref.Scheme, strings.Join(Schemes(), ", "))
	}
	return b, ref.Value, nil
}
