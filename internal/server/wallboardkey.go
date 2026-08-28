package server

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/pascalgross/farrier/internal/id"
	"github.com/pascalgross/farrier/internal/store"
)

// wallboardKeyPrefix marks a wallboard key in a log, a paste or a secret scanner's ruleset.
//
// Deliberately not the `frr_` that enrolment tokens and API tokens share. Two credentials under one
// prefix means a scanner that finds one cannot say what was leaked, and the two want opposite
// responses: an enrolment token is revoked by consuming or expiring it, a wallboard key by deleting a
// row. It also means a key pasted into an Authorization header on an administrative route is never
// *tried* as an API token, because the prefix does not match the one that provider looks for.
const wallboardKeyPrefix = "frb_"

// wallboardSecretBytes is how much randomness the secret half of a key carries.
//
// Thirty-two, like a session token, an enrolment token and an API token, because it is the same kind of
// thing: a credential this process generates and compares by hash. It is the number that makes storing
// an unsalted, unstretched SHA-256 correct — there is no dictionary to attack a value drawn uniformly
// from 2^256 — so it is stated here rather than left to the generator.
const wallboardSecretBytes = 32

// NewWallboardKey returns the key a screen presents and the digest the control plane stores.
//
// The tenant travels inside the key, and that is the load-bearing decision in this file rather than a
// convenience. It means the lookup happens inside a transaction that has already set `farrier.tenant`,
// so the wallboard_shares table needs no `farrier.resolve_key` exemption — the narrow, read-only escape
// four tables already take to be found before the tenant is known. A fifth one on a table reached by an
// unauthenticated request would be the widest of them, so the design avoids needing it at all.
//
// It is safe to put there because the digest covers the whole key. Editing the tenant segment to name
// another fleet produces a string that hashes to a value no row holds, so the edit is refused by the
// lookup before the tenant predicate and the row-level security policy are even reached. Those two
// remain, as the second and third things refusing it.
//
// The tenant's id rather than its slug, and that is the other half. A slug is "a short stable handle
// for URLs, logs and support tickets" and frequently names the customer; the whole discipline of what
// this feature publishes is that it never says whose fleet is on the screen.
func NewWallboardKey(tenant store.TenantID) (key, hash string, err error) {
	raw := make([]byte, wallboardSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("server: generating a wallboard key: %w", err)
	}
	key = wallboardKeyPrefix + string(tenant) + "." + strings.ToLower(id.Encoding.EncodeToString(raw))
	return key, HashToken(key), nil
}

// splitWallboardKey reads the fleet out of a presented key, and reports whether it is shaped like one.
//
// It validates nothing about the secret beyond its presence: the secret is checked by hashing it and
// looking for the row, which is the only check that means anything, and a shape rule here would be a
// second place for the two to disagree. What it does do is refuse a key with no tenant segment before a
// database round trip, because `Store.In("")` is a handle to no fleet and asking it anything is a
// question with a misleading answer.
func splitWallboardKey(key string) (store.TenantID, bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(key), wallboardKeyPrefix)
	if !found {
		return "", false
	}
	tenant, secret, found := strings.Cut(rest, ".")
	if !found || tenant == "" || secret == "" {
		return "", false
	}
	return store.TenantID(tenant), true
}
