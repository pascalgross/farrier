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
// row.
//
// It is worth being precise about what the prefix does *not* do, because the obvious claim is wrong.
// auth.APITokens hashes whatever bearer token it is given and looks the digest up; it does not read
// the prefix, so a wallboard key presented to an administrative route is tried like any other string
// and refused because no row matches — not because of the four characters in front. The prefix is for
// the person and the scanner reading the string, and the refusal is the lookup's.
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
// second place for the two to disagree.
//
// The tenant segment is different, and is checked, because it does not reach a hash — it reaches
// `Store.In`, and from there a `set_config` in a database transaction. An unauthenticated caller who
// could put arbitrary bytes there could make the control plane answer 500 and write an ERROR line for
// a request that is simply wrong, which is a refusal wearing the clothes of an outage; and this route
// answers callers nobody has authenticated. So the segment must look like an identifier this control
// plane could have issued before it is allowed to become one — a shape check rather than a lookup,
// because whether that fleet exists is the row-level security policy's answer and not this function's.
func splitWallboardKey(key string) (store.TenantID, bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(key), wallboardKeyPrefix)
	if !found {
		return "", false
	}
	tenant, secret, found := strings.Cut(rest, ".")
	if !found || secret == "" || !safeAsTenantID(tenant) {
		return "", false
	}
	return store.TenantID(tenant), true
}

// maxTenantIDLength bounds the fleet segment of a presented key.
//
// internal/id emits twenty-six characters and the schema puts no ceiling on the column, so this is
// generous by an order of magnitude rather than a shape rule: what it is for is that a caller nobody
// has authenticated does not choose the length of a string this process is about to copy.
const maxTenantIDLength = 256

// safeAsTenantID reports whether a fleet segment may be handed to Store.In.
//
// Bounded, non-empty, and printable ASCII. It is deliberately *not* a check that the string looks like
// an identifier this control plane issued, and not a check that the fleet exists — the second is the
// row-level security policy's answer and the first would be a second, weaker copy of it that a future
// change to internal/id would silently invalidate.
//
// What it defends against is narrower and real. The segment does not reach a hash function; it reaches
// `Store.In`, and from there `set_config('farrier.tenant', …)` inside a transaction. A byte PostgreSQL
// will not accept in a parameter turns a request that is simply wrong into a 500 and an ERROR line —
// a refusal wearing the clothes of an outage, on the one route in this server that answers callers
// nobody has authenticated, and therefore a line anybody on the internet could write into an
// operator's journal at whatever rate the limiter allows.
func safeAsTenantID(s string) bool {
	if s == "" || len(s) > maxTenantIDLength {
		return false
	}
	for _, r := range s {
		if r < ' ' || r > '~' {
			return false
		}
	}
	return true
}
