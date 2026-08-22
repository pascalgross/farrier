package canonical

import (
	"crypto/sha256"
	"encoding/hex"
)

// DigestPrefix names the hash algorithm digests in this package use.
//
// It is a constant rather than a literal because it appears on the wire, in the database and in log
// lines, and a future change of algorithm should be one edit followed by a compile error at every
// place that assumed the old one.
const DigestPrefix = "sha256:"

// DigestBytes returns the prefixed SHA-256 digest of bytes that are already canonical.
//
// It exists alongside Digest so that a caller which has just canonicalised something does not
// canonicalise it a second time. The heartbeat path does exactly that on every beat, for every host.
func DigestBytes(canonicalJSON []byte) string {
	sum := sha256.Sum256(canonicalJSON)
	return DigestPrefix + hex.EncodeToString(sum[:])
}

// SaltedDigest returns the prefixed SHA-256 digest of a salt followed by a value.
//
// It exists for /etc/machine-id, which systemd documents as confidential and which must therefore
// never be transmitted raw. The salt is generated per host at package installation and never leaves
// the machine: without it, the same machine-id hashed by two different fleets would produce the same
// value, and anybody who saw both could correlate them.
func SaltedDigest(salt, value []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write(value)
	return DigestPrefix + hex.EncodeToString(h.Sum(nil))
}
