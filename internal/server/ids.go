package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// idAlphabet is Crockford's base32, without I, L, O and U.
//
// Host identifiers end up in log lines, in support tickets and read aloud over the phone during an
// incident. Excluding the characters that are misread as one another is a small kindness that costs
// nothing and is impossible to retrofit once identifiers are in the wild.
const idAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// idEncoding encodes identifiers in Crockford base32 with no padding.
var idEncoding = base32.NewEncoding(idAlphabet).WithPadding(base32.NoPadding)

// NewID returns a lexically sortable, random identifier.
//
// The first six bytes are a millisecond timestamp, so identifiers sort by creation time — which means
// an index on the primary key is also an index on age, and a page of hosts or jobs comes back in a
// sensible order without a second column. The remaining ten bytes are random, which is far more than
// enough that two control planes generating identifiers independently will never collide.
func NewID() (string, error) {
	var raw [16]byte

	// Six bytes of millisecond timestamp, written most significant byte first so that byte-wise
	// ordering is time ordering. Six bytes carries milliseconds until the year 10889, and taking the
	// low six bytes of a positive int64 needs no conversion that could overflow.
	ms := time.Now().UnixMilli()
	for i := range 6 {
		// Masked explicitly. Taking the low byte is the intent, and writing it out means neither a
		// reader nor a linter has to decide whether an unmasked conversion was meant to be a
		// truncation or was an oversight that happens to work.
		raw[5-i] = byte((ms >> (8 * i)) & 0xff)
	}
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", fmt.Errorf("server: generating an identifier: %w", err)
	}
	return idEncoding.EncodeToString(raw[:]), nil
}

// NewEnrollmentToken returns a bootstrap token and the hash to store.
//
// Only the hash is ever persisted, so a database dump does not let its holder enrol hosts. The token is
// shown to the operator once, at creation, and is not recoverable afterwards — which is worth saying in
// the UI, because the alternative is somebody storing it somewhere convenient in case they need it
// again.
func NewEnrollmentToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("server: generating an enrolment token: %w", err)
	}
	token = "frr_" + strings.ToLower(idEncoding.EncodeToString(raw))
	return token, HashToken(token), nil
}

// HashToken returns the stored form of a bootstrap token.
//
// SHA-256 with no salt and no stretching is correct here and would not be for a password: the token is
// 256 bits of uniform randomness, so there is no dictionary to attack and a work factor would only slow
// down the enrolment path.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}
