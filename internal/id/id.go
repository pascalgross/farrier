// Package id generates the identifiers Farrier puts in front of people.
//
// It is its own package because two things generate them — the control plane, for hosts and for
// unsigned jobs, and `farrier sign`, for a job it is about to sign offline — and an identifier that had
// two shapes would be an identifier nothing could validate. internal/protocol states the shape a job id
// may take; this produces one that satisfies it.
package id

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"
)

// alphabet is Crockford's base32, without I, L, O and U.
//
// Identifiers end up in log lines, in support tickets and read aloud over the phone during an incident.
// Excluding the characters that are misread as one another is a small kindness that costs nothing and
// is impossible to retrofit once identifiers are in the wild.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Encoding encodes identifiers in Crockford base32 with no padding.
//
// Exported because enrolment tokens are encoded the same way and should stay readable by the same eyes,
// even though a token is a secret rather than an identifier.
var Encoding = base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)

// New returns a lexically sortable, random identifier.
//
// The first six bytes are a millisecond timestamp, so identifiers sort by creation time — which means
// an index on the primary key is also an index on age, and a page of hosts or jobs comes back in a
// sensible order without a second column. The remaining ten bytes are random, which is far more than
// enough that two control planes generating identifiers independently will never collide — and, since
// `farrier sign` also generates them on an operator's laptop, that a fleet's identifiers do not need a
// central allocator to stay unique.
func New() (string, error) {
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
		return "", fmt.Errorf("id: generating an identifier: %w", err)
	}
	return Encoding.EncodeToString(raw[:]), nil
}
