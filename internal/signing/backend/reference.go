package backend

import (
	"fmt"
	"strings"
)

// FileScheme is the explicit spelling of a filesystem path.
//
// It exists so that a path which would otherwise be read as a scheme has a way to say it is a path,
// and so that the rule below has no case where an operator is stuck.
const FileScheme = "file"

// Reference is a key reference split into the backend that owns it and the part that backend reads.
//
// It is a type rather than two return values because it travels from the command line into a registry
// lookup and then into a backend, and a pair of bare strings passed positionally is a bug waiting for
// somebody to swap them.
type Reference struct {
	// Scheme names the backend, without its colon.
	Scheme string

	// Value is everything after the colon, verbatim.
	Value string
}

// ParseReference splits a --key reference into a backend and the remainder.
//
// The rule is: **a reference names a backend if and only if it begins with a registered scheme
// followed by a colon.** Everything else is a filesystem path, which is what every existing
// invocation types and what the file backend takes.
//
// Three things about that rule are deliberate.
//
// It never touches the filesystem. Deciding by probing what happens to exist would make one string
// mean different things on two machines, and this is the input that authorises rebooting a fleet: it
// has to be decidable by reading it. The cost is one collision — a *relative* path whose first
// segment begins with a registered scheme name and a colon, such as a file literally called
// "awskms:notes" — and the escape is "./awskms:notes" or "file:awskms:notes".
//
// An unregistered scheme is refused rather than treated as a path. A reference that looks like
// "pkcs11:token=ops" in a build with no PKCS#11 backend must say so; falling through would report
// that no such file exists, which sends the operator looking in the wrong place entirely.
//
// Nothing is percent-decoded and net/url is not used. net/url would accept "awskms:arn%3Aaws%3A…" and
// normalise it, and two spellings of one key reference is precisely the ambiguity that makes a
// trusted-signers audit unreliable six months later.
func ParseReference(reference string, schemes []string) (Reference, error) {
	if strings.TrimSpace(reference) == "" {
		return Reference{}, fmt.Errorf("signing: a key reference is required")
	}

	scheme, rest, found := strings.Cut(reference, ":")
	if !found {
		return Reference{Scheme: FileScheme, Value: reference}, nil
	}
	// A path is anything whose colon comes after a separator: "/home/x/a:b", "./ops.key", and every
	// absolute path there is. Checked before the scheme table so that a path can never be shadowed by
	// a scheme somebody registers later.
	if strings.ContainsAny(scheme, "/\\") {
		return Reference{Scheme: FileScheme, Value: reference}, nil
	}
	if scheme == FileScheme {
		return Reference{Scheme: FileScheme, Value: rest}, nil
	}

	for _, known := range schemes {
		if scheme == known {
			return Reference{Scheme: scheme, Value: rest}, nil
		}
	}

	// Only now, and only to make the message useful: a bare word with a colon in it that names no
	// backend is almost always a typo for one that exists, and listing them is the fastest fix. A
	// reference that was meant to be a path in the working directory gets told how to say so.
	return Reference{}, fmt.Errorf(
		"signing: %q names no signing backend. The backends this build has are %s, "+
			"and anything else is read as a path — write %s to be explicit about a path whose first "+
			"segment looks like a scheme",
		scheme, strings.Join(schemes, ", "), FileScheme+":"+reference)
}

// SplitKeyID separates a trailing "#key-id" fragment from a reference value.
//
// The fragment exists because a cloud key's resource name is not an identity anybody wants to read.
// KeyID is what a host's trusted-signers file lists and what the audit log records, and an ARN is
// neither: it is long, it names an account rather than a person, and it is not stable across a fleet
// that rotates keys. So the operator chooses the identity, in the same string as the key it belongs
// to — which is issue #11's "learn a backend from the key reference" applied to the identity as well.
//
// Neither an ARN, a Cloud KMS resource name nor an Azure vault path can contain a "#", so cutting on
// the last one is unambiguous. It cuts on the last rather than the first so that a future reference
// format containing one is still split at the identity.
func SplitKeyID(value string) (rest, keyID string) {
	i := strings.LastIndex(value, "#")
	if i < 0 {
		return value, ""
	}
	return value[:i], value[i+1:]
}
