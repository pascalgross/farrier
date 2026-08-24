package backend

import (
	"strings"
	"testing"
)

// schemes is the set the parser is asked about, standing in for what a build has registered.
var schemes = []string{"awskms", "azurekms", "gcpkms", "pkcs11"}

// TestAReferenceIsAPathUnlessItNamesABackend covers the rule the whole parser is.
//
// Every existing invocation in the documentation and in operators' shell history passes a path, and
// every one of them has to keep working. The scheme table is consulted only for a bare word followed
// by a colon.
func TestAReferenceIsAPathUnlessItNamesABackend(t *testing.T) {
	for _, c := range []struct {
		// in is what an operator typed.
		in string

		// scheme is the backend it must select.
		scheme string

		// value is what that backend must be handed.
		value string
	}{
		{"/home/ops/.config/farrier/ops.key", FileScheme, "/home/ops/.config/farrier/ops.key"},
		{"./ops.key", FileScheme, "./ops.key"},
		{"ops.key", FileScheme, "ops.key"},
		// A colon after a separator is part of a path, not a scheme. This is every absolute path on a
		// machine where somebody has put a colon in a directory name.
		{"/home/ops/a:b/ops.key", FileScheme, "/home/ops/a:b/ops.key"},
		{"./a:b", FileScheme, "./a:b"},
		// The explicit spelling, which is the escape for the one genuine collision.
		{"file:awskms:notes", FileScheme, "awskms:notes"},
		{"pkcs11:token=ops;object=k?module-path=/m.so", "pkcs11", "token=ops;object=k?module-path=/m.so"},
		{"awskms:arn:aws:kms:eu-central-1:1:key/abc#ops", "awskms", "arn:aws:kms:eu-central-1:1:key/abc#ops"},
	} {
		got, err := ParseReference(c.in, schemes)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.Scheme != c.scheme || got.Value != c.value {
			t.Errorf("%q parsed as %s / %q, expected %s / %q", c.in, got.Scheme, got.Value, c.scheme, c.value)
		}
	}
}

// TestAnUnknownSchemeNamesTheOnesThatExist proves the refusal is useful.
//
// A reference naming a backend this build does not have must say so. Falling through to the file
// backend would report that no such file exists, which sends an operator looking at their filesystem
// for a problem that is in their build.
func TestAnUnknownSchemeNamesTheOnesThatExist(t *testing.T) {
	_, err := ParseReference("gpgagent:whatever", schemes)
	if err == nil {
		t.Fatal("an unregistered scheme was accepted")
	}
	for _, scheme := range schemes {
		if !strings.Contains(err.Error(), scheme) {
			t.Errorf("the refusal does not mention %q: %v", scheme, err)
		}
	}
	if !strings.Contains(err.Error(), "file:") {
		t.Errorf("the refusal does not say how to spell a path: %v", err)
	}
}

// TestParsingTouchesNoFilesystem is the property the rule rests on.
//
// A reference that named a backend if and only if no such file existed would mean different things on
// two machines, and this is the input that authorises rebooting a fleet. The assertion is that a
// reference which cannot possibly exist on disk still parses as a backend, and one that does exist
// still parses as a path — neither of which depends on what is there.
func TestParsingTouchesNoFilesystem(t *testing.T) {
	ref, err := ParseReference("awskms:arn:aws:kms:eu-central-1:1:key/abc#ops", schemes)
	if err != nil || ref.Scheme != "awskms" {
		t.Fatalf("a scheme that names nothing on disk did not parse as a scheme: %+v %v", ref, err)
	}

	// A real file in a real directory, whose first segment happens to look like a scheme name.
	existing := t.TempDir() + "/awskms:notes"
	ref, err = ParseReference(existing, schemes)
	if err != nil || ref.Scheme != FileScheme || ref.Value != existing {
		t.Fatalf("a path was not parsed as one: %+v %v", ref, err)
	}
}

// TestAnEmptyReferenceIsRefused keeps a missing flag from being read as a path called "".
func TestAnEmptyReferenceIsRefused(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if _, err := ParseReference(in, schemes); err == nil {
			t.Errorf("%q was accepted as a key reference", in)
		}
	}
}

// TestSplitKeyIDTakesTheLastFragment covers the identity half of a cloud reference.
//
// Cloud resource names carry colons and slashes and never a "#", so the split is unambiguous — and it
// is the last one so that a future format carrying its own would still yield the identity.
func TestSplitKeyIDTakesTheLastFragment(t *testing.T) {
	for _, c := range []struct {
		// in is the reference value.
		in string

		// rest is the resource half.
		rest string

		// keyID is the identity half.
		keyID string
	}{
		{"arn:aws:kms:eu-central-1:1:key/abc#ops-kms-1", "arn:aws:kms:eu-central-1:1:key/abc", "ops-kms-1"},
		{"projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1#ops",
			"projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "ops"},
		{"vault.vault.azure.net/keys/n/v", "vault.vault.azure.net/keys/n/v", ""},
		{"a#b#c", "a#b", "c"},
	} {
		rest, keyID := SplitKeyID(c.in)
		if rest != c.rest || keyID != c.keyID {
			t.Errorf("%q split as %q / %q, expected %q / %q", c.in, rest, keyID, c.rest, c.keyID)
		}
	}
}
