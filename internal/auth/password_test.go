package auth

import (
	"errors"
	"strings"
	"testing"
)

// TestAPasswordVerifiesAgainstItsOwnHashAndNothingElse is the round trip, and the two ways it must fail.
//
// It is the whole contract of the pair: the right password verifies, a wrong one does not, and a
// password that is right for a different account does not either. The last case is the one a bug in the
// salt handling would break — every hash carries its own salt, so two accounts choosing the same
// password must produce different stored values.
func TestAPasswordVerifiesAgainstItsOwnHashAndNothingElse(t *testing.T) {
	const password = "correct horse battery staple"

	first, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hashing again: %v", err)
	}

	if first == second {
		t.Fatal("two hashes of the same password are identical; the salt is not being used")
	}
	if !VerifyPassword(first, password) {
		t.Error("a password does not verify against its own hash")
	}
	if !VerifyPassword(second, password) {
		t.Error("the second hash of the same password does not verify")
	}
	if VerifyPassword(first, password+"!") {
		t.Error("a wrong password verified")
	}
	if VerifyPassword(first, "") {
		t.Error("an empty password verified")
	}
}

// TestAHashCarriesTheParametersItWasMadeWith pins the encoding.
//
// The format is what makes the cost raisable: a hash written under today's parameters has to keep
// verifying after they are raised, which is only possible if the parameters travel with the digest. A
// change that dropped them would pass the round-trip test above and lock every existing operator out
// on the day somebody edited a constant.
func TestAHashCarriesTheParametersItWasMadeWith(t *testing.T) {
	hash, err := HashPassword("a password long enough")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	for _, want := range []string{"$argon2id$", "$v=19$", "m=65536", "t=3", "p=4"} {
		if !strings.Contains(hash, want) {
			t.Errorf("the stored hash %q does not carry %q", hash, want)
		}
	}
	if got := strings.Count(hash, "$"); got != 5 {
		t.Errorf("the stored hash has %d fields; the PHC format has five separators", got)
	}
}

// TestAnUnreadableHashIsARefusalRatherThanAnError is the sign-in path's failure mode.
//
// Every one of these is a row nobody can sign in as, and the caller must not be able to tell which kind
// of nobody: a malformed hash, a truncated one and a wrong password all answer false. The last two
// cases are the ones that matter for more than tidiness — a parameter read out of the database reaches
// an allocation, so a row asking for sixteen gigabytes has to be refused before it is honoured.
func TestAnUnreadableHashIsARefusalRatherThanAnError(t *testing.T) {
	cases := []struct {
		// name says what is wrong with the stored value.
		name string

		// stored is the hash as it would come out of the database.
		stored string
	}{
		{"empty", ""},
		{"not a PHC string", "hunter2"},
		{"another algorithm", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ"},
		{"a version this build does not implement", "$argon2id$v=16$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ"},
		{"a missing parameter", "$argon2id$v=19$m=65536,t=3$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ"},
		{"a memory cost above the ceiling", "$argon2id$v=19$m=16777216,t=3,p=4$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ"},
		{"a lane count of zero", "$argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ"},
		{"a salt that is not base64", "$argon2id$v=19$m=65536,t=3,p=4$!!!!$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ"},
		{"a truncated digest", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2E$YQ"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if VerifyPassword(c.stored, "any password at all") {
				t.Fatal("an unreadable stored hash verified a password")
			}
			if NeedsRehash(c.stored) {
				t.Error("an unreadable stored hash was reported as merely out of date")
			}
		})
	}
}

// TestAShortPasswordIsRefusedWhenItIsChosenAndNotWhenItIsPresented is the asymmetry in the two paths.
//
// Telling somebody choosing a password that it is too short is help. Telling somebody signing in the
// same thing is a length oracle over a credential, so verification has no such branch: a short password
// simply does not match, like any other wrong one.
func TestAShortPasswordIsRefusedWhenItIsChosenAndNotWhenItIsPresented(t *testing.T) {
	if _, err := HashPassword("short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("hashing a five-character password returned %v", err)
	}
	if _, err := HashPassword(strings.Repeat("x", MaxPasswordLength+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("hashing an over-long password returned %v", err)
	}

	hash, err := HashPassword(strings.Repeat("x", MinPasswordLength))
	if err != nil {
		t.Fatalf("hashing a password of exactly the minimum length: %v", err)
	}
	if VerifyPassword(hash, "short") {
		t.Error("a short password verified against a longer one's hash")
	}
	if VerifyPassword(hash, strings.Repeat("x", MaxPasswordLength+1)) {
		t.Error("an over-long password verified")
	}
}

// TestARaisedCostIsNoticedAtTheOneMomentItCanBeApplied pins NeedsRehash.
//
// It exists so that raising the parameters is something an installation grows into. The sign-in path is
// the only place the password is known, so a hash written under weaker parameters has to be recognised
// there or never at all — and a hash written under today's must not be, or every sign-in would rewrite
// a row for no reason.
func TestARaisedCostIsNoticedAtTheOneMomentItCanBeApplied(t *testing.T) {
	current, err := HashPassword("a password long enough")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	if NeedsRehash(current) {
		t.Error("a hash written by this build was reported as out of date")
	}

	// A well-formed hash at a lower cost, of the kind an older build would have written.
	weaker := "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$" +
		strings.Repeat("a", 43)
	if !NeedsRehash(weaker) {
		t.Error("a hash written at a lower cost was not reported as out of date")
	}
}
