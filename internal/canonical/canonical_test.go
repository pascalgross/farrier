package canonical

import (
	"errors"
	"strings"
	"testing"
)

// TestNormalizeSortsKeysAndStripsWhitespace covers the two rules everything else depends on.
//
// If either of these were wrong, every signature and every heartbeat digest would still be internally
// consistent — and would disagree with any other implementation of docs/PROTOCOL.md §8. That is the
// kind of bug that only shows up when somebody writes a second agent.
func TestNormalizeSortsKeysAndStripsWhitespace(t *testing.T) {
	in := `{
	  "zebra": 1,
	  "alpha": { "b": 2, "a": 1 },
	  "Mixed": [3, 2, 1]
	}`
	want := `{"Mixed":[3,2,1],"alpha":{"a":1,"b":2},"zebra":1}`
	got, err := Normalize([]byte(in))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestNormalizeDoesNotEscapeHTMLCharacters covers the difference from encoding/json's default.
//
// Go escapes <, > and & as a defence against JSON embedded in HTML. That is right for a web response
// and wrong for a signed payload, because it makes the bytes depend on which encoder produced them.
func TestNormalizeDoesNotEscapeHTMLCharacters(t *testing.T) {
	got, err := Normalize([]byte(`{"unit":"a<b>c&d"}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if want := `{"unit":"a<b>c&d"}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if strings.Contains(string(got), `\u003c`) {
		t.Error("output contains Go's default HTML escaping")
	}
}

// TestNormalizeRejectsFloats covers the deliberate refusal.
//
// The protocol contains no floating-point values, so one arriving in a signed payload is a mistake. The
// failure mode of guessing at a rendering is a signature that verifies on one implementation and not
// the other, which is discovered by an operator rather than by a test.
func TestNormalizeRejectsFloats(t *testing.T) {
	for _, in := range []string{`{"x":1.5}`, `{"x":1e3}`, `{"x":1.0}`, `[0.1]`} {
		_, err := Normalize([]byte(in))
		if err == nil {
			t.Errorf("%s was accepted", in)
			continue
		}
		if !errors.Is(err, ErrFloat) {
			t.Errorf("%s produced %v, which does not wrap ErrFloat", in, err)
		}
	}
}

// TestNormalizeEscapesControlCharacters asserts the escaping rules for the characters JSON requires.
func TestNormalizeEscapesControlCharacters(t *testing.T) {
	got, err := Normalize([]byte(`{"s":"a\nb\tc\u0001d\"e\\f"}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := `{"s":"a\nb\tc\u0001d\"e\\f"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestNormalizeRejectsTrailingData asserts a payload must be exactly one JSON value.
//
// Two concatenated objects where one was expected is the shape of a smuggling attempt: an
// implementation that read the first and ignored the rest could be given a payload that verified
// against one meaning and was acted on with another.
func TestNormalizeRejectsTrailingData(t *testing.T) {
	if _, err := Normalize([]byte(`{"a":1}{"b":2}`)); err == nil {
		t.Error("trailing data was accepted")
	}
}

// TestNormalizeIsIdempotent asserts canonicalising twice changes nothing.
//
// The agent canonicalises bytes that arrived over the wire, which may already be canonical. If that
// were not a no-op, whether a signature verified would depend on how many times the payload had been
// handled.
func TestNormalizeIsIdempotent(t *testing.T) {
	once, err := Normalize([]byte(`{"b":2,"a":{"d":4,"c":[1,2]}}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	twice, err := Normalize(once)
	if err != nil {
		t.Fatalf("second Normalize: %v", err)
	}
	if string(once) != string(twice) {
		t.Errorf("not idempotent:\nonce  %s\ntwice %s", once, twice)
	}
}

// TestMarshalMatchesTheDocumentedJobPayload pins the exact bytes docs/PROTOCOL.md §8 shows.
//
// The document shows the signed payload with its keys in canonical order. If this test and the
// document ever disagree, one of them is a bug, and pinning it here is how that gets noticed.
func TestMarshalMatchesTheDocumentedJobPayload(t *testing.T) {
	payload := map[string]any{
		"jobId":     "01J9ABC",
		"hostId":    "01J9HOST",
		"intent":    "service.restart",
		"params":    map[string]any{"unit": "nginx.service"},
		"notBefore": "2026-08-22T14:00:00Z",
		"notAfter":  "2026-08-22T14:30:00Z",
		"nonce":     "b64nonce",
	}
	want := `{"hostId":"01J9HOST","intent":"service.restart","jobId":"01J9ABC","nonce":"b64nonce",` +
		`"notAfter":"2026-08-22T14:30:00Z","notBefore":"2026-08-22T14:00:00Z",` +
		`"params":{"unit":"nginx.service"}}`
	got, err := Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestDigestIsStableAcrossKeyOrder is the property heartbeat digests rely on.
//
// Digest-first heartbeats work only if an agent and a server that hold the same facts compute the same
// string. Two Go maps with the same contents iterate in different orders, so a digest taken over
// non-canonical bytes would differ between two runs of the same program.
func TestDigestIsStableAcrossKeyOrder(t *testing.T) {
	a, err := Digest(map[string]any{"x": 1, "y": 2, "z": map[string]any{"b": 1, "a": 2}})
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	b, err := Digest(map[string]any{"z": map[string]any{"a": 2, "b": 1}, "y": 2, "x": 1})
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if a != b {
		t.Errorf("digests differ for equal values: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, DigestPrefix) {
		t.Errorf("digest %q is not prefixed with the algorithm", a)
	}
}

// TestSaltedDigestDependsOnTheSalt covers the machine-id case.
//
// The salt exists so that the same machine-id hashed by two different fleets does not produce the same
// value; if it did, anybody who saw both could correlate them. A test that only checked the digest was
// non-empty would pass with the salt ignored.
func TestSaltedDigestDependsOnTheSalt(t *testing.T) {
	id := []byte("2f6e1b2a4c5d4e6f8a9b0c1d2e3f4a5b")
	one := SaltedDigest([]byte("salt-one"), id)
	two := SaltedDigest([]byte("salt-two"), id)
	if one == two {
		t.Error("the same machine-id under two salts produced the same digest")
	}
	if one != SaltedDigest([]byte("salt-one"), id) {
		t.Error("SaltedDigest is not deterministic")
	}
	if strings.Contains(one, string(id)) {
		t.Error("the digest contains the raw machine-id")
	}
}

// FuzzNormalizeIsIdempotentAndStable asserts the two properties over arbitrary input.
//
// Whatever bytes arrive, canonicalising them either fails or produces output that canonicalises to
// itself. That is the property every signature check depends on, and stating it over fuzzed input
// rather than a fixture is what makes it hold for payload shapes nobody has written yet.
func FuzzNormalizeIsIdempotentAndStable(f *testing.F) {
	for _, seed := range []string{
		`{}`, `[]`, `null`, `0`, `"x"`,
		`{"b":1,"a":2}`, `{"a":{"c":1,"b":[1,2,{"z":0,"y":1}]}}`,
		`{"s":"<>&"}`, `{"s":"\u0000"}`, `{"n":-1}`, `{"n":9007199254740993}`,
		`{"f":1.5}`, `  {"a" : 1 }  `,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		once, err := Normalize([]byte(raw))
		if err != nil {
			return
		}
		twice, err := Normalize(once)
		if err != nil {
			t.Fatalf("canonical output %q failed to re-canonicalise: %v", once, err)
		}
		if string(once) != string(twice) {
			t.Fatalf("not idempotent for %q:\nonce  %s\ntwice %s", raw, once, twice)
		}
		if DigestBytes(once) != DigestBytes(twice) {
			t.Fatalf("digest differs between canonicalisations of %q", raw)
		}
	})
}

// TestGuaranteeAReEncodedPayloadCanonicalisesIdentically is the property signing actually rests on.
//
// A job's params reach the agent as decoded values — off the wire, and through a jsonb column that has
// already normalised key order, whitespace and duplicate keys — so nothing on either side can verify a
// signature against the bytes somebody typed. What both sides do instead is canonicalise their own
// decoded view, through this package, which is the single implementation of the encoding.
//
// So the question that decides whether a signature verifies is this one: does JSON that differs only in
// the ways transport is allowed to change it canonicalise to the same bytes? It has to, or an
// unmodified job would fail to verify somewhere between the signer and the host. The cases below are
// exactly the transformations a JSON encoder, a database and a decode-then-re-encode round trip make.
func TestGuaranteeAReEncodedPayloadCanonicalisesIdentically(t *testing.T) {
	const want = `{"hostId":"01JHOST","intent":"host.reboot","params":{"delayMinutes":5,"reason":"kernel"}}`

	for _, form := range []struct {
		name string
		json string
	}{
		{"as signed", want},
		{"reordered keys", `{"params":{"reason":"kernel","delayMinutes":5},"intent":"host.reboot","hostId":"01JHOST"}`},
		{"pretty printed", "{\n  \"hostId\": \"01JHOST\",\n  \"intent\": \"host.reboot\",\n" +
			"  \"params\": {\n    \"delayMinutes\": 5,\n    \"reason\": \"kernel\"\n  }\n}\n"},
		// jsonb keeps the last of a repeated key, and so does Go's decoder. A payload that reached the
		// agent through the database therefore has one where the signer's had two, and the two must
		// still canonicalise alike.
		{"a repeated key collapsed in transit", `{"hostId":"01JHOST","intent":"service.stop","intent":"host.reboot","params":{"delayMinutes":5,"reason":"kernel"}}`},
	} {
		t.Run(form.name, func(t *testing.T) {
			got, err := Normalize([]byte(form.json))
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if string(got) != want {
				t.Errorf("canonicalised to\n  %s\nwant\n  %s\n"+
					"A signature is computed over this form on both sides, so two forms of the same "+
					"value that canonicalise differently are a valid job the host refuses.",
					got, want)
			}
		})
	}
}

// TestGuaranteeADifferentValueCanonicalisesDifferently is the other half, and the reason the first means
// anything.
//
// A canonicaliser that returned a constant would satisfy every assertion above. What signing needs is
// that a payload somebody altered does not reach the same bytes as the one that was signed — which is
// what makes the verification a refusal rather than a coincidence.
func TestGuaranteeADifferentValueCanonicalisesDifferently(t *testing.T) {
	const signed = `{"intent":"host.reboot","params":{"delayMinutes":5}}`

	for _, tampered := range []string{
		`{"intent":"host.reboot","params":{"delayMinutes":0}}`,
		`{"intent":"service.stop","params":{"delayMinutes":5}}`,
		`{"intent":"host.reboot","params":{"delayMinutes":5,"extra":1}}`,
		`{"intent":"host.reboot","params":{"delayMinutes":"5"}}`,
	} {
		original, err := Normalize([]byte(signed))
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		altered, err := Normalize([]byte(tampered))
		if err != nil {
			t.Fatalf("Normalize(%s): %v", tampered, err)
		}
		if string(original) == string(altered) {
			t.Errorf("%s canonicalises to the same bytes as the signed payload", tampered)
		}
	}
}
