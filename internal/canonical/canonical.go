// Package canonical encodes values the one way both sides of the Farrier protocol agree on.
//
// It exists because two different things depend on byte-identical encoding and would otherwise depend
// on two implementations agreeing by luck. Signatures are computed over the canonical form of a job
// payload, so an agent that encoded a field differently from the operator's signing tool would reject
// every valid signature. Heartbeat digests are computed the same way, so a server and an agent that
// disagreed would exchange full inventory reports forever while both believed they were saving
// bandwidth.
//
// The rules are stated in docs/PROTOCOL.md §8 and implemented here exactly once:
//
//   - object keys sorted ascending by Unicode code point;
//   - no insignificant whitespace and no trailing newline;
//   - UTF-8 with shortest-form escaping, and <, > and & left alone — Go's default HTML escaping is a
//     browser-safety measure that has no place in a signed payload and would make the output depend on
//     which encoder produced it;
//   - integers rendered without a decimal point or an exponent, and floating-point values rejected
//     outright rather than rendered by some rule the other implementation might not share.
//
// Rejecting floats is the unusual choice and the deliberate one. The protocol contains no
// floating-point values, so the only way one arrives in a signed payload is a mistake — and the failure
// mode of guessing at a rendering is a signature that verifies on one implementation and not the other,
// discovered by an operator at three in the morning.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// ErrFloat reports that a value contained a floating-point number.
//
// It is a distinct error because it is the one canonicalisation failure that indicates a design
// mistake rather than bad input: somebody added a float field to a signed structure, and the fix is to
// change the field rather than to handle the error.
var ErrFloat = errors.New("canonical: floating-point values are not permitted")

// Marshal encodes a value in canonical form.
//
// It works by encoding with the standard library and then re-encoding the result, rather than by
// walking the original value with reflection. That is slower and entirely worth it: it means struct
// tags, omitempty, custom MarshalJSON implementations and every other encoding decision behave exactly
// as they do everywhere else in the codebase, and the canonical form is a normalisation of the ordinary
// JSON rather than a second, subtly different serialiser.
func Marshal(v any) ([]byte, error) {
	first, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	return Normalize(first)
}

// Normalize rewrites already-encoded JSON into canonical form.
//
// It is exported separately from Marshal because the agent receives job payloads as bytes and must
// canonicalise exactly what arrived, not a re-encoding of its own decoded view. Those are usually the
// same and the difference is exactly where a signature-verification bug would live.
func Normalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	if dec.More() {
		return nil, errors.New("canonical: trailing data after the JSON value")
	}

	var out bytes.Buffer
	if err := write(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// write emits one decoded JSON value in canonical form.
func write(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		return writeNumber(buf, t)
	case string:
		return writeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// sort.Strings compares byte-wise, which for valid UTF-8 is the same order as comparing by
		// Unicode code point. That equivalence is why docs/PROTOCOL.md can state the rule in terms of
		// code points and this can be one call.
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := write(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported value of type %T", v)
	}
	return nil
}

// writeNumber emits a number, rejecting anything that is not an integer.
func writeNumber(buf *bytes.Buffer, n json.Number) error {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return fmt.Errorf("%w: %s", ErrFloat, s)
	}
	if _, err := n.Int64(); err != nil {
		return fmt.Errorf("canonical: %s is not representable as an integer: %w", s, err)
	}
	buf.WriteString(s)
	return nil
}

// writeString emits a JSON string with shortest-form escaping and no HTML escaping.
//
// Only the escapes JSON requires are emitted: the two structural characters, the five short forms, and
// \u00XX for the remaining control characters. Everything else, including <, > and &, is written
// literally. Go's encoding/json escapes those three by default as a defence against JSON embedded in
// HTML, which is a sensible default for a web response and wrong for a signed payload, because it
// makes the bytes depend on which encoder produced them.
func writeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canonical: string is not valid UTF-8")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return nil
}

// Digest returns the SHA-256 digest of a value's canonical form, prefixed with its algorithm.
//
// The "sha256:" prefix is carried on the wire so that a future change of hash is a value both sides can
// see rather than a silent reinterpretation of the same field. Heartbeat digests are compared for
// equality only, which means a mismatched algorithm must read as "different", and it does.
func Digest(v any) (string, error) {
	raw, err := Marshal(v)
	if err != nil {
		return "", err
	}
	return DigestBytes(raw), nil
}
