package pkcs11

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Scheme is the reference prefix that selects this backend.
const Scheme = "pkcs11"

// uri is a parsed RFC 7512 PKCS#11 URI, reduced to the attributes this backend acts on.
//
// RFC 7512 is used rather than a syntax of Farrier's own because it is what every other tool that
// talks to a token already speaks — OpenSSL, GnuTLS and p11-kit all take one — so an operator who has
// configured a token once can paste what they already have. It is also the only vendor-neutral way to
// name a key, which is the property docs/EXTENDING.md promises about this backend: no vendor is
// hard-coded, and a YubiKey, a Nitrokey and SoftHSM are named the same way.
type uri struct {
	// modulePath is the shared library to load. Required.
	modulePath string

	// token is the token label to search for, empty to accept the only token present.
	token string

	// slotID names a slot directly, for the tokens whose label is unhelpful. Negative when unset.
	slotID int64

	// object is the CKA_LABEL of the key, and doubles as the identity in trusted-signers.
	object string

	// id is the CKA_ID of the key, decoded from the URI's percent-encoding.
	//
	// Preferred over the label for portability: a PIV token exposes slot 9c as CKA_ID 0x02 with a
	// vendor-worded label, so matching on the label is fragile across vendors in exactly the way this
	// backend exists not to be.
	id []byte

	// pinSource is a file to read the PIN from, for scripting.
	pinSource string
}

// parseURI reads an RFC 7512 PKCS#11 URI, with the scheme already stripped.
//
// Two attributes the RFC defines are refused rather than honoured, and both refusals are the point.
// `pin-value` puts a PIN in a command line, where every user on the machine can read it from the
// process list — the same reason `farrier key generate` never took a passphrase as a flag.
// `module-name` asks for a library to be found by name in a system module registry, which this build
// does not consult; naming the path is what makes "which library did this load" answerable from the
// reference itself.
func parseURI(ref string) (uri, error) {
	out := uri{slotID: -1}

	path, query, _ := strings.Cut(ref, "?")
	for _, attr := range splitNonEmpty(path, ";") {
		name, raw, ok := strings.Cut(attr, "=")
		if !ok {
			return uri{}, fmt.Errorf("pkcs11: %q is not a name=value attribute", attr)
		}
		value, err := unescape(raw)
		if err != nil {
			return uri{}, fmt.Errorf("pkcs11: the %s attribute is not valid percent-encoding: %w", name, err)
		}
		switch name {
		case "token":
			out.token = value
		case "object":
			out.object = value
		case "id":
			out.id = []byte(value)
		case "slot-id":
			n, convErr := strconv.ParseInt(value, 10, 64)
			if convErr != nil || n < 0 {
				return uri{}, fmt.Errorf("pkcs11: slot-id must be a non-negative number, not %q", value)
			}
			out.slotID = n
		case "model", "manufacturer", "serial", "type", "object-type", "library-manufacturer",
			"library-description", "library-version", "slot-manufacturer", "slot-description":
			// Accepted and ignored: they are legitimate RFC 7512 attributes that narrow a search this
			// backend narrows by token and label instead. Refusing a URI that carries one would make a
			// reference that works in every other tool fail here, which is the opposite of the reason
			// for using the standard syntax at all.
		default:
			return uri{}, fmt.Errorf("pkcs11: %q is not a PKCS#11 URI path attribute", name)
		}
	}

	for _, attr := range splitNonEmpty(query, "&") {
		name, raw, ok := strings.Cut(attr, "=")
		if !ok {
			return uri{}, fmt.Errorf("pkcs11: %q is not a name=value attribute", attr)
		}
		value, err := unescape(raw)
		if err != nil {
			return uri{}, fmt.Errorf("pkcs11: the %s attribute is not valid percent-encoding: %w", name, err)
		}
		switch name {
		case "module-path":
			out.modulePath = value
		case "pin-source":
			out.pinSource = value
		case "pin-value":
			return uri{}, fmt.Errorf("pkcs11: pin-value is refused. A PIN on a command line is readable " +
				"from the process list by every user on the machine; use pin-source=/path/to/file, or " +
				"let the tool prompt")
		case "module-name":
			return uri{}, fmt.Errorf("pkcs11: module-name needs a module registry this build does not " +
				"consult; give module-path=/path/to/module.so instead")
		default:
			return uri{}, fmt.Errorf("pkcs11: %q is not a PKCS#11 URI query attribute", name)
		}
	}

	if out.modulePath == "" {
		return uri{}, fmt.Errorf("pkcs11: the reference needs module-path=/path/to/module.so — " +
			"for example pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so")
	}
	if out.object == "" && len(out.id) == 0 {
		return uri{}, fmt.Errorf("pkcs11: the reference needs object=<label> or id=<hex> to say which " +
			"key to sign with; a token holding one key is not a safe assumption to build into a tool " +
			"that authorises reboots")
	}
	return out, nil
}

// keyID is the identity this key is recorded under in trusted-signers and in the audit log.
//
// The object label, because that is the name a person gave the key when they generated it on the
// token, and the audit log's job is to answer "which key authorised this" in words somebody
// recognises. A key found by CKA_ID alone falls back to the hex id — unhelpful, and better than an
// empty field, and the message on the way in tells the operator to label the key.
func (u uri) keyID() string {
	if u.object != "" {
		return u.object
	}
	return Scheme + ":" + hex.EncodeToString(u.id)
}

// splitNonEmpty splits on a separator and drops empty fields.
//
// A URI with a trailing separator, or two in a row, is something a person typed rather than an error
// worth refusing — and an empty field would otherwise reach the name=value check and fail with a
// message about an attribute that is not there.
func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, part := range strings.Split(s, sep) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// unescape decodes RFC 7512's percent-encoding.
//
// Written out rather than borrowed from net/url, which decodes "+" as a space in query components —
// correct for HTML form encoding and wrong for a PKCS#11 URI, where a "+" is a "+". A CKA_ID is
// arbitrary bytes and is normally written percent-encoded, so this is the one place in the signing
// path where decoding is right rather than an ambiguity.
func unescape(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("%q ends inside an escape", s)
		}
		decoded, err := hex.DecodeString(s[i+1 : i+3])
		if err != nil {
			return "", fmt.Errorf("%q is not a hexadecimal escape", s[i:i+3])
		}
		out.WriteByte(decoded[0])
		i += 2
	}
	return out.String(), nil
}
