package kms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// SigV4 in full, which is smaller than its reputation.
//
// That reputation belongs almost entirely to S3: object-key URI encoding, UNSIGNED-PAYLOAD, chunked
// signing, query-string presigning, SigV4a. None of it applies here. This makes one POST to a fixed
// host with the path "/", no query string, a JSON body already in memory and five signed headers, and
// the parts everybody gets wrong are the parts that are absent.

// sigV4Algorithm is the signature scheme's name, as it appears in the credential scope.
const sigV4Algorithm = "AWS4-HMAC-SHA256"

// awsCredential is one set of AWS credentials.
type awsCredential struct {
	// accessKeyID and secretAccessKey are the long-lived or session pair.
	accessKeyID     string
	secretAccessKey string

	// sessionToken is present for temporary credentials, and must then be signed as a header — KMS
	// refuses a request whose x-amz-security-token is outside SignedHeaders.
	sessionToken string
}

// signV4 signs a request in place, for one service in one region.
//
// The body is passed as bytes rather than read back off the request, because the signature covers a
// hash of it: a caller that serialised the document twice would sign one and send the other, and the
// failure — a signature mismatch from AWS — reads as a credential problem rather than as the bug it is.
func signV4(req *http.Request, body []byte, cred awsCredential, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	if cred.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", cred.sessionToken)
	}

	signedHeaders, canonicalHeaders := canonicalHeaderSet(req)
	payloadHash := hex.EncodeToString(sha256Sum(body))

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req),
		canonicalQuery(req),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		scope,
		hex.EncodeToString(sha256Sum([]byte(canonicalRequest))),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(deriveSigningKey(cred.secretAccessKey, dateStamp,
		region, service), []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, cred.accessKeyID, scope, signedHeaders, signature))
}

// canonicalHeaderSet renders the signed headers and their canonical form.
//
// Lower-cased names, sorted, values trimmed, one per line with a trailing newline — and the same list
// again, semicolon-separated, as SignedHeaders. Host is included explicitly because Go keeps it on the
// request rather than in the header map, and a Host outside the signed set is a request AWS refuses.
func canonicalHeaderSet(req *http.Request) (signedHeaders, canonicalHeaders string) {
	names := make([]string, 0, len(req.Header)+1)
	values := map[string]string{}
	for name, list := range req.Header {
		lower := strings.ToLower(name)
		names = append(names, lower)
		values[lower] = strings.TrimSpace(strings.Join(list, ","))
	}
	if _, ok := values["host"]; !ok {
		names = append(names, "host")
		values["host"] = req.URL.Host
	}
	sort.Strings(names)

	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteString(":")
		canonical.WriteString(values[name])
		canonical.WriteString("\n")
	}
	return strings.Join(names, ";"), canonical.String()
}

// canonicalURI renders the request's path as SigV4 wants it.
//
// KMS is always the literal "/", so this is one line in production. It is written out rather than
// hard-coded because a hard-coded "/" cannot be checked against AWS's own published worked example,
// which signs a path and a query string — and a signing implementation nothing checks against the
// specification's arithmetic is one that agrees only with itself.
func canonicalURI(req *http.Request) string {
	if path := req.URL.EscapedPath(); path != "" {
		return path
	}
	return "/"
}

// canonicalQuery renders the query string as SigV4 wants it: sorted, and encoded per RFC 3986.
//
// Empty for every request this package makes. Present for the same reason canonicalURI is.
func canonicalQuery(req *http.Request) string {
	values := req.URL.Query()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var pairs []string
	for _, key := range keys {
		list := append([]string(nil), values[key]...)
		sort.Strings(list)
		for _, value := range list {
			pairs = append(pairs, rfc3986Escape(key)+"="+rfc3986Escape(value))
		}
	}
	return strings.Join(pairs, "&")
}

// rfc3986Escape percent-encodes everything outside RFC 3986's unreserved set.
//
// url.QueryEscape is not this: it encodes a space as "+" and leaves "~" alone, and SigV4 wants "%20"
// and "%7E". The two disagree on exactly the characters that appear in real parameter values.
func rfc3986Escape(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(unreserved, s[i]) >= 0 {
			out.WriteByte(s[i])
			continue
		}
		fmt.Fprintf(&out, "%%%02X", s[i])
	}
	return out.String()
}

// deriveSigningKey runs SigV4's four-step HMAC chain.
//
// The chain is what scopes a signature to one day, one region and one service, so a signature captured
// from a KMS call cannot be replayed against another service or on another day.
func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	key := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	key = hmacSHA256(key, []byte(region))
	key = hmacSHA256(key, []byte(service))
	return hmacSHA256(key, []byte("aws4_request"))
}

// hmacSHA256 is one link of the chain.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// sha256Sum returns a SHA-256 digest as a slice.
func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
