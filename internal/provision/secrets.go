package provision

import (
	"fmt"
	"regexp"
)

// consequence is the half of every warning that makes it actionable.
//
// docs/SECURITY.md §7 and issue #17 are both explicit that "possible secret detected" is not a warning
// anybody can act on. What an operator needs to weigh is where the bytes end up, so every warning below
// says exactly that, once, in the same words.
const consequence = "user-data is plaintext in the cloud metadata service and in " +
	"/var/lib/cloud/instance/user-data.txt, readable by anything with instance or metadata access"

// secretShape is one pattern worth warning about.
//
// The list below is deliberately short and high-signal, because false positives are the failure mode
// that matters here: cloud-init user-data legitimately carries an ssh_authorized_keys block and a
// chpasswd stanza for a break-glass account, and a detector that cried wolf on those would teach
// operators to ignore the one warning that was real. `-----BEGIN … PRIVATE KEY-----` is unambiguous; a
// 32-character hex string is not, and is therefore absent.
type secretShape struct {
	// pattern matches the shape in a body.
	pattern *regexp.Regexp

	// what names the finding in the operator's own vocabulary.
	what string
}

// shapes is the closed list of secret shapes the detector knows.
var shapes = []secretShape{
	{
		// Any PEM private-key block: RSA, EC, OPENSSH, PKCS#8 and encrypted variants all match, and
		// nothing else on earth writes this header for another reason.
		pattern: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		what:    "a private-key block",
	},
	{
		// A password-shaped YAML key with an inline value. The value being on the same line is what
		// separates "a password is written here" from cloud-init's chpasswd/users structure being
		// present at all, which is legitimate and common. hashed_passwd is deliberately included: a
		// crypt hash is still a credential worth keeping out of world-readable metadata.
		//
		// The horizontal-space classes are the whole of "on the same line", and they are spelled out
		// rather than written \s because \s matches a newline: with it, the trailing \s*\S skipped
		// blank lines to find the next non-space character anywhere further down the document, so an
		// empty `passwd:` key in a users block warned about an inline value that was not there. That
		// is precisely the false positive this shape is written to avoid, and it survived because the
		// one test case covering it happened to end the string.
		pattern: regexp.MustCompile(`(?m)^[ \t]*(passwd|password|hashed_passwd)[ \t]*:[ \t]*\S`),
		what:    "a password field with an inline value",
	},
	{
		// AWS access key ids carry a fixed, checkable prefix. The id alone is only half a credential,
		// and where there is an id the secret key is usually three lines away.
		pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		what:    "an AWS access key id",
	},
	{
		// GitHub's post-2021 token formats, all of which embed their type after a fixed prefix.
		pattern: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`),
		what:    "a GitHub token",
	},
	{
		// Slack tokens: bot, user, app and workspace variants share the xox prefix.
		pattern: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
		what:    "a Slack token",
	},
}

// Warnings reports the secret shapes in a body, with the consequence spelled out.
//
// It warns and never blocks, and the reasoning is worth keeping in front of whoever is tempted to
// change that: legitimate user-data carries things that look like secrets, so a refusal would be wrong
// often enough that operators would route around it — and a control that is routinely bypassed teaches
// people to ignore the next one too. The warning's job is to make the trade visible, not to make the
// choice.
//
// It runs on save and on render both, because a template that was clean can be made dirty by the
// parameters substituted into it.
func Warnings(body string) []string {
	var out []string
	for _, shape := range shapes {
		if shape.pattern.MatchString(body) {
			out = append(out, fmt.Sprintf("this contains %s, and %s", shape.what, consequence))
		}
	}
	return out
}
