// Package provision renders stored cloud-init templates into the user-data an operator pastes into
// Terraform, Proxmox, MAAS or a cloud provider's field, and warns about secret-shaped content on the
// way.
//
// It is Tier 1 of docs/SECURITY.md §7, and the property that makes it safe to have at all is what it
// refuses to be: rendering here is substituting values into a document, and nothing more. There is no
// conditional, no loop, no include, no expression language, and above all no way for a template to
// cause anything to execute — a renderer that gained a `{{ exec }}` or a conditional that shells out
// would defeat the guarantee without touching the intent catalogue at all, because it would be the exec
// channel wearing a hat. cloud-init interprets the result, on the machine, at first boot; Farrier only
// ever hands the text over.
//
// Rendered output is a credential in its own right — it usually carries a live enrolment token — and
// the handlers in internal/server treat it as one: shown once over an authenticated, non-cacheable
// response, and never written to a log line or an audit entry.
package provision

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MaxBodyBytes bounds a template body.
//
// Well above any real cloud-init document — EC2 caps user-data at 16 KiB and most templates are under
// one — and low enough that the templates table cannot become somebody's blob store. It is enforced at
// the API boundary, where the operator who hit it can be told, rather than deep in the store.
const MaxBodyBytes = 64 << 10

// placeholderPattern matches one substitution site, such as {{hostname}} or {{ enrollmentToken }}.
//
// The name charset is deliberately narrow: a parameter is an identifier, not an expression, and the
// pattern refusing anything with spaces, dots-into-calls or operators inside the braces is the
// mechanical half of "this never grows into a template language".
var placeholderPattern = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}`)

// TokenPlaceholder is the one parameter name the render endpoint fills in itself.
//
// A template that says {{enrollmentToken}} gets a token minted for that render, because the token is
// the half of the output that makes it a credential and minting it at render time is what keeps it
// single-use and expiring. It is a reserved name rather than a convention so that a caller-supplied
// parameter cannot quietly stand in for it.
const TokenPlaceholder = "enrollmentToken"

// Placeholders returns the distinct parameter names a body substitutes, sorted.
//
// It exists so the API can tell a client what a template needs before anybody renders it, and so the
// render handler can decide whether to mint an enrolment token without a second parse.
func Placeholders(body string) []string {
	seen := map[string]bool{}
	for _, match := range placeholderPattern.FindAllStringSubmatch(body, -1) {
		seen[match[1]] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Render substitutes parameters into a template body and returns the user-data.
//
// It is strict in both directions, and the strictness is operator protection rather than pedantry. A
// placeholder with no parameter would render literal braces into a document cloud-init then applies —
// a hostname of "{{hostname}}" on a real machine — and a parameter matching no placeholder is a typo
// that would otherwise be discovered on the booted instance. Both are errors naming the name.
func Render(body string, params map[string]string) (string, error) {
	var missing []string
	used := map[string]bool{}

	rendered := placeholderPattern.ReplaceAllStringFunc(body, func(site string) string {
		name := placeholderPattern.FindStringSubmatch(site)[1]
		value, ok := params[name]
		if !ok {
			missing = append(missing, name)
			return site
		}
		used[name] = true
		return value
	})

	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("provision: the template needs a value for %s",
			strings.Join(dedupe(missing), ", "))
	}

	var unused []string
	for name := range params {
		if !used[name] {
			unused = append(unused, name)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		return "", fmt.Errorf("provision: the template has no placeholder named %s — "+
			"a parameter nothing substitutes is usually a typo for one that exists",
			strings.Join(unused, ", "))
	}
	return rendered, nil
}

// dedupe removes adjacent duplicates from a sorted slice.
//
// A placeholder used five times is one missing parameter, not five, and an error message that repeats
// itself reads as five different problems.
func dedupe(sorted []string) []string {
	out := sorted[:0]
	for i, s := range sorted {
		if i == 0 || sorted[i-1] != s {
			out = append(out, s)
		}
	}
	return out
}
