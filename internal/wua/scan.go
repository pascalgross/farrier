package wua

// securityCategoryID is the CategoryID Windows Update gives the Security Updates classification.
//
// It is matched on rather than the category's display name because the name is localised: a German
// host reports "Sicherheitsupdates", and a classifier keyed on the English string would report every
// security update on that host as an ordinary one. That is the fourth of this platform's
// silent-wrong-answer traps, and the one most likely to survive review, because it is invisible on
// every machine the author is likely to test on.
const securityCategoryID = "0FA1201D-4330-4FA8-8AE9-B877473B6441"

// classify decides whether an update is a security update, and is the weakest claim Farrier makes.
//
// On Linux the equivalent is exact: apt states the origin of every candidate, the platform knows its
// family's security origins, and the answer is a property of the archive the package comes from.
// Windows has no equivalent, and this is an approximation of one built from two imperfect signals:
//
//   - The Security Updates category, matched by its stable CategoryID rather than its localised name.
//     This is the reliable half.
//   - A non-empty MSRC severity, which means the update carries a security rating at all.
//
// Either is taken as security, because the failure directions are not symmetric. Reporting an update
// as security when it is not costs an operator a little urgency; missing one costs them the number this
// product exists to show. What neither signal can do is subdivide: a Windows cumulative update is one
// indivisible package, so "security" here describes the whole of it, including the non-security changes
// it carries. docs/SECURITY.md §12.5 is why packages.applySecurity is refused on Windows rather than
// built on top of this.
func classify(categoryIDs []string, severity string) bool {
	for _, id := range categoryIDs {
		if equalFoldGUID(id, securityCategoryID) {
			return true
		}
	}
	return severity != ""
}

// equalFoldGUID compares two GUIDs written with or without braces and in either case.
//
// WUA returns a CategoryID as a braced, upper-case string, but that is a formatting convention rather
// than a documented guarantee, and a comparison that assumed it would fail silently — reporting every
// update as non-security — if it ever changed.
func equalFoldGUID(a, b string) bool {
	return normaliseGUID(a) == normaliseGUID(b)
}

// normaliseGUID strips braces and folds case, so that two spellings of one identifier compare equal.
func normaliseGUID(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '{' || c == '}':
			continue
		case c >= 'a' && c <= 'z':
			out = append(out, c-('a'-'A'))
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
