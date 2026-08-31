package wua

import "testing"

// TestClassifyReadsTheCategoryRatherThanItsName is the localisation trap, asserted.
//
// The security count is the number this product exists to show, and on Windows it is decided here
// rather than by an archive the package came from. The obvious implementation compares the category's
// display name to "Security Updates" and is wrong on every host that is not in English: a German
// Windows Server reports "Sicherheitsupdates", so a name-keyed classifier reports every security update
// on that fleet as ordinary. Nothing about that failure is visible — the dashboard shows a number, and
// the number is plausible.
//
// So classification is by CategoryID, which Microsoft does not localise.
func TestClassifyReadsTheCategoryRatherThanItsName(t *testing.T) {
	const securityID = "{0FA1201D-4330-4FA8-8AE9-B877473B6441}"
	const driverID = "{EBFC1FC5-71A4-4F7B-9ACA-3B9A503104A0}"

	if !classify([]string{securityID}, "") {
		t.Error("an update in the Security Updates category was not classified as security")
	}
	if !classify([]string{driverID, securityID}, "") {
		t.Error("a security category alongside another was missed")
	}
	if classify([]string{driverID}, "") {
		t.Error("an update in no security category was classified as security")
	}
	if classify(nil, "") {
		t.Error("an update with no categories and no severity was classified as security")
	}
}

// TestClassifyAcceptsASeverityWhenTheCategoryIsAbsent pins the second, weaker signal.
//
// MsrcSeverity is documented with four values and comes back empty for the cumulative updates that make
// up most of what a Server host has pending — so it cannot be the primary signal. It is taken as
// sufficient on its own anyway, because the two failure directions are not symmetric: reporting an
// update as security when it is not costs an operator a little urgency, and missing one costs them the
// number they installed this for.
func TestClassifyAcceptsASeverityWhenTheCategoryIsAbsent(t *testing.T) {
	for _, severity := range []string{"Critical", "Important", "Moderate", "Low"} {
		if !classify(nil, severity) {
			t.Errorf("an update rated %q was not classified as security", severity)
		}
	}
	// Empty is the common case and must not count, or every pending update on a Server host would be
	// reported as a security update and the split would say nothing at all.
	if classify(nil, "") {
		t.Error("an update with an empty severity was classified as security")
	}
}

// TestGUIDComparisonSurvivesBothSpellings pins a formatting assumption that is not a documented one.
//
// WUA returns a CategoryID braced and upper-case, and every machine anybody has tested on does so. That
// is a convention rather than a guarantee, and the failure if it ever changed would be silent in the
// worst direction: every update classified as non-security, on every host, with a dashboard that still
// renders a number.
func TestGUIDComparisonSurvivesBothSpellings(t *testing.T) {
	const canonical = "0FA1201D-4330-4FA8-8AE9-B877473B6441"
	for _, spelling := range []string{
		canonical,
		"{" + canonical + "}",
		"0fa1201d-4330-4fa8-8ae9-b877473b6441",
		"{0fa1201d-4330-4fa8-8ae9-b877473b6441}",
	} {
		if !equalFoldGUID(spelling, securityCategoryID) {
			t.Errorf("%q did not compare equal to the security category id", spelling)
		}
	}

	// And it must still distinguish. A comparison loose enough to accept every spelling would be one
	// loose enough to accept a different identifier.
	for _, other := range []string{
		"",
		"{EBFC1FC5-71A4-4F7B-9ACA-3B9A503104A0}",
		"0FA1201D-4330-4FA8-8AE9-B877473B6442", // one digit apart
	} {
		if equalFoldGUID(other, securityCategoryID) {
			t.Errorf("%q compared equal to the security category id", other)
		}
	}
}
