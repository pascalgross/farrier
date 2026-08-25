package main

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/pascalgross/farrier/internal/signing/backend"
)

// implementedHeading introduces the table docs/EXTENDING.md keeps the backend list in.
const implementedHeading = "Implemented today:"

// unwrittenPrefix introduces the sentence naming the backends that are specified but do not exist.
const unwrittenPrefix = "Specified and not yet written:"

// TestTheBackendsThisBuildLinksAreTheOnesTheDocumentationLists keeps one list honest instead of three.
//
// Issue #39: signing.Signer's doc comment called pkcs11 and kms "not yet written" for two releases
// after they shipped, while docs/EXTENDING.md — the document that comment pointed at — was already
// right. Stale-while-its-target-is-current is the worse failure, because nothing looks inconsistent
// from either vantage point alone, and the reader who stops at the interface is the likelier of the
// two. The comment no longer enumerates, so one list remains and this asserts it.
//
// It asserts the schemes rather than the backend names, because a scheme is what an operator types
// after --key and what the registry keys on, so it is the column where being wrong costs somebody an
// afternoon. Three of them belong to one backend, which is why the document's table carries both.
//
// It lives in this package because this is the only one that links every backend that ships: the
// registry knows nothing until an init has run, and the agent and the control plane must keep it that
// way. This is not a guarantee test — the backend list is not a security boundary, unlike the intent
// catalogue the workflow in .github/workflows/guarantee.yml greps the documentation for — so it runs in
// `make test`, where it fails on the machine of whoever added the backend rather than in CI.
func TestTheBackendsThisBuildLinksAreTheOnesTheDocumentationLists(t *testing.T) {
	lines := extendingDocument(t)

	documented := documentedSchemes(t, lines)
	linked := backend.Schemes()

	if strings.Join(documented, ", ") != strings.Join(linked, ", ") {
		t.Errorf("farrier links %s and docs/EXTENDING.md lists %s under %q.\n"+
			"The document is the one place the set is stated; a build that shipped a backend it does "+
			"not name would leave an operator reaching for a key file for want of knowing better.",
			strings.Join(linked, ", "), strings.Join(documented, ", "), implementedHeading)
	}

	unwritten := unwrittenParagraph(t, lines)
	for _, scheme := range linked {
		if strings.Contains(unwritten, "`"+scheme+"`") {
			t.Errorf("docs/EXTENDING.md calls %s unwritten, and farrier links it: %q", scheme, unwritten)
		}
	}
}

// extendingDocument reads docs/EXTENDING.md into lines.
//
// The path is derived from this file's own location rather than from the working directory, so that the
// test behaves the same however `go test` is invoked.
func extendingDocument(t *testing.T) []string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine the path of this test file")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to the filesystem root without finding go.mod")
		}
		dir = parent
	}

	content, err := os.ReadFile(filepath.Join(dir, "docs", "EXTENDING.md"))
	if err != nil {
		t.Fatalf("reading docs/EXTENDING.md: %v", err)
	}
	return strings.Split(string(content), "\n")
}

// documentedSchemes returns the reference schemes the document's table lists, sorted.
//
// A scheme is a backticked cell ending in a colon, which is how the table spells the thing an operator
// types; "or any path" in the same cell is prose and carries no colon, so it falls out on its own.
//
// It fails rather than returning nothing when the heading or the table has moved, because a check that
// silently found an empty set would pass for exactly as long as it was useless.
func documentedSchemes(t *testing.T, lines []string) []string {
	t.Helper()

	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == implementedHeading {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("docs/EXTENDING.md no longer contains the line %q; move this test with the table",
			implementedHeading)
	}

	const schemeColumn = 1

	var schemes []string
	for _, line := range lines[start+1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) <= schemeColumn {
			t.Fatalf("a row of the table under %q has fewer than %d columns: %q",
				implementedHeading, schemeColumn+1, line)
		}
		for _, token := range strings.Split(cells[schemeColumn], ",") {
			token = strings.TrimSpace(token)
			if !strings.HasPrefix(token, "`") || !strings.HasSuffix(token, ":`") {
				// The header row, the separator, and prose such as "or any path".
				continue
			}
			schemes = append(schemes, strings.TrimSuffix(strings.Trim(token, "`"), ":"))
		}
	}
	if len(schemes) == 0 {
		t.Fatalf("no table rows follow %q in docs/EXTENDING.md", implementedHeading)
	}

	sort.Strings(schemes)
	return schemes
}

// unwrittenParagraph returns the document's paragraph naming the backends that are specified and absent.
//
// The whole paragraph rather than the line the sentence starts on, because prose here is wrapped at a
// hundred columns and a name that landed on the second line would otherwise be a hole in the check that
// nothing would ever reveal.
func unwrittenParagraph(t *testing.T, lines []string) string {
	t.Helper()

	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), unwrittenPrefix) {
			continue
		}
		var paragraph []string
		for _, rest := range lines[i:] {
			if strings.TrimSpace(rest) == "" {
				break
			}
			paragraph = append(paragraph, strings.TrimSpace(rest))
		}
		return strings.Join(paragraph, " ")
	}
	t.Fatalf("docs/EXTENDING.md no longer contains a line beginning %q; move this test with it",
		unwrittenPrefix)
	return ""
}
