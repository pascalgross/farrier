package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the repository root, relative to this package.
const repoRoot = "../.."

// TestTheRealSiteBuilds is the check that keeps the documents' cross-references honest.
//
// It is here rather than only in the workflow so that `go test ./...` catches a link that stopped
// resolving. The documents are the specification somebody would reimplement the protocol from, and a
// reference that quietly rots is how a specification stops being one — nobody notices, because nobody
// follows every link by hand.
func TestTheRealSiteBuilds(t *testing.T) {
	out := t.TempDir()
	if err := build(repoRoot, out, "https://github.com/pascalgross/farrier", "main"); err != nil {
		t.Fatalf("the documentation site does not build: %v", err)
	}
	for _, p := range pages {
		if _, err := os.Stat(filepath.Join(out, p.Output)); err != nil {
			t.Errorf("%s was not written: %v", p.Output, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "site.css")); err != nil {
		t.Errorf("the stylesheet was not written: %v", err)
	}
}

// TestEveryPageSourceExists catches a page added to the list and never written.
//
// The page list is a literal rather than a directory walk, which is deliberate — ordering carries
// meaning here — and the cost of a literal is that it can name a file nobody created.
func TestEveryPageSourceExists(t *testing.T) {
	for _, p := range pages {
		if _, err := os.Stat(filepath.Join(repoRoot, p.Source)); err != nil {
			t.Errorf("the page list names %s, which does not exist: %v", p.Source, err)
		}
	}
}

// TestABrokenLinkFailsTheBuild asserts the failure the whole check exists for.
//
// A validator that silently passes is worse than none, because it is believed. This writes a small
// repository with a link to nothing and requires the build to refuse it.
func TestABrokenLinkFailsTheBuild(t *testing.T) {
	root := t.TempDir()
	write(t, root, "README.md", "# Farrier\n\n[gone](docs/NOPE.md)\n")

	saved := pages
	t.Cleanup(func() { pages = saved })
	pages = []page{{Source: "README.md", Output: "index.html", Title: "Farrier"}}

	err := build(root, filepath.Join(root, "public"), "https://example.invalid/r", "main")
	if err == nil {
		t.Fatal("a link to a file that does not exist was published")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("the failure does not say what is wrong: %v", err)
	}
}

// TestABrokenAnchorFailsTheBuild covers the half of link rot that still resolves to a file.
//
// A link to a section that has been renamed lands the reader at the top of a long document with no
// indication that anything is wrong, which is the more misleading of the two failures.
func TestABrokenAnchorFailsTheBuild(t *testing.T) {
	root := t.TempDir()
	write(t, root, "README.md", "# Farrier\n\n[section](guide.md#gone)\n")
	write(t, root, "guide.md", "# Guide\n\n## A section that is here\n")

	saved := pages
	t.Cleanup(func() { pages = saved })
	pages = []page{
		{Source: "README.md", Output: "index.html", Title: "Farrier"},
		{Source: "guide.md", Output: "guide.html", Title: "Guide"},
	}

	err := build(root, filepath.Join(root, "public"), "https://example.invalid/r", "main")
	if err == nil {
		t.Fatal("a link to a heading that does not exist was published")
	}
	if !strings.Contains(err.Error(), "not a heading") {
		t.Errorf("the failure does not say what is wrong: %v", err)
	}
}

// TestLinksToUnpublishedFilesPointAtTheForge covers the third outcome of link rewriting.
//
// The documents link to the licence, to packaging scripts and to Go source. Those are not pages, and a
// reader of the published site has no checkout — so the link has to become one that works for them
// rather than either breaking or being dropped.
func TestLinksToUnpublishedFilesPointAtTheForge(t *testing.T) {
	root := t.TempDir()
	write(t, root, "README.md", "# Farrier\n\n[licence](LICENSE) and [helpers](helpers)\n")
	write(t, root, "LICENSE", "Apache-2.0\n")
	if err := os.MkdirAll(filepath.Join(root, "helpers"), 0o755); err != nil {
		t.Fatalf("creating a directory: %v", err)
	}

	saved := pages
	t.Cleanup(func() { pages = saved })
	pages = []page{{Source: "README.md", Output: "index.html", Title: "Farrier"}}

	out := filepath.Join(root, "public")
	if err := build(root, out, "https://example.invalid/r", "v1"); err != nil {
		t.Fatalf("building: %v", err)
	}
	body := read(t, filepath.Join(out, "index.html"))
	if !strings.Contains(body, "https://example.invalid/r/blob/v1/LICENSE") {
		t.Error("a link to a file was not rewritten to the forge")
	}
	// A directory is a tree, not a blob. The wrong one is a 404 on GitHub.
	if !strings.Contains(body, "https://example.invalid/r/tree/v1/helpers") {
		t.Error("a link to a directory was not rewritten to a tree URL")
	}
}

// TestAlertsBecomeCallouts pins the emphasis the documents place deliberately.
//
// GitHub renders `> [!IMPORTANT]` as a coloured callout and every other renderer shows the literal
// text. The guarantee's exceptions are written in those blocks, so flattening them on the published
// site would remove exactly the emphasis somebody chose.
func TestAlertsBecomeCallouts(t *testing.T) {
	expanded := string(expandAlerts([]byte("> [!IMPORTANT]\n> Read this.\n")))
	if !strings.Contains(expanded, `class="callout callout-important"`) {
		t.Errorf("an alert was not expanded into a callout:\n%s", expanded)
	}
	if !strings.Contains(expanded, "Read this.") {
		t.Errorf("expanding an alert lost its body:\n%s", expanded)
	}

	// An ordinary quote is left alone; it is not an alert and must not acquire a label.
	plain := string(expandAlerts([]byte("> Just a quote.\n")))
	if strings.Contains(plain, "callout") {
		t.Errorf("an ordinary blockquote was turned into a callout:\n%s", plain)
	}
}

// TestExternalLinksAreLeftAlone asserts the rewriting does not touch what it does not own.
func TestExternalLinksAreLeftAlone(t *testing.T) {
	for _, dest := range []string{
		"https://example.invalid", "http://example.invalid", "mailto:a@example.invalid",
		"//example.invalid",
	} {
		if !isExternal(dest) {
			t.Errorf("%q was treated as a repository-relative link", dest)
		}
	}
	for _, dest := range []string{"SECURITY.md", "../LICENSE", "docs/INSTALL.md#one"} {
		if isExternal(dest) {
			t.Errorf("%q was treated as external", dest)
		}
	}
}

// write creates a file and the directories above it.
func write(t *testing.T, root, name, body string) {
	t.Helper()

	full := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("creating a directory for %s: %v", name, err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// read returns a file's contents, failing the test if it cannot.
func read(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(body)
}
