package wua

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGuaranteeOnlyTabledMethodsCanBeCalled is what this package's AST exemption is bought with.
//
// internal/intent's execChokepoints permits comcall_windows.go to dispatch through a function pointer,
// on the stated grounds that the compile-time property it gives up is replaced by a stronger run-time
// one. This is that run-time property, asserted rather than described: a member outside the table is
// refused before anything is dereferenced, and so is a call whose argument count does not match — which
// matters more than it looks, because the count is what decides how many VARIANTs COM reads out of the
// DISPPARAMS array, and a call declaring one argument while passing none would have Invoke read a
// VARIANT from memory this package never wrote.
//
// It runs on Linux, which is the point of permit() being in the portable half of the package. Every job
// in .github/workflows runs on ubuntu-latest; an assertion living beside the syscall would be a comment.
func TestGuaranteeOnlyTabledMethodsCanBeCalled(t *testing.T) {
	refused := []Method{
		"",
		"IUpdateSession.CreateUpdateInstaller",
		"IUpdateSession.CreateUpdateDownloader",
		"IUpdate.AcceptEula",
		"IUpdate.CopyFromCache",
		"IUpdateInstaller.Install",
		"IUpdateDownloader.Download",
		"IUpdateServiceManager.AddScanPackageService",
		"IUpdateSearcher.search",  // case is not a way past
		"IUpdateSearcher.Search ", // nor is whitespace
		"Search",                  // nor is dropping the interface
	}
	for _, m := range refused {
		if _, err := permit(m, 0); !errors.Is(err, ErrNotPermitted) {
			t.Errorf("permit(%q) returned %v; every member outside the table must be refused", m, err)
		}
	}

	// And a permitted member is still refused when the call does not match its shape.
	if _, err := permit(SearcherSearch, 0); err == nil {
		t.Error("IUpdateSearcher.Search was permitted with no arguments; it takes one")
	}
	if _, err := permit(SearcherSearch, 2); err == nil {
		t.Error("IUpdateSearcher.Search was permitted with two arguments; it takes one")
	}
	if _, err := permit(CollectionCount, 1); err == nil {
		t.Error("IUpdateCollection.Count was permitted with an argument; it takes none")
	}

	// The table must actually permit the members the scan needs, or this test would pass by refusing
	// everything and the package would be dead code that looks safe.
	for _, m := range []Method{SessionCreateUpdateSearcher, SearcherSearch, ResultUpdates, UpdateTitle} {
		if _, err := permit(m, methods[m].args); err != nil {
			t.Errorf("permit(%q) refused a member the scan needs: %v", m, err)
		}
	}
}

// TestGuaranteeTheMethodTableHoldsNoWriteCapability is the claim the Linux allowlist cannot make.
//
// internal/run's allowlist is a statement about identity: apt-get may run, and what it then does is
// whatever apt-get can do. This table is a statement about capability, and that is the whole
// justification for a second AST exemption existing at all — so it has to be true rather than intended.
// The process that links this package cannot download an update and cannot install one, because the
// members that would are in neither table and permit() refuses anything not in them.
//
// It checks by name as well as by the writes flag. A flag is only as good as the person who set it, and
// the four member names below are the ones whose absence is the actual security property.
func TestGuaranteeTheMethodTableHoldsNoWriteCapability(t *testing.T) {
	if len(methods) == 0 {
		t.Fatal("the method table is empty; this test would pass vacuously")
	}
	if WritesHost() {
		t.Error("a member of the method table is marked as changing the host. That is not a table " +
			"entry, it is a change to docs/SECURITY.md §12.3: a Windows host has no root helper, so " +
			"nothing would re-read its policy and nothing would bound the operation.")
	}

	// The capability names, matched on the member rather than the whole identifier so that adding them
	// under any interface is caught.
	forbidden := map[string]string{
		"install":                "installing an update",
		"download":               "downloading an update",
		"copyfromcache":          "extracting update content",
		"accepteula":             "accepting a licence on the host's behalf",
		"createupdateinstaller":  "obtaining an installer",
		"createupdatedownloader": "obtaining a downloader",
		"addscanpackageservice":  "registering an update service",
		"uninstall":              "removing an update",
		"commit":                 "committing a staged installation",
		"rebootifrequired":       "restarting the host",
	}
	for m, spec := range methods {
		_, memberName, found := strings.Cut(string(m), ".")
		if !found {
			t.Errorf("%q does not name its interface; the table's entries are Interface.Member", m)
			continue
		}
		if memberName != spec.name {
			t.Errorf("%q is spelled %q in the table; the two must match or GetIDsOfNames resolves "+
				"a member the reviewer did not read", m, spec.name)
		}
		if why, bad := forbidden[strings.ToLower(spec.name)]; bad {
			t.Errorf("the method table permits %q, which is %s.\n"+
				"This process exists to read. See docs/SECURITY.md §12.3 and §12.5.", m, why)
		}
	}

	// One creatable class, and it is the session. IUpdateInstaller and IUpdateDownloader are not
	// classes and cannot be created directly — they are reached only through the two IUpdateSession
	// members above, which is why the two tables together are what makes the claim true.
	classes := CreatableClasses()
	if len(classes) != 1 || classes[0] != updateSessionCLSID {
		t.Errorf("this package can create %v; it may create only the update session", classes)
	}
}

// TestGuaranteeEveryTabledMethodHasACaller keeps the permitted set equal to the reached set.
//
// It is the counterpart of internal/run's TestGuaranteeEveryAllowlistedProgramHasACaller, and it exists
// for the reason that one does: a permitted capability with no call site is not inert. It is a decision
// taken early and out of sight, so that the day somebody writes the first call, the review that should
// have asked "may this process do that at all" has already silently happened. /usr/bin/systemctl sat in
// exactly that state on the Linux side, and this table is where the same thing would happen here.
func TestGuaranteeEveryTabledMethodHasACaller(t *testing.T) {
	root := repoRoot(t)
	named := namedMethodConstants(t, root)

	if len(named) == 0 {
		t.Fatal("no Method constants were found; this test would pass vacuously")
	}
	for m := range methods {
		if !named[m] {
			t.Errorf("the method table permits %q and no code in this package invokes it.\n"+
				"A permitted COM member nothing calls is a review that has already happened out of "+
				"sight. Remove it, or write the caller in the same commit.", m)
		}
	}
}

// namedMethodConstants returns every Method constant this package's own source invokes.
//
// It walks the AST rather than grepping, so that a name inside a comment or a string does not count as
// a call site, and it reads the build-tagged files too — this test runs on Linux and the callers live
// in files constrained to Windows, which a check that only saw what compiles here would miss entirely.
func namedMethodConstants(t *testing.T, root string) map[Method]bool {
	t.Helper()

	// Identifier to Method, built from the declarations rather than assumed, so a renamed constant does
	// not silently stop counting.
	byIdent := map[string]Method{}

	dir := filepath.Join(root, "internal", "wua")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}
		files[entry.Name()] = f
	}

	// First pass: which identifier is which Method value.
	for _, f := range files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				lit, ok := vs.Values[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value := strings.Trim(lit.Value, `"`)
				if _, isMethod := methods[Method(value)]; isMethod {
					byIdent[vs.Names[0].Name] = Method(value)
				}
			}
		}
	}

	// Second pass: which of those identifiers appears as an argument somewhere other than its own
	// declaration. A constant that only exists in the table and in its own const block has no caller.
	called := map[Method]bool{}
	for name, f := range files {
		if name == "comcall.go" {
			// The table and the declarations live here; naming a constant beside its own definition is
			// not a call site.
			continue
		}
		ast.Inspect(f, func(node ast.Node) bool {
			ident, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if m, isMethod := byIdent[ident.Name]; isMethod {
				called[m] = true
			}
			return true
		})
	}
	return called
}

// repoRoot walks up from the working directory until it finds the directory holding go.mod.
//
// Duplicated from internal/intent's copy rather than shared, for the reason the interpreter list is
// duplicated: a guarantee test that imported a helper from another package would fail differently when
// that package changed, and these checks are meant to be readable on their own.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("finding the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
