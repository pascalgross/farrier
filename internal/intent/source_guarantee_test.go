package intent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// scannedRoots are the directories whose Go source must contain no path from a message to a shell.
//
// web/ is absent because it is TypeScript and cannot invoke a process on a managed host; testfleet/ is
// absent because it is the harness that deliberately drives real machines over SSH, and holding it to
// this rule would only teach people to add exemptions.
var scannedRoots = []string{"cmd", "internal", "helpers"}

// interpreterBasenames are program names that turn their arguments into code.
//
// The list is longer than "sh and bash" because the mechanism being prevented is not one specific
// shell but the general act of handing a string to something that will interpret it. env, xargs and
// find are here because each of them will run an arbitrary program on request, which is the same
// capability with a different spelling.
var interpreterBasenames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "csh": true,
	"tcsh": true, "fish": true, "ash": true, "busybox": true,
	"perl": true, "python": true, "python3": true, "ruby": true, "lua": true, "node": true,
	"awk": true, "gawk": true, "mawk": true, "sed": true,
	"env": true, "xargs": true, "find": true, "eval": true,
	"nsenter": true, "chroot": true, "unshare": true, "setarch": true,
	"ssh": true, "scp": true, "sshpass": true,
	"sudo": true, "su": true, "runuser": true, "pkexec": true, "doas": true,
	"curl": true, "wget": true,
}

// execChokepoint is the one file permitted to execute a program named by a variable.
//
// internal/run replaces the compile-time property this test enforces everywhere else with a stronger
// run-time one: it holds a closed allowlist of absolute program paths and refuses anything else before
// reaching exec. Concentrating process execution in one audited file is better security design than
// scattering exec calls across the tree, and it is only an exemption from *this* check, not from the
// rule — TestGuaranteeOnlyAllowlistedProgramsCanRun in that package asserts the allowlist is actually
// enforced, and TestGuaranteeTheAllowlistHoldsNoInterpreters asserts what is in it.
//
// It is a single named path rather than a pattern on purpose. A second entry here would need its own
// justification in this comment, which is exactly the friction that should exist.
const execChokepoint = "internal/run/run.go"

// shellTextFragments are substrings that indicate an assembled shell command line.
//
// The AST check above already establishes what programs get run, so this textual pass only has to
// catch the other route: a command line built into a string and handed to something that did not look
// like an exec call where a reviewer read it. It is kept to fragments that cannot plausibly appear for
// any other reason, because a list broad enough to catch every mention of a shell would also catch the
// code that refuses shells, and the first exemption is how this kind of check stops being believed.
var shellTextFragments = []string{
	"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash",
	"sh -c", "bash -c",
}

// repoRoot walks up from this file until it finds the directory holding go.mod.
//
// It exists because the guarantee tests assert a property of the whole repository, not of one package,
// and go test gives no reliable handle on the module root. Walking up from the test's own source path
// works under go test, under an IDE, and in CI without configuration.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine the path of this test file")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to the filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// goFilesUnder returns every non-test Go file below root, keyed by the directory holding it.
//
// Test files are excluded deliberately: a test may legitimately need a shell to set up a fixture, and
// a rule that forbade it would be worked around with an exemption comment rather than obeyed. The
// property that matters is about code that ships.
func goFilesUnder(t *testing.T, root string) map[string][]string {
	t.Helper()
	byDir := map[string][]string{}
	for _, sub := range scannedRoots {
		base := filepath.Join(root, sub)
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			dir := filepath.Dir(path)
			byDir[dir] = append(byDir[dir], path)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", base, err)
		}
	}
	return byDir
}

// TestGuaranteeNoCodePathReachesAShell asserts every process Farrier starts is a compile-time constant.
//
// This is the mechanical form of the first sentence of docs/SECURITY.md §2.1. Two things are checked
// for every exec call in shipped code: that the program is an absolute path fixed at compile time —
// so it can be neither chosen at run time nor resolved through PATH — and that it is not an
// interpreter. Together those mean there is no expression in the repository whose value could become
// the thing that runs, which is a much stronger statement than "we do not call sh".
func TestGuaranteeNoCodePathReachesAShell(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	// The exemption must name a file that exists. Without this, deleting or renaming internal/run
	// would silently turn the exemption into a dead constant and leave the check looking satisfied.
	if _, err := os.Stat(filepath.Join(root, execChokepoint)); err != nil {
		t.Fatalf("the exec chokepoint %s does not exist: %v.\nIf process execution has moved, move the "+
			"exemption with it and move the allowlist tests too.", execChokepoint, err)
	}

	for _, files := range goFilesUnder(t, root) {
		consts := map[string]string{}
		parsed := map[string]*ast.File{}

		for _, path := range files {
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			parsed[path] = f
			collectStringConsts(f, consts)
		}

		for path, f := range parsed {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			ast.Inspect(f, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				pkg, fn, ok := selectorParts(call.Fun)
				if !ok {
					return true
				}

				var programArg ast.Expr
				switch {
				case pkg == "exec" && fn == "Command":
					if len(call.Args) > 0 {
						programArg = call.Args[0]
					}
				case pkg == "exec" && fn == "CommandContext":
					if len(call.Args) > 1 {
						programArg = call.Args[1]
					}
				case pkg == "syscall" && (fn == "Exec" || fn == "ForkExec"):
					if len(call.Args) > 0 {
						programArg = call.Args[0]
					}
				case pkg == "os" && fn == "StartProcess":
					if len(call.Args) > 0 {
						programArg = call.Args[0]
					}
				default:
					return true
				}

				pos := fset.Position(call.Pos())
				if rel == execChokepoint {
					return true
				}
				if programArg == nil {
					t.Errorf("%s:%d: %s.%s called with no program argument", rel, pos.Line, pkg, fn)
					return true
				}

				program, resolved := resolveStringExpr(programArg, consts)
				if !resolved {
					t.Errorf("%s:%d: the program passed to %s.%s is not a compile-time constant.\n"+
						"Farrier requires every executed program to be a literal absolute path, or a "+
						"package-level string constant, so that no expression in the repository can "+
						"become the thing that runs. See docs/SECURITY.md §2.1.", rel, pos.Line, pkg, fn)
					return true
				}
				if !strings.HasPrefix(program, "/") {
					t.Errorf("%s:%d: %s.%s runs %q, which is not an absolute path. Resolving a program "+
						"through PATH lets whoever controls the environment choose it.",
						rel, pos.Line, pkg, fn, program)
				}
				if base := filepath.Base(program); interpreterBasenames[base] {
					t.Errorf("%s:%d: %s.%s runs the interpreter %q. No code path in Farrier may lead "+
						"from a network message to something that interprets its arguments.",
						rel, pos.Line, pkg, fn, program)
				}
				return true
			})
		}
	}

	for _, files := range goFilesUnder(t, root) {
		for _, path := range files {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			lower := strings.ToLower(string(src))
			for _, frag := range shellTextFragments {
				if strings.Contains(lower, frag) {
					t.Errorf("%s contains the fragment %q. Shipped code never assembles a shell "+
						"invocation, in any form.", rel, frag)
				}
			}
		}
	}
}

// collectStringConsts records every package-level string constant declared in a file.
//
// It exists so that the exec check can accept the idiom the project actually wants people to use —
// naming binary paths as constants near the top of the file — without accepting an arbitrary
// identifier whose value could come from anywhere.
func collectStringConsts(f *ast.File, into map[string]string) {
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil {
					into[name.Name] = v
				}
			}
		}
	}
}

// selectorParts splits an expression like exec.CommandContext into its package and function names.
//
// It returns false for anything that is not a plain qualified identifier, which is intentional: a call
// made through a function value or an interface is not something this check can reason about, and the
// project does not do that for process execution.
func selectorParts(e ast.Expr) (pkg, fn string, ok bool) {
	sel, isSel := e.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	ident, isIdent := sel.X.(*ast.Ident)
	if !isIdent {
		return "", "", false
	}
	return ident.Name, sel.Sel.Name, true
}

// resolveStringExpr resolves an expression to a compile-time string, if it is one.
//
// Only two forms are accepted, a string literal and a reference to a package-level string constant,
// because those are the only two whose value a reviewer can see without leaving the file they are
// reading. Concatenation is deliberately not resolved even when both halves are constant: allowing it
// would mean the check had to decide how much assembly is too much, and the answer this project wants
// is none.
func resolveStringExpr(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.Ident:
		s, ok := consts[v.Name]
		return s, ok
	case *ast.SelectorExpr:
		s, ok := consts[v.Sel.Name]
		return s, ok
	default:
		return "", false
	}
}

// TestGuaranteeRootHelpersTakeNoPolicyPath is local policy sovereignty at the helper's own inputs.
//
// The agent can write /var/lib/farrier. A helper that accepted --policy would therefore be a helper a
// compromised agent could point at a file it had just written itself, and local policy would end there:
// the enforcement would still run, as root, against exactly the policy the attacker chose. The same
// applies to the socket the agent reaches the helper on, which is why privsep.Request carries no field
// a path could occupy — TestGuaranteeARequestCannotNameAProgram asserts that half.
//
// The check is on the source rather than on behaviour because the failure is a flag somebody adds back
// for testing and forgets to remove. internal/helper.Authorise still takes a path, which is what tests
// and `farrier-agent policy check` use; nothing reachable from the agent does.
func TestGuaranteeRootHelpersTakeNoPolicyPath(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	helperDir := filepath.Join(root, "helpers")
	entries, err := os.ReadDir(helperDir)
	if err != nil {
		t.Fatalf("reading %s: %v", helperDir, err)
	}
	if len(entries) != 3 {
		t.Errorf("there are %d root helpers, expected exactly 3. There is deliberately no fourth, "+
			"and certainly not one that runs a configured command.", len(entries))
	}

	forbidden := map[string]string{
		"policy": "a caller-chosen policy file defeats local policy sovereignty entirely",
		"config": "a caller-chosen configuration file is a policy file with a different name",
		"exec":   "a helper never takes a program to run",
		"cmd":    "a helper never takes a command",
		"script": "a helper never takes a script",
		"shell":  "a helper never takes a shell fragment",
		"path":   "a helper never takes a path to act on; parameters are typed and validated",
		"file":   "a helper never takes a file to act on",
		"url":    "a helper never fetches anything",
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		main := filepath.Join(helperDir, entry.Name(), "main.go")
		f, err := parser.ParseFile(fset, main, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", main, err)
		}

		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			pkg, fn, ok := selectorParts(call.Fun)
			if !ok || pkg != "flag" || len(call.Args) == 0 {
				return true
			}
			if !strings.HasPrefix(fn, "String") && !strings.HasPrefix(fn, "Int") &&
				!strings.HasPrefix(fn, "Bool") && !strings.HasPrefix(fn, "Duration") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for fragment, reason := range forbidden {
				if strings.Contains(strings.ToLower(name), fragment) {
					pos := fset.Position(call.Pos())
					t.Errorf("%s/main.go:%d: the root helper defines a --%s flag: %s",
						entry.Name(), pos.Line, name, reason)
				}
			}
			return true
		})
	}
}
