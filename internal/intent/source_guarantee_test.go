package intent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// unscannedRoots are the top-level directories whose Go source is deliberately not held to this rule.
//
// It is stated as an exclusion rather than as a list of what *is* scanned, and the difference is the
// point. A fixed inclusion list covers the directories that existed when somebody wrote it: move the
// agent's process-spawning code into a new top-level package and the check quietly stops seeing it,
// with nothing red to say so. Deriving the scanned set from the layout means a new directory is
// scanned by default and a directory that should not be has to be named here, in a commit somebody
// reviews.
//
// Two names are in it. tools/ is build tooling that never runs on a managed host and legitimately runs
// other programs — the doc-comment checker and the site generator — which is the same judgement
// .golangci.yml records for depguard. testfleet/ is the harness that deliberately drives real machines
// over SSH; it holds no Go today, and it is named so that it stays exempt if it ever does.
//
// web/ needs no entry: it is TypeScript, and this walk only looks at Go.
var unscannedRoots = map[string]string{
	"tools":     "build tooling, which runs on a maintainer's machine and never on a managed host",
	"testfleet": "the integration harness, whose whole job is driving real machines over SSH",
}

// scannedRoots returns every top-level directory holding shipped Go source.
//
// It fails rather than returning a short list, in each of the two ways this could quietly go wrong: a
// repository with no scannable root at all, and an exclusion above naming a directory that no longer
// exists. The second is the one that rots — an exemption outlives the thing it exempted, and what is
// left is a name that would silently exempt some future directory that happened to be called the same.
func scannedRoots(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}

	var roots []string
	present := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		present[entry.Name()] = true
		if _, excluded := unscannedRoots[entry.Name()]; excluded {
			continue
		}
		if holdsShippedGo(t, filepath.Join(root, entry.Name())) {
			roots = append(roots, entry.Name())
		}
	}

	for name, reason := range unscannedRoots {
		if !present[name] {
			t.Fatalf("unscannedRoots names %q (%s), and there is no such directory.\n"+
				"An exemption that outlives the code it exempted is one that will silently cover "+
				"whatever is next given that name. Remove it.", name, reason)
		}
	}
	if len(roots) == 0 {
		t.Fatal("no top-level directory holds shipped Go source; this check would pass vacuously")
	}
	sort.Strings(roots)
	return roots
}

// holdsShippedGo reports whether a directory tree contains any non-test Go file.
//
// Non-test only, and the exclusion is the same one goFilesUnder makes: a test may legitimately need a
// shell to build a fixture, and a directory holding nothing but tests has no shipped code to check.
func holdsShippedGo(t *testing.T, dir string) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return found
}

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

	// The Windows spellings, present although Farrier ships no Windows binary. rundll32, regsvr32 and
	// msiexec are here for the same reason env and xargs are: each runs a program of the caller's
	// choosing, which is the capability this list is about rather than the word "shell". refused.go has
	// refused an *intent* named "powershell" since long before this line; only the check that reads
	// source had not been told.
	"powershell": true, "pwsh": true, "cmd": true,
	"wscript": true, "cscript": true, "mshta": true,
	"rundll32": true, "regsvr32": true, "msiexec": true,
	"wmic": true, "forfiles": true,
	"certutil": true, "bitsadmin": true,
}

// programBasename reduces a program path to the name looked up in interpreterBasenames.
//
// It exists because filepath.Base is not the right function here and is wrong without saying so. This
// test runs on a Linux runner, where filepath.Base of a Windows path returns the whole string — there
// is no "/" in `C:\Windows\System32\cmd.exe` to split on — so the lookup would match nothing and the
// check would pass while reading the name it exists to refuse. Splitting on both separators, folding
// case and dropping the executable suffix gives one program one name here, whoever wrote the path.
func programBasename(program string) string {
	name := program
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	// Only the two suffixes Windows treats as a bare command name. A longer list would fold a program
	// genuinely called "deploy.cmd" onto "deploy" and answer a question nobody asked.
	for _, suffix := range []string{".exe", ".com"} {
		if after, found := strings.CutSuffix(name, suffix); found {
			return after
		}
	}
	return name
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

// repoRoot walks up from the working directory until it finds the directory holding go.mod.
//
// It exists because the guarantee tests assert a property of the whole repository, not of one package,
// and go test gives no reliable handle on the module root. The working directory is the package's own
// source directory under go test, under an IDE, and in CI, which is handle enough.
//
// It is not runtime.Caller, which is the obvious thing to reach for and is wrong here: under -trimpath
// a caller's file name is module-relative, the walk upwards from it finds no go.mod, and these tests
// fail on a repository that is entirely correct. Every binary this project ships is built with
// -trimpath, so the flag reaching GOFLAGS is a matter of time — and a guarantee test that fails for a
// reason having nothing to do with its guarantee teaches people to disbelieve it.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine the working directory: %v", err)
	}
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
	for _, sub := range scannedRoots(t, root) {
		base := filepath.Join(root, sub)
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

				shape, isExec := classifyExecCall(pkg, fn)
				if !isExec {
					return true
				}

				pos := fset.Position(call.Pos())
				if rel == execChokepoint {
					return true
				}

				// A shape whose program this check cannot read is refused outright rather than
				// examined. A raw trap number and a pointer say nothing a reviewer of *this* test
				// could act on, and "the check did not recognise it" must not be the same outcome as
				// "the check found nothing wrong".
				if shape.opaque {
					t.Errorf("%s:%d: %s.%s executes through a shape this check cannot read.\n"+
						"%s Every process Farrier starts goes through internal/run. "+
						"See docs/SECURITY.md §2.1.", rel, pos.Line, pkg, fn, shape.why)
					return true
				}

				var programArg ast.Expr
				if len(call.Args) > shape.programArg {
					programArg = call.Args[shape.programArg]
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
				// Asked before the absolute-path rule so that its answer is the one an author reads: a
				// Windows path fails both, and "not an absolute path" is the less useful thing to be
				// told about powershell.exe.
				if interpreterBasenames[programBasename(program)] {
					t.Errorf("%s:%d: %s.%s runs the interpreter %q. No code path in Farrier may lead "+
						"from a network message to something that interprets its arguments.",
						rel, pos.Line, pkg, fn, program)
				}
				if !strings.HasPrefix(program, "/") {
					t.Errorf("%s:%d: %s.%s runs %q, which is not an absolute path. Resolving a program "+
						"through PATH lets whoever controls the environment choose it.",
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

// execShape describes what one recognised way of starting a process looks like to this check.
//
// The two fields are alternatives rather than a pair: either the program is an argument this check can
// resolve to a compile-time string, or the shape is one whose program is not readable here at all and
// the call is refused for that reason alone.
type execShape struct {
	// programArg is the index of the argument naming the program.
	programArg int

	// opaque marks a shape whose program cannot be read from the call site.
	opaque bool

	// why explains, in the failure message, what makes the shape unreadable.
	why string
}

// classifyExecCall recognises a call that starts a process, and says what this check can learn from it.
//
// The list is longer than the obvious four, and every addition beyond them closes a hole the earlier
// version had: os/exec is denied by depguard, but golang.org/x/sys/unix is an indirect dependency that
// would compile, and `syscall` is imported by shipped files already. So `unix.Exec(shell, []string{
// shell, "-c", cmd}, env)` used to pass every check in this file — the switch did not match it, the
// import was not denied, and the text scan saw no literal shell fragment. That is a general remote
// execution primitive introduced with `make guarantee` green, which is the one outcome this file
// exists to make impossible.
//
// Unrecognised shapes on the two packages that can reach execve are refused rather than ignored, which
// is why this returns a shape for `Exec`-prefixed names it has never heard of.
func classifyExecCall(pkg, fn string) (execShape, bool) {
	switch pkg {
	case "exec":
		switch fn {
		case "Command":
			return execShape{programArg: 0}, true
		case "CommandContext":
			return execShape{programArg: 1}, true
		}
	case "os":
		if fn == "StartProcess" {
			return execShape{programArg: 0}, true
		}
	case "syscall", "unix":
		switch fn {
		case "Exec", "ForkExec", "Execve":
			return execShape{programArg: 0}, true
		case "Fexecve":
			return execShape{opaque: true,
				why: "it executes an open file descriptor, so the program has no name at the call site."}, true
		}
		// Everything else on these two packages that could reach execve. A raw syscall names its
		// operation with an integer and its arguments with pointers, so there is nothing here to
		// resolve to a path — and Execveat's directory-relative form is the same problem with a
		// nicer spelling.
		if strings.HasPrefix(fn, "Syscall") || strings.HasPrefix(fn, "RawSyscall") ||
			strings.HasPrefix(fn, "Exec") {
			return execShape{opaque: true,
				why: "its program is a trap number or a descriptor rather than a path this check can read."}, true
		}
	}
	return execShape{}, false
}

// TestGuaranteeNoExecCommandIsBuiltAsAStructLiteral closes the one exec route that is not a call.
//
// exec.Cmd can be constructed directly — `&exec.Cmd{Path: p, Args: a}` — and then Run, Start or Output
// called on it. That is a method call on a value, which the selector-based scan above cannot follow to
// a program argument, so it is refused at construction instead. Today the os/exec import is denied
// everywhere but internal/run, which already stops this; the check is here so that the AST test states
// the property on its own rather than resting on a linter configuration a commit could edit.
func TestGuaranteeNoExecCommandIsBuiltAsAStructLiteral(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	for _, files := range goFilesUnder(t, root) {
		for _, path := range files {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			if rel == execChokepoint {
				continue
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			ast.Inspect(f, func(node ast.Node) bool {
				lit, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				pkg, name, ok := selectorParts(lit.Type)
				if !ok || pkg != "exec" || name != "Cmd" {
					return true
				}
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d: an exec.Cmd is constructed here as a struct literal.\n"+
					"A command built field by field escapes the argument check on exec.Command, and "+
					"every process Farrier starts goes through internal/run. See docs/SECURITY.md §2.1.",
					rel, pos.Line)
				return true
			})
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

// alertingFiles are the source files that make up the alerting path.
//
// Named rather than discovered, because the property below is about these files and a pattern that
// swept the package would either miss a file added later or catch the job API next door. A new file on
// this path belongs in this list, and adding one is the moment to ask whether it should be.
var alertingFiles = []string{
	"internal/server/alerts.go",
	"internal/server/alertsapi.go",
}

// jobMakingCalls are the store operations that put work on a host, by method name.
//
// The names are the complete set from store.Store: CreateJob queues work and ApproveJob releases work
// somebody else queued. Either one, reached from the alerting path, would turn a control plane that
// asks into one that acts on a schedule of its own.
var jobMakingCalls = map[string]string{
	"CreateJob":  "queues work on a host",
	"ApproveJob": "releases work queued for a host",
}

// TestGuaranteeAnAlertRuleCannotProduceAJob is the line docs/SECURITY.md §8.3 draws, as a check.
//
// A rule produces a notification. A rule never produces a job. "Auto-remediate: apply security updates
// when more than five are pending" is the obvious next request and it is a different feature with a
// different threat model: it does not break the guarantee — the host's own policy still bounds it, and
// anything destructive still needs an offline signature from a key in that host's own trusted-signers
// — but it converts the control plane from something that asks into something that acts on a schedule
// of its own. That deserves its own argument, and until it has had one this is a compile-time-visible
// property rather than a sentence in three documents.
//
// It is an assertion about source rather than about behaviour because behaviour cannot show the
// absence of a path. A test that queued no job would pass equally well against a build that queued one
// under a condition the test did not construct.
func TestGuaranteeAnAlertRuleCannotProduceAJob(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	for _, rel := range alertingFiles {
		path := filepath.Join(root, rel)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s does not exist: %v.\nIf the alerting path has moved, move this list with it.",
				rel, err)
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", rel, err)
		}
		// Any mention of the name, not only a call of it. A method value assigned and invoked three
		// lines later is the same path with an extra step, and the check that only looked at call
		// expressions missed exactly that when it was tried against a deliberate mutation.
		ast.Inspect(f, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if what, forbidden := jobMakingCalls[sel.Sel.Name]; forbidden {
				pos := fset.Position(sel.Pos())
				t.Errorf("%s:%d: the alerting path reaches %s, which %s.\n"+
					"A rule produces a notification and never a job — see docs/SECURITY.md §8.3. "+
					"Auto-remediation is a separate feature with its own argument.",
					rel, pos.Line, sel.Sel.Name, what)
			}
			return true
		})
	}
}

// managedHostBinaries are the programs that run on a machine somebody else owns.
//
// The agent, the control plane and the three root helpers. `farrier` is deliberately not here: it is
// the operator's own tool, run by a person at a terminal, and it is the one program that may load a
// PKCS#11 module or reach a network — which is the whole reason the property below is about these
// five and not about the repository.
var managedHostBinaries = []string{
	"cmd/farrier-agent",
	"cmd/farrier-server",
	"helpers/apply-updates",
	"helpers/restart-unit",
	"helpers/reboot-host",
}

// forbiddenOnAManagedHost are import paths that must not be reachable from those programs.
//
// Both entries are about the same sentence, which docs/SECURITY.md §3 and docs/EXTENDING.md both
// state: there is no runtime plugin loader in the agent, ever, and dlopen is named as an example of
// what that means. The signing backends now contain one — `farrier` loads a PKCS#11 module an operator
// names — and purego is what it loads with. Neither may become reachable from a program that runs on a
// managed host, and "it is not today" is a fact about the current import graph rather than a property,
// which is what this test converts it into.
var forbiddenOnAManagedHost = map[string]string{
	"github.com/pascalgross/farrier/internal/signing/backend": "the signing-backend registry, which " +
		"exists so that only the operator's own tool links a backend",
	"github.com/ebitengine/purego": "a foreign-function interface, which is how the PKCS#11 backend " +
		"loads a module the operator names",
}

// TestGuaranteeTheAgentBinaryIsLinuxOnly pins what a build for another platform is allowed to produce.
//
// The tree very nearly cross-compiles for Windows already: everything the agent needs builds except one
// reference to syscall.Stat_t, and nothing in the packages below it carries a build tag, because the
// Linux-ness of this codebase lives in behaviour rather than in constraints. internal/collect compiles
// for Windows and would then read /etc/os-release and execute /usr/bin/apt-get. So the risk is not a
// build that fails; it is a build that succeeds and produces an agent that reports nothing correctly
// while an operator reads the running service as support for their platform.
//
// The constraint on cmd/farrier-agent is what makes that impossible to do by accident, and this test is
// what keeps the constraint from being dropped by somebody clearing a build error. Deleting the tag is
// not forbidden — it is the commit that ships a Windows agent — but it may not happen quietly, and it
// may not happen before there is something for the tag to be widened *to*. Widening it means editing
// this test in the same commit, which is the same friction the catalogue's expected-set literal exists
// to create.
func TestGuaranteeTheAgentBinaryIsLinuxOnly(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "cmd", "farrier-agent", "main.go")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v.\nIf the agent's main package has moved, move this test with it.", path, err)
	}
	// The constraint has to be in the build-constraint region — before the package clause — or the Go
	// tool treats it as an ordinary comment and the file builds everywhere while looking constrained.
	head, _, found := strings.Cut(string(raw), "\npackage ")
	if !found {
		t.Fatalf("%s has no package clause", path)
	}
	if !strings.Contains(head, "//go:build linux\n") {
		t.Errorf("cmd/farrier-agent/main.go does not carry //go:build linux before its package clause.\n" +
			"A build of the agent for another platform must not succeed: every collector, the helper\n" +
			"sockets and the package manager it drives are Linux, and a binary that starts and reports\n" +
			"nothing correctly is worse than one that never built. If a Windows agent now exists, widen\n" +
			"the constraint and this test together, and say in docs/SECURITY.md which of the three\n" +
			"mechanisms it enforces by test rather than by convention.")
	}
}

// TestGuaranteeNoManagedHostBinaryLoadsASigningBackend keeps the safe seam safe.
//
// internal/signing's own doc comment argues that an open-ended set of signing backends is safe because
// the verifier never changes: a host sees a public key and a signature over a canonical payload and
// cannot learn which backend produced it, so adding one "cannot widen the agent's attack surface by
// even one branch". That argument holds only while the agent links no backend, and after issue #22 a
// backend dlopens a shared library.
//
// So it is asserted rather than reviewed for. The import closure is computed over this module's own
// packages, which is enough: a first-party package is the only way one of these paths could be reached.
func TestGuaranteeNoManagedHostBinaryLoadsASigningBackend(t *testing.T) {
	root := repoRoot(t)
	imports := moduleImportGraph(t, root)

	for _, entry := range managedHostBinaries {
		if _, ok := imports[entry]; !ok {
			t.Fatalf("%s has no packages; if a binary has moved, move this list with it", entry)
		}
		for path, chain := range reachableFrom(imports, entry) {
			for forbidden, why := range forbiddenOnAManagedHost {
				if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
					t.Errorf("%s reaches %s, which is %s.\n  through: %s\n"+
						"See docs/SECURITY.md §3: there is no runtime plugin loader in the agent, ever.",
						entry, path, why, strings.Join(chain, " → "))
				}
			}
		}
	}
}

// moduleImportGraph maps each first-party package directory to the packages it imports.
//
// Built by parsing rather than by shelling out to `go list`, because a test that ran a program to
// prove nothing runs a program would be an odd thing to have in this file — and because depguard
// denies os/exec here as it does everywhere else.
func moduleImportGraph(t *testing.T, root string) map[string][]string {
	t.Helper()
	const modulePath = "github.com/pascalgross/farrier/"

	graph := map[string][]string{}
	fset := token.NewFileSet()
	for _, sub := range scannedRoots(t, root) {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			rel, relErr := filepath.Rel(root, filepath.Dir(path))
			if relErr != nil {
				return relErr
			}
			for _, spec := range f.Imports {
				imported, unquoteErr := strconv.Unquote(spec.Path.Value)
				if unquoteErr != nil {
					continue
				}
				graph[rel] = append(graph[rel], imported)
			}
			if _, ok := graph[rel]; !ok {
				graph[rel] = nil
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", base, err)
		}
	}

	// Keyed by directory so a first-party import can be followed: the module path maps onto the
	// directory layout exactly, which is what makes this walk possible without a build.
	_ = modulePath
	return graph
}

// reachableFrom returns every import reachable from one package, with the chain that reached it.
//
// The chain is what makes a failure actionable. "farrier-agent reaches purego" is a fact somebody then
// has to go and find; "farrier-agent → internal/agent → internal/signing/backend/pkcs11 → purego" is
// the line to delete.
func reachableFrom(graph map[string][]string, entry string) map[string][]string {
	const modulePath = "github.com/pascalgross/farrier/"

	seen := map[string][]string{}
	var walk func(dir string, chain []string)
	walk = func(dir string, chain []string) {
		for _, imported := range graph[dir] {
			if _, done := seen[imported]; done {
				continue
			}
			next := append(append([]string(nil), chain...), imported)
			seen[imported] = next
			if inside, ok := strings.CutPrefix(imported, modulePath); ok {
				walk(inside, next)
			}
		}
	}
	walk(entry, []string{entry})
	return seen
}
