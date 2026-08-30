package run

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	//nolint:depguard // The WaitDelay test below reproduces the apt-get→dpkg shape: a grandchild that
	// inherits the direct child's output pipes and outlives it. run's own API rightly cannot express
	// pipe inheritance, so the fixture process — this test binary re-executing itself — starts its
	// child directly. This is test code inside the one package allowed to start processes at all.
	"os/exec"
)

// interpreterBasenames are program names that turn their arguments into code.
//
// This list is duplicated from the guarantee suite in internal/intent on purpose. The two checks assert
// different things — that one is about source anywhere in the tree, this one is about the contents of
// the allowlist — and sharing the list would couple a security check to an import.
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

	// The Windows spellings of the same capability. They are here although Farrier ships no Windows
	// binary, because the list is what the check consults and a list that knows only the Unix names
	// would let the first Windows allowlist entry through in review — while internal/intent's
	// executionShapedFragments has refused an *intent* named "powershell" since before this line
	// existed. The project had already decided; only the guard had not been told.
	"powershell": true, "pwsh": true, "cmd": true,
	"wscript": true, "cscript": true, "mshta": true,
	"rundll32": true, "regsvr32": true, "msiexec": true,
	"wmic": true, "forfiles": true,
	"certutil": true, "bitsadmin": true,
}

// programBasename reduces a program path to the name looked up in interpreterBasenames.
//
// It exists because filepath.Base is not the right function here and fails silently when it is wrong.
// The checks below run on a Linux runner, where filepath.Base of
// `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` is the entire string — there is no "/" to
// split on — so the interpreter lookup would match nothing and report success. Splitting on both
// separators, folding case and dropping the executable suffix means one program has one name here,
// whichever platform wrote the path and whichever platform runs the test.
func programBasename(program string) string {
	name := program
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	// Only the two suffixes Windows treats as a bare command name. Trimming a longer list would map
	// a program genuinely called "deploy.cmd" onto "deploy" and answer a question nobody asked.
	for _, suffix := range []string{".exe", ".com"} {
		if after, found := strings.CutSuffix(name, suffix); found {
			return after
		}
	}
	return name
}

// TestGuaranteeOnlyAllowlistedProgramsCanRun is what earns this package its exemption.
//
// internal/run is the one file permitted to execute a program named by a variable rather than a
// compile-time constant, because the allowlist below is a stronger property than the one it replaces.
// This test is the proof of that claim: a program outside the list is refused before exec, whatever it
// is and however it was constructed.
func TestGuaranteeOnlyAllowlistedProgramsCanRun(t *testing.T) {
	refused := []Program{
		"/bin/sh",
		"/bin/bash",
		"/usr/bin/env",
		"/usr/bin/python3",
		"/usr/bin/apt", // apt, not apt-get: even the near-miss is refused
		"apt-get",      // relative, so PATH would choose it
		"/usr/bin/apt-get ",
		"../../usr/bin/apt-get",
		"/usr/bin/apt-get;/bin/sh",
		"",
		"/usr/bin/true",
	}
	for _, p := range refused {
		res, err := Command(context.Background(), p, "--version")
		if err == nil {
			t.Errorf("%q was executed", p)
			continue
		}
		if !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%q produced %v, which does not wrap ErrNotAllowed", p, err)
		}
		if res != nil {
			t.Errorf("%q produced a result despite being refused", p)
		}
	}
}

// TestGuaranteeTheAllowlistHoldsNoInterpreters asserts what may be in the list at all.
//
// The allowlist is the complete set of processes Farrier can start. Every member must be an absolute
// path, so that nothing about the environment can change which binary runs, and none may be a program
// that turns its arguments into code — which is the same requirement the source-level check makes
// everywhere else, stated here about data rather than about syntax.
func TestGuaranteeTheAllowlistHoldsNoInterpreters(t *testing.T) {
	list := Allowlist()
	if len(list) == 0 {
		t.Fatal("the allowlist is empty; this test would pass vacuously")
	}
	for _, p := range list {
		s := string(p)
		// The interpreter question is asked first so that its answer is the one an author reads. A
		// Windows path fails the absolute-path rule below as well, and "is not an absolute path" is
		// the less useful of the two things to be told about powershell.exe.
		if interpreterBasenames[programBasename(s)] {
			t.Errorf("%q is an interpreter and may not be in the allowlist", p)
		}
		if !strings.HasPrefix(s, "/") {
			t.Errorf("%q is not an absolute POSIX path. Farrier ships no Windows binary yet; when it "+
				"does, this rule gains a Windows form rather than losing its Linux one.", p)
		}
		if s != strings.TrimSpace(s) {
			t.Errorf("%q has surrounding whitespace", p)
		}
		if strings.Contains(s, "..") {
			t.Errorf("%q contains a relative path component", p)
		}
	}
}

// TestGuaranteeTheInterpreterCheckReadsAWindowsPath is the regression test for a hole that was open.
//
// Until this test existed, both interpreterBasenames maps held only Unix names and the lookup used
// filepath.Base, so `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` in the allowlist would
// have passed TestGuaranteeTheAllowlistHoldsNoInterpreters twice over: the map had no entry to match,
// and on a Linux runner filepath.Base returns the whole string so there was nothing to look up anyway.
// A guard that reads the one name it most needs to refuse and says nothing is worse than no guard,
// because the green check is what a reviewer trusts instead of reading.
//
// It asserts the check, not the allowlist. The allowlist is POSIX-only today and the test above already
// pins that; what is proved here is that the day a Windows path is proposed, the answer is no.
func TestGuaranteeTheInterpreterCheckReadsAWindowsPath(t *testing.T) {
	refused := []string{
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Program Files\PowerShell\7\pwsh.exe`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\wscript.exe`,
		`C:\Windows\System32\rundll32.exe`,
		`C:\Windows\System32\msiexec.exe`,
		`c:\windows\system32\CMD.EXE`, // case is not a way past
		"powershell.exe",              // bare, as an argument vector's first element
		"/usr/bin/pwsh",               // the Unix packaging of the same interpreter
	}
	for _, program := range refused {
		if !interpreterBasenames[programBasename(program)] {
			t.Errorf("%q is not recognised as an interpreter; programBasename gave %q",
				program, programBasename(program))
		}
	}

	// The suffix trimming must not reach past the two Windows treats as a bare command name, or a
	// program legitimately called "deploy.cmd" would be read as "cmd" and refused for the wrong reason.
	for _, program := range []string{"/usr/bin/apt-get", "/opt/farrier/deploy.cmd", "/usr/sbin/shutdown"} {
		if interpreterBasenames[programBasename(program)] {
			t.Errorf("%q is refused as an interpreter, which is a false positive", program)
		}
	}
}

// TestGuaranteeEveryAllowlistedProgramHasACaller keeps the runnable set equal to the reachable set.
//
// An allowlisted program with no call site is not harmless. It is a decision taken early and out of
// sight: the review that should ask "may this program run on a managed host at all" has already
// happened by the time somebody adds the first caller, and what that reviewer sees instead is one line
// naming something the allowlist already blesses. /usr/bin/systemctl sat here in exactly that state —
// flag-rich, reachable by nothing, with a doc comment describing a fallback that had never been
// written — while every unit operation went over D-Bus.
//
// So the rule is that the two sets are the same one, and the way to add a program is in the commit that
// calls it.
func TestGuaranteeEveryAllowlistedProgramHasACaller(t *testing.T) {
	root := repoRoot(t)

	declared := allowlistConstantNames(t, root)
	if len(declared) != len(Allowlist()) {
		t.Fatalf("run.go declares %d Program constants and the allowlist holds %d entries.\n"+
			"Every declared program must be in the allowlist and every allowlisted program must be "+
			"declared, or one of the two lists is not the set it claims to be.",
			len(declared), len(Allowlist()))
	}

	used := programNamesUsedOutsideThisPackage(t, root)
	for _, name := range declared {
		if !used[name] {
			t.Errorf("run.%s is in the allowlist and nothing outside internal/run names it.\n"+
				"Remove it until the commit that adds a caller, so that whether this program may run "+
				"is decided by whoever reviews that caller rather than in advance.", name)
		}
	}
}

// allowlistConstantNames returns the identifiers of the Program constants declared in run.go.
//
// It reads the source rather than the map because the map is keyed by path and the rest of the
// repository names these by identifier: `run.AptGet`, not "/usr/bin/apt-get". Matching on the
// identifier is what lets the caller scan below be a plain AST walk with no type information.
func allowlistConstantNames(t *testing.T, root string) []string {
	t.Helper()

	path := filepath.Join(root, "internal", "run", "run.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var names []string
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
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "Program" {
				continue
			}
			for _, name := range vs.Names {
				names = append(names, name.Name)
			}
		}
	}
	if len(names) == 0 {
		t.Fatalf("no Program constants found in %s; this check would pass vacuously", path)
	}
	return names
}

// programNamesUsedOutsideThisPackage returns every `run.X` identifier shipped code refers to.
//
// Non-test files only, and internal/run's own files excluded. A test that named a program would keep
// an otherwise dead entry alive, which is the state this check exists to find.
func programNamesUsedOutsideThisPackage(t *testing.T, root string) map[string]bool {
	t.Helper()

	used := map[string]bool{}
	fset := token.NewFileSet()
	for _, sub := range []string{"cmd", "internal", "helpers"} {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if filepath.Dir(path) == filepath.Join(root, "internal", "run") {
				return nil
			}
			f, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if parseErr != nil {
				return parseErr
			}
			ast.Inspect(f, func(node ast.Node) bool {
				sel, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "run" {
					used[sel.Sel.Name] = true
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", base, err)
		}
	}
	return used
}

// repoRoot walks up from the working directory until it finds the directory holding go.mod.
//
// The working directory is the package's own source directory under go test, which is a handle the
// module root can be reached from. It is deliberately not runtime.Caller: under -trimpath, which every
// binary this project ships is built with, a caller's file name is module-relative and the walk finds
// no go.mod at all.
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

// TestGuaranteeAptIsNeverUsedInsteadOfAptGet pins one of the verified traps.
//
// apt 3.0, shipped in Ubuntu 25.04, reorganised apt's output into colourised columns; 26.04 ships apt
// 3.1. apt-get keeps the machine-oriented format. A refactor to the "nicer" command breaks update
// detection on the newest supported release while still passing on the oldest, which is the worst way
// to discover it — so the allowlist may not contain apt at all.
func TestGuaranteeAptIsNeverUsedInsteadOfAptGet(t *testing.T) {
	for _, p := range Allowlist() {
		if filepath.Base(string(p)) == "apt" {
			t.Errorf("%q is in the allowlist; Farrier uses apt-get, whose output format is stable", p)
		}
	}
}

// TestCommandReplacesTheEnvironment asserts the caller's environment does not leak into the child.
//
// Inheriting the environment would let whatever set PATH or LD_PRELOAD change what an allowlisted
// program does, which would make the allowlist a statement about file names rather than about
// behaviour.
func TestCommandReplacesTheEnvironment(t *testing.T) {
	t.Setenv("FARRIER_TEST_LEAK", "should-not-appear")

	// /usr/bin/apt-get is on the allowlist and present on the distributions Farrier targets. Where it
	// is absent — a developer's machine, a minimal CI image — there is nothing to observe and the
	// assertion about environment handling is made by reading Options.Env's documented contract.
	if _, err := os.Stat(string(AptGet)); err != nil {
		t.Skipf("%s is not installed here", AptGet)
	}
	res, err := CommandWith(context.Background(), Options{Timeout: 30 * time.Second}, AptGet, "--version")
	if err != nil {
		t.Fatalf("apt-get --version: %v", err)
	}
	if strings.Contains(string(res.Stdout)+string(res.Stderr), "should-not-appear") {
		t.Error("the caller's environment reached the child process")
	}
	if res.ExitCode != 0 {
		t.Errorf("apt-get --version exited %d", res.ExitCode)
	}
}

// TestCommandTimesOut asserts no invocation is unbounded.
//
// An apt operation blocked on a conffile prompt waits for input that never arrives. An agent that
// waited with it would stop reporting on the host, which is the opposite of what it is for.
func TestCommandTimesOut(t *testing.T) {
	if _, err := os.Stat(string(AptGet)); err != nil {
		t.Skipf("%s is not installed here", AptGet)
	}
	ctx := context.Background()
	// A one-nanosecond timeout expires before the process can finish, whatever it is.
	_, err := CommandWith(ctx, Options{Timeout: time.Nanosecond}, AptGet, "--version")
	if err == nil {
		t.Fatal("an invocation with a one-nanosecond timeout succeeded")
	}
	if !strings.Contains(err.Error(), "timed out") && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not report a timeout", err)
	}
}

// TestLimitedWriterBoundsOutput asserts a chatty program cannot exhaust memory.
func TestLimitedWriterBoundsOutput(t *testing.T) {
	var buf bytes.Buffer
	w := &limitedWriter{buf: &buf, limit: 10}

	n, err := w.Write([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The full length is reported as written even though only part was kept: a program that prints too
	// much has not failed, and reporting a short write would make it look as though it had.
	if n != 16 {
		t.Errorf("Write reported %d bytes, want 16", n)
	}
	if got := buf.String(); got != "0123456789" {
		t.Errorf("retained %q, want %q", got, "0123456789")
	}

	if _, err := w.Write([]byte("more")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if buf.Len() != 10 {
		t.Errorf("buffer grew past the limit to %d bytes", buf.Len())
	}
}

// TestGuaranteeNoInvocationCanOutliveItsDeadline pins the bound that makes a timeout mean something.
//
// exec.CommandContext signals the direct child when a deadline fires, and nothing else. apt-get spawns
// dpkg, and dpkg inherits the pipes this package reads output from — so without a wait delay, Wait
// blocks on that pipe for as long as the surviving dpkg holds it, which on a large upgrade is many
// minutes past the timeout that was supposed to bound it. The helper hangs, and the agent sees a helper
// that has simply stopped answering.
//
// The property is asserted about the constants rather than by killing a real dpkg, because the failure
// mode needs a package transaction in flight and the regression it guards against is somebody removing
// one line.
func TestGuaranteeNoInvocationCanOutliveItsDeadline(t *testing.T) {
	if WaitDelay <= 0 {
		t.Fatal("WaitDelay is zero, so a program whose child holds the output pipes can block Wait " +
			"indefinitely and the invocation's timeout stops bounding anything")
	}
	if WaitDelay >= DefaultTimeout {
		t.Errorf("WaitDelay is %s and the default timeout is %s; the delay is meant to be the short "+
			"grace period after the deadline, not a second deadline", WaitDelay, DefaultTimeout)
	}
}

// runTestModeVar selects what this binary does when re-executed as a fixture process.
const runTestModeVar = "FARRIER_RUN_TEST_MODE"

// fixtureLifetime is how long a fixture process lives when nothing kills it first.
//
// It only has to be far past every bound the WaitDelay test asserts: if the wiring under test is
// deleted, this is how long Wait blocks on the held pipe, and the test must have failed its upper
// bound long before then.
const fixtureLifetime = 5 * time.Minute

// TestMain lets this binary stand in for the processes the WaitDelay test needs.
//
// The apt-get→dpkg shape — a direct child killed at the deadline while a grandchild it spawned keeps
// holding the output pipes — cannot be arranged with the allowlisted programs, which mostly do not
// exist on a build machine and none of which lingers on command. Re-executing the test binary in a
// named mode is the standard way to be one's own fixture process, and it keeps the arrangement inside
// the one package allowed to start processes at all.
func TestMain(m *testing.M) {
	switch os.Getenv(runTestModeVar) {
	case "spawn-a-pipe-holder":
		spawnAPipeHolder()
	case "hold-the-pipe":
		time.Sleep(fixtureLifetime)
	default:
		os.Exit(m.Run())
	}
}

// spawnAPipeHolder starts a grandchild inheriting this process's stdout and stderr, then waits to die.
//
// This process is the direct child CommandWith started, so its stdout and stderr are the pipes the
// caller reads. Handing them to a process that outlives this one is exactly what apt-get does with
// dpkg. The sleep only keeps this process alive until the caller's deadline kills it; the grandchild
// is what remains, holding the pipe.
func spawnAPipeHolder() {
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{runTestModeVar + "=hold-the-pipe"}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		os.Exit(1)
	}
	time.Sleep(fixtureLifetime)
}

// TestATimedOutInvocationReturnsPromptly is the same property observed rather than asserted.
//
// The shape is apt-get's, reproduced with real processes: the direct child is killed at the deadline
// and a grandchild it spawned keeps holding the output pipes. Both bounds below matter. The upper one
// is the property — Wait gives the pipes up once WaitDelay expires instead of blocking for as long as
// the grandchild lives. The lower one proves the shape was actually reproduced: a run with no
// pipe-holding grandchild returns well inside WaitDelay, and a test that could not tell the
// difference would keep passing with the WaitDelay wiring deleted — the previous version of this test
// did exactly that, timing a process that was already dead.
func TestATimedOutInvocationReturnsPromptly(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolving the test binary: %v", err)
	}

	// The test binary joins the allowlist for the duration of this test, which only an in-package
	// test can arrange. What is under test is what happens after exec, not who may be execed —
	// TestGuaranteeOnlyAllowlistedProgramsCanRun holds that line, and the entry is removed before it
	// could see it.
	program := Program(exe)
	if allowed[program] {
		t.Fatalf("%s is already allowlisted, which cannot be right", exe)
	}
	allowed[program] = true
	t.Cleanup(func() { delete(allowed, program) })

	// Generous room for the child to start the pipe holder before the deadline kills it; the lower
	// bound below catches the day it is not enough.
	const timeout = 2 * time.Second

	started := time.Now()
	_, err = CommandWith(context.Background(), Options{
		Timeout: timeout,
		Env:     []string{runTestModeVar + "=spawn-a-pipe-holder"},
	}, program)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("an invocation built to outlive its deadline reported success")
	}
	if elapsed < WaitDelay {
		t.Errorf("the invocation returned after %s, inside WaitDelay (%s), so no grandchild was "+
			"holding the pipes and the wait was never exercised", elapsed, WaitDelay)
	}
	if elapsed > timeout+WaitDelay+30*time.Second {
		t.Errorf("a timed-out invocation took %s to return; it must not linger past its wait delay", elapsed)
	}
}
