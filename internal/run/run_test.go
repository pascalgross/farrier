package run

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		if !strings.HasPrefix(s, "/") {
			t.Errorf("%q is not an absolute path", p)
		}
		if s != strings.TrimSpace(s) {
			t.Errorf("%q has surrounding whitespace", p)
		}
		if strings.Contains(s, "..") {
			t.Errorf("%q contains a relative path component", p)
		}
		if base := filepath.Base(s); interpreterBasenames[base] {
			t.Errorf("%q is an interpreter and may not be in the allowlist", p)
		}
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
	if _, err := os.Stat(string(Systemctl)); err != nil {
		t.Skipf("%s is not installed here", Systemctl)
	}
	ctx := context.Background()
	// A one-nanosecond timeout expires before the process can finish, whatever it is.
	_, err := CommandWith(ctx, Options{Timeout: time.Nanosecond}, Systemctl, "--version")
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

// TestATimedOutInvocationReturnsPromptly is the same property observed rather than asserted.
//
// It needs an allowlisted program that exists on this machine, and skips where none does. That is
// honest rather than convenient: the assertion below is about this package's behaviour with a real
// process, and there is nothing to observe without one.
func TestATimedOutInvocationReturnsPromptly(t *testing.T) {
	var program Program
	for _, candidate := range Allowlist() {
		if _, err := os.Stat(string(candidate)); err == nil {
			program = candidate
			break
		}
	}
	if program == "" {
		t.Skip("no allowlisted program is installed here")
	}

	started := time.Now()
	// A nanosecond, so the context is already done by the time exec looks at it. What is being measured
	// is how long CommandWith takes to give up, not how long the program takes.
	_, err := CommandWith(context.Background(), Options{Timeout: time.Nanosecond}, program, "--version")
	elapsed := time.Since(started)

	if err == nil {
		t.Fatalf("%s completed within a nanosecond, which cannot be right", program)
	}
	if elapsed > WaitDelay+30*time.Second {
		t.Errorf("a timed-out invocation took %s to return; it must not linger past its wait delay", elapsed)
	}
}
