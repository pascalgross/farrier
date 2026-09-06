// Package prompt reads secrets and answers from a terminal, for the two commands that need them.
//
// It exists because both binaries now ask: `hostseal` for the passphrase that unlocks a signing key, and
// `hostseal-server accounts` for an operator's password. The alternative was a second copy of the shared
// reader below, and a second copy is the wrong thing to have here specifically — the bug it exists to
// prevent is silent, was diagnosed once already, and would be diagnosed again from scratch.
//
// The rule the whole package serves is one line long: **a passphrase or a password is never a
// command-line argument**, because argv is world-readable in ps and shows up in shell history.
// Everything here is what it costs to keep that true while still working in a script.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// input is the one reader every prompt in a process shares.
//
// One, and not one per prompt, because a buffered reader reads ahead. Two prompts with two readers
// meant the first swallowed the second's line and the second reported "no passphrase on standard
// input" while standard input plainly had one — which made a command whose second prompt is a
// confirmation impossible to script.
var input *bufio.Reader

// Line reads one line from the shared reader, without its terminator.
//
// End of input is an empty line rather than an error, and each caller decides what that means. For a
// passphrase it is a refusal; for a yes-or-no question it is a no.
func Line() (string, error) {
	if input == nil {
		input = bufio.NewReader(os.Stdin)
	}
	line, err := input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// Secret reads a passphrase or a password without echoing it.
//
// When standard input is not a terminal — a script, a CI job — it is read as a line instead, so that
// automation works without the tool pretending it can prompt. That is a deliberate accommodation
// rather than an oversight: refusing to work non-interactively would push people to put the secret on
// the command line, where every user on the machine can read it from the process list.
func Secret(message string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// A whole line rather than Fscanln, which stops at the first space — so a passphrase of four
		// words would have been silently truncated to one. Only the trailing newline is stripped:
		// leading and inner spaces are part of the secret.
		line, err := Line()
		if err != nil {
			return nil, fmt.Errorf("reading a passphrase from standard input: %w", err)
		}
		if line == "" {
			return nil, errors.New("no passphrase on standard input")
		}
		return []byte(line), nil
	}

	fmt.Fprint(os.Stderr, message)
	secret, err := term.ReadPassword(fd)
	// ReadPassword consumes the operator's Return without echoing it, so the line break has to be
	// written here — before the error check, or a failure leaves the next output glued to the prompt.
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("reading a passphrase: %w", err)
	}
	return secret, nil
}

// Confirm asks a yes-or-no question on the terminal.
//
// Anything other than an explicit yes is a no, including an empty line and a closed input. A signature
// authorises a machine to be rebooted; defaulting to yes on a stray newline would be the wrong way for
// this to be wrong.
func Confirm(message string) (bool, error) {
	fmt.Fprint(os.Stderr, message)

	// The shared reader, not a fresh one. A buffered reader created here would read past its own line
	// and take whatever followed with it — and the line before this one is a passphrase.
	answer, err := Line()
	if err != nil {
		return false, fmt.Errorf("reading the answer: %w", err)
	}
	// End of input is a no rather than an error: piping /dev/null at this command should decline
	// rather than authorise.
	return strings.EqualFold(strings.TrimSpace(answer), "y") ||
		strings.EqualFold(strings.TrimSpace(answer), "yes"), nil
}
