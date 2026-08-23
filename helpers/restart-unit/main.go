// Command restart-unit is the root helper that starts, stops or restarts a systemd unit.
//
// It is installed as /usr/libexec/farrier/restart-unit and is reachable from the agent only through the
// socket its unit is activated on, /run/farrier/restart-unit.sock, which is owned root:farrier and mode
// 0660. The agent's own sandbox is what makes that necessary rather than sudo: with NoNewPrivileges in
// force, execve drops the setuid bit and sudo cannot become root at all. See internal/privsep.
//
// The unit is a validated name, never a path. Accepting a path would let the agent point systemd at a
// unit file outside the system's own unit directories, which is a way to reach code that no policy list
// of unit names would catch. The name goes through the same catalogue decoder the agent used, on this
// side of the privilege boundary, and is then checked against services.restartable in the root-owned
// policy file.
//
// The operation is a D-Bus call rather than an invocation of systemctl. That is the same choice the
// agent makes when reading unit state, for a different reason: here the point is that a unit name
// passed over D-Bus is a typed argument to a method, never a token on a command line, so there is no
// layer between this program and systemd that could interpret it.
package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"

	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/helper"
	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/privsep"
)

// actions maps the helper's --action flag to the catalogue member it corresponds to.
//
// The mapping is explicit rather than derived by string concatenation so that no value of --action can
// name an intent that is not one of these three.
var actions = map[string]intent.Name{
	"start":   intent.ServiceStart,
	"stop":    intent.ServiceStop,
	"restart": intent.ServiceRestart,
}

// jobMode is the systemd job mode every unit operation here uses.
//
// "replace" cancels a conflicting job already queued for the same unit, which is what systemctl does
// and what an operator asking for a restart means. "fail" would refuse whenever the host happened to be
// mid-operation on that unit — a race that would surface as an intermittent job failure nobody could
// reproduce.
const jobMode = "replace"

// unitJobTimeout bounds how long the helper waits for systemd to finish the job.
//
// It is well under the two minutes internal/privsep allows a service operation, so a unit whose
// ExecStop hangs produces a helper that says so rather than an agent that gives up on a helper still
// waiting. systemd applies its own TimeoutStopSec to the unit underneath; this is the bound on waiting
// for systemd itself to report back.
const unitJobTimeout = 90 * time.Second

// main parses the fixed command line and either answers the socket or performs one operation.
func main() {
	var (
		action   = flag.String("action", "", "start, stop or restart")
		unit     = flag.String("unit", "", "systemd unit name, for example nginx.service")
		jobID    = flag.String("job-id", "", "control-plane job id, recorded in the audit log")
		issuedAt = flag.String("issued-at", "", "RFC 3339 time the job was issued")
		serve    = flag.Bool("serve", false, "answer one request from the socket systemd activated")
		dryRun   = flag.Bool("dry-run", false, "evaluate policy and print the decision, changing nothing")
		version  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println("farrier restart-unit " + buildinfo.String())
		return
	}
	if flag.NArg() > 0 {
		helper.Fatalf(helper.ExitUsage, "takes no positional arguments, got %q", flag.Args())
	}
	helper.SetupLogging("restart-unit")

	h := helper.Helper{
		Component: "restart-unit",
		Socket:    privsep.RestartUnitSocket,
		Execute:   act,
	}
	if *serve {
		h.Serve()
		return
	}

	name, ok := actions[*action]
	if !ok {
		helper.Fatalf(helper.ExitUsage, "--action must be start, stop or restart, got %q", *action)
	}
	h.Main(helper.Request{
		JobID:    *jobID,
		Intent:   name,
		Params:   helper.ParamsJSON(map[string]any{"unit": *unit}),
		IssuedAt: helper.ParseIssuedAt(*issuedAt),
	}, *dryRun)
}

// act starts, stops or restarts the unit named in the validated parameters.
//
// The name comes from job.Params and never from the command line, which is what guarantees the value
// reaching systemd is the one the catalogue's pattern accepted. The two are the same string today; they
// stop being the same string the moment somebody adds a convenience to the flag parsing, and this is
// the shape that survives that.
func act(ctx context.Context, job helper.Job) (string, error) {
	unit, ok := job.Params.(intent.UnitParams)
	if !ok {
		return "", fmt.Errorf("restart-unit: %s did not decode to a unit name", job.Intent)
	}

	ctx, cancel := context.WithTimeout(ctx, unitJobTimeout)
	defer cancel()

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("restart-unit: connecting to systemd over D-Bus: %w", err)
	}
	defer conn.Close()

	// Buffered, so that systemd's reply does not block on a receiver that has gone away with the
	// context. An unbuffered channel here would leak the goroutine go-systemd uses to deliver it.
	finished := make(chan string, 1)
	switch job.Intent {
	case intent.ServiceStart:
		_, err = conn.StartUnitContext(ctx, unit.Unit, jobMode, finished)
	case intent.ServiceStop:
		_, err = conn.StopUnitContext(ctx, unit.Unit, jobMode, finished)
	case intent.ServiceRestart:
		_, err = conn.RestartUnitContext(ctx, unit.Unit, jobMode, finished)
	default:
		// Unreachable while Perform checks the intent against this helper's socket, and kept as a hard
		// failure rather than a silent success so that serving a fourth intent from here would be a
		// visible error rather than an operation that reported success having done nothing.
		return "", fmt.Errorf("restart-unit: %s is not a unit operation", job.Intent)
	}
	if err != nil {
		return "", fmt.Errorf("restart-unit: asking systemd to %s %s: %w", verb(job.Intent), unit.Unit, err)
	}

	select {
	case result := <-finished:
		// systemd reports the outcome as a string rather than as an error, and "done" is the only one
		// that means the unit is now in the state that was asked for. Treating anything else as success
		// would report a job that timed out or was cancelled as having worked.
		if result != "done" {
			return fmt.Sprintf("systemd reported %q", result),
				fmt.Errorf("restart-unit: systemd could not %s %s: %s", verb(job.Intent), unit.Unit, result)
		}
		return fmt.Sprintf("%s %s: done", verb(job.Intent), unit.Unit), nil
	case <-ctx.Done():
		return "", fmt.Errorf("restart-unit: systemd did not finish the %s of %s within %s: %w",
			verb(job.Intent), unit.Unit, unitJobTimeout, ctx.Err())
	}
}

// verb renders a unit intent as the word an operator reading a journal expects.
func verb(n intent.Name) string {
	switch n {
	case intent.ServiceStart:
		return "start"
	case intent.ServiceStop:
		return "stop"
	case intent.ServiceRestart:
		return "restart"
	default:
		return string(n)
	}
}
