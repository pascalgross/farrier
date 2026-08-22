// Command restart-unit is the root helper that starts, stops or restarts a systemd unit.
//
// It is installed as /usr/libexec/farrier/restart-unit and is reachable from the agent only through
// the fixed-argv entry in /etc/sudoers.d/farrier.
//
// The unit is a validated name, never a path. Accepting a path would let the agent point systemd at a
// unit file outside the system's own unit directories, which is a way to reach code that no policy
// list of unit names would catch. The name goes through the same catalogue decoder the agent used, on
// this side of the privilege boundary, and is then checked against services.restartable in the
// root-owned policy file.
//
// Phase 0 ships no write capability: the authorisation sequence is complete and the execution is
// absent.
package main

import (
	"flag"
	"fmt"

	"github.com/pascalgross/farrier/internal/buildinfo"
	"github.com/pascalgross/farrier/internal/helper"
	"github.com/pascalgross/farrier/internal/intent"
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

// main parses the fixed command line, enforces local policy, and would then act on the unit.
func main() {
	var (
		action   = flag.String("action", "", "start, stop or restart")
		unit     = flag.String("unit", "", "systemd unit name, for example nginx.service")
		jobID    = flag.String("job-id", "", "control-plane job id, recorded in the audit log")
		issuedAt = flag.String("issued-at", "", "RFC 3339 time the job was issued")
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

	name, ok := actions[*action]
	if !ok {
		helper.Fatalf(helper.ExitUsage, "--action must be start, stop or restart, got %q", *action)
	}

	params := helper.Dispatch(helper.Request{
		JobID:    *jobID,
		Intent:   name,
		Params:   helper.ParamsJSON(map[string]any{"unit": *unit}),
		IssuedAt: helper.ParseIssuedAt(*issuedAt),
	}, *dryRun)

	// Phase 1 replaces this with a systemd D-Bus call using the validated unit name from params, not
	// from the flag. Going through the decoded value is what guarantees the name that reaches systemd
	// is the one the catalogue's pattern accepted.
	helper.Fatalf(helper.ExitNotImplemented,
		"this build has no service executor: phase 0 ships no write capability. "+
			"Local policy permitted %q; nothing was changed.", params.Describe())
}
