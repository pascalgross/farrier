//go:build windows

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"
)

// ServiceName is the name the agent is registered under with the service control manager.
//
// It matches the name packaging/windows/Install-HostSealAgent.ps1 creates, and the virtual account the
// installer runs it as is derived from it: NT SERVICE\hostseal-agent. The two must agree, because the
// account exists only as a consequence of the service being registered under this name.
const ServiceName = "hostseal-agent"

// runService runs the agent loop, under the service control manager where there is one.
//
// The check is svc.IsWindowsService rather than a flag, because the answer is a property of how the
// process was started and not a claim its arguments should be able to make. Run from a console —
// installing, debugging, reading `hostseal-agent facts` — the agent behaves exactly as it does on Linux
// and stops on Ctrl+C. Started by the SCM it must register within its start-up deadline and answer
// control messages, or the SCM kills it and reports a service that failed to start.
func runService(loop func(context.Context) int) int {
	inService, err := svc.IsWindowsService()
	if err != nil {
		slog.Error("could not tell whether this process is a service", "error", err)
		return 1
	}
	if !inService {
		// SIGTERM is not delivered on Windows; Ctrl+C is what a console gets, and it arrives as
		// os.Interrupt.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return loop(ctx)
	}

	h := &serviceHandler{loop: loop}
	if err := svc.Run(ServiceName, h); err != nil {
		slog.Error("the service control manager rejected this service", "error", err)
		return 1
	}
	return h.code
}

// serviceHandler answers the service control manager on behalf of the agent loop.
//
// It exists because the SCM's contract is a conversation rather than a signal: the process must report
// StartPending, then Running, then answer Interrogate for as long as it lives, and move to StopPending
// before it goes. A service that simply exits on a stop request is reported as having crashed, which is
// what an operator would then be investigating instead of the shutdown they asked for.
type serviceHandler struct {
	// loop is the agent's own work, which runs until its context is cancelled.
	loop func(context.Context) int

	// code is what the loop returned, read after svc.Run has finished.
	//
	// It is a field rather than a return value because Execute's signature belongs to the svc package
	// and cannot carry it, and because the exit code is the one thing about the run that matters after
	// the handler is gone.
	code int
}

// Execute runs the agent under the service control manager and reports its state.
//
// AcceptStop and AcceptShutdown, and no more. AcceptPauseAndContinue is deliberately absent: pausing a
// fleet agent would mean a host that is enrolled, reachable and silently not reporting, which is the
// failure shape docs/SECURITY.md §8 exists to avoid — and the stop that *is* wanted, the one the control
// plane cannot override, is the paused marker file beside the policy.
func (h *serviceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	go func() { done <- h.loop(ctx) }()

	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case change := <-r:
			switch change.Cmd {
			case svc.Interrogate:
				// The SCM asks this periodically and expects its own view echoed back. Answering with a
				// state of this handler's own construction is how a healthy service ends up reported as
				// hung.
				s <- change.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				// Waited for rather than abandoned. The agent fsyncs a pending job result before an
				// operation that may not return, and returning here while that was in flight would be
				// the one case where the spool exists and does not help.
				h.code = <-done
				return false, uint32(h.code) //nolint:gosec // an exit code is small and non-negative.
			default:
				// An unrecognised control is ignored rather than treated as a stop. The SCM sends
				// device and power notifications to services that never asked for them.
				slog.Debug("ignoring an unrequested service control", "cmd", change.Cmd)
			}
		case code := <-done:
			// The agent stopped on its own — an unrecoverable error, or a context this handler did not
			// cancel. Reporting it as a service failure is what puts it in the event log and lets the
			// SCM's own restart policy apply.
			h.code = code
			return false, uint32(code) //nolint:gosec // an exit code is small and non-negative.
		}
	}
}

// privilegedEndpoints returns the helper sockets this build can reach, for the start-up log.
//
// There are none, and that is the design rather than a gap: a Windows agent executes only the read tier,
// so there is no privileged operation for a helper to perform. Returning nil rather than an empty
// non-nil slice makes the field absent from the log line instead of present and empty, which is the
// same distinction the facts document draws everywhere else. See docs/SECURITY.md §12.3.
func privilegedEndpoints() []string { return nil }
