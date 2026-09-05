//go:build linux

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/pascalgross/hostseal/internal/privsep"
)

// runService runs the agent loop under this platform's service manager.
//
// On Linux there is nothing to join: systemd starts the process, expects it to stay in the foreground,
// and asks it to stop with SIGTERM. So this is a signal handler and the loop, which is what the agent
// did before the function existed — the indirection is here so that Windows, where a service must
// register with the control manager and answer its messages, can differ without runCommand knowing.
func runService(loop func(context.Context) int) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return loop(ctx)
}

// privilegedEndpoints returns the helper sockets this build can reach, for the start-up log.
//
// An operator reading the first line in the journal should be able to see what privileged path this
// agent has, and on Linux that is the three sockets in /run/hostseal.
func privilegedEndpoints() []string { return privsep.Endpoints() }
