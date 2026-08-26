#!/bin/sh
# The container's entry point: create the certificate authority if this is a first start, then serve.
#
# `farrier-server serve` refuses to start without a CA, and tells you to run `ca init`. That is the
# right behaviour for a package install, where the two commands are two things an administrator does
# deliberately; it is friction in a container, where the first start is the install and there is nobody
# at a terminal to read the message. So the CA is created here when it is absent, and never touched when
# it is present — an existing authority is the one thing in this directory that must not be replaced,
# because every enrolled agent verifies this control plane against it.
set -eu

CA_DIR="${FARRIER_CA_DIR:-/var/lib/farrier-server/ca}"

# No arguments means serve, which is what CMD says and what an operator overriding `command:` in Compose
# usually means when they pass only flags.
if [ "$#" -eq 0 ]; then
	set -- serve
fi
case "$1" in
-*) set -- serve "$@" ;;
esac

if [ "$1" = "serve" ]; then
	shift
	if [ ! -f "$CA_DIR/ca.crt" ]; then
		echo "farrier-server: no certificate authority in $CA_DIR; creating one." >&2
		farrier-server ca init --ca-dir "$CA_DIR"
	fi
	# The defaults go in front of whatever the caller passed, because Go's flag package lets a later
	# occurrence win: `command: ["serve", "--addr", ":9443"]` overrides the address and keeps the rest.
	if [ -n "${FARRIER_AGENT_HOSTNAME:-}" ]; then
		set -- serve --addr "${FARRIER_ADDR:-:8443}" --ca-dir "$CA_DIR" \
			--tls-server-name "$FARRIER_AGENT_HOSTNAME" "$@"
	else
		set -- serve --addr "${FARRIER_ADDR:-:8443}" --ca-dir "$CA_DIR" "$@"
	fi
fi

# exec, so that the server is pid 1 and receives SIGTERM directly. Without it a stop would kill this
# shell and leave the control plane fifteen seconds of drain it never gets to use — which is when it
# finishes the alert mail and webhook deliveries that are already in flight.
exec farrier-server "$@"
