#!/bin/sh
# The container's entry point: create the certificate authority if this is a first start, then serve.
#
# `hostseal-server serve` refuses to start without a CA, and tells you to run `ca init`. That is the
# right behaviour for a package install, where the two commands are two things an administrator does
# deliberately; it is friction in a container, where the first start is the install and there is nobody
# at a terminal to read the message. So the CA is created here when it is absent, and never touched when
# it is present — an existing authority is the one thing in this directory that must not be replaced,
# because every enrolled agent verifies this control plane against it.
set -eu

CA_DIR="${HOSTSEAL_CA_DIR:-/var/lib/hostseal-server/ca}"

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
		echo "hostseal-server: no certificate authority in $CA_DIR; creating one." >&2
		hostseal-server ca init --ca-dir "$CA_DIR"
	fi
	# The defaults go in front of whatever the caller passed, because Go's flag package lets a later
	# occurrence win: `command: ["serve", "--addr", ":9443"]` overrides the address and keeps the rest.
	#
	# The agent hostname supplies two different settings and they are not the same setting. The first
	# is a name on the server's own certificate, so an agent's TLS verification succeeds. The second is
	# the address the enrolment instructions in the interface tell an operator to type — which cannot
	# be derived from the request, because the Traefik overlay serves that interface on a second
	# hostname where the agent API is deliberately refused.
	#
	# HOSTSEAL_AGENT_URL wins when it is set, for the deployment that reaches agents on a port other
	# than 443 or under a path prefix; the hostname is the shorthand for the ordinary case.
	if [ -n "${HOSTSEAL_AGENT_URL:-}" ]; then
		agent_url="$HOSTSEAL_AGENT_URL"
	elif [ -n "${HOSTSEAL_AGENT_HOSTNAME:-}" ]; then
		agent_url="https://$HOSTSEAL_AGENT_HOSTNAME"
	else
		agent_url=""
	fi

	if [ -n "$agent_url" ]; then
		set -- --agent-url "$agent_url" "$@"
	fi
	if [ -n "${HOSTSEAL_AGENT_HOSTNAME:-}" ]; then
		set -- --tls-server-name "$HOSTSEAL_AGENT_HOSTNAME" "$@"
	fi
	set -- serve --addr "${HOSTSEAL_ADDR:-:8443}" --ca-dir "$CA_DIR" "$@"
fi

# exec, so that the server is pid 1 and receives SIGTERM directly. Without it a stop would kill this
# shell and leave the control plane fifteen seconds of drain it never gets to use — which is when it
# finishes the alert mail and webhook deliveries that are already in flight.
exec hostseal-server "$@"
