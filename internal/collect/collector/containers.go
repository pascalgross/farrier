package collector

import (
	"context"

	"github.com/pascalgross/hostseal/internal/collect"
	"github.com/pascalgross/hostseal/internal/policy"
)

// containersCollector reports the Docker containers visible on this host, without the docker group.
//
// It exists because on the machines HostSeal is aimed at the systemd view is close to content-free:
// docker.service is active, and whether the thing the machine exists to run is up is visible nowhere.
// The answer here is deliberately the smaller one. Container state lives behind /var/run/docker.sock,
// which is root:docker, and the two ways to reach it are both refused — the agent is never added to
// the docker group, because docs/SECURITY.md §6 says socket access is root equivalence, and there is no
// fourth root helper, because docs/SECURITY.md §3 says there are exactly three and the guarantee suite
// enforces it. So this reads /proc and /sys/fs/cgroup as the unprivileged hostseal user, which needs no
// privilege at all and produces no image names, no exit codes and no restart counts.
//
// What it does produce is the part an operator would otherwise have to take on trust: which containers
// run as root, which hold the full capability set, which have no seccomp filter, and which have the
// Docker socket mounted into them. That last one is the same root equivalence, one layer down, found on
// a host rather than assumed from a deployment manifest nobody has read.
//
// It is a struct rather than a CollectorFunc because it is the first collector with something to say
// about the policy, and PolicyGated is a method rather than a closure field.
type containersCollector struct{}

// init registers the containers collector.
func init() {
	Register(containersCollector{})
}

// Name is the key this collector's output appears under in the facts document.
func (containersCollector) Name() string { return "containers" }

// Collect reads the host's container state from /proc and the cgroup tree.
//
// It never returns an error. Every way the scan can come up short — no Docker installed, a cgroup
// controller that is not enabled, a /proc this agent cannot see into — is a fact the report itself
// states, and an error would instead drop the section entirely and tell an operator nothing.
func (containersCollector) Collect(context.Context) (any, error) {
	return collect.CollectContainers(), nil
}

// PermittedBy reports whether the host's local policy allows container state to be reported.
//
// It is false unless `[containers] report = true` is written in /etc/hostseal/policy.toml. That default
// is the point rather than caution: a host that reports its package state has not thereby agreed to
// tell the control plane what its owner's business runs, and the shipped answer to a question nobody
// has been asked is no.
func (containersCollector) PermittedBy(p policy.Policy) bool { return p.Containers.Report }
