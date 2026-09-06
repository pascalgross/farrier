// Package collector holds the registry of extra fact collectors and the ones HostSeal ships.
//
// It is a separate package from internal/collect so that registering a collector cannot create an
// import cycle: a collector needs the types, and the fact gatherer needs the registry.
//
// Adding a fact means adding a file here and one Register call in its init. Nothing else in the
// codebase learns about it, which is the property docs/EXTENDING.md promises about this seam — and the
// registration is compile-time, because a collector is code that runs on every managed host and goes
// through the same review as anything else that does.
package collector

import (
	"sort"
	"sync"

	"github.com/pascalgross/hostseal/internal/collect"
)

// registry holds the registered collectors by name.
var registry = struct {
	// mu guards byName. Registration happens in init, but reading happens from the heartbeat loop, and
	// a lock is cheaper than reasoning about whether that will always be true.
	mu sync.RWMutex

	// byName is the registered set.
	byName map[string]collect.Collector
}{byName: map[string]collect.Collector{}}

// Register adds a collector, panicking on a duplicate name.
//
// A panic rather than an error because this runs in init: a duplicate name means two collectors would
// write the same key in the facts document, one silently winning, and a fleet reporting a fact nobody
// can account for is much worse than a binary that refuses to start.
func Register(c collect.Collector) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if _, exists := registry.byName[c.Name()]; exists {
		panic("collector: two collectors are registered as " + c.Name())
	}
	registry.byName[c.Name()] = c
}

// All returns every registered collector, ordered by name.
//
// The ordering is part of the contract: the facts document is digested and compared, and a map's random
// iteration order would make every heartbeat look like a change and defeat the digest-first design
// entirely.
func All() []collect.Collector {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	out := make([]collect.Collector, 0, len(registry.byName))
	for _, c := range registry.byName {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
