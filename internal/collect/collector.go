package collect

import (
	"context"

	"github.com/pascalgross/farrier/internal/policy"
)

// Collector produces one named section of a host's fact report.
//
// It is the seam for adding a fact without touching the core. Collectors are read-only by construction
// and run as the unprivileged farrier user with no capabilities; a collector that needs root is not a
// collector, it is a request for a new intent, which is a different and much longer conversation.
//
// Registration is compile-time, in internal/collect/collector, and that is not a limitation the way it
// would be for a plugin API. A collector is code running on every managed host, so it goes through the
// same review as anything else that does.
type Collector interface {
	// Name is the key this collector's output appears under in the facts document.
	//
	// It has to be stable: it ends up in a JSON document that is digested, stored and compared, so
	// renaming one makes every host in a fleet look changed on the same afternoon.
	Name() string

	// Collect gathers this section, or reports why it could not.
	//
	// An error is not fatal to the report. A collector that fails leaves its section absent and its
	// reason in the journal, because a host missing one fact is far more useful than a host missing
	// from the fleet list.
	Collect(ctx context.Context) (any, error)
}

// PolicyGated is the optional half of the Collector seam, for a section a host may refuse to send.
//
// Most facts are not worth refusing: a unit list and a package count say nothing about a host that its
// hostname does not. Some are — container names and command lines are considerably more revealing than
// a unit list — and a host willing to report its package state has not thereby agreed to report those.
// A collector that says so implements this, and Gather asks before collecting.
//
// It is an optional interface rather than a parameter on Collect so that adding an ordinary collector
// stays a name and a function. It is asked of the policy rather than answered by the collector reading
// the policy file itself, because a collector that called policy.Load would be reading the file a
// second time, on its own schedule, with no guarantee of agreeing with the policy the rest of the
// agent is enforcing at that moment — and a fact reported under a permission that was withdrawn two
// minutes ago is a permission that was not withdrawn.
//
// A refused section is absent from the facts document, not empty. The host's policy travels in the
// same heartbeat, so a client can say "this host does not report containers" rather than "this host
// has none".
type PolicyGated interface {
	// PermittedBy reports whether the host's local policy allows this section to be reported.
	PermittedBy(p policy.Policy) bool
}

// CollectorFunc adapts a function to the Collector interface.
//
// It exists because most collectors are a name and a function, and requiring a struct for each would
// be ceremony with no reader benefit.
type CollectorFunc struct {
	// name is the key this collector's output appears under.
	name string

	// collect gathers the section.
	collect func(ctx context.Context) (any, error)
}

// NewCollectorFunc builds a Collector from a name and a function.
func NewCollectorFunc(name string, collect func(ctx context.Context) (any, error)) Collector {
	return CollectorFunc{name: name, collect: collect}
}

// Name is the key this collector's output appears under in the facts document.
func (c CollectorFunc) Name() string { return c.name }

// Collect gathers this section, or reports why it could not.
func (c CollectorFunc) Collect(ctx context.Context) (any, error) { return c.collect(ctx) }
