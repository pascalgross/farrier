// Package intent defines the closed catalogue of operations a HostSeal job can be.
//
// It exists to make one sentence of docs/SECURITY.md mechanically true: "the wire protocol carries an
// enumerated, typed operation — never a command string". Everything in this package is arranged so
// that a reviewer can read a single file and know the complete set of things the control plane is
// able to ask a host to do.
//
// Three properties are deliberate and are asserted by the guarantee test suite rather than left to
// convention:
//
//   - The catalogue is a compile-time map, not a registry. There is no Register function, no
//     configuration file that adds a member, and no way to reach it from a network message. New
//     intents arrive only as reviewed source changes, and the expected-set literal in
//     guarantee_test.go fails CI until it is updated in the same commit.
//   - Parameters decode into concrete Go types with strict JSON and a validator each, never into a
//     free-form map that some later layer interprets. A parameter that cannot be expressed as a
//     constrained value is a parameter this project does not accept.
//   - The package is shared verbatim by the agent and the control plane. Both sides therefore agree
//     about what an intent is by construction, rather than by two implementations that match until
//     they do not.
//
// All ten members have an executor. The last to arrive was packages.applySecurity, and the order was
// deliberate: it is the one *routine* member, and docs/PROTOCOL.md §5.1 says an agent MUST NOT execute
// one until it verifies a signature by the control plane's online key. The helper could always perform
// it; what was missing was that verification, and shipping the executor first would have made applying
// packages to a fleet an operation authorised by mTLS alone. The Implemented flag is what held it back,
// and the guarantee suite still requires a written reason beside any member that is ever held back
// again.
package intent

import (
	"fmt"
	"sort"
)

// Name is the wire identifier of a catalogue member, such as "services.list".
//
// It is a distinct type rather than a bare string so that a value arriving from the network cannot be
// passed where a program path, a unit name or a free-form label is expected. That mistake is exactly
// the class of bug this package exists to make impossible, and the compiler is cheaper at catching it
// than a reviewer is.
type Name string

// String returns the wire form of the name, satisfying fmt.Stringer.
//
// It exists so that log lines and error messages interpolate an intent without an explicit conversion
// at every call site, which is the sort of small friction that leads people to use plain strings.
func (n Name) String() string { return string(n) }

// The read-only members of the catalogue. They are unprivileged and unsigned: mTLS is sufficient
// authorisation because they read nothing an unprivileged local user could not read, and they change
// nothing.
const (
	// FactsCollect gathers host inventory: OS, kernel, hardware, network and uptime.
	FactsCollect Name = "facts.collect"

	// PackagesListUpgradable reports pending updates, split into security and regular.
	//
	// It is the one number this product exists to show, which is why the split is computed from
	// per-distribution origin patterns in internal/collect rather than from a single hard-coded
	// suffix that would be quietly wrong on Debian.
	PackagesListUpgradable Name = "packages.listUpgradable"

	// ServicesList reports systemd unit state.
	//
	// It reads over the D-Bus interface rather than parsing systemctl output, because systemctl has
	// no machine-readable mode: list-units ignores -o/--output, which selects a journal format.
	ServicesList Name = "services.list"

	// RebootCheckRequired reports whether the host needs a reboot, and which services still run
	// replaced libraries.
	//
	// It exists separately from FactsCollect because the answer changes on a different timescale than
	// the rest of the inventory, and because needrestart's answer — "which running processes still
	// hold the old OpenSSL" — is more actionable than the reboot marker most dashboards stop at.
	RebootCheckRequired Name = "reboot.checkRequired"
)

// The routine member of the catalogue. It is privileged and requires a signature from the control
// plane's online key, but not an offline one.
const (
	// PackagesApplySecurity applies updates from security origins only, subject to local policy.
	//
	// It is the single privileged operation that does not require an offline signature, because it is
	// what the host would do on its own unattended-upgrades timer anyway. The control plane can at
	// most make a host do sooner what its own policy already permits it to do unattended; a host with
	// allow = "none" refuses it outright.
	PackagesApplySecurity Name = "packages.applySecurity"
)

// The destructive members of the catalogue. Each requires a signature from a key in the host's own
// /etc/hostseal/trusted-signers, plus second-person approval in the control plane.
//
// There is deliberately no graded tier below this by blast radius. A design in which "small"
// destructive operations took weaker authorisation would weaken the claim to "cannot reboot your fleet
// in one action" without reducing the risk, since a control plane holding two operator accounts could
// simply walk the fleet host by host.
const (
	// PackagesApplyAll applies every available update, subject to local policy.
	PackagesApplyAll Name = "packages.applyAll"

	// ServiceStart starts a unit named on the local policy's restartable list.
	ServiceStart Name = "service.start"

	// ServiceStop stops a unit named on the local policy's restartable list.
	ServiceStop Name = "service.stop"

	// ServiceRestart restarts a unit named on the local policy's restartable list.
	ServiceRestart Name = "service.restart"

	// HostReboot reboots the host, subject to the local policy's reboot rule and window.
	//
	// It is the intent whose result must survive the operation itself: the job completes by the host
	// disappearing, so the agent fsyncs a pending result to disk before invoking the helper and
	// delivers it on next start.
	HostReboot Name = "host.reboot"
)

// Class is the authorisation tier of a catalogue member.
//
// It exists as a property of the intent rather than a field on the job so that the tier cannot be
// chosen by whoever sends the job. A control plane that could label host.reboot as "read" would defeat
// the signature requirement without ever touching the signature code.
type Class string

// The three authorisation tiers. See docs/SECURITY.md §3 for what each one means on the wire.
const (
	// ClassRead is unprivileged and unsigned; mTLS alone authorises it.
	ClassRead Class = "read"

	// ClassRoutine is privileged and signed by the control plane's online key.
	ClassRoutine Class = "routine"

	// ClassDestructive is privileged and signed by a key in the host's own trusted-signers file.
	ClassDestructive Class = "destructive"
)

// Privileged reports whether the class needs a root helper and a policy check.
//
// It exists so that the agent's dispatch path asks a question about the class instead of listing
// intent names, which is the pattern that rots the first time someone adds a member and forgets one
// of the lists.
func (c Class) Privileged() bool { return c == ClassRoutine || c == ClassDestructive }

// RequiresOfflineSignature reports whether a signature from the host's trusted-signers is required.
//
// The distinction matters at exactly one place — the agent's acceptance check — and returning it from
// the class keeps that place from re-deriving policy that belongs to the catalogue. A signature by the
// control plane's online key is never acceptable where this returns true.
func (c Class) RequiresOfflineSignature() bool { return c == ClassDestructive }

// RequiresOnlineSignature reports whether a signature by the control plane's own key is required.
//
// The counterpart of RequiresOfflineSignature, and deliberately not its negation: a read intent needs
// neither, and the two privileged tiers need different ones. Keeping both as questions the catalogue
// answers means the acceptance check asks rather than decides, and means no single boolean can be
// inverted somewhere and turn a destructive intent into one the control plane may authorise alone.
func (c Class) RequiresOnlineSignature() bool { return c == ClassRoutine }

// Valid reports whether the class is one of the three defined tiers.
//
// It exists because Class is a string type, so a zero value or a value decoded from JSON can be
// anything; every path that accepts a class from outside this package must fail closed on it.
func (c Class) Valid() bool {
	return c == ClassRead || c == ClassRoutine || c == ClassDestructive
}

// Spec is the complete definition of one catalogue member.
//
// It is a value rather than an interface so that the whole catalogue can be written as one map literal
// a reviewer reads top to bottom. An interface would let members be defined in files nobody thinks to
// open, which is the property the closed catalogue is meant not to have.
type Spec struct {
	// Name is the wire identifier.
	Name Name

	// Class is the authorisation tier.
	Class Class

	// Summary is one line of human-readable description, shown in the UI and in hostseal sign.
	Summary string

	// Implemented reports whether an executor exists behind this member on the agent.
	//
	// The agent refuses an unimplemented intent the same way it refuses an unknown one, which makes
	// this flag the last gate in front of a capability rather than a note about the roadmap. Setting it
	// is the act that gives a build the ability to do something to a host, and the guarantee suite
	// treats it that way: the expectation is written out member by member, with a reason for each
	// member that is false.
	Implemented bool

	// MayNotReturn reports that the operation can complete by the host disappearing, whatever its
	// parameters say.
	//
	// It exists as a property of the catalogue rather than a name the agent checks for, because the
	// consequence of forgetting it is silent: host.reboot completes by the machine going away, so an
	// agent that wrote its result afterwards would write nothing at all, and the job would sit in the
	// queue looking like a host that had gone quiet. The agent fsyncs a provisional result before
	// invoking anything marked this way, and the guarantee suite pins which members are.
	//
	// It is the floor and not the whole answer. Ask MayNotReturn, which also accounts for the
	// parameters, rather than reading this field directly.
	MayNotReturn bool

	// Decode parses and validates the intent's parameters.
	//
	// It is a required field — the guarantee suite fails if any member leaves it nil — because "this
	// intent happens to take no parameters" must be expressed as a decoder that rejects everything
	// except the empty object, not as an absent check that silently accepts whatever arrives.
	Decode func(raw []byte) (Params, error)
}

// catalogue is the complete, closed set of operations HostSeal can perform.
//
// It is unexported and has no mutating accessor on purpose: exporting the map, or providing a Register
// function, would turn the catalogue into a registry and make the set of possible operations a
// property of what was linked in rather than of what is written here.
var catalogue = map[Name]Spec{
	FactsCollect: {
		Name:        FactsCollect,
		Class:       ClassRead,
		Summary:     "Collect host inventory",
		Implemented: true,
		Decode:      decodeEmpty(FactsCollect),
	},
	PackagesListUpgradable: {
		Name:        PackagesListUpgradable,
		Class:       ClassRead,
		Summary:     "List upgradable packages, security separated from regular",
		Implemented: true,
		Decode:      decodeEmpty(PackagesListUpgradable),
	},
	ServicesList: {
		Name:        ServicesList,
		Class:       ClassRead,
		Summary:     "List systemd unit state",
		Implemented: true,
		Decode:      decodeEmpty(ServicesList),
	},
	RebootCheckRequired: {
		Name:        RebootCheckRequired,
		Class:       ClassRead,
		Summary:     "Check whether a reboot is required and which services need restarting",
		Implemented: true,
		Decode:      decodeEmpty(RebootCheckRequired),
	},

	PackagesApplySecurity: {
		Name:    PackagesApplySecurity,
		Class:   ClassRoutine,
		Summary: "Apply security updates, subject to local policy",
		// The only routine member, and the only one the control plane signs for itself. What bounds it
		// is not the signature but the host's own policy: updates.allow decides whether security
		// updates may be applied at all, and the root helper re-reads that file rather than trusting
		// the agent. So the worst a control plane can do with this intent is make a host do sooner what
		// it already permits itself to do unattended — which is what makes an online key acceptable
		// here and unacceptable for every member below. See docs/SECURITY.md §3.
		//
		// Its own decoder, not the one packages.applyAll uses. Sharing it let this intent carry
		// rebootIfRequired, which made the sentence above untrue: the worst a control plane could do
		// was reboot the host, using a key it holds itself.
		Implemented: true,
		Decode:      decodeApplySecurity,
	},

	PackagesApplyAll: {
		Name:        PackagesApplyAll,
		Class:       ClassDestructive,
		Summary:     "Apply all available updates, subject to local policy",
		Implemented: true,
		Decode:      decodeApplyAll,
	},
	ServiceStart: {
		Name:        ServiceStart,
		Class:       ClassDestructive,
		Summary:     "Start a systemd unit on the policy's restartable list",
		Implemented: true,
		Decode:      decodeUnit(ServiceStart),
	},
	ServiceStop: {
		Name:        ServiceStop,
		Class:       ClassDestructive,
		Summary:     "Stop a systemd unit on the policy's restartable list",
		Implemented: true,
		Decode:      decodeUnit(ServiceStop),
	},
	ServiceRestart: {
		Name:        ServiceRestart,
		Class:       ClassDestructive,
		Summary:     "Restart a systemd unit on the policy's restartable list",
		Implemented: true,
		Decode:      decodeUnit(ServiceRestart),
	},
	HostReboot: {
		Name:         HostReboot,
		Class:        ClassDestructive,
		Summary:      "Reboot the host, subject to the policy's reboot rule",
		Implemented:  true,
		MayNotReturn: true,
		Decode:       decodeReboot(HostReboot),
	},
}

// Lookup returns the spec for a name, and whether the name is in the catalogue.
//
// It is the only way to get from a value that arrived over the network to something HostSeal will act
// on, and it is deliberately a total function with a boolean rather than one that returns a
// zero-valued Spec: a caller that ignores the second result gets a Spec with an empty Class, which
// fails every subsequent check closed.
func Lookup(n Name) (Spec, bool) {
	s, ok := catalogue[n]
	return s, ok
}

// Has reports whether a name is in the catalogue.
//
// It exists for the call sites that only need membership — request validation, UI filtering — so that
// they do not carry an unused Spec around and tempt someone into using its zero value.
func Has(n Name) bool {
	_, ok := catalogue[n]
	return ok
}

// All returns every spec, ordered by name.
//
// The ordering is part of the contract rather than incidental: this feeds documentation generation and
// the guarantee test's comparison against the expected literal set, and a map's random iteration order
// would make both of those produce spurious diffs.
func All() []Spec {
	out := make([]Spec, 0, len(catalogue))
	for _, s := range catalogue {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns every catalogue name, ordered.
//
// It exists so that callers that only need the identifiers — the guarantee test, the API's capability
// listing — do not have to project All() and can be read without knowing what a Spec is.
func Names() []Name {
	out := make([]Name, 0, len(catalogue))
	for n := range catalogue {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// MayNotReturn reports whether this operation, with these parameters, can take the host away.
//
// The catalogue's own flag is a property of the intent and cannot see the parameters, and there is one
// operation where that is not enough: packages.applyAll with rebootIfRequired reboots the host at the
// end, exactly as host.reboot does, while its Spec quite correctly says that applying updates does not
// normally take a machine away. An agent that consulted only the Spec would skip the provisional result
// for that job, the host would reboot, and the job would sit in the queue looking like a host that had
// gone quiet — the failure the flag exists to prevent, arriving through the one path the flag cannot
// see.
//
// The alternative was to mark both apply intents unconditionally, which would spool a provisional
// "succeeded" for the great majority of update jobs that never reboot at all. That is a worse trade:
// the provisional record exists to be replaced, and one written for a job that was never going to need
// it is a claim of success sitting on disk for the length of a forty-minute upgrade.
func MayNotReturn(s Spec, p Params) bool {
	if s.MayNotReturn {
		return true
	}
	apply, ok := p.(ApplyParams)
	return ok && apply.RebootIfRequired
}

// Decode resolves a name and parses its parameters in one step.
//
// It exists so that the agent's job-acceptance path cannot accidentally decode parameters with the
// wrong intent's decoder, which would be a way to smuggle a unit name into an intent whose validator
// does not constrain it. Splitting the lookup from the decode makes that mistake possible; combining
// them makes it not.
func Decode(n Name, raw []byte) (Spec, Params, error) {
	s, ok := Lookup(n)
	if !ok {
		return Spec{}, nil, fmt.Errorf("intent: unknown intent %q", n)
	}
	p, err := s.Decode(raw)
	if err != nil {
		return Spec{}, nil, fmt.Errorf("intent: %s: %w", n, err)
	}
	return s, p, nil
}
