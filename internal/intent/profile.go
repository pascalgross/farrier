package intent

import "sort"

// Profile is the set of catalogue members one kind of host is willing to execute.
//
// It exists because "implemented" turned out to be two questions wearing one answer. Spec.Implemented
// is a property of the *build* — whether an executor was written — and it is a single global boolean,
// so it cannot say "this member has an executor on Linux and cannot have one on Windows". Adding a
// platform field to Spec would have made the catalogue's own sentence false: intent.go promises that a
// reviewer reads one file and knows the complete set of things the control plane can ask a host to do,
// and a per-platform column turns that into a set the reader has to compute.
//
// So the catalogue stays exactly as it is — ten members, one map, one expected-set literal — and the
// platform question is asked separately, here, against a second closed compile-time map. The two are
// checked against each other by the guarantee suite rather than kept in step by hand.
//
// A profile is chosen at link time, never at run time and never from the network. See the hostProfile
// constant in internal/agent, which is a const in a build-tagged file precisely so that nothing can
// assign to it.
type Profile string

// String returns the wire form of the profile, satisfying fmt.Stringer.
//
// It exists for the same reason Name.String does: log lines and error messages interpolate a profile
// without an explicit conversion, which is the sort of small friction that leads people to pass plain
// strings around instead.
func (p Profile) String() string { return string(p) }

// The profiles Farrier builds an agent for.
const (
	// ProfileLinux is every member of the catalogue, which is what an Ubuntu or Debian host runs.
	ProfileLinux Profile = "linux"

	// ProfileWindowsReadOnly is the read tier only, which is what a Windows host runs.
	//
	// The name says read-only rather than naming a release, because the restriction is not a gap
	// waiting to be filled in a later version. It follows from docs/SECURITY.md §12.2: local policy
	// sovereignty is enforced by a fresh root helper that re-reads the host's own policy, Windows has
	// nothing of that shape, and without it a privileged operation would rest on the agent process
	// alone. A Windows agent that grew a privileged tier would be a different security argument, not a
	// later release of this one.
	ProfileWindowsReadOnly Profile = "windows-read-only"
)

// profiles maps each profile to the members a host running it will execute.
//
// It is written out member by member rather than derived from the class, and that is deliberate.
// "Every read-class member" would mean a future read intent joins the Windows profile the moment it is
// added, with nobody deciding that it should — and the Windows read tier is exactly where that
// decision needs making, because packages.listUpgradable already shows that a member can be read-class
// on Linux and privileged work on Windows (docs/SECURITY.md §12.4). The guarantee suite checks the
// other direction, which is the one a literal cannot get wrong safely: nothing outside the read tier
// may appear here.
//
// Unexported with no mutating accessor, for the reason the catalogue itself is: a registry would make
// the set of things a host will do a property of what was linked in rather than of what is written
// here.
var profiles = map[Profile]map[Name]bool{
	ProfileLinux: {
		FactsCollect:           true,
		PackagesListUpgradable: true,
		ServicesList:           true,
		RebootCheckRequired:    true,
		PackagesApplySecurity:  true,
		PackagesApplyAll:       true,
		ServiceStart:           true,
		ServiceStop:            true,
		ServiceRestart:         true,
		HostReboot:             true,
	},
	ProfileWindowsReadOnly: {
		FactsCollect:           true,
		PackagesListUpgradable: true,
		ServicesList:           true,
		RebootCheckRequired:    true,
	},
}

// ValidProfile reports whether a profile is one this build knows.
//
// It exists because Profile is a string type, so a value that arrived from a heartbeat, a database
// column or a zero value can be anything. Every path that accepts a profile from outside this package
// must fail closed on it — and on the control plane, where a profile arrives over the wire, "unknown"
// must mean "gate nothing here and let the host refuse", never "allow everything".
func ValidProfile(p Profile) bool {
	_, ok := profiles[p]
	return ok
}

// InProfile reports whether a host running this profile will execute this intent.
//
// It returns false for an unknown profile and for an unknown intent, which is the safe direction for
// both: the caller that matters is the agent's acceptance check, and a profile it does not recognise
// must refuse work rather than wave it through.
func InProfile(p Profile, n Name) bool {
	members, ok := profiles[p]
	if !ok {
		return false
	}
	return members[n]
}

// ProfileMembers returns the members of a profile, ordered by name.
//
// The ordering is part of the contract rather than incidental, for the same reason All() is ordered:
// this feeds the capability listing and the guarantee suite's comparison, and a map's random iteration
// order would make both produce spurious diffs.
func ProfileMembers(p Profile) []Name {
	members := profiles[p]
	out := make([]Name, 0, len(members))
	for n := range members {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Profiles returns every known profile, ordered.
//
// It exists so that the guarantee suite and the documentation generator can walk the set without
// knowing what is in it, which is what keeps a new profile from being added with no test looking at it.
func Profiles() []Profile {
	out := make([]Profile, 0, len(profiles))
	for p := range profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
