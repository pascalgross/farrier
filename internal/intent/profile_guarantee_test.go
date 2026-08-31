package intent

import "testing"

// TestGuaranteeEveryProfileMemberIsACatalogueMember keeps the two closed maps from drifting apart.
//
// profiles is a second literal beside the catalogue, and a second literal is a second place to be
// wrong. The failure it would produce is quiet in the worst direction: a profile naming an intent the
// catalogue no longer has would simply never match, so a renamed member would silently drop out of the
// set a Windows host executes and the only symptom would be jobs answered "unsupported_intent" by a
// host that ought to run them.
func TestGuaranteeEveryProfileMemberIsACatalogueMember(t *testing.T) {
	for _, profile := range Profiles() {
		members := ProfileMembers(profile)
		if len(members) == 0 {
			t.Errorf("profile %s has no members; a profile that permits nothing is not a profile, "+
				"it is a host that should not have been built", profile)
		}
		for _, name := range members {
			if !Has(name) {
				t.Errorf("profile %s names %q, which is not in the catalogue.\n"+
					"Renaming a catalogue member means renaming it here in the same commit; "+
					"a profile entry that matches nothing removes a capability with no error.",
					profile, name)
			}
		}
	}
}

// TestGuaranteeTheLinuxProfileIsTheWholeCatalogue pins the profile mechanism as additive-by-omission.
//
// The whole design rests on the Linux agent being unchanged by the introduction of profiles: an
// existing host must execute exactly what it executed before, so the profile check added to accept()
// can never be the reason a Linux job is refused. If a member is ever added to the catalogue and not to
// this profile, the effect is that every Linux host silently stops accepting it — which would look like
// a control-plane bug for as long as it took somebody to find this map.
func TestGuaranteeTheLinuxProfileIsTheWholeCatalogue(t *testing.T) {
	inProfile := map[Name]bool{}
	for _, name := range ProfileMembers(ProfileLinux) {
		inProfile[name] = true
	}
	for _, name := range Names() {
		if !inProfile[name] {
			t.Errorf("%q is in the catalogue and not in the linux profile.\n"+
				"Adding a catalogue member means adding it here in the same commit, or every Linux "+
				"host refuses it with unsupported_intent and nothing says why.", name)
		}
	}
	if len(inProfile) != len(Names()) {
		t.Errorf("the linux profile has %d members and the catalogue has %d",
			len(inProfile), len(Names()))
	}
}

// TestGuaranteeTheWindowsProfileHoldsOnlyReadIntents is the assertion the literal exists to allow.
//
// profiles is written out member by member rather than derived from the class, so that a future read
// intent does not join the Windows profile without anybody deciding it should. That choice is only safe
// in one direction: a literal can under-state the read tier harmlessly, and over-stating it — one
// destructive name typed into the wrong block — would give a Windows host a privileged operation with
// no root helper to bound it and no policy re-read behind it. docs/SECURITY.md §12.3 is what this
// enforces: without a privilege boundary of the same shape, §1's second and third clauses would rest on
// the agent process alone.
//
// It checks the class rather than a list of four names on purpose. A list would have to be edited
// alongside the profile, by the same hand, in the same commit — which is not a check, it is a copy.
func TestGuaranteeTheWindowsProfileHoldsOnlyReadIntents(t *testing.T) {
	members := ProfileMembers(ProfileWindowsReadOnly)
	if len(members) == 0 {
		t.Fatal("the windows profile is empty; this test would pass vacuously")
	}
	for _, name := range members {
		spec, ok := Lookup(name)
		if !ok {
			continue // reported by TestGuaranteeEveryProfileMemberIsACatalogueMember
		}
		if spec.Class != ClassRead {
			t.Errorf("the windows profile names %q, which is class %q.\n"+
				"A Windows host has no root helper, so there is nothing to re-read the host's own "+
				"policy and nothing to bound a privileged operation: it would rest on the agent "+
				"process alone. See docs/SECURITY.md §12.3. If this is now wrong, the change is a "+
				"security argument in that document, not an entry in this map.", name, spec.Class)
		}
		if spec.MayNotReturn {
			t.Errorf("the windows profile names %q, which can take the host away", name)
		}
	}
}

// TestGuaranteeAProfileNeverWidensAnUnknownOne pins the fail-closed direction of the lookup.
//
// InProfile is consulted by the agent's acceptance check, where the profile comes from a compiled-in
// constant and the intent from the network. A build carrying a profile string nothing recognises — a
// typo, a zero value, a future name reached by an older binary — must refuse every intent rather than
// permit every intent, and a boolean is exactly the shape of thing that gets inverted during a
// refactor without anybody noticing.
func TestGuaranteeAProfileNeverWidensAnUnknownOne(t *testing.T) {
	for _, unknown := range []Profile{"", "windows", "linux ", "WINDOWS-READ-ONLY", "all"} {
		if ValidProfile(unknown) {
			t.Errorf("%q is treated as a known profile", unknown)
		}
		if len(ProfileMembers(unknown)) != 0 {
			t.Errorf("%q has members", unknown)
		}
		for _, name := range Names() {
			if InProfile(unknown, name) {
				t.Errorf("profile %q permits %q; an unrecognised profile must permit nothing",
					unknown, name)
			}
		}
	}

	// And the known ones must not permit a name that is not an intent at all, which is the same
	// question asked from the other side: the agent looks up whatever arrived on the wire.
	for _, profile := range Profiles() {
		if InProfile(profile, "shell.exec") || InProfile(profile, "") {
			t.Errorf("profile %s permits a name that is not in the catalogue", profile)
		}
	}
}
