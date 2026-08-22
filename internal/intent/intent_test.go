package intent

import (
	"errors"
	"testing"
)

// TestLookupReturnsFalseForUnknownNames asserts the membership half of Lookup.
//
// It is separate from the guarantee suite because it tests the accessor's behaviour rather than the
// catalogue's contents: a Lookup that returned ok for anything would make every downstream check
// pass vacuously, and that failure would not be visible in the catalogue itself.
func TestLookupReturnsFalseForUnknownNames(t *testing.T) {
	if _, ok := Lookup("no.such.intent"); ok {
		t.Error("Lookup reported an unknown intent as present")
	}
	spec, ok := Lookup(ServicesList)
	if !ok {
		t.Fatal("Lookup did not find services.list")
	}
	if spec.Name != ServicesList || spec.Class != ClassRead {
		t.Errorf("Lookup returned %+v for services.list", spec)
	}
}

// TestAllIsOrderedByName asserts the ordering contract of All.
//
// The ordering feeds documentation generation and the guarantee comparison, both of which would
// produce spurious diffs on a map's random iteration order.
func TestAllIsOrderedByName(t *testing.T) {
	specs := All()
	if len(specs) == 0 {
		t.Fatal("All returned nothing")
	}
	for i := 1; i < len(specs); i++ {
		if specs[i-1].Name >= specs[i].Name {
			t.Errorf("All is not ordered: %q precedes %q", specs[i-1].Name, specs[i].Name)
		}
	}
	if len(Names()) != len(specs) {
		t.Errorf("Names returned %d entries, All returned %d", len(Names()), len(specs))
	}
}

// TestDecodeAcceptsWellFormedParameters covers the happy path of each parameter shape.
//
// The guarantee suite proves that hostile input is refused, which is the property that matters, but a
// decoder that refused everything would satisfy it just as well. This is the test that stops the
// catalogue from being safe by being useless.
func TestDecodeAcceptsWellFormedParameters(t *testing.T) {
	cases := []struct {
		name     Name
		raw      string
		describe string
	}{
		{FactsCollect, `{}`, "facts.collect"},
		{ServicesList, ``, "services.list"},
		{ServiceRestart, `{"unit":"nginx.service"}`, "service.restart nginx.service"},
		{PackagesApplySecurity, `{"rebootIfRequired":false}`, "packages.applySecurity"},
		{PackagesApplyAll, `{"rebootIfRequired":true}`, "packages.applyAll (reboot if required)"},
		{HostReboot, `{"delaySeconds":60,"message":"kernel update"}`, `host.reboot in 60s ("kernel update")`},
		{HostReboot, `{}`, "host.reboot"},
	}
	for _, tc := range cases {
		spec, params, err := Decode(tc.name, []byte(tc.raw))
		if err != nil {
			t.Errorf("Decode(%q, %q) failed: %v", tc.name, tc.raw, err)
			continue
		}
		if spec.Name != tc.name {
			t.Errorf("Decode(%q) returned spec for %q", tc.name, spec.Name)
		}
		if params.Intent() != tc.name {
			t.Errorf("Decode(%q) returned params for %q", tc.name, params.Intent())
		}
		if got := params.Describe(); got != tc.describe {
			t.Errorf("Decode(%q, %q).Describe() = %q, want %q", tc.name, tc.raw, got, tc.describe)
		}
	}
}

// TestDecodeRejectsOutOfRangeRebootDelay covers the one numeric bound in the catalogue.
//
// It exists because numeric parameters are the ones people forget to constrain: a string parameter
// visibly needs a pattern, whereas an int looks harmless until it is a delay long enough that the
// reboot an operator authorised happens after the maintenance window closed.
func TestDecodeRejectsOutOfRangeRebootDelay(t *testing.T) {
	for _, raw := range []string{`{"delaySeconds":-1}`, `{"delaySeconds":3601}`} {
		if _, _, err := Decode(HostReboot, []byte(raw)); err == nil {
			t.Errorf("Decode(host.reboot, %s) was accepted", raw)
		}
	}
}

// TestUnknownFieldErrorIsIdentifiable asserts callers can distinguish a strictness failure.
//
// The control plane needs to tell an operator "your job carried a field this agent does not know"
// differently from "your job was malformed", because the first one usually means an agent that is
// older than the UI that produced the job, and that is an upgrade, not a bug.
func TestUnknownFieldErrorIsIdentifiable(t *testing.T) {
	_, _, err := Decode(ServiceRestart, []byte(`{"unit":"nginx.service","force":true}`))
	if err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("error %v does not wrap ErrUnknownField", err)
	}
}

// TestClassPredicatesAreConsistent asserts the class helpers agree with each other.
//
// Privileged and RequiresOfflineSignature are asked at different points in the agent's acceptance
// path, and a disagreement between them would mean an intent that needed a root helper but not a
// signature, which is the exact hole the destructive tier exists to close.
func TestClassPredicatesAreConsistent(t *testing.T) {
	for _, c := range []Class{ClassRead, ClassRoutine, ClassDestructive} {
		if !c.Valid() {
			t.Errorf("class %q reports itself invalid", c)
		}
		if c.RequiresOfflineSignature() && !c.Privileged() {
			t.Errorf("class %q demands an offline signature but is not privileged", c)
		}
	}
	for _, c := range []Class{"", "admin", "READ", "destructive "} {
		if c.Valid() {
			t.Errorf("class %q reports itself valid", c)
		}
		if c.Privileged() || c.RequiresOfflineSignature() {
			t.Errorf("unknown class %q does not fail closed", c)
		}
	}
}
