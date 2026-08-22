package collector

import (
	"context"
	"testing"
)

// TestTheShippedCollectorsRun asserts every registered collector produces something.
//
// A collector that always fails would be invisible: Gather logs the failure and leaves the section
// absent, which is correct behaviour and looks exactly like a collector nobody registered.
func TestTheShippedCollectorsRun(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("no collectors are registered; the seam is documented in docs/EXTENDING.md as shipping one")
	}

	for _, c := range all {
		if c.Name() == "" {
			t.Error("a collector has no name; its output would have no key in the facts document")
		}
		section, err := c.Collect(context.Background())
		if err != nil {
			t.Errorf("%s: %v", c.Name(), err)
			continue
		}
		if section == nil {
			t.Errorf("%s returned no error and no section", c.Name())
		}
	}
}

// TestAllIsOrderedByName is the property the facts digest depends on.
//
// The facts document is digested and compared, so a map's random iteration order would make every
// heartbeat look like a change and defeat the digest-first design entirely.
func TestAllIsOrderedByName(t *testing.T) {
	first := All()
	for range 20 {
		next := All()
		if len(next) != len(first) {
			t.Fatalf("All returned %d collectors then %d", len(first), len(next))
		}
		for i := range next {
			if next[i].Name() != first[i].Name() {
				t.Fatalf("All is not stably ordered: %q then %q at position %d",
					first[i].Name(), next[i].Name(), i)
			}
		}
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].Name() >= first[i].Name() {
			t.Errorf("All is not ordered: %q precedes %q", first[i-1].Name(), first[i].Name())
		}
	}
}

// TestRegisterRefusesADuplicateName covers the panic, which is deliberate.
//
// Two collectors under one name means one silently wins and a fleet reports a fact nobody can account
// for. Registration happens in init, so refusing to start is much better than starting wrong.
func TestRegisterRefusesADuplicateName(t *testing.T) {
	existing := All()
	if len(existing) == 0 {
		t.Skip("nothing is registered to duplicate")
	}
	defer func() {
		if recover() == nil {
			t.Error("registering a duplicate name did not panic")
		}
	}()
	Register(existing[0])
}
