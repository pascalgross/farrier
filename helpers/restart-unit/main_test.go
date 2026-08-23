package main

import (
	"testing"

	"github.com/pascalgross/farrier/internal/intent"
	"github.com/pascalgross/farrier/internal/privsep"
)

// TestGuaranteeTheActionFlagNamesOnlyUnitIntents asserts --action cannot reach anything else.
//
// The flag is the administrator's hand-run path into this helper. It maps three words onto three
// catalogue members through an explicit table rather than by building a name from the string, so no
// value of --action can name an intent outside the set this helper serves — and the socket path is
// checked separately, in Perform, against the same routing table the agent uses.
func TestGuaranteeTheActionFlagNamesOnlyUnitIntents(t *testing.T) {
	expected := map[string]intent.Name{
		"start":   intent.ServiceStart,
		"stop":    intent.ServiceStop,
		"restart": intent.ServiceRestart,
	}
	if len(actions) != len(expected) {
		t.Fatalf("there are %d actions, expected exactly %d", len(actions), len(expected))
	}
	for word, want := range expected {
		got, ok := actions[word]
		if !ok {
			t.Errorf("--action %s is no longer accepted", word)
			continue
		}
		if got != want {
			t.Errorf("--action %s names %q, expected %q", word, got, want)
		}
		if endpoint, ok := privsep.Endpoint(got); !ok || endpoint != privsep.RestartUnitSocket {
			t.Errorf("%q is served by %q rather than by this helper's socket", got, endpoint)
		}
	}
}

// TestEveryIntentThisHelperServesHasAVerb asserts the journal never reads "restart-unit: service.stop".
//
// verb is what an operator sees in the job result and in the journal. A catalogue member added to this
// helper's socket without a case here would fall through to the raw intent name, which is not wrong so
// much as it is the sort of small ugliness that signals nobody looked at the output.
func TestEveryIntentThisHelperServesHasAVerb(t *testing.T) {
	words := map[string]bool{"start": true, "stop": true, "restart": true}
	for _, name := range intent.Names() {
		endpoint, ok := privsep.Endpoint(name)
		if !ok || endpoint != privsep.RestartUnitSocket {
			continue
		}
		if !words[verb(name)] {
			t.Errorf("intent %q renders as %q, which is not a unit verb", name, verb(name))
		}
	}
}
