package collector

import (
	"context"
	"testing"

	"github.com/pascalgross/farrier/internal/collect"
	"github.com/pascalgross/farrier/internal/policy"
)

// containers returns the registered containers collector.
//
// It is looked up through All rather than constructed directly, because the thing worth asserting is
// that the registered collector behaves this way — a second instance built in the test would prove
// nothing about the one that runs on a host.
func containers(t *testing.T) collect.Collector {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "containers" {
			return c
		}
	}
	t.Fatal("no collector is registered as \"containers\"")
	return nil
}

// TestTheContainerSectionIsOffUntilAHostOptsIn is the shipped default, asserted rather than assumed.
//
// A gate that defaults on is not a gate. Container names describe what a business runs, and this is a
// disclosure a host makes to a control plane it may not own — the same reason trusted-signers ships
// empty. A change that flipped the default would otherwise be a one-word diff nobody caught.
func TestTheContainerSectionIsOffUntilAHostOptsIn(t *testing.T) {
	gated, ok := containers(t).(collect.PolicyGated)
	if !ok {
		t.Fatal("the containers collector is not policy-gated, so every host reports container state")
	}

	if gated.PermittedBy(policy.Default()) {
		t.Error("the built-in default reports container state")
	}
	if gated.PermittedBy(policy.Closed()) {
		t.Error("a host whose policy could not be read reports container state; a policy that failed " +
			"to load must disclose less, not more")
	}

	opted, err := policy.Parse([]byte("[containers]\nreport = true\n"))
	if err != nil {
		t.Fatalf("parsing a policy that opts in: %v", err)
	}
	if !gated.PermittedBy(opted) {
		t.Error("a host that wrote report = true does not report container state")
	}
}

// TestTheContainerCollectorAnswersOnAHostWithNoDocker covers the machine this runs on.
//
// TestTheShippedCollectorsRun executes every registered collector for real, so this collector has to
// return a usable, non-nil section wherever the tests happen to run — a laptop, a CI runner, a
// container with no cgroup delegation. Every way the scan can come up short is a fact the report
// itself states; an error would drop the section, which tells an operator nothing.
func TestTheContainerCollectorAnswersOnAHostWithNoDocker(t *testing.T) {
	section, err := containers(t).Collect(context.Background())
	if err != nil {
		t.Fatalf("the containers collector failed: %v", err)
	}
	report, ok := section.(collect.ContainerReport)
	if !ok {
		t.Fatalf("the section is %T, not a collect.ContainerReport", section)
	}
	if report.Containers == nil {
		t.Error("the container list is nil rather than an empty list; an absent section and a host " +
			"with no containers must not encode the same way")
	}
	if !report.ScanComplete && report.Note == "" {
		t.Error("an incomplete scan carries no note saying what stopped it")
	}
}
