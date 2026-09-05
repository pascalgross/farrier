// Package updatescan is the data contract between the Windows update scan and whatever reads it.
//
// It exists because of one import. internal/collect/platform's Windows implementation needs the shape of
// the scan's result to parse it, and internal/wua is where that shape used to live — so importing the
// type pulled the COM code into the agent's import closure, and
// TestGuaranteeOnlyTheScanBinaryReachesCOM refused it. The refusal was right: docs/SECURITY.md §3 says
// there is no runtime plugin loader in the agent, ever, and "the DLL is only loaded lazily" is an
// argument about behaviour where the guarantee is about reachability.
//
// So the contract is here, where it has no dependencies at all, and internal/wua — which does the COM —
// is reachable only from cmd/hostseal-update-scan. A package holding nothing but types is the cheapest
// possible way to keep an import graph honest, and the alternative was to weaken the test that noticed.
package updatescan

// Update is one pending update, as the scan process reports it.
//
// It is a plain data type with no build tag because it is the contract across a process boundary: the
// scan binary writes it as JSON on Windows, and the platform implementation that reads it is compiled
// on every platform the repository builds. Keeping the shape here rather than in either end is what
// stops the two from drifting.
type Update struct {
	// Title is the update's own name, as Windows Update states it.
	Title string `json:"title"`

	// KB is the first knowledge-base article, such as "KB5034129", or empty.
	//
	// First rather than all: an update can carry several, and the one that identifies it is the one an
	// operator searches for. The rest are in the update's own description, which is not reported.
	KB string `json:"kb,omitempty"`

	// Categories are the update's classification names, such as "Security Updates".
	//
	// They are the closest Windows has to apt's release origins, and are reported for the same reason:
	// the classification is what decides the number this product exists to show, so an operator has to
	// be able to see what the classification actually was rather than only its conclusion.
	Categories []string `json:"categories,omitempty"`

	// Security reports whether Windows classifies this as a security update.
	//
	// See classify for what that means and where it is weaker than the apt answer.
	Security bool `json:"security"`

	// Severity is the MSRC severity, one of Critical, Important, Moderate or Low, or empty.
	//
	// Empty is the common case and not a failure. The property is documented with four values, and is
	// reported empty for the cumulative updates that make up most of what a Server host has pending —
	// which is why it informs the security classification rather than deciding it.
	Severity string `json:"severity,omitempty"`

	// Downloaded reports that the update is already staged locally and awaiting installation.
	Downloaded bool `json:"downloaded,omitempty"`

	// RebootRequired reports that installing this update will need a restart.
	RebootRequired bool `json:"rebootRequired,omitempty"`
}

// ScanResult is the whole document the scan process writes to its standard output.
//
// It carries its own failure rather than relying on an exit code alone, because the two failures a
// caller must distinguish look identical from outside: a scan that ran and found nothing pending, and a
// scan that could not run at all. The first is a fact about the host and the second is the absence of
// one, and collect.PackageReport.Incomplete exists on the Linux side for exactly this distinction.
type ScanResult struct {
	// Updates are the pending updates, empty where none are pending.
	Updates []Update `json:"updates"`

	// Complete reports that the scan ran to a conclusion.
	//
	// False means the numbers in this document are not an answer. The agent turns that into
	// PackageReport{Incomplete: true}, which is the same thing it reports on Linux when another process
	// holds the apt lock — a host in no position to claim it has nothing pending.
	Complete bool `json:"complete"`

	// Error is why the scan did not complete, for an operator reading a job result.
	Error string `json:"error,omitempty"`

	// Source names where the update metadata came from, such as "Windows Update" or "WSUS".
	//
	// It is reported because it changes what the numbers mean. A host managed by WSUS is told about a
	// different set of updates from one talking to Microsoft directly, and an operator comparing two
	// hosts needs to know which they are looking at before concluding that one is behind.
	Source string `json:"source,omitempty"`
}
