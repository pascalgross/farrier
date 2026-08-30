// Package wua reads pending Windows updates, and is the only package in Farrier that calls COM.
//
// It exists because there is no other way to ask the question. The registry does not hold the answer,
// DISM reports what is installed rather than what is pending, UsoClient.exe has no documented interface
// at all, and Microsoft declines to publish the schema of the offline scan file so that the Windows
// Update Agent stays the only supported reader. Enumerating updates means loading wuapi.dll and calling
// it, or not answering the question.
//
// docs/SECURITY.md §3 refuses a runtime code loader **in the agent**, and that refusal is kept
// literally: nothing here is reachable from farrier-agent. This package is linked only by
// cmd/farrier-update-scan, a short-lived unprivileged process that holds no credential, opens no
// socket, and writes one JSON document to its standard output before exiting.
// TestGuaranteeOnlyTheScanBinaryReachesCOM asserts the import graph, using the machinery that already
// keeps the signing backends away from managed-host binaries. The agent starts it through internal/run
// with a fixed argument vector, exactly as it starts apt-get on Linux — it does not parse apt's
// internals either.
//
// # The chokepoint
//
// comcall.go is a second exemption from the AST check in internal/intent, and it is paid for the same
// way internal/run paid for the first. A COM method call is a jump through a function pointer, which
// Go can only express as syscall.SyscallN; classifyExecCall sees a raw syscall, cannot read what it
// reaches, and refuses it — correctly, because "the check did not recognise it" must not be the same
// outcome as "the check found nothing wrong". What earns the exemption is that the compile-time
// property the check enforces is replaced by a stronger run-time one, in exactly one file:
//
//   - Only the classes in the classes table can be created. There is one.
//   - Only the methods in the methods table can be called. Anything else is refused by call() before a
//     function pointer is dereferenced.
//   - Only IDispatch vtable slots are used directly, and only the five that are fixed for every COM
//     object that has ever existed. Nothing here computes a per-interface offset, so no method is
//     reached by an index somebody remembered.
//
// And it buys something the Linux allowlist cannot state. internal/run's allowlist is about
// *identity*: apt-get may run, and what apt-get then does is whatever apt-get can do. The methods table
// is about *capability*: IUpdateDownloader and IUpdateInstaller appear nowhere in it, and
// TestGuaranteeTheMethodTableHoldsNoWriteCapability proves their absence. This process cannot download
// and cannot install, and that is a machine-checked fact rather than a claim about intent.
package wua

import (
	"errors"
	"fmt"
)

// ErrNotPermitted reports an attempt to reach a COM member that is not in the permitted set.
//
// It is distinguished from a COM failure because the two mean opposite things to whoever reads it: a
// COM failure is a host whose Windows Update stack is unwell, while this is a bug in this build that a
// test should have caught, and the guarantee suite exists so that it is caught.
var ErrNotPermitted = errors.New("wua: this COM member is not in the permitted set")

// Method is a COM method or property this package is permitted to invoke.
//
// It is a distinct string type carrying the interface as well as the member — "IUpdateSearcher.Search"
// rather than "Search" — so that the table reads as a statement about a surface rather than a list of
// verbs, and so that two interfaces with a same-named member cannot be confused for one entry.
type Method string

// The complete set of COM members this package may invoke.
//
// Written out rather than derived, and grouped by interface so that a reviewer can see the whole
// surface at once. The set is small because the question is small: create a session, make a searcher,
// point it at the host's configured update source, search for what is not installed, and read the title
// and a few properties of each result.
const (
	// On IUpdateSession, the only class this package creates.
	SessionClientApplicationID  Method = "IUpdateSession.ClientApplicationID"
	SessionCreateUpdateSearcher Method = "IUpdateSession.CreateUpdateSearcher"

	// On IUpdateSearcher.
	SearcherOnline          Method = "IUpdateSearcher.Online"
	SearcherServerSelection Method = "IUpdateSearcher.ServerSelection"
	SearcherSearch          Method = "IUpdateSearcher.Search"

	// On ISearchResult.
	ResultResultCode Method = "ISearchResult.ResultCode"
	ResultUpdates    Method = "ISearchResult.Updates"

	// On IUpdateCollection.
	CollectionCount Method = "IUpdateCollection.Count"
	CollectionItem  Method = "IUpdateCollection.Item"

	// On IUpdate.
	UpdateTitle          Method = "IUpdate.Title"
	UpdateMsrcSeverity   Method = "IUpdate.MsrcSeverity"
	UpdateIsDownloaded   Method = "IUpdate.IsDownloaded"
	UpdateCategories     Method = "IUpdate.Categories"
	UpdateKBArticleIDs   Method = "IUpdate.KBArticleIDs"
	UpdateRebootRequired Method = "IUpdate.RebootRequired"

	// On ICategoryCollection and ICategory, reached from IUpdate.Categories.
	CategoriesCount Method = "ICategoryCollection.Count"
	CategoriesItem  Method = "ICategoryCollection.Item"
	CategoryName    Method = "ICategory.Name"
	CategoryID      Method = "ICategory.CategoryID"

	// On IStringCollection, reached from IUpdate.KBArticleIDs.
	StringsCount Method = "IStringCollection.Count"
	StringsItem  Method = "IStringCollection.Item"
)

// invocation is how a member is reached: as a method call, a property read, or a property write.
//
// COM distinguishes these at the call site rather than in the name — the same DISPID is invoked with
// DISPATCH_METHOD, DISPATCH_PROPERTYGET or DISPATCH_PROPERTYPUT — so the table has to carry it. Getting
// it wrong is not a compile error and not always a run-time one, which is why it is data here rather
// than an argument a caller passes.
type invocation uint16

// The three ways a member is reached, with the values IDispatch::Invoke expects.
const (
	invokeMethod  invocation = 0x1
	invokePropGet invocation = 0x2
	invokePropPut invocation = 0x4
)

// member is what the table knows about one permitted COM member.
type member struct {
	// name is the member name as the type library spells it, passed to GetIDsOfNames.
	name string

	// how is the invocation kind. A property read and a method call are different operations on the
	// same identifier, and the table decides which this is rather than the caller.
	how invocation

	// args is the exact number of arguments the call must supply.
	//
	// It is checked rather than trusted because the argument count is what decides how many VARIANTs
	// Invoke reads from the DISPPARAMS array. A call that declared one argument and passed none would
	// have COM read a VARIANT from memory this package did not write, which is the one mistake in here
	// that would not announce itself.
	args int

	// writes marks a member that changes the host rather than reading it.
	//
	// Nothing in the table sets it today, and that is the point: it exists so that
	// TestGuaranteeTheMethodTableHoldsNoWriteCapability asserts a property of the table rather than a
	// list of names somebody has to keep in step. Setting it on an entry is the change that has to be
	// argued for in docs/SECURITY.md §12.3, not merely reviewed.
	writes bool
}

// methods is the closed set of COM members call() will dispatch, and the reason this file is exempt.
//
// A member that is not here has no route to a function pointer from this package, whatever an
// intermediate object's type library offers and however the object was obtained. That is the run-time
// property replacing the compile-time one the AST check enforces everywhere else, and
// TestGuaranteeOnlyTabledMethodsCanBeCalled proves it is actually enforced rather than merely written
// down.
//
// The two properties written to — Online and ServerSelection — are writes to this process's own
// searcher object and change nothing on the host. They are the settings that keep the scan honest:
// ServerSelection = ssDefault makes the host's own configured update source the one consulted, so a
// machine managed by WSUS is scanned against WSUS rather than against Microsoft's servers behind its
// administrator's back.
var methods = map[Method]member{
	SessionClientApplicationID:  {name: "ClientApplicationID", how: invokePropPut, args: 1},
	SessionCreateUpdateSearcher: {name: "CreateUpdateSearcher", how: invokeMethod, args: 0},

	SearcherOnline:          {name: "Online", how: invokePropPut, args: 1},
	SearcherServerSelection: {name: "ServerSelection", how: invokePropPut, args: 1},
	SearcherSearch:          {name: "Search", how: invokeMethod, args: 1},

	ResultResultCode: {name: "ResultCode", how: invokePropGet, args: 0},
	ResultUpdates:    {name: "Updates", how: invokePropGet, args: 0},

	CollectionCount: {name: "Count", how: invokePropGet, args: 0},
	CollectionItem:  {name: "Item", how: invokePropGet, args: 1},

	UpdateTitle:          {name: "Title", how: invokePropGet, args: 0},
	UpdateMsrcSeverity:   {name: "MsrcSeverity", how: invokePropGet, args: 0},
	UpdateIsDownloaded:   {name: "IsDownloaded", how: invokePropGet, args: 0},
	UpdateCategories:     {name: "Categories", how: invokePropGet, args: 0},
	UpdateKBArticleIDs:   {name: "KBArticleIDs", how: invokePropGet, args: 0},
	UpdateRebootRequired: {name: "RebootRequired", how: invokePropGet, args: 0},

	CategoriesCount: {name: "Count", how: invokePropGet, args: 0},
	CategoriesItem:  {name: "Item", how: invokePropGet, args: 1},
	CategoryName:    {name: "Name", how: invokePropGet, args: 0},
	CategoryID:      {name: "CategoryID", how: invokePropGet, args: 0},

	StringsCount: {name: "Count", how: invokePropGet, args: 0},
	StringsItem:  {name: "Item", how: invokePropGet, args: 1},
}

// permit is the check that earns this package its exemption, and it is deliberately not in the
// Windows-only half of the package.
//
// call() is guarded by a build tag, because a COM dispatch cannot compile anywhere else — and a check
// that only existed there would be a check no CI this project runs could execute. Every job in
// .github/workflows runs on ubuntu-latest, so an assertion living beside the syscall would be
// documentation rather than a test. Splitting the decision from the dispatch is what lets
// TestGuaranteeOnlyTabledMethodsCanBeCalled run on the machines that actually build this repository,
// and prove the refusal rather than describe it.
//
// It returns the member so that the caller cannot look it up a second time and get a different answer.
// A check that hands back nothing invites the call site to re-read the map, and two reads of one table
// is one more than a refusal needs.
func permit(m Method, argc int) (member, error) {
	spec, ok := methods[m]
	if !ok {
		return member{}, fmt.Errorf("%w: %s", ErrNotPermitted, m)
	}
	if argc != spec.args {
		return member{}, fmt.Errorf("wua: %s takes %d arguments, not %d", m, spec.args, argc)
	}
	if spec.writes {
		// Unreachable while the table holds no such entry, and kept as the last gate rather than as a
		// comment: a member marked as changing the host is a security decision that belongs in
		// docs/SECURITY.md §12.3, and until that is written this package refuses to dispatch it even if
		// somebody has added it to the table.
		return member{}, fmt.Errorf("%w: %s changes the host, which this process may not do",
			ErrNotPermitted, m)
	}
	return spec, nil
}

// Methods returns every permitted member, so that the guarantee suite can walk the table.
//
// It exists for the same reason internal/run exports its allowlist: an operator auditing what a Farrier
// binary can reach on their host should be able to ask the binary rather than read the source, and a
// test should assert against the real table rather than a copy of it.
func Methods() map[Method]string {
	out := make(map[Method]string, len(methods))
	for k, v := range methods {
		out[k] = v.name
	}
	return out
}

// WritesHost reports whether any permitted member changes the host rather than reading it.
//
// The answer is false and the guarantee suite requires it to stay false. It is a function rather than a
// constant so that it is computed from the table, which is the thing that would actually change.
func WritesHost() bool {
	for _, m := range methods {
		if m.writes {
			return true
		}
	}
	return false
}

// updateSessionCLSID is the only COM class this package will create.
//
// It is CLSID_UpdateSession from wuapi.h. Everything else this package touches is an object handed back
// by a call on an object that traces to this one, which is what makes a single entry here a bound on
// the whole graph rather than only on the first step: no CLSID that is not this one is ever passed to
// CoCreateInstance, so wuapi.dll is the only server this process asks the registry to load.
const updateSessionCLSID = "{4CB43D7F-7EEE-4906-8698-60DA1C38F2FE}"

// CreatableClasses returns the CLSIDs this package may create, for the guarantee suite.
//
// One entry, and a test asserts it stays one. IUpdateDownloader and IUpdateInstaller are not classes and
// cannot be created directly — they are reached only through IUpdateSession::CreateUpdateDownloader and
// ::CreateUpdateInstaller, neither of which is in the methods table — so the two tables together are
// what makes "this process cannot install anything" true rather than either alone.
func CreatableClasses() []string { return []string{updateSessionCLSID} }
