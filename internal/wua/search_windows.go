//go:build windows

package wua

import (
	"fmt"

	"github.com/pascalgross/farrier/internal/updatescan"
)

// searchCriteria is what Farrier asks Windows Update for, and every clause of it is deliberate.
//
// "IsInstalled=0" is the question: what is pending. "IsHidden=0" respects an administrator who has
// hidden an update on this host — Farrier reports what the machine's own owner has not already
// declined, and listing a hidden update would be arguing with them through a dashboard.
// "Type='Software'" excludes drivers, which are a different decision with a different risk and which
// no reasonable fleet tool reports as an outstanding patch.
//
// There is deliberately no severity clause. MsrcSeverity is a property of a returned update and not a
// criterion the search language accepts, so "security updates only" cannot be asked for here — it can
// only be decided afterwards, by classify, from what came back. That asymmetry is the honest reason
// Farrier reports a security *count* on Windows and refuses to *apply* a security-only subset.
const searchCriteria = "IsInstalled=0 and IsHidden=0 and Type='Software'"

// serverSelectionDefault is ssDefault: consult whatever update source this host is configured to use.
//
// This is the one setting in this package with a security consequence, and the alternative is the
// mistake. ssWindowsUpdate (2) reaches Microsoft's servers directly and would bypass a WSUS server the
// host's administrator chose — so a fleet governed by WSUS would be scanned against a different set of
// updates from the one it is actually offered, and Farrier would report numbers that contradict the
// organisation's own patching authority. Farrier follows the host; it does not overrule it.
const serverSelectionDefault = 0

// searchResultSucceeded and searchResultSucceededWithErrors are the two ISearchResult codes that carry
// usable results. Anything else means the list is not an answer.
const (
	searchResultSucceeded           = 2
	searchResultSucceededWithErrors = 3
)

// Scan asks Windows Update what is pending on this host.
//
// It returns a result rather than an error for a failed scan, because the caller's job is to serialise
// the outcome either way: "the scan could not run" is a fact the control plane needs, and
// losing it to a non-zero exit code would leave a host looking as though it had no updates pending. An
// error is returned only where the result could not be constructed at all.
//
// The whole operation is bounded by the caller's process lifetime rather than by a context. WUA offers
// no cancellation that is safe to use — IUpdateSearcher has BeginSearch and EndSearch for asynchronous
// work, but abandoning a synchronous Search mid-flight leaves the update session in a state Microsoft
// does not document — so the agent bounds this the way it bounds apt: by the deadline it gives the
// process it started, and by killing it if that expires.
func Scan(clientID string) (updatescan.ScanResult, error) {
	uninitialise, err := Initialize()
	if err != nil {
		return updatescan.ScanResult{}, err
	}
	defer uninitialise()

	session, err := NewUpdateSession()
	if err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}
	defer session.Release()

	// Identifying the caller is not decoration: it is what an administrator reading the Windows Update
	// log sees when they ask why a scan started, and an unnamed client is one they cannot trace back.
	if id, free, err := variantBSTR(clientID); err == nil {
		defer free()
		if _, err := call(session, SessionClientApplicationID, id); err != nil {
			// Not fatal. A scan that could not name itself is still a scan.
			_ = err
		}
	}

	searcherVar, err := call(session, SessionCreateUpdateSearcher)
	if err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}
	searcher := searcherVar.asObject()
	if searcher == nil {
		const why = "the update searcher could not be created"
		return updatescan.ScanResult{Complete: false, Error: why}, nil
	}
	defer searcher.Release()

	if _, err := call(searcher, SearcherServerSelection, variantI4(serverSelectionDefault)); err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}
	// Online. The scan reaches the host's configured update source and takes minutes; that cost is
	// accepted deliberately, because an offline scan answers a different and weaker question — what the
	// last scan found — with no documented statement of how stale it may be.
	if _, err := call(searcher, SearcherOnline, variantBool(true)); err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}

	criteria, free, err := variantBSTR(searchCriteria)
	if err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}
	defer free()

	resultVar, err := call(searcher, SearcherSearch, criteria)
	if err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}
	result := resultVar.asObject()
	if result == nil {
		return updatescan.ScanResult{Complete: false, Error: "the search returned no result object"}, nil
	}
	defer result.Release()

	if codeVar, err := call(result, ResultResultCode); err == nil {
		if code, ok := codeVar.asInt(); ok &&
			code != searchResultSucceeded && code != searchResultSucceededWithErrors {
			return updatescan.ScanResult{
				Complete: false,
				Error:    fmt.Sprintf("the search finished with result code %d", code),
			}, nil
		}
	}

	updatesVar, err := call(result, ResultUpdates)
	if err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}
	updates := updatesVar.asObject()
	if updates == nil {
		// An empty collection is a real answer: nothing is pending.
		return updatescan.ScanResult{Complete: true, Updates: []updatescan.Update{}}, nil
	}
	defer updates.Release()

	list, err := readUpdates(updates)
	if err != nil {
		return updatescan.ScanResult{Complete: false, Error: err.Error()}, nil
	}
	return updatescan.ScanResult{Complete: true, Updates: list}, nil
}

// maxUpdates bounds how many updates one scan reports.
//
// It matches collect.MaxPackages in spirit and is restated rather than imported, for the reason
// winapi's own cap is: this package sits below internal/collect and must not depend on it. A host with
// more pending updates than this has a problem the count already communicates.
const maxUpdates = 500

// readUpdates walks the collection and reads each update's reported properties.
//
// A failure on one update is skipped rather than fatal. WUA returns entries whose metadata is
// incomplete — superseded ones, ones whose category collection is empty — and a scan that gave up on
// the first of those would report nothing on the hosts most in need of reporting.
func readUpdates(collection *object) ([]updatescan.Update, error) {
	countVar, err := call(collection, CollectionCount)
	if err != nil {
		return nil, err
	}
	count, ok := countVar.asInt()
	if !ok || count < 0 {
		return nil, fmt.Errorf("wua: the update collection reported no usable count")
	}
	if count > maxUpdates {
		count = maxUpdates
	}

	out := make([]updatescan.Update, 0, count)
	for i := int32(0); i < count; i++ {
		itemVar, err := call(collection, CollectionItem, variantI4(i))
		if err != nil {
			continue
		}
		item := itemVar.asObject()
		if item == nil {
			continue
		}
		out = append(out, readUpdate(item))
		item.Release()
	}
	return out, nil
}

// readUpdate reads the properties of one update.
//
// Every read is best effort and an unreadable property leaves its field zero, because none of them is
// load-bearing on its own: an update with no title is still a pending update and still counts.
func readUpdate(item *object) updatescan.Update {
	u := updatescan.Update{}

	if v, err := call(item, UpdateTitle); err == nil {
		u.Title = v.asString()
	}
	if v, err := call(item, UpdateMsrcSeverity); err == nil {
		u.Severity = v.asString()
	}
	if v, err := call(item, UpdateIsDownloaded); err == nil {
		u.Downloaded = v.asBool()
	}
	if v, err := call(item, UpdateRebootRequired); err == nil {
		u.RebootRequired = v.asBool()
	}
	if v, err := call(item, UpdateKBArticleIDs); err == nil {
		if ids := v.asObject(); ids != nil {
			if kbs := readStrings(ids); len(kbs) > 0 {
				u.KB = "KB" + kbs[0]
			}
			ids.Release()
		}
	}

	var categoryIDs []string
	if v, err := call(item, UpdateCategories); err == nil {
		if cats := v.asObject(); cats != nil {
			u.Categories, categoryIDs = readCategories(cats)
			cats.Release()
		}
	}
	u.Security = classify(categoryIDs, u.Severity)
	return u
}

// readCategories returns a collection's category names and their identifiers.
//
// Both are returned because they answer different questions: the names are what an operator reads, and
// the identifiers are what classify decides on. Reporting only the names would leave the security
// count resting on a localised string.
func readCategories(collection *object) (names, ids []string) {
	countVar, err := call(collection, CategoriesCount)
	if err != nil {
		return nil, nil
	}
	count, ok := countVar.asInt()
	if !ok {
		return nil, nil
	}
	for i := int32(0); i < count; i++ {
		itemVar, err := call(collection, CategoriesItem, variantI4(i))
		if err != nil {
			continue
		}
		category := itemVar.asObject()
		if category == nil {
			continue
		}
		if v, err := call(category, CategoryName); err == nil {
			if name := v.asString(); name != "" {
				names = append(names, name)
			}
		}
		if v, err := call(category, CategoryID); err == nil {
			if id := v.asString(); id != "" {
				ids = append(ids, id)
			}
		}
		category.Release()
	}
	return names, ids
}

// readStrings reads an IStringCollection, which is how WUA returns the KB article list.
func readStrings(collection *object) []string {
	countVar, err := call(collection, StringsCount)
	if err != nil {
		return nil
	}
	count, ok := countVar.asInt()
	if !ok {
		return nil
	}
	var out []string
	for i := int32(0); i < count; i++ {
		v, err := call(collection, StringsItem, variantI4(i))
		if err != nil {
			continue
		}
		if s := v.asString(); s != "" {
			out = append(out, s)
		}
	}
	return out
}
