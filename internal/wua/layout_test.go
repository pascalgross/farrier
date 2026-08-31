package wua

import (
	"testing"
	"unsafe"
)

// TestGuaranteeTheVariantLayoutMatchesWindows is what the linter exclusion is bought with.
//
// .golangci.yml excludes comcall_windows.go from govet's unsafeptr check and from gosec, on the grounds
// that the conversions there are safe for a reason a linter cannot see: the memory belongs to oleaut32's
// allocator rather than to Go's heap. That argument holds only while the structures Go declares actually
// match the ones Windows writes. A VARIANT whose value slot sat at the wrong offset would read a BSTR
// pointer out of the reserved words, and the failure would be a crash or worse in a process that had
// just been told a linter was satisfied.
//
// It is a compile-time-shaped test rather than a round trip, because a round trip needs Windows and this
// runs on the Linux machines that build the repository. What it can check is exactly what could be wrong
// by hand: sizes and offsets.
//
// The expected numbers are the documented 64-bit layout. VARIANT is twenty-four bytes — a two-byte type
// tag, three reserved words, and an eight-byte value, padded out by the sixteen-byte DECIMAL member of
// the union — and the value slot begins at offset eight.
func TestGuaranteeTheVariantLayoutMatchesWindows(t *testing.T) {
	var v variant

	if got, want := unsafe.Sizeof(v), uintptr(24); got != want {
		t.Errorf("sizeof(variant) is %d, want %d.\n"+
			"COM writes a VARIANT into memory this package allocates. A structure of the wrong size "+
			"means Invoke writes past it or reads a value that was never written.", got, want)
	}
	if got, want := unsafe.Offsetof(v.vt), uintptr(0); got != want {
		t.Errorf("variant.vt is at offset %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(v.val), uintptr(8); got != want {
		t.Errorf("variant.val is at offset %d, want %d.\n"+
			"Every read in this package is guarded by the type tag and then takes this slot. At the "+
			"wrong offset it would read a BSTR pointer out of the reserved words.", got, want)
	}

	// DISPPARAMS is the other structure COM reads from this package's memory. Two pointers and two
	// unsigned counts: twenty-four bytes on a 64-bit machine, with the counts after the pointers.
	var p dispParams
	if got, want := unsafe.Sizeof(p), uintptr(24); got != want {
		t.Errorf("sizeof(dispParams) is %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(p.argc), uintptr(16); got != want {
		t.Errorf("dispParams.argc is at offset %d, want %d.\n"+
			"This field is how many VARIANTs Invoke reads out of the argument array. Read from the "+
			"wrong offset it is whatever happened to be in memory.", got, want)
	}
	if got, want := unsafe.Offsetof(p.namedArgc), uintptr(20); got != want {
		t.Errorf("dispParams.namedArgc is at offset %d, want %d", got, want)
	}
}

// TestGuaranteeVariantBoolUsesCOMsTrue pins the one constant that is wrong in the obvious spelling.
//
// VARIANT_BOOL's true is -1, not 1. A VARIANT_BOOL set to 1 is neither true nor false to most COM
// implementations, and the ones that accept it do so by accident — so an agent built against one of
// those would work everywhere the author tested and fail on somebody's server.
//
// It matters at exactly one call site, and that call site is not a detail: put_Online decides whether
// the update scan reaches the host's configured update source at all. A silently-false Online would make
// every host report the results of whenever Windows last scanned on its own, with no indication that
// Farrier had not asked.
func TestGuaranteeVariantBoolUsesCOMsTrue(t *testing.T) {
	if variantTrue != -1 {
		t.Errorf("variantTrue is %d; COM's VARIANT_BOOL true is -1", variantTrue)
	}
	if variantFalse != 0 {
		t.Errorf("variantFalse is %d; COM's VARIANT_BOOL false is 0", variantFalse)
	}
}

// TestGuaranteeTheCOMConstantsMatchTheHeaders pins the numbers Microsoft's headers define.
//
// Every constant here is a value from wtypes.h or oaidl.h that Go has no way to check. Getting one
// wrong does not fail to compile and mostly does not fail at all — it produces a call that COM accepts
// and answers differently from the one that was meant, on a machine nobody in this project owns.
//
// It also keeps them visible to the linter. `unused` runs against the Linux build, where the callers are
// behind a build tag, so without this every one of these reads as dead code — and the tempting fix, a
// //nolint on each, would mean the numbers are asserted by nothing at all. Testing them is both the
// honest fix and the cheaper one.
func TestGuaranteeTheCOMConstantsMatchTheHeaders(t *testing.T) {
	// VARTYPE tags. Each names which member of the VARIANT union holds the value, so a wrong tag reads
	// the right eight bytes as the wrong type — a BSTR pointer as an integer, or worse.
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"VT_I4", vtI4, 3},
		{"VT_BSTR", vtBstr, 8},
		{"VT_DISPATCH", vtDispatch, 9},
		{"VT_BOOL", vtBool, 11},
		{"VT_UI4", vtUI4, 19},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}

	// DISPID_PROPERTYPUT. Without this named argument a property write is a call with a value and
	// nothing to assign it to, and Invoke answers DISP_E_PARAMNOTOPTIONAL. It is negative, which is the
	// kind of constant that gets copied without its sign.
	if dispidPropertyPut != -3 {
		t.Errorf("dispidPropertyPut is %d, want -3", dispidPropertyPut)
	}

	// CLSCTX_INPROC_SERVER. The scan deliberately asks for an in-process server and nothing else: a
	// wider context would let COM start a local server or reach out of process, which is a different
	// security question from the one docs/SECURITY.md §12.6 answers about registry-directed DLL loading.
	if clsctxInprocServer != 0x1 {
		t.Errorf("clsctxInprocServer is %#x, want 0x1", clsctxInprocServer)
	}

	// LOCALE_USER_DEFAULT. WUA's member names are not localised, so this only decides how a returned
	// error string is formatted — but a zero here is LOCALE_NEUTRAL, which some type libraries refuse.
	if localeUserDefault != 0x0400 {
		t.Errorf("localeUserDefault is %#x, want 0x400", localeUserDefault)
	}
}

// TestGuaranteeTheReservedWordsHoldTheValueSlotInPlace is why three unread fields exist.
//
// variant.reserved1 through reserved3 are never read and never written, and that is exactly their job:
// they are the six bytes between the type tag and the value that Windows' own VARIANT has. Delete them
// as unused — which is what a reader tidying up would do, and what `unused` would encourage — and val
// moves from offset 8 to offset 2, so every read in this package takes the wrong eight bytes.
//
// Asserting their offsets is what makes them visibly load-bearing rather than visibly dead.
func TestGuaranteeTheReservedWordsHoldTheValueSlotInPlace(t *testing.T) {
	var v variant
	for _, f := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"reserved1", unsafe.Offsetof(v.reserved1), 2},
		{"reserved2", unsafe.Offsetof(v.reserved2), 4},
		{"reserved3", unsafe.Offsetof(v.reserved3), 6},
	} {
		if f.got != f.want {
			t.Errorf("variant.%s is at offset %d, want %d.\n"+
				"These three fields are never read. They exist so that val sits at offset 8, which is "+
				"where Windows writes it.", f.name, f.got, f.want)
		}
	}

	// The two pointer fields of DISPPARAMS, for the same reason: COM reads the argument array through
	// them, so their position is the contract even though nothing on this platform sets them.
	var p dispParams
	if got := unsafe.Offsetof(p.args); got != 0 {
		t.Errorf("dispParams.args is at offset %d, want 0", got)
	}
	if got := unsafe.Offsetof(p.namedArgs); got != 8 {
		t.Errorf("dispParams.namedArgs is at offset %d, want 8", got)
	}
}
