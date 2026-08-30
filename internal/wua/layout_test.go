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
