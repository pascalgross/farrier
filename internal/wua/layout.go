package wua

// This file holds the memory layout COM reads and writes, and nothing that calls it.
//
// The split is the same one permit() makes in comcall.go, for the same reason: every job in
// .github/workflows runs on ubuntu-latest, so anything declared behind //go:build windows is documented
// rather than tested. The structures below are exactly what could be wrong by hand — an offset counted
// once, in a file nobody can run — and TestGuaranteeTheVariantLayoutMatchesWindows checks them on the
// machines that actually build this repository.

// COM constants, named here rather than repeated as literals at the call sites.
const (
	clsctxInprocServer = 0x1

	// dispidPropertyPut is the named argument a property write must carry. Without it, Invoke treats a
	// DISPATCH_PROPERTYPUT call as having no value to assign and fails with DISP_E_PARAMNOTOPTIONAL.
	dispidPropertyPut = -3

	// localeUserDefault is the LCID passed to GetIDsOfNames and Invoke. WUA's member names are not
	// localised, so this only decides how a returned error string is formatted.
	localeUserDefault = 0x0400

	vtI4       = 3
	vtBstr     = 8
	vtDispatch = 9
	vtBool     = 11
	vtUI4      = 19

	// variantTrue is VARIANT_BOOL's true, which is -1 rather than 1. A VARIANT_BOOL set to 1 is
	// neither true nor false to most COM implementations, and the ones that accept it do so by
	// accident.
	variantTrue  = -1
	variantFalse = 0
)

// variant is a COM VARIANT, the tagged union every IDispatch argument and result travels in.
//
// The layout is the documented one for 64-bit Windows: a two-byte type tag, three reserved words, and
// then the value, with the whole structure padded to twenty-four bytes by the DECIMAL member of the
// union. It is declared here rather than taken from a library because the only alternatives are cgo,
// which the shipped build does not use, and go-ole, whose idiomatic call is dynamic dispatch on a
// method-name string supplied by the caller — the exact shape internal/intent's AST check refuses
// everywhere else.
type variant struct {
	vt        uint16
	reserved1 uint16
	reserved2 uint16
	reserved3 uint16
	val       uintptr
	_         uintptr // the tail of the DECIMAL member; never read
}

// dispParams is COM's DISPPARAMS: the arguments handed to IDispatch::Invoke.
type dispParams struct {
	args      *variant
	namedArgs *int32
	argc      uint32
	namedArgc uint32
}
