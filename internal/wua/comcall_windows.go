//go:build windows

package wua

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IDispatch vtable slots, and the only offsets this package computes.
//
// These five are fixed for every COM object that has ever existed: IUnknown defines the first three and
// IDispatch the next four, and no interface may reorder them. Every *other* method is reached by
// resolving its name through GetIDsOfNames and calling Invoke, rather than by an offset counted down an
// interface definition. That is a deliberate trade of one run-time lookup for the removal of a whole
// class of defect: a mistaken per-interface offset calls the wrong function through a valid pointer,
// which is undefined behaviour that no amount of reading catches, and which cannot be tested from a
// machine that is not running Windows.
const (
	slotRelease       = 2
	slotGetIDsOfNames = 5
	slotInvoke        = 6
)

// ole32 and oleaut32 hold the four entry points this package needs that are ordinary DLL exports.
//
// They are LazyDLL rather than direct wrappers because golang.org/x/sys/windows wraps CoInitializeEx and
// CoUninitialize but not CoCreateInstance, SysAllocString or SysFreeString. Loading them by name from a
// system DLL is not a plugin mechanism: NewLazySystemDLL resolves only under %SystemRoot%\System32, the
// names are compile-time constants, and none of them is reachable from a value this process reads.
var (
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	oleaut32 = windows.NewLazySystemDLL("oleaut32.dll")

	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	procSysAllocString   = oleaut32.NewProc("SysAllocString")
	procSysFreeString    = oleaut32.NewProc("SysFreeString")
	procSysStringLen     = oleaut32.NewProc("SysStringLen")
)

// object is a COM object this package holds a reference to.
//
// It carries its own vtable pointer rather than being a bare uintptr so that a caller cannot pass an
// arbitrary integer where an interface pointer is expected, and so that Release is a method on the
// thing that needs releasing.
type object struct {
	ptr *uintptr
}

// Release drops this object's reference.
//
// COM is reference counted and this package creates objects in loops — one per update, one per category
// — so a leaked reference is not a tidiness question: it keeps wuapi.dll's session alive for the life of
// the process. The process is short-lived by design, which bounds the damage, but a scan of a host with
// two hundred pending updates would otherwise hold two hundred objects for no reason.
func (o *object) Release() {
	if o == nil || o.ptr == nil {
		return
	}
	vtbl := *(**[16]uintptr)(unsafe.Pointer(o.ptr))
	//nolint:errcheck // Release returns the new reference count, never an HRESULT, and there is
	// nothing a caller could do about it: this runs from defer on a path that is already unwinding.
	_, _, _ = syscall.SyscallN(vtbl[slotRelease], uintptr(unsafe.Pointer(o.ptr)))
	o.ptr = nil
}

// initialize joins this thread to a COM apartment, and returns the function that leaves it.
//
// runtime.LockOSThread is not optional and is the reason the scan is a separate process rather than a
// goroutine in the agent. A COM apartment belongs to an operating-system thread, and a goroutine that
// migrated to another thread would make every subsequent call fail with an error naming nothing
// relevant. In a short-lived single-purpose process the discipline is trivial; in a long-running agent
// with a scheduler it is a defect waiting for a busy machine.
func initialize() (func(), error) {
	runtime.LockOSThread()
	// COINIT_APARTMENTTHREADED. WUA is documented against an apartment-threaded caller, and the
	// multithreaded model would let COM call back on a thread this package has not locked.
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("wua: joining a COM apartment: %w", err)
	}
	return func() {
		windows.CoUninitialize()
		runtime.UnlockOSThread()
	}, nil
}

// newUpdateSession creates the one COM class this package is permitted to create.
//
// The CLSID is the package constant and never a parameter, so there is no expression in this package
// whose value could become the class that gets loaded. It is asked for as IID_IDispatch rather than as
// IID_IUpdateSession because every call after this one goes through Invoke: requesting the dual
// interface's vtable and then not using it would be an offset this package has no reason to compute.
func newUpdateSession() (*object, error) {
	clsid, err := windows.GUIDFromString(updateSessionCLSID)
	if err != nil {
		return nil, fmt.Errorf("wua: the update-session CLSID is malformed: %w", err)
	}
	iid, err := windows.GUIDFromString("{00020400-0000-0000-C000-000000000046}") // IID_IDispatch
	if err != nil {
		return nil, fmt.Errorf("wua: the IDispatch IID is malformed: %w", err)
	}

	var ptr *uintptr
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsid)),
		0, // no aggregation
		clsctxInprocServer,
		uintptr(unsafe.Pointer(&iid)),
		uintptr(unsafe.Pointer(&ptr)),
	)
	if hr != 0 {
		return nil, fmt.Errorf("wua: creating the update session: %w", hresult(hr))
	}
	if ptr == nil {
		return nil, errors.New("wua: the update session was created as a nil pointer")
	}
	return &object{ptr: ptr}, nil
}

// call is the chokepoint: the one function in Farrier that dispatches through a COM function pointer.
//
// Every call is checked against the methods table first, by name and by argument count, and refused
// before a pointer is dereferenced if it is not there. That check is what this file's exemption from
// internal/intent's AST rule is bought with, and TestGuaranteeOnlyTabledMethodsCanBeCalled is the proof
// that it is enforced rather than merely written above.
//
// The DISPID is resolved from the member name through GetIDsOfNames rather than assumed. That costs one
// round trip per call and removes the possibility of invoking the wrong member of the right object,
// which is a failure this project could not test for from a Linux machine and would not see in review.
func call(o *object, m Method, args ...*variant) (variant, error) {
	spec, err := permit(m, len(args))
	if err != nil {
		return variant{}, err
	}
	if o == nil || o.ptr == nil {
		return variant{}, fmt.Errorf("wua: %s was called on a released object", m)
	}

	dispid, err := dispidOf(o, spec.name)
	if err != nil {
		return variant{}, fmt.Errorf("wua: resolving %s: %w", m, err)
	}

	// COM reads the argument array in reverse order. Copying rather than aliasing the caller's slice
	// keeps that reversal inside this function, where it is stated once.
	flat := make([]variant, len(args))
	for i, a := range args {
		flat[len(args)-1-i] = *a
	}

	params := dispParams{argc: uint32(len(flat))}
	if len(flat) > 0 {
		params.args = &flat[0]
	}
	named := int32(dispidPropertyPut)
	if spec.how == invokePropPut {
		params.namedArgs = &named
		params.namedArgc = 1
	}

	var result variant
	var argErr uint32
	// EXCEPINFO is passed as nil. Filling it in means owning three BSTRs COM allocated, and the
	// information it carries is a description WUA duplicates in the HRESULT this already returns.
	vtbl := *(**[16]uintptr)(unsafe.Pointer(o.ptr))
	hr, _, _ := syscall.SyscallN(vtbl[slotInvoke],
		uintptr(unsafe.Pointer(o.ptr)),
		uintptr(dispid),
		uintptr(unsafe.Pointer(&windows.GUID{})), // IID_NULL, as Invoke requires
		localeUserDefault,
		uintptr(spec.how),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&result)),
		0,
		uintptr(unsafe.Pointer(&argErr)),
	)
	runtime.KeepAlive(flat)
	if hr != 0 {
		return variant{}, fmt.Errorf("wua: %s: %w", m, hresult(hr))
	}
	return result, nil
}

// dispidOf resolves a member name to its dispatch identifier.
//
// The name comes from the methods table and never from a caller, so this is a lookup of a compile-time
// constant rather than a dynamic dispatch. That distinction is the whole difference between this and
// go-ole's oleutil.CallMethod(obj, name, ...), which takes the name as an argument and is structurally
// the same shape as exec.Command.
func dispidOf(o *object, name string) (int32, error) {
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var dispid int32
	iidNull := windows.GUID{}
	vtbl := *(**[16]uintptr)(unsafe.Pointer(o.ptr))
	hr, _, _ := syscall.SyscallN(vtbl[slotGetIDsOfNames],
		uintptr(unsafe.Pointer(o.ptr)),
		uintptr(unsafe.Pointer(&iidNull)),
		uintptr(unsafe.Pointer(&wide)),
		1,
		localeUserDefault,
		uintptr(unsafe.Pointer(&dispid)),
	)
	runtime.KeepAlive(wide)
	if hr != 0 {
		return 0, fmt.Errorf("%q is not a member of this object: %w", name, hresult(hr))
	}
	return dispid, nil
}

// hresult turns a COM status into an error Go can compare and a person can read.
func hresult(hr uintptr) error {
	return windows.Errno(uint32(hr)) //nolint:gosec // an HRESULT is a 32-bit value by definition.
}

// --- VARIANT construction and reading -------------------------------------------------------------
//
// Kept together and small. Each constructor produces exactly one shape, and each reader refuses a
// VARIANT that is not the shape it expects rather than reinterpreting the union — reading a BSTR out of
// a VARIANT holding an I4 would dereference an integer as a pointer.

// bstr allocates a COM string, and returns it with the function that frees it.
//
// The caller must free it, and every call site here does so with defer. A BSTR is allocated by
// oleaut32's own allocator and cannot be freed by Go's, which is why this is a pair rather than a value.
func bstr(s string) (uintptr, func(), error) {
	wide, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return 0, func() {}, err
	}
	ptr, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(wide)))
	runtime.KeepAlive(wide)
	if ptr == 0 {
		return 0, func() {}, errors.New("wua: SysAllocString returned nothing")
	}
	return ptr, func() { _, _, _ = procSysFreeString.Call(ptr) }, nil
}

// variantBSTR builds a string argument, and returns the function that frees its storage.
func variantBSTR(s string) (*variant, func(), error) {
	ptr, free, err := bstr(s)
	if err != nil {
		return nil, func() {}, err
	}
	return &variant{vt: vtBstr, val: ptr}, free, nil
}

// variantI4 builds a 32-bit integer argument.
func variantI4(n int32) *variant {
	return &variant{vt: vtI4, val: uintptr(uint32(n))} //nolint:gosec // a deliberate reinterpretation.
}

// variantBool builds a VARIANT_BOOL argument, using COM's -1 for true.
func variantBool(b bool) *variant {
	v := int32(variantFalse)
	if b {
		v = variantTrue
	}
	return &variant{vt: vtBool, val: uintptr(uint32(v))} //nolint:gosec // a deliberate reinterpretation.
}

// asString reads a BSTR out of a VARIANT and frees it.
//
// An empty VARIANT reads as an empty string rather than as an error, because WUA genuinely returns one:
// MsrcSeverity is documented with four values and is reported empty for the cumulative updates that
// make up most of what a Server host has pending. Treating that as a failure would turn the commonest
// answer into an error.
func (v variant) asString() string {
	if v.vt != vtBstr || v.val == 0 {
		return ""
	}
	defer func() { _, _, _ = procSysFreeString.Call(v.val) }()
	n, _, _ := procSysStringLen.Call(v.val)
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(v.val)), int(n)))
}

// asInt reads an integer out of a VARIANT, accepting the three tags WUA uses for one.
func (v variant) asInt() (int32, bool) {
	switch v.vt {
	case vtI4, vtUI4:
		return int32(uint32(v.val)), true //nolint:gosec // narrowing a 32-bit value held in a uintptr.
	case vtBool:
		if int16(uint16(v.val)) != variantFalse { //nolint:gosec // VARIANT_BOOL is a 16-bit value.
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

// asBool reads a VARIANT_BOOL, defaulting to false for anything that is not one.
func (v variant) asBool() bool {
	n, ok := v.asInt()
	return ok && n != 0
}

// asObject reads an interface pointer out of a VARIANT.
//
// The reference belongs to the caller, who must Release it. An empty VARIANT is a real answer here —
// IUpdate.Categories on an update with none — so it returns nil rather than an error, and every caller
// checks.
func (v variant) asObject() *object {
	if v.vt != vtDispatch || v.val == 0 {
		return nil
	}
	return &object{ptr: (*uintptr)(unsafe.Pointer(v.val))}
}
