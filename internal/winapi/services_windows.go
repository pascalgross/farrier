//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Service is the state of one Windows service.
//
// The field names are the ones collect.Unit already carries, and the mapping is deliberate rather than
// lazy — see ToUnit, which is where the translation and its cost are argued.
type Service struct {
	// Name is the service's key name, such as "W3SVC". Windows has no ".service" suffix.
	Name string

	// DisplayName is the name an operator sees in services.msc.
	DisplayName string

	// StartType is how the service is configured to start: auto, demand, disabled, boot, system.
	//
	// Empty where the agent's account could not open the service for SERVICE_QUERY_CONFIG. That is a
	// real and expected outcome for a non-administrator on some services, and it is reported as absent
	// rather than guessed at.
	StartType string

	// State is what the service is doing now: running, stopped, start-pending and the rest.
	State string
}

// serviceStates maps the SCM's current-state numbers onto the words Farrier reports.
//
// The words are chosen to read the way systemd's do — "running", "stopped" — rather than to transcribe
// the constant names, because these strings are rendered in a fleet list beside Linux hosts and an
// operator scanning that list should not have to learn two vocabularies for one idea.
var serviceStates = map[uint32]string{
	windows.SERVICE_STOPPED:          "stopped",
	windows.SERVICE_START_PENDING:    "start-pending",
	windows.SERVICE_STOP_PENDING:     "stop-pending",
	windows.SERVICE_RUNNING:          "running",
	windows.SERVICE_CONTINUE_PENDING: "continue-pending",
	windows.SERVICE_PAUSE_PENDING:    "pause-pending",
	windows.SERVICE_PAUSED:           "paused",
}

// startTypes maps the SCM's start-type numbers onto the words Farrier reports.
var startTypes = map[uint32]string{
	windows.SERVICE_BOOT_START:   "boot",
	windows.SERVICE_SYSTEM_START: "system",
	windows.SERVICE_AUTO_START:   "auto",
	windows.SERVICE_DEMAND_START: "demand",
	windows.SERVICE_DISABLED:     "disabled",
}

// ListServices enumerates the host's Win32 services, and reports whether the list was truncated.
//
// The SCM is opened with SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE rather than with
// golang.org/x/sys/windows/svc/mgr, and that is the whole reason this function exists instead of four
// lines calling that package. mgr.Connect requests SC_MANAGER_ALL_ACCESS unconditionally, which a
// non-administrator does not have — so the convenient route would have forced the agent to run as an
// administrator to answer a read-only question, and the least-privilege posture in docs/SECURITY.md
// §12.3 would have been given up for an import.
//
// EnumServicesStatusEx **silently omits** services the caller cannot query, rather than failing: it
// returns the ones it can and says nothing about the rest. That is this platform's second
// silent-wrong-answer trap and it is the reason ListServices reports a count it could not read rather
// than presenting a short list as a complete one. A fleet view that quietly dropped the services an
// unprivileged agent cannot see would be worse than one that says how many it missed, because the
// missing ones are exactly the ones somebody locked down on purpose.
func ListServices() ([]Service, bool, error) {
	scm, err := windows.OpenSCManager(nil, nil,
		windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, false, fmt.Errorf("winapi: opening the service control manager: %w", err)
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()

	raw, err := enumerateServices(scm)
	if err != nil {
		return nil, false, err
	}

	truncated := len(raw) > maxServices
	if truncated {
		raw = raw[:maxServices]
	}

	out := make([]Service, 0, len(raw))
	for i := range raw {
		s := Service{
			Name:        windows.UTF16PtrToString(raw[i].ServiceName),
			DisplayName: windows.UTF16PtrToString(raw[i].DisplayName),
			State:       stateName(raw[i].ServiceStatusProcess.CurrentState),
		}
		// Best effort, and per service. A non-administrator legitimately cannot open every service for
		// SERVICE_QUERY_CONFIG, and one refusal must not cost the whole list.
		s.StartType = startTypeOf(scm, raw[i].ServiceName)
		out = append(out, s)
	}
	return out, truncated, nil
}

// maxServices bounds the list before it is turned into report entries.
//
// It matches collect.MaxServices, and is restated here rather than imported so that this package
// depends on nothing of Farrier's above it — internal/collect imports the platform, not the reverse.
// The guarantee suite checks the two agree.
const maxServices = 500

// enumerateServices runs the two-call EnumServicesStatusEx dance and returns every entry.
//
// The API is called once to learn the buffer size and again to fill it, and it can still return
// ERROR_MORE_DATA with a resume handle if services appear between the two calls — so this loops rather
// than assuming the second call is the last. The buffer is a []byte reinterpreted as a slice of
// ENUM_SERVICE_STATUS_PROCESS, because the structures are followed in the same allocation by the
// strings their pointers refer to; copying the structs out without the buffer would leave those
// pointers dangling, which is why the conversion happens while the buffer is still alive.
func enumerateServices(scm windows.Handle) ([]windows.ENUM_SERVICE_STATUS_PROCESS, error) {
	var (
		out    []windows.ENUM_SERVICE_STATUS_PROCESS
		resume uint32
	)
	for {
		var needed, returned uint32
		err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, nil, 0, &needed, &returned, &resume, nil)
		if err == nil {
			// Nothing left to read.
			return out, nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("winapi: sizing the service list: %w", err)
		}
		if needed == 0 {
			return out, nil
		}

		buf := make([]byte, needed)
		err = windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, &buf[0], needed, &needed, &returned,
			&resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("winapi: reading the service list: %w", err)
		}
		if returned > 0 {
			entries := unsafe.Slice(
				(*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), int(returned))
			out = append(out, entries...)
		}
		if err == nil || resume == 0 {
			return out, nil
		}
		if len(out) > maxServices*4 {
			// A guard against a resume handle that never settles. Four times the cap is far past what
			// any real host has, and returning what was read beats looping on a machine in a state
			// nobody predicted.
			return out, nil
		}
	}
}

// startTypeOf opens one service for its configuration and returns its start type, or "".
//
// It is separated so that its failure is visibly per-service and visibly tolerated. SERVICE_QUERY_CONFIG
// is not granted to Authenticated Users on every service, and treating one refusal as an error would
// mean an agent that reports nothing on a hardened host — the machine most worth reporting on.
func startTypeOf(scm windows.Handle, name *uint16) string {
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return ""
	}
	defer func() { _ = windows.CloseServiceHandle(h) }()

	var needed uint32
	err = windows.QueryServiceConfig(h, nil, 0, &needed)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return ""
	}
	if needed == 0 {
		return ""
	}
	buf := make([]byte, needed)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceConfig(h, cfg, needed, &needed); err != nil {
		return ""
	}
	return startTypes[cfg.StartType]
}

// stateName renders a service's current state, naming the number where the map has no word for it.
//
// An unmapped state is reported as "state N" rather than as an empty string, because a state Windows
// added after this was written is a fact about the host and not an absence of one.
func stateName(state uint32) string {
	if name, ok := serviceStates[state]; ok {
		return name
	}
	return fmt.Sprintf("state %d", state)
}
