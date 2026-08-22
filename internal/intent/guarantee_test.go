package intent

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// expectedCatalogue is the complete set of intents Farrier is allowed to have, written as a literal.
//
// It is duplicated from intent.go on purpose. A test that derived the expectation from the catalogue
// would assert only that the catalogue equals itself; this one fails the moment a member is added,
// removed or renamed, so the change cannot land without someone editing this literal in the same
// commit and a reviewer seeing that edit in the diff. That friction is the mechanism by which
// docs/SECURITY.md §1 survives contributors who never read the design brief.
var expectedCatalogue = map[Name]Class{
	"facts.collect":           ClassRead,
	"packages.listUpgradable": ClassRead,
	"services.list":           ClassRead,
	"reboot.checkRequired":    ClassRead,
	"packages.applySecurity":  ClassRoutine,
	"packages.applyAll":       ClassDestructive,
	"service.start":           ClassDestructive,
	"service.stop":            ClassDestructive,
	"service.restart":         ClassDestructive,
	"host.reboot":             ClassDestructive,
}

// TestGuaranteeCatalogueMatchesExpectedSet asserts the catalogue is exactly the expected literal set.
//
// This is the load-bearing test of the whole project. Everything Farrier claims about not shipping
// remote execution reduces to "the set of things the control plane can ask for is this list and no
// other", and this is where that is checked rather than asserted.
func TestGuaranteeCatalogueMatchesExpectedSet(t *testing.T) {
	for _, s := range All() {
		wantClass, ok := expectedCatalogue[s.Name]
		if !ok {
			t.Errorf("intent %q is in the catalogue but not in expectedCatalogue.\n"+
				"If you are adding an intent deliberately, add it to expectedCatalogue in this file, "+
				"document it in docs/SECURITY.md §3 and docs/PROTOCOL.md, and expect a careful review.",
				s.Name)
			continue
		}
		if s.Class != wantClass {
			t.Errorf("intent %q has class %q, expected %q: an intent's authorisation tier may not be "+
				"changed without changing this expectation", s.Name, s.Class, wantClass)
		}
	}
	for n := range expectedCatalogue {
		if !Has(n) {
			t.Errorf("intent %q is expected but missing from the catalogue: removing an intent is a "+
				"breaking protocol change and needs the expectation updated too", n)
		}
	}
}

// TestGuaranteeNoIntentNameIsExecutionShaped asserts no member is named like remote execution.
//
// The failure this defends against is not a maintainer who decides to add a shell. It is one who adds
// something adjacent under a name that reads as harmless in a diff — "packages.execHook",
// "facts.collectScript" — where the reviewer's attention is on the implementation rather than the
// name.
func TestGuaranteeNoIntentNameIsExecutionShaped(t *testing.T) {
	for _, n := range Names() {
		lower := strings.ToLower(string(n))
		for _, frag := range executionShapedFragments {
			if strings.Contains(lower, frag) {
				t.Errorf("intent %q contains the execution-shaped fragment %q.\n"+
					"If this operation is legitimate, rename it. Being made to rename it is this check "+
					"working: an operation whose natural name contains %q is worth arguing about in a "+
					"pull request.", n, frag, frag)
			}
		}
	}
}

// TestGuaranteeRefusedNamesAreAbsent asserts the permanently refused operations are not present.
//
// docs/SECURITY.md lists these with a reason each so that the answer to the request is a document
// rather than an argument. This test is what makes the document binding.
func TestGuaranteeRefusedNamesAreAbsent(t *testing.T) {
	for _, n := range Refused {
		if Has(n) {
			t.Fatalf("intent %q is permanently refused (see docs/SECURITY.md, \"Permanently refused\") "+
				"but is present in the catalogue", n)
		}
	}
}

// TestGuaranteeEveryIntentHasClassAndDecoder asserts every member is fully specified.
//
// A member with no decoder would accept whatever arrived; a member with an invalid class would fall
// through the agent's authorisation switch. Both are the kind of omission that produces no symptom
// until the one job that exploits it, so they are checked rather than reviewed for.
func TestGuaranteeEveryIntentHasClassAndDecoder(t *testing.T) {
	for _, s := range All() {
		if !s.Class.Valid() {
			t.Errorf("intent %q has invalid class %q", s.Name, s.Class)
		}
		if s.Decode == nil {
			t.Errorf("intent %q has no parameter decoder: an intent that takes no parameters still "+
				"needs a decoder that rejects everything except the empty object", s.Name)
		}
		if strings.TrimSpace(s.Summary) == "" {
			t.Errorf("intent %q has no summary: farrier sign renders it to an operator who is about "+
				"to authorise the job offline", s.Name)
		}
		if s.Name == "" {
			t.Errorf("catalogue contains a spec with an empty name")
		}
	}
}

// TestGuaranteeDestructiveIntentsRequireOfflineSignature asserts the class contract.
//
// The guarantee's third mechanism is that destructive operations need a key the control plane does not
// hold. That reduces entirely to RequiresOfflineSignature being true for exactly the destructive tier,
// so it is checked here rather than trusted to the one caller that asks.
func TestGuaranteeDestructiveIntentsRequireOfflineSignature(t *testing.T) {
	for _, s := range All() {
		switch s.Class {
		case ClassRead:
			if s.Class.Privileged() {
				t.Errorf("intent %q is read-only but reports as privileged", s.Name)
			}
			if s.Class.RequiresOfflineSignature() {
				t.Errorf("intent %q is read-only but demands an offline signature", s.Name)
			}
		case ClassRoutine:
			if !s.Class.Privileged() {
				t.Errorf("intent %q is routine but does not report as privileged", s.Name)
			}
			if s.Class.RequiresOfflineSignature() {
				t.Errorf("intent %q is routine but demands an offline signature; there is exactly one "+
					"routine intent and it is the one the host would run on its own timer anyway", s.Name)
			}
		case ClassDestructive:
			if !s.Class.Privileged() {
				t.Errorf("intent %q is destructive but does not report as privileged", s.Name)
			}
			if !s.Class.RequiresOfflineSignature() {
				t.Fatalf("intent %q is destructive but does not require an offline signature. There is "+
					"deliberately no graded tier by blast radius: a control plane with two operator "+
					"accounts could walk the fleet host by host.", s.Name)
			}
		default:
			t.Errorf("intent %q has unknown class %q", s.Name, s.Class)
		}
	}
}

// TestGuaranteePhaseZeroShipsNoWriteCapability asserts nothing privileged has an executor yet.
//
// Phase 0 ships the routine and destructive specs so the protocol, the UI and the documentation can be
// built against the final shape, with no executor behind them. This test is what stops "wire up the
// executor" from arriving as an incidental part of an unrelated change; deleting it is a deliberate,
// visible act when phase 1 begins.
func TestGuaranteePhaseZeroShipsNoWriteCapability(t *testing.T) {
	for _, s := range All() {
		if s.Class.Privileged() && s.Implemented {
			t.Errorf("intent %q is privileged and marked Implemented, but phase 0 ships no write "+
				"capability at all. If you are starting phase 1, update this test in the same commit.",
				s.Name)
		}
		if s.Class == ClassRead && !s.Implemented {
			t.Errorf("read-only intent %q has no executor", s.Name)
		}
	}
}

// safeParamCharacters is the only character set any decoded string parameter may contain.
//
// It is checked generically, over every string field of every decoded Params value, rather than
// per-intent. A per-intent check would be exactly as strong as somebody's memory when they add the
// next intent, and this is the one invariant that must not depend on that.
var safeParamCharacters = regexp.MustCompile(`^[A-Za-z0-9 .,:@_-]*$`)

// TestGuaranteeUnitNamesRejectKnownAttacks asserts the unit validator refuses hostile shapes.
//
// These inputs are the ones that would matter if a unit name ever reached a shell, a path resolver or
// an argument parser. None of them should reach any of those today; the point of the table is that
// they still do not on the day someone changes how the helper invokes systemctl.
func TestGuaranteeUnitNamesRejectKnownAttacks(t *testing.T) {
	bad := []string{
		"nginx.service; rm -rf /",
		"nginx.service && reboot",
		"nginx.service | tee /etc/passwd",
		"$(reboot).service",
		"`reboot`.service",
		"nginx.service\nreboot",
		"nginx.service\x00.socket",
		"../../etc/systemd/system/evil.service",
		"..%2f..%2fevil.service",
		"-nginx.service",
		"--user.service",
		".service",
		"nginx.service ",
		" nginx.service",
		"nginx.mount",
		"nginx.device",
		"nginx",
		"nginx.service.evil",
		"/etc/systemd/system/evil.service",
		"nginx.service?x=1",
		strings.Repeat("a", 250) + ".service",
	}
	for _, unit := range bad {
		raw, err := json.Marshal(map[string]string{"unit": unit})
		if err != nil {
			t.Fatalf("marshalling test input: %v", err)
		}
		if _, _, err := Decode(ServiceRestart, raw); err == nil {
			t.Errorf("unit name %q was accepted and must not be", unit)
		}
	}

	good := []string{
		"nginx.service",
		"docker.socket",
		"apt-daily.timer",
		"getty@tty1.service",
		"user_session.service",
		"farrier-agent.service",
	}
	for _, unit := range good {
		raw, err := json.Marshal(map[string]string{"unit": unit})
		if err != nil {
			t.Fatalf("marshalling test input: %v", err)
		}
		if _, _, err := Decode(ServiceRestart, raw); err != nil {
			t.Errorf("unit name %q was rejected and should be accepted: %v", unit, err)
		}
	}
}

// TestGuaranteeUnknownFieldsAreRejected asserts strict decoding across the whole catalogue.
//
// A control plane able to attach unrecognised fields to a job would have a channel for smuggling
// values past a validator into whatever later code decided to be helpful about them. Checking it for
// every member rather than one is the difference between a property and a coincidence.
func TestGuaranteeUnknownFieldsAreRejected(t *testing.T) {
	for _, n := range Names() {
		raw := []byte(`{"totallyUnexpectedField":"x"}`)
		if _, _, err := Decode(n, raw); err == nil {
			t.Errorf("intent %q accepted an unknown parameter field", n)
		}
	}
}

// TestGuaranteeOversizeParametersAreRejected asserts the decoder bound holds for every member.
//
// The decoders are the first thing a job's untrusted bytes reach, so an unbounded decode anywhere in
// the catalogue is a denial-of-service primitive available to whoever can reach the endpoint.
func TestGuaranteeOversizeParametersAreRejected(t *testing.T) {
	huge := []byte(`{"unit":"` + strings.Repeat("a", maxParamsBytes) + `.service"}`)
	for _, n := range Names() {
		if _, _, err := Decode(n, huge); err == nil {
			t.Errorf("intent %q accepted a %d-byte parameter object", n, len(huge))
		}
	}
}

// TestGuaranteeUnknownIntentIsRefused asserts Decode fails closed on names outside the catalogue.
//
// It covers the refused list explicitly, because "shell.exec is not implemented" and "shell.exec is
// refused with an error" are the same thing today and must stay the same thing after any future
// refactor of the dispatch path.
func TestGuaranteeUnknownIntentIsRefused(t *testing.T) {
	unknown := append([]Name{"", "facts", "facts.collect.extra", "FACTS.COLLECT"}, Refused...)
	for _, n := range unknown {
		if _, _, err := Decode(n, []byte(`{}`)); err == nil {
			t.Errorf("Decode accepted unknown intent %q", n)
		}
	}
}

// FuzzGuaranteeParamsNeverEscapeConstraints asserts that no input produces an unconstrained parameter.
//
// The invariant is deliberately stated over the decoded value rather than the input: whatever bytes
// arrive, anything the decoders hand back must contain only characters that cannot mean anything to a
// shell, a path resolver or an argument parser, and any unit name must match the catalogue's pattern.
// Stating it that way means the property survives a future intent whose author did not think to add a
// case here.
func FuzzGuaranteeParamsNeverEscapeConstraints(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"unit":"nginx.service"}`,
		`{"unit":"nginx.service; rm -rf /"}`,
		`{"unit":"$(reboot).service"}`,
		"{\"unit\":\"a\\u0000.service\"}",
		`{"unit":"../../evil.service"}`,
		`{"delaySeconds":60,"message":"patching"}`,
		`{"delaySeconds":-1}`,
		`{"delaySeconds":99999999999999999999}`,
		`{"message":"$(reboot)"}`,
		"{\"message\":\"a\\nb\"}",
		`{"rebootIfRequired":true}`,
		`{"unit":["a.service"]}`,
		`{"unit":{"$ne":null}}`,
		`[]`,
		`null`,
		`"unit"`,
		``,
		`{"unit":"nginx.service"}{"unit":"other.service"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		for _, n := range Names() {
			_, params, err := Decode(n, []byte(raw))
			if err != nil {
				continue
			}
			if params.Intent() != n {
				t.Fatalf("intent %q decoded parameters belonging to %q", n, params.Intent())
			}
			for _, s := range stringFieldsOf(params) {
				if !safeParamCharacters.MatchString(s) {
					t.Fatalf("intent %q accepted parameter string %q, which contains characters "+
						"outside %s", n, s, safeParamCharacters)
				}
			}
			if up, ok := params.(UnitParams); ok {
				if err := validateUnit(up.Unit); err != nil {
					t.Fatalf("intent %q produced a UnitParams whose unit %q fails validateUnit: %v",
						n, up.Unit, err)
				}
			}
			// Describe feeds farrier sign, which is what an operator reads before authorising a job
			// offline. A control character there could hide part of the operation in a terminal.
			if !safeParamCharacters.MatchString(strings.NewReplacer(`"`, "", "(", "", ")", "").Replace(params.Describe())) {
				t.Fatalf("intent %q rendered an unsafe description %q", n, params.Describe())
			}
		}
	})
}

// stringFieldsOf returns every string-kinded field of a Params value, including unexported ones.
//
// Reflection is used here rather than a per-type accessor because the point of the fuzz invariant is
// that it holds for parameter types nobody has written yet. A hand-maintained accessor would be
// exactly as complete as somebody remembered to make it.
func stringFieldsOf(p Params) []string {
	v := reflect.ValueOf(p)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String {
			out = append(out, f.String())
		}
	}
	return out
}
