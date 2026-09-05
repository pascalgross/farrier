package intent

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// expectedCatalogue is the complete set of intents HostSeal is allowed to have, written as a literal.
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
// This is the load-bearing test of the whole project. Everything HostSeal claims about not shipping
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
			t.Errorf("intent %q has no summary: hostseal sign renders it to an operator who is about "+
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

// unimplemented is every catalogue member that has no executor, with the reason it does not.
//
// It is a map with the reason as the value rather than a list of names, because a member without an
// executor is a decision somebody made and the next person to read this file needs to know which
// decision. An empty map would be the ordinary state of a finished catalogue; a member appearing here
// without a reason is what the test refuses.
var unimplemented = map[Name]string{}

// TestGuaranteeEveryCatalogueMemberIsImplementedOrHasAWrittenReasonNotToBe replaces the phase 0 pin.
//
// Until phase 1 this test asserted the opposite — that *nothing* privileged had an executor — and said
// that starting phase 1 meant updating it in the same commit. This is that update. What it pins now is
// the harder and longer-lived property: a build gains the ability to change a host by one field being
// set, so every member that does not have it set must have a reason written down beside it, and every
// member that does must be one somebody meant to turn on.
//
// The reason this matters more than it looks: packages.applySecurity is not merely unfinished. Turning
// its flag on is a single-character change that would silently drop a signature requirement, because
// the routine class checks no signature and the online-key check that is supposed to replace it does
// not exist. The flag is currently the whole of what prevents that.
func TestGuaranteeEveryCatalogueMemberIsImplementedOrHasAWrittenReasonNotToBe(t *testing.T) {
	for _, s := range All() {
		reason, expected := unimplemented[s.Name]
		switch {
		case s.Implemented && expected:
			t.Errorf("intent %q is marked Implemented, but this file records why it must not be:\n  %s\n"+
				"If that reason no longer holds, remove the entry from `unimplemented` in the same "+
				"commit and expect a careful review.", s.Name, reason)
		case !s.Implemented && !expected:
			t.Errorf("intent %q has no executor and no reason recorded for why not.\n"+
				"An intent the agent refuses is invisible on a dashboard as anything other than a job "+
				"that did not work, so the reason belongs in `unimplemented` in this file rather than "+
				"in somebody's memory.", s.Name)
		}
	}
	for name := range unimplemented {
		if !Has(name) {
			t.Errorf("%q is recorded as unimplemented but is not in the catalogue at all", name)
		}
	}
}

// TestGuaranteeTheRoutineTierIsNeverAuthorisedByMTLSAlone states the rule generally.
//
// It is deliberately about the *class* rather than about packages.applySecurity, because the specific
// name is not the point. Any future routine member arrives with the same question, and the answer this
// pins is that routine is signed — by the control plane's own key — and is never the tier for which no
// signature is checked at all.
//
// This test previously held the line the other way round: while there was no online key, it required
// that no routine intent have an executor. That was the same rule at an earlier moment. What must not
// happen is for a routine intent to be executable while nothing verifies a signature for it, and the
// two halves of that are asserted in two places — here, that the catalogue demands an online signature,
// and in internal/agent, that the acceptance sequence actually checks one.
func TestGuaranteeTheRoutineTierIsNeverAuthorisedByMTLSAlone(t *testing.T) {
	var routine int
	for _, s := range All() {
		if s.Class != ClassRoutine {
			continue
		}
		routine++

		if !s.Class.RequiresOnlineSignature() {
			t.Errorf("routine intent %q requires no signature of any kind. Routine is privileged, so "+
				"this would make it an operation authorised by mTLS alone — see docs/PROTOCOL.md §5.1 "+
				"step 5.", s.Name)
		}
		if s.Class.RequiresOfflineSignature() {
			// Not a weakening but a confusion, and worth catching: an offline signature is the
			// destructive tier's authority, and a routine intent that demanded one would either be
			// unsatisfiable — the control plane cannot produce one — or would mean the tiers had been
			// merged.
			t.Errorf("routine intent %q requires an offline signature. The two tiers verify against "+
				"different anchors and neither substitutes for the other; see docs/SECURITY.md §3.",
				s.Name)
		}
	}
	if routine == 0 {
		t.Fatal("no routine intent in the catalogue, so this test asserts nothing. If the tier has " +
			"been removed, remove this test and the reasoning in docs/SECURITY.md §3 with it.")
	}
}

// TestGuaranteeTheTwoSignatureTiersNeverOverlap is the separation the whole design rests on.
//
// A destructive intent is authorised by a key in the host's own trusted-signers, which the control
// plane does not hold. A routine intent is authorised by the control plane's own key. If one class ever
// demanded both, or a class demanded neither while being privileged, the acceptance sequence would have
// a branch nobody wrote — and the plausible way that happens is somebody replacing two predicates with
// one boolean and inverting it.
func TestGuaranteeTheTwoSignatureTiersNeverOverlap(t *testing.T) {
	for _, s := range All() {
		offline := s.Class.RequiresOfflineSignature()
		online := s.Class.RequiresOnlineSignature()

		switch {
		case offline && online:
			t.Errorf("%q requires both an offline and an online signature; the acceptance sequence "+
				"checks one branch, so one of the two would go unverified", s.Name)
		case s.Class.Privileged() && !offline && !online:
			t.Errorf("%q is privileged and requires no signature; that is an operation authorised by "+
				"mTLS alone", s.Name)
		case !s.Class.Privileged() && (offline || online):
			t.Errorf("%q is a read intent that demands a signature. Nothing produces one for a read "+
				"intent, so every one of them would be refused on every host", s.Name)
		}
	}
}

// TestGuaranteeEveryReadIntentHasAnExecutor asserts the unprivileged half is whole.
//
// A read intent with no executor would be a host that reports nothing and looks like a host that is
// down, which is the one failure a fleet tool must not have.
func TestGuaranteeEveryReadIntentHasAnExecutor(t *testing.T) {
	for _, s := range All() {
		if s.Class == ClassRead && !s.Implemented {
			t.Errorf("read-only intent %q has no executor", s.Name)
		}
	}
}

// TestGuaranteeIntentsThatMayNotReturnArePinned asserts the set is exactly what the agent handles.
//
// An operation marked MayNotReturn gets its result fsynced to disk before it starts, because it can
// complete by the host disappearing. Forgetting the flag on a future intent is silent: the operation
// works, and its result is simply never reported, so the job sits in the queue looking like a host that
// has gone quiet.
func TestGuaranteeIntentsThatMayNotReturnArePinned(t *testing.T) {
	expected := map[Name]bool{HostReboot: true}

	for _, s := range All() {
		if s.MayNotReturn != expected[s.Name] {
			t.Errorf("intent %q has MayNotReturn=%v, expected %v.\n"+
				"If a new operation can take the host away mid-execution, add it here — the agent "+
				"fsyncs a provisional result before starting anything marked this way, and an "+
				"unmarked one reports nothing at all.", s.Name, s.MayNotReturn, expected[s.Name])
		}
	}
}

// TestGuaranteeAnUpdateThatRebootsIsTreatedAsAnOperationThatMayNotReturn covers the parameters.
//
// The Spec flag above cannot see them, and there is exactly one case where that is not enough:
// packages.applyAll with rebootIfRequired ends by rebooting the host, precisely as host.reboot does,
// while its Spec quite correctly says that applying updates does not normally take a machine away. An
// agent that consulted only the flag would skip the provisional result for that job, the host would
// reboot, and the job would sit in the queue looking like a host that had gone quiet — the failure the
// flag exists to prevent, arriving through the one path the flag cannot see.
func TestGuaranteeAnUpdateThatRebootsIsTreatedAsAnOperationThatMayNotReturn(t *testing.T) {
	for _, name := range []Name{PackagesApplyAll} {
		spec, ok := Lookup(name)
		if !ok {
			t.Fatalf("%q is not in the catalogue", name)
		}

		_, plain, err := Decode(name, []byte(`{"rebootIfRequired":false}`))
		if err != nil {
			t.Fatalf("decoding %q: %v", name, err)
		}
		if MayNotReturn(spec, plain) {
			t.Errorf("%q without a follow-up reboot is treated as an operation that may not return; "+
				"every ordinary update job would then spool a provisional \"succeeded\" it never "+
				"needed", name)
		}

		_, rebooting, err := Decode(name, []byte(`{"rebootIfRequired":true}`))
		if err != nil {
			t.Fatalf("decoding %q: %v", name, err)
		}
		if !MayNotReturn(spec, rebooting) {
			t.Fatalf("%q with rebootIfRequired is not treated as an operation that may not return. "+
				"It reboots the host at the end, so its result must be on disk before it starts — "+
				"otherwise the host comes back patched and the job is never reported at all.", name)
		}
	}

	// And the static flag still decides on its own where there are no parameters to consult.
	spec, _ := Lookup(HostReboot)
	_, params, err := Decode(HostReboot, []byte(`{}`))
	if err != nil {
		t.Fatalf("decoding host.reboot: %v", err)
	}
	if !MayNotReturn(spec, params) {
		t.Error("host.reboot is not treated as an operation that may not return")
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
		"hostseal-agent.service",
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
			// Describe feeds hostseal sign, which is what an operator reads before authorising a job
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

// TestGuaranteeTheRoutineTierCannotExpressAReboot is the mechanism behind docs/SECURITY.md §3's
// sentence "a signature by the online key must not authorise a reboot".
//
// The routine tier is the one the control plane signs for itself, with no human present, so every
// parameter a routine intent accepts is a parameter an attacker owning the control plane can set. It
// follows that no routine intent may accept one that reaches destructive work — and that has to be
// asserted over the catalogue rather than over one intent, because the way it went wrong was a decoder
// shared between a routine member and a destructive one, which no test naming a single intent would
// have caught.
//
// Asserted by EFFECT rather than by class. TestGuaranteeTheOnlineKeyCannotAuthoriseADestructiveJob
// already covers class — it proves the online key cannot sign something the catalogue calls
// destructive. It passed throughout the period when packages.applySecurity could reboot a host,
// because a reboot reached through a routine intent's parameters is never classified as anything.
func TestGuaranteeTheRoutineTierCannotExpressAReboot(t *testing.T) {
	routine := 0
	for name, spec := range catalogue {
		if spec.Class != ClassRoutine {
			continue
		}
		routine++

		// The static flag first: a routine intent must not be one the catalogue itself says may take
		// the host away.
		if spec.MayNotReturn {
			t.Errorf("%q is routine and its Spec says it may not return; an operation that takes a "+
				"host away cannot be authorised by a key the control plane holds", name)
		}

		// And the flag must not be reachable through parameters either. rebootIfRequired is the one
		// that got in; a future one would be caught by the same shape, because what is asserted is
		// that no accepted parameter object makes MayNotReturn true.
		if _, params, err := Decode(name, []byte(`{"rebootIfRequired":true}`)); err == nil {
			if MayNotReturn(spec, params) {
				t.Errorf("%q is routine and accepts rebootIfRequired, so the control plane's own key "+
					"authorises a reboot. docs/SECURITY.md §3 says it must not: a reboot needs a key "+
					"from the host's own trusted-signers, which the control plane does not hold", name)
			} else {
				t.Errorf("%q is routine and accepts rebootIfRequired without acting on it. An "+
					"accepted-and-ignored parameter is one flipped condition away from being "+
					"honoured; refuse it in the decoder instead", name)
			}
		}
	}

	// A catalogue with no routine member would pass every assertion above without exercising one.
	if routine == 0 {
		t.Fatal("no routine intent in the catalogue; this test asserted nothing")
	}
}

// TestGuaranteeApplySecurityNamesTheIntentToUseInstead is about the refusal being usable.
//
// "Patch and reboot" is a reasonable thing to want, and the answer is two authorisations rather than
// none. A refusal that only said "unknown field" would leave an operator guessing at which of ten
// catalogue members does the other half.
func TestGuaranteeApplySecurityNamesTheIntentToUseInstead(t *testing.T) {
	_, _, err := Decode(PackagesApplySecurity, []byte(`{"rebootIfRequired":true}`))
	if err == nil {
		t.Fatal("packages.applySecurity accepted rebootIfRequired")
	}
	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("the refusal is %v; it should be an unknown-field error so callers can classify it", err)
	}
	for _, want := range []string{string(HostReboot), "trusted-signers"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}
