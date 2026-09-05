package policy

import (
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/intent"
)

// mustDecode builds validated intent parameters or fails the test.
//
// The tests go through intent.Decode rather than constructing parameters directly because Params is a
// sealed interface: a test that could build one by hand would be testing a path production code cannot
// reach.
func mustDecode(t *testing.T, name intent.Name, raw string) intent.Params {
	t.Helper()
	_, params, err := intent.Decode(name, []byte(raw))
	if err != nil {
		t.Fatalf("decoding %s params %q: %v", name, raw, err)
	}
	return params
}

// openWindowPolicy returns a permissive policy whose maintenance window is always open.
//
// It exists so that a test asserting one refusal does not accidentally pass because of a different
// one; starting from "everything permitted" and closing exactly one setting is what makes each case
// prove what it claims to.
func openWindowPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := Parse([]byte(`
[updates]
allow = "all"
auto_apply = true
window = "daily 00:00-00:00"
timezone = "UTC"
reboot = "window"

[services]
restartable = ["nginx.service", "hostseal-*.service"]

[limits]
max_job_age_seconds = 900
`))
	if err != nil {
		t.Fatalf("parsing fixture policy: %v", err)
	}
	return p
}

// nowUTC is the fixed instant every decision test evaluates at.
//
// A fixed clock rather than time.Now is what lets a maintenance-window test run on a Tuesday.
var nowUTC = time.Date(2026, 8, 22, 13, 0, 0, 0, time.UTC)

// TestDecideAllowsReadIntentsUnconditionally covers the unprivileged tier.
//
// Read intents run as the hostseal user with no capabilities and read nothing an unprivileged local
// user could not read. Gating them on policy would blind an operator to the state of a host without
// protecting anything, so the only interesting assertion is that even a fully closed policy permits
// them.
func TestDecideAllowsReadIntentsUnconditionally(t *testing.T) {
	closed := Closed()
	for _, name := range []intent.Name{
		intent.FactsCollect, intent.PackagesListUpgradable,
		intent.ServicesList, intent.RebootCheckRequired,
	} {
		req := Request{Intent: name, Params: mustDecode(t, name, `{}`), IssuedAt: nowUTC}
		d := Decide(closed, req, Env{Now: nowUTC})
		if !d.Allowed {
			t.Errorf("%s was refused by a closed policy: %s", name, d.Reason)
		}
	}
}

// TestDecideRefusesEverythingWhenPaused covers the local kill switch.
//
// systemctl stop and /etc/hostseal/paused are a stop the control plane cannot override, which is why
// there is deliberately no agent.resume intent. The read intents are included because pausing a host
// means pausing it, not "pausing the interesting half".
func TestDecideRefusesEverythingWhenPaused(t *testing.T) {
	p := openWindowPolicy(t)
	for _, name := range intent.Names() {
		raw := `{}`
		if name == intent.ServiceStart || name == intent.ServiceStop || name == intent.ServiceRestart {
			raw = `{"unit":"nginx.service"}`
		}
		req := Request{Intent: name, Params: mustDecode(t, name, raw), IssuedAt: nowUTC}
		d := Decide(p, req, Env{Now: nowUTC, Paused: true})
		if d.Allowed {
			t.Errorf("%s was permitted on a paused host", name)
		}
		if d.Code != CodePaused {
			t.Errorf("%s on a paused host reported code %q, want %q", name, d.Code, CodePaused)
		}
	}
}

// TestDecideRefusesJobsOlderThanTheLocalLimit covers limits.max_job_age_seconds.
//
// The limit is enforced locally so that it still holds when the control plane is the thing that went
// wrong: a restart signed on Tuesday must not execute on Friday because the agent was offline in
// between.
func TestDecideRefusesJobsOlderThanTheLocalLimit(t *testing.T) {
	p := openWindowPolicy(t)
	req := Request{
		Intent:   intent.ServiceRestart,
		Params:   mustDecode(t, intent.ServiceRestart, `{"unit":"nginx.service"}`),
		IssuedAt: nowUTC.Add(-2 * time.Hour),
	}
	d := Decide(p, req, Env{Now: nowUTC})
	if d.Allowed {
		t.Fatal("a two-hour-old job was permitted with a 900-second limit")
	}
	if d.Code != CodeExpired {
		t.Errorf("code %q, want %q", d.Code, CodeExpired)
	}

	req.IssuedAt = nowUTC.Add(-10 * time.Second)
	if d := Decide(p, req, Env{Now: nowUTC}); !d.Allowed {
		t.Errorf("a ten-second-old job was refused: %s", d.Reason)
	}
}

// TestDecideUpdatesAppliesTheMinimumRule is the matrix of central request against local policy.
//
// Reading it as a grid is the point: for every combination, the answer is permitted exactly when the
// local setting is at least what the intent asks for. No cell says "permitted because the control
// plane insisted".
func TestDecideUpdatesAppliesTheMinimumRule(t *testing.T) {
	cases := []struct {
		local   Allow
		name    intent.Name
		allowed bool
	}{
		{AllowNone, intent.PackagesApplySecurity, false},
		{AllowNone, intent.PackagesApplyAll, false},
		{AllowSecurity, intent.PackagesApplySecurity, true},
		{AllowSecurity, intent.PackagesApplyAll, false},
		{AllowAll, intent.PackagesApplySecurity, true},
		{AllowAll, intent.PackagesApplyAll, true},
	}
	for _, tc := range cases {
		p := openWindowPolicy(t)
		p.Updates.Allow = tc.local
		// Per-intent, because only the destructive member has parameters at all now.
		raw := `{}`
		if tc.name == intent.PackagesApplyAll {
			raw = `{"rebootIfRequired":false}`
		}
		req := Request{
			Intent:   tc.name,
			Params:   mustDecode(t, tc.name, raw),
			IssuedAt: nowUTC,
		}
		d := Decide(p, req, Env{Now: nowUTC})
		if d.Allowed != tc.allowed {
			t.Errorf("updates.allow=%q %s: allowed=%v, want %v (%s)",
				tc.local, tc.name, d.Allowed, tc.allowed, d.Reason)
		}
		if !d.Allowed && d.Code != CodeUpdatesNotAllowed {
			t.Errorf("updates.allow=%q %s: code %q, want %q",
				tc.local, tc.name, d.Code, CodeUpdatesNotAllowed)
		}
	}
}

// TestDecideRefusesUnitsNotOnTheRestartableList covers services.restartable.
func TestDecideRefusesUnitsNotOnTheRestartableList(t *testing.T) {
	p := openWindowPolicy(t)
	for _, tc := range []struct {
		unit    string
		allowed bool
	}{
		{"nginx.service", true},
		{"hostseal-agent.service", true},
		{"sshd.service", false},
		{"postgresql.service", false},
	} {
		for _, name := range []intent.Name{intent.ServiceStart, intent.ServiceStop, intent.ServiceRestart} {
			req := Request{
				Intent:   name,
				Params:   mustDecode(t, name, `{"unit":"`+tc.unit+`"}`),
				IssuedAt: nowUTC,
			}
			d := Decide(p, req, Env{Now: nowUTC})
			if d.Allowed != tc.allowed {
				t.Errorf("%s %s: allowed=%v, want %v (%s)", name, tc.unit, d.Allowed, tc.allowed, d.Reason)
			}
		}
	}
}

// TestDecideRebootHonoursModeAndWindow covers updates.reboot and the maintenance window together.
//
// The two are separate settings and both must hold. A policy of reboot="window" with no window
// configured is always open, which is deliberate: the operator who wrote that meant "reboots are
// fine", and demanding they also invent a window would be answering a question they did not ask.
func TestDecideRebootHonoursModeAndWindow(t *testing.T) {
	saturdayAfternoon := time.Date(2026, 8, 22, 14, 0, 0, 0, time.UTC)
	sundayEarly := time.Date(2026, 8, 23, 3, 30, 0, 0, time.UTC)

	cases := []struct {
		name    string
		mode    RebootMode
		window  string
		now     time.Time
		allowed bool
		code    string
	}{
		{"never refuses inside a window", RebootNever, "Sun 03:00-05:00", sundayEarly, false, CodeRebootNotAllowed},
		{"never refuses always-open", RebootNever, "", sundayEarly, false, CodeRebootNotAllowed},
		{"window permits inside", RebootWindow, "Sun 03:00-05:00", sundayEarly, true, CodeAllowed},
		{"window refuses outside", RebootWindow, "Sun 03:00-05:00", saturdayAfternoon, false, CodeOutsideWindow},
		{"an explicit all-day window is always open", RebootWindow, "daily 00:00-00:00", saturdayAfternoon, true, CodeAllowed},
	}
	for _, tc := range cases {
		p := openWindowPolicy(t)
		p.Updates.Reboot = tc.mode
		p.Updates.Window = tc.window
		if err := p.validate(); err != nil {
			t.Fatalf("%s: revalidating fixture: %v", tc.name, err)
		}
		req := Request{
			Intent:   intent.HostReboot,
			Params:   mustDecode(t, intent.HostReboot, `{}`),
			IssuedAt: tc.now,
		}
		d := Decide(p, req, Env{Now: tc.now})
		if d.Allowed != tc.allowed {
			t.Errorf("%s: allowed=%v, want %v (%s)", tc.name, d.Allowed, tc.allowed, d.Reason)
		}
		if d.Code != tc.code {
			t.Errorf("%s: code %q, want %q", tc.name, d.Code, tc.code)
		}
	}
}

// TestDecideTreatsAFollowUpRebootAsAReboot covers rebootIfRequired on an update intent.
//
// Letting it through on the strength of the update permission alone would make reboot="never" mean
// "never, unless the update job asked nicely", which is the sort of exception that turns a guarantee
// into a guideline.
func TestDecideTreatsAFollowUpRebootAsAReboot(t *testing.T) {
	p := openWindowPolicy(t)
	p.Updates.Reboot = RebootNever

	req := Request{
		Intent:   intent.PackagesApplyAll,
		Params:   mustDecode(t, intent.PackagesApplyAll, `{"rebootIfRequired":true}`),
		IssuedAt: nowUTC,
	}
	d := Decide(p, req, Env{Now: nowUTC})
	if d.Allowed {
		t.Fatal("an update with rebootIfRequired was permitted on a host that forbids reboots")
	}
	if d.Code != CodeRebootNotAllowed {
		t.Errorf("code %q, want %q", d.Code, CodeRebootNotAllowed)
	}

	// The same job without the follow-up reboot is fine, which is what makes the refusal specific.
	req.Params = mustDecode(t, intent.PackagesApplyAll, `{"rebootIfRequired":false}`)
	if d := Decide(p, req, Env{Now: nowUTC}); !d.Allowed {
		t.Errorf("the same update without a reboot was refused: %s", d.Reason)
	}
}

// TestDecideRefusesUnknownIntents asserts the decision function fails closed.
//
// A future intent that reaches Decide without a case is refused rather than permitted, so forgetting
// to add one is a visible outage rather than an invisible hole.
func TestDecideRefusesUnknownIntents(t *testing.T) {
	p := openWindowPolicy(t)
	req := Request{Intent: "shell.exec", IssuedAt: nowUTC}
	d := Decide(p, req, Env{Now: nowUTC})
	if d.Allowed {
		t.Fatal("an intent outside the catalogue was permitted")
	}
	if d.Code != CodeUnknownIntent {
		t.Errorf("code %q, want %q", d.Code, CodeUnknownIntent)
	}
}

// TestGuaranteeControlPlaneCannotExceedLocalPolicy is the policy half of docs/SECURITY.md §1.
//
// It states the guarantee directly rather than testing the pieces: with the most restrictive policy a
// host can carry, no privileged request of any shape is permitted, whatever the control plane asks
// for and whenever it asks. It is named for the guarantee suite so that `make guarantee` runs it and
// the required CI check covers it.
func TestGuaranteeControlPlaneCannotExceedLocalPolicy(t *testing.T) {
	locked, err := Parse([]byte(`
[updates]
allow = "none"
auto_apply = false
reboot = "never"

[services]
restartable = []

[limits]
max_job_age_seconds = 900
`))
	if err != nil {
		t.Fatalf("parsing the locked-down policy: %v", err)
	}

	paramShapes := map[intent.Name][]string{
		// No rebootIfRequired shapes: the routine member refuses the field outright, because a reboot
		// authorised by the control plane's own online key is what docs/SECURITY.md §3 forbids.
		intent.PackagesApplySecurity: {`{}`, ``},
		intent.PackagesApplyAll:      {`{}`, `{"rebootIfRequired":true}`, `{"rebootIfRequired":false}`},
		intent.ServiceStart:          {`{"unit":"nginx.service"}`, `{"unit":"hostseal-agent.service"}`},
		intent.ServiceStop:           {`{"unit":"sshd.service"}`, `{"unit":"docker.service"}`},
		intent.ServiceRestart:        {`{"unit":"nginx.service"}`},
		intent.HostReboot:            {`{}`, `{"delaySeconds":0}`, `{"delaySeconds":3600,"message":"now"}`},
	}

	instants := []time.Time{
		nowUTC,
		time.Date(2026, 8, 23, 3, 30, 0, 0, time.UTC), // inside a typical maintenance window
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	for _, spec := range intent.All() {
		if !spec.Class.Privileged() {
			continue
		}
		shapes, ok := paramShapes[spec.Name]
		if !ok {
			t.Fatalf("privileged intent %q has no parameter shapes in this test. Add them: this test "+
				"is what proves the control plane cannot exceed local policy, and an intent it does "+
				"not exercise is an intent it does not cover.", spec.Name)
		}
		for _, raw := range shapes {
			for _, now := range instants {
				req := Request{
					Intent:   spec.Name,
					Params:   mustDecode(t, spec.Name, raw),
					IssuedAt: now,
				}
				d := Decide(locked, req, Env{Now: now})
				if d.Allowed {
					t.Errorf("a host with allow=none, reboot=never and no restartable units permitted "+
						"%s with params %s at %s: %s", spec.Name, raw, now, d.Reason)
				}
			}
		}
	}
}
