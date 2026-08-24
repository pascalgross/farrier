package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/protocol"
)

// sharedMachineID is one physical machine's identity, enrolled into both tenants below.
//
// The schema makes the machine-id claim per tenant rather than per installation, because across
// tenants it would be an oracle: enrolling a machine and being told it is already enrolled tells you
// that somebody else manages it. That the same hash can be live twice is therefore a property worth
// asserting, and it is one a store keyed on the hash alone would fail.
const sharedMachineID = "sha256:one-physical-machine"

// sharedJobID is the identifier both tenants choose for a job.
//
// This is the collision that actually happens. A signed job's id comes from the customer's own offline
// signer and is theirs to pick, so "01JSHAREDJOB" — or "reboot-2026-08-23" — is a reasonable thing for
// two customers to choose on the same day. Host ids are not in this category: they are generated here
// and stay globally unique, which is why the two tenants below have different ones.
const sharedJobID = "01JSHAREDJOB"

// sharedTemplateName is the template name both tenants choose.
//
// Same reasoning as the job id: a template name is typed by an operator, and "standard-server" is
// exactly what two unrelated customers call their standard server. A leak here would hand one
// customer's provisioning secrets — enrolment tokens, break-glass credentials — to the other, which is
// why the probes check whose bytes came back rather than whether any did.
const sharedTemplateName = "standard-server"

// twoTenants builds two populated tenants against one store, for the isolation tests.
//
// They collide everywhere the schema allows a collision — the same job id, the same machine-id hash —
// because that is what a leak would have to return in order to look like the caller's own data. Two
// tenants built from entirely distinct identifiers would pass against a store with no isolation at all,
// since there would be nothing for a broken query to hand back that a test could recognise as wrong.
//
// Both jobs are queued behind a release, because a job nothing would ever move is a job no write
// probe can prove was left alone: the ApproveJob isolation probe needs beta's row to be exactly one
// release away, or an update that leaked across the boundary would have had nothing to change. The two
// still differ in the rule stamped on the row — alpha's release must come from a second person distinct
// from the creator, beta's from anybody — which keeps a field here that reading the wrong tenant's row
// would get wrong. The tenants' own settings differ the same way, second_person against none.
func twoTenants(t *testing.T, s Store) (alpha, beta Scoped) {
	t.Helper()

	alpha = testTenant(t, s, "alpha", ApprovalSecondPerson)
	beta = testTenant(t, s, "beta", ApprovalNone)

	ctx := context.Background()
	for _, tenant := range []struct {
		// scoped is the handle, and hostID is the host enrolled into it.
		scoped Scoped
		hostID string
	}{{alpha, alphaHostID}, {beta, betaHostID}} {
		enrolTestHostAs(t, tenant.scoped, tenant.hostID, "web-01.example.org", sharedMachineID)

		if err := tenant.scoped.CreateEnrollmentToken(ctx, EnrollmentToken{
			Hash:      "hash-" + string(tenant.scoped.Tenant()),
			Label:     string(tenant.scoped.Tenant()) + "-token",
			Group:     "web-prod",
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}); err != nil {
			t.Fatalf("creating a token for %s: %v", tenant.scoped.Tenant(), err)
		}

		job := jobFor(sharedJobID, "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2ln"
		if err := tenant.scoped.CreateJob(ctx, NewJob{
			Job:                      job,
			HostID:                   tenant.hostID,
			CreatedBy:                "test:" + string(tenant.scoped.Tenant()),
			ApprovalRequired:         true,
			ApprovalDistinctOperator: tenant.scoped == alpha,
		}); err != nil {
			t.Fatalf("creating a job for %s: %v", tenant.scoped.Tenant(), err)
		}

		// The same template name in both tenants, with each tenant's identity in the sealed bytes and
		// the author, so that a listing or a lookup that leaked would return something recognisably not
		// the caller's own.
		if _, err := tenant.scoped.CreateTemplateVersion(ctx, TemplateVersion{
			Name:       sharedTemplateName,
			BodySealed: []byte("sealed-for-" + string(tenant.scoped.Tenant())),
			CreatedAt:  time.Now().UTC(),
			CreatedBy:  "test:" + string(tenant.scoped.Tenant()),
		}); err != nil {
			t.Fatalf("creating a template for %s: %v", tenant.scoped.Tenant(), err)
		}

		// The observability rows, colliding on every identifier the schema lets collide: the same
		// event id, the same rule id, each tenant's identity in the summaries and authors so a leak
		// is recognisable as one.
		if err := tenant.scoped.RecordEvent(ctx, Event{
			ID: sharedEventID, Kind: "job.failed", HostID: tenant.hostID,
			Summary: "event-for-" + string(tenant.scoped.Tenant()), At: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("recording an event for %s: %v", tenant.scoped.Tenant(), err)
		}
		if err := tenant.scoped.RecordUnitTransitions(ctx, tenant.hostID, []UnitTransition{
			{Unit: "nginx.service", From: "active", To: "failed", At: time.Now().UTC()},
		}); err != nil {
			t.Fatalf("recording a transition for %s: %v", tenant.scoped.Tenant(), err)
		}
		if err := tenant.scoped.CreateAlertRule(ctx, AlertRule{
			ID: sharedRuleID, Condition: ConditionHostSilent, Threshold: 10, Enabled: true,
			CreatedAt: time.Now().UTC(), CreatedBy: "test:" + string(tenant.scoped.Tenant()),
		}); err != nil {
			t.Fatalf("creating a rule for %s: %v", tenant.scoped.Tenant(), err)
		}
		if err := tenant.scoped.UpsertAlertState(ctx, AlertState{
			RuleID: sharedRuleID, HostID: tenant.hostID, Firing: true, Since: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("recording a state for %s: %v", tenant.scoped.Tenant(), err)
		}
	}
	return alpha, beta
}

// The two hosts, one per tenant.
//
// Different identifiers because host ids are generated by the control plane and are globally unique by
// construction — the collision worth testing is the one an operator can cause, which is the job id.
const (
	// alphaHostID is the host in the first tenant.
	alphaHostID = "01JALPHAHOST"

	// betaHostID is the host in the second, and the id every write probe below aims at.
	betaHostID = "01JBETAHOST"

	// betaJobID is a job only beta has, for the probes that must fail to reach it.
	betaJobID = "01JBETAJOB"

	// betaClaimedHostID is a second host only beta has, carrying the claimed job below.
	betaClaimedHostID = "01JBETACLAIMEDHOST"

	// betaClaimedJobID is a job of beta's that the fixture claims before any probe runs.
	//
	// A result can only be recorded for claimed work, so the RecordResult probe needs a row already in
	// that state. Claiming it in the fixture rather than relying on the ClaimJobs probe having run
	// first is what makes the probe hold in every map order instead of about half of them.
	betaClaimedJobID = "01JBETACLAIMEDJOB"

	// betaOnlyTemplateName is a template only beta stores, for the lookup that must find nothing.
	betaOnlyTemplateName = "beta-private"

	// sharedEventID is the inbox event id both tenants hold, because the schema permits it.
	sharedEventID = "01JSHAREDEVENT"

	// sharedRuleID is the alert rule id both tenants hold.
	sharedRuleID = "01JSHAREDRULE"

	// betaOnlyRuleID is a rule only beta holds, for the delete and upsert probes that must miss.
	betaOnlyRuleID = "01JBETARULE"
)

// deliveryStamp is the fixed time the delivery-report probe writes.
//
// Fixed rather than time.Now, because the probe asserts on what did *not* change in the other
// tenant's rows, and a moving value makes a failure read as a timing problem rather than a leak.
var deliveryStamp = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// TestGuaranteeOneTenantCannotSeeAnother is the isolation boundary, asserted rather than assumed.
//
// It is driven by reflection over the Scoped interface rather than by a list of calls, and that is the
// whole point of it. A hand-written list is a list somebody adds a method without joining, and the
// method they forget will be the new one — written in a hurry, reviewed as an addition rather than as a
// boundary. Here, a method added to Scoped and not named below fails the test until somebody decides
// what "isolated" means for it.
//
// What it proves is narrow and worth stating exactly: for every method on Scoped, calling it on
// tenant A against a store that also holds tenant B's data must not return B's data and must not
// mutate it. It does not prove the SQL is right — PostgreSQL's row-level security proves that, and
// TestGuaranteeRowLevelSecurityIsTheRuleNotThePredicate proves the policy is switched on.
func TestGuaranteeOneTenantCannotSeeAnother(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		alpha, beta := twoTenants(t, s)

		// Every method on Scoped, and what "isolated" means for each. A method missing from here fails
		// the completeness check below.
		probes := map[string]func(t *testing.T){
			"Tenant": func(t *testing.T) {
				if alpha.Tenant() == beta.Tenant() {
					t.Fatal("two tenants report the same identity")
				}
			},

			// Reads: a colliding identifier must resolve to the caller's own row, and a listing must
			// contain only the caller's rows.
			"GetHost": func(t *testing.T) {
				host, err := alpha.GetHost(ctx, alphaHostID)
				if err != nil {
					t.Fatalf("alpha cannot read its own host: %v", err)
				}
				if host.Hostname != "web-01.example.org" {
					t.Fatalf("read back %+v", host)
				}
				// Proved by the job below rather than by the host row, which is identical in both.
				job, err := alpha.GetJob(ctx, sharedJobID)
				if err != nil {
					t.Fatalf("alpha cannot read its own job: %v", err)
				}
				if job.CreatedBy != "test:"+string(alpha.Tenant()) {
					t.Errorf("alpha read a job created by %q, which is not its own", job.CreatedBy)
				}
			},
			"GetHostByMachineID": func(t *testing.T) {
				// The same machine-id hash is live in both, which the schema now permits per tenant.
				host, err := alpha.GetHostByMachineID(ctx, sharedMachineID)
				if err != nil {
					t.Fatalf("alpha cannot find its own host by machine id: %v", err)
				}
				if host.ID != alphaHostID {
					t.Fatalf("found %+v", host)
				}
			},
			"ListHosts": func(t *testing.T) {
				hosts, err := alpha.ListHosts(ctx)
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				if len(hosts) != 1 {
					t.Fatalf("alpha sees %d hosts; it has one and every other host is beta's", len(hosts))
				}
			},
			"ListJobs": func(t *testing.T) {
				jobs, err := alpha.ListJobs(ctx, JobFilter{})
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				if len(jobs) != 1 {
					t.Fatalf("alpha sees %d jobs; it has one and beta has one", len(jobs))
				}
				if jobs[0].CreatedBy != "test:"+string(alpha.Tenant()) {
					t.Errorf("alpha's listing contains a job created by %q", jobs[0].CreatedBy)
				}
			},
			"GetJob": func(t *testing.T) {
				job, err := alpha.GetJob(ctx, sharedJobID)
				if err != nil {
					t.Fatalf("alpha cannot read its own job: %v", err)
				}
				if job.CreatedBy != "test:"+string(alpha.Tenant()) {
					t.Errorf("alpha read beta's job: created by %q", job.CreatedBy)
				}
			},
			"ListEnrollmentTokens": func(t *testing.T) {
				tokens, err := alpha.ListEnrollmentTokens(ctx)
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				// By content rather than by count: the probes run in map order, so another of them may
				// already have added a token of alpha's. What must never appear is beta's.
				var mine bool
				for _, token := range tokens {
					if token.Hash == "hash-"+string(beta.Tenant()) {
						t.Error("alpha's token listing contains a token issued to beta")
					}
					if token.Label == string(alpha.Tenant())+"-token" {
						mine = true
					}
				}
				if !mine {
					t.Fatalf("alpha's own token is missing from its listing: %+v", tokens)
				}
			},

			// Writes: an operation aimed at another tenant's row must fail, and must leave it alone.
			"CreateJob": func(t *testing.T) {
				// Aimed at beta's host id, from alpha. The id exists — in beta — so a store with no
				// isolation would accept it and file alpha's job against beta's machine.
				job := jobFor("01JCROSS", "facts.collect")
				err := alpha.CreateJob(ctx, NewJob{
					Job: job, HostID: betaHostID, CreatedBy: "test:alpha",
				})
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("creating a job for a host alpha does not have returned %v, want ErrNotFound", err)
				}
			},
			"ApproveJob": func(t *testing.T) {
				// The probe is only as good as the state it starts from: beta's job must be exactly one
				// release away, or an approval that leaked across the boundary would have had nothing to
				// change and the comparison below could never fail. That is not hypothetical — an
				// earlier version of this probe ran against a beta job that did not require approval,
				// so ApproveJob's own WHERE clause protected it and the probe passed against a store
				// with no isolation at all.
				before, err := beta.GetJob(ctx, sharedJobID)
				if err != nil {
					t.Fatalf("reading beta's job: %v", err)
				}
				if !before.ApprovalRequired || before.ApprovedBy != "" || !before.ApprovedAt.IsZero() {
					t.Fatalf("beta's job is not waiting for a release, so nothing below can fail: %+v", before)
				}

				// Alpha releasing what it believes is its own job must not release beta's, even though
				// the id is identical and beta's is waiting for exactly this. Alpha's own copy is the
				// one that must move — the collision resolving to the caller's row is the property.
				if err := alpha.ApproveJob(ctx, sharedJobID, "test:someone-else", time.Now().UTC()); err != nil {
					t.Fatalf("alpha releasing its own job: %v", err)
				}

				after, err := beta.GetJob(ctx, sharedJobID)
				if err != nil {
					t.Fatalf("re-reading beta's job: %v", err)
				}
				if after.ApprovedBy != "" || !after.ApprovedAt.IsZero() {
					t.Fatalf("alpha released beta's job: approved by %q at %s",
						after.ApprovedBy, after.ApprovedAt)
				}

				// And the untouched row really was one release away: the same call from its own tenant
				// succeeds, which is what proves the comparison above was able to fail.
				if err := beta.ApproveJob(ctx, sharedJobID, "test:someone-else", time.Now().UTC()); err != nil {
					t.Fatalf("beta releasing the job alpha's call must not have reached: %v", err)
				}
			},
			"RevokeHost": func(t *testing.T) {
				_ = alpha.RevokeHost(ctx, betaHostID)
				host, err := beta.GetHost(ctx, betaHostID)
				if err != nil {
					t.Fatalf("reading beta's host: %v", err)
				}
				if host.Revoked {
					t.Fatal("alpha revoked a host belonging to beta")
				}
			},
			"DeleteHost": func(t *testing.T) {
				_ = alpha.DeleteHost(ctx, betaHostID)
				if _, err := beta.GetHost(ctx, betaHostID); err != nil {
					t.Fatalf("alpha deleted a host belonging to beta: %v", err)
				}
			},
			"RecordHeartbeat": func(t *testing.T) {
				_ = alpha.RecordHeartbeat(ctx, betaHostID, HeartbeatUpdate{
					AgentVersion: "forged", LastSeen: time.Now().UTC(),
				})
				host, err := beta.GetHost(ctx, betaHostID)
				if err != nil {
					t.Fatalf("reading beta's host: %v", err)
				}
				if host.AgentVersion == "forged" {
					t.Fatal("alpha wrote a heartbeat onto a host belonging to beta")
				}
			},
			"StoreFacts": func(t *testing.T) {
				assertDocumentIsNotWritable(t, alpha.StoreFacts, beta, func(h Host) string {
					return h.FactsDigest
				})
			},
			"StorePolicy": func(t *testing.T) {
				assertDocumentIsNotWritable(t, alpha.StorePolicy, beta, func(h Host) string {
					return h.PolicyDigest
				})
			},
			"StoreSigners": func(t *testing.T) {
				assertDocumentIsNotWritable(t, alpha.StoreSigners, beta, func(h Host) string {
					return h.SignersDigest
				})
			},
			"ClaimJobs": func(t *testing.T) {
				// Beta's host has a claimable job waiting on it. Alpha claiming for that host id — an
				// id it does not own, but one it could learn from a log line or a support ticket — must
				// come back empty, and must not take beta's work off beta's queue on the way.
				claimed, err := alpha.ClaimJobs(ctx, betaHostID, 10)
				if err != nil {
					t.Fatalf("claiming: %v", err)
				}
				if len(claimed) != 0 {
					t.Fatalf("alpha claimed %d job(s) for a host belonging to beta: %+v",
						len(claimed), claimed)
				}
				// And beta's job is still there to be claimed, rather than having been consumed by a
				// claim that then discarded it — which would deliver the job to nobody at all.
				stillThere, err := beta.ClaimJobs(ctx, betaHostID, 10)
				if err != nil {
					t.Fatalf("beta claiming its own work: %v", err)
				}
				if len(stillThere) == 0 {
					t.Fatal("alpha's claim consumed beta's job without delivering it")
				}
			},
			"RecordResult": func(t *testing.T) {
				// Aimed at the job the fixture claimed, not at betaJobID: a result can only be recorded
				// for claimed work, so a probe aimed at an unclaimed job is refused for the wrong
				// reason and proves nothing about tenancy. An earlier version of this probe did exactly
				// that whenever it ran before the ClaimJobs probe — a pass in about half of map orders,
				// which is also a latent flake in the other half.
				_, err := alpha.RecordResult(ctx, betaClaimedHostID, protocol.ResultRequest{
					JobID: betaClaimedJobID, Status: protocol.StatusSucceeded,
				})
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("alpha reported a result for beta's job and got %v, want ErrNotFound", err)
				}
				rec, err := beta.GetJob(ctx, betaClaimedJobID)
				if err != nil {
					t.Fatalf("reading beta's claimed job back: %v", err)
				}
				if rec.Result != nil || !rec.CompletedAt.IsZero() {
					t.Fatalf("alpha's refused result still completed beta's job: %+v", rec)
				}

				// And the refusal was tenancy and nothing else: the identical call from the job's own
				// tenant is accepted, which proves the row was in a recordable state all along.
				if _, err := beta.RecordResult(ctx, betaClaimedHostID, protocol.ResultRequest{
					JobID: betaClaimedJobID, Status: protocol.StatusSucceeded,
				}); err != nil {
					t.Fatalf("beta recording the result alpha was refused: %v", err)
				}
			},
			"CreateEnrollmentToken": func(t *testing.T) {
				// A token created by alpha must not appear in beta's listing, which is the leak that
				// would let one customer enrol a machine into another's fleet.
				if err := alpha.CreateEnrollmentToken(ctx, EnrollmentToken{
					Hash: "hash-crossing", Label: "alpha-second", Group: "web-prod",
					CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
				}); err != nil {
					t.Fatalf("creating a token: %v", err)
				}
				tokens, err := beta.ListEnrollmentTokens(ctx)
				if err != nil {
					t.Fatalf("listing beta's tokens: %v", err)
				}
				for _, token := range tokens {
					if token.Hash == "hash-crossing" {
						t.Fatal("a token alpha created is listed for beta")
					}
				}
			},
			"ConsumeEnrollmentToken": func(t *testing.T) {
				_, err := alpha.ConsumeEnrollmentToken(ctx, "hash-"+string(beta.Tenant()), "01JNEW", time.Now())
				if !errors.Is(err, ErrTokenUnusable) {
					t.Fatalf("alpha redeemed a token issued to beta: %v", err)
				}
			},
			"CreateEnrolledHost": func(t *testing.T) {
				// twoTenants enrols one host into each with the same machine-id hash, which the schema
				// permits per tenant and would refuse if the claim were installation-wide. What must
				// not follow is that either can then read the other's row.
				if _, err := beta.GetHost(ctx, betaHostID); err != nil {
					t.Fatalf("beta cannot read the host it enrolled: %v", err)
				}
				if _, err := alpha.GetHost(ctx, betaHostID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("alpha read a host beta enrolled, getting %v; want ErrNotFound", err)
				}
			},
			"AddCertificate": func(t *testing.T) {
				err := alpha.AddCertificate(ctx, Certificate{
					Fingerprint: "fp-crossing", HostID: betaHostID, TenantID: alpha.Tenant(),
					Serial: "02", IssuedAt: time.Now(), NotAfter: time.Now().Add(time.Hour),
				})
				if err == nil {
					t.Fatal("alpha issued a certificate against a host belonging to beta")
				}
			},
			"GetEnrollmentToken": func(t *testing.T) {
				// A token issued by beta must be unusable from alpha — the same one answer unknown,
				// expired and consumed get, so holding another fleet's token teaches nothing.
				if _, err := alpha.GetEnrollmentToken(ctx, "hash-"+string(beta.Tenant())); !errors.Is(err, ErrTokenUnusable) {
					t.Fatalf("alpha read a token issued to beta: %v", err)
				}
				token, err := alpha.GetEnrollmentToken(ctx, "hash-"+string(alpha.Tenant()))
				if err != nil {
					t.Fatalf("alpha cannot read its own token: %v", err)
				}
				if token.Label != string(alpha.Tenant())+"-token" {
					t.Fatalf("alpha's token lookup returned %+v", token)
				}
			},
			"CreateTemplateVersion": func(t *testing.T) {
				// Both tenants hold sharedTemplateName at v1. A new version created by alpha must
				// continue alpha's own numbering and must not supersede what beta's latest resolves to.
				version, err := alpha.CreateTemplateVersion(ctx, TemplateVersion{
					Name:       sharedTemplateName,
					BodySealed: []byte("sealed-for-" + string(alpha.Tenant()) + "-v2"),
					CreatedAt:  time.Now().UTC(),
					CreatedBy:  "test:" + string(alpha.Tenant()),
				})
				if err != nil {
					t.Fatalf("alpha creating a second version: %v", err)
				}
				if version < 2 {
					t.Fatalf("alpha's second version was numbered %d", version)
				}
				latest, err := beta.GetTemplateVersion(ctx, sharedTemplateName, 0)
				if err != nil {
					t.Fatalf("reading beta's latest: %v", err)
				}
				if latest.CreatedBy != "test:"+string(beta.Tenant()) {
					t.Fatalf("beta's latest template was created by %q", latest.CreatedBy)
				}
			},
			"ListTemplates": func(t *testing.T) {
				templates, err := alpha.ListTemplates(ctx)
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				var mine bool
				for _, tpl := range templates {
					if tpl.CreatedBy == "test:"+string(beta.Tenant()) {
						t.Errorf("alpha's template listing contains beta's %q", tpl.Name)
					}
					if tpl.Name == sharedTemplateName {
						mine = true
					}
				}
				if !mine {
					t.Fatalf("alpha's own template is missing from its listing: %+v", templates)
				}
			},
			"GetTemplateVersion": func(t *testing.T) {
				// The colliding name must resolve to the caller's own bytes.
				tpl, err := alpha.GetTemplateVersion(ctx, sharedTemplateName, 1)
				if err != nil {
					t.Fatalf("alpha cannot read its own template: %v", err)
				}
				if string(tpl.BodySealed) != "sealed-for-"+string(alpha.Tenant()) {
					t.Fatalf("alpha read template bytes %q, which are not its own", tpl.BodySealed)
				}
				// And a name only beta holds is nothing rather than beta's.
				if _, err := alpha.GetTemplateVersion(ctx, betaOnlyTemplateName, 0); !errors.Is(err, ErrNotFound) {
					t.Fatalf("alpha read a template only beta has: %v", err)
				}
			},
			"RecordEvent": func(t *testing.T) {
				// An event recorded by alpha must not surface in beta's inbox, whatever id it carries.
				if err := alpha.RecordEvent(ctx, Event{
					ID: "01JCROSSEVENT", Kind: "job.failed", Summary: "crossing", At: time.Now().UTC(),
				}); err != nil {
					t.Fatalf("recording: %v", err)
				}
				events, err := beta.ListEvents(ctx, EventFilter{})
				if err != nil {
					t.Fatalf("listing beta's events: %v", err)
				}
				for _, e := range events {
					if e.ID == "01JCROSSEVENT" {
						t.Fatal("an event alpha recorded is in beta's inbox")
					}
				}
			},
			"ListEvents": func(t *testing.T) {
				events, err := alpha.ListEvents(ctx, EventFilter{})
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				var mine bool
				for _, e := range events {
					if e.Summary == "event-for-"+string(beta.Tenant()) {
						t.Error("alpha's inbox holds beta's event")
					}
					if e.Summary == "event-for-"+string(alpha.Tenant()) {
						mine = true
					}
				}
				if !mine {
					t.Fatalf("alpha's own event is missing from its inbox: %+v", events)
				}
			},
			"RecordUnitTransitions": func(t *testing.T) {
				// Aimed at beta's host from alpha: refused — the composite foreign key's job — and
				// beta's history untouched.
				err := alpha.RecordUnitTransitions(ctx, betaHostID, []UnitTransition{
					{Unit: "forged.service", From: "active", To: "failed", At: time.Now().UTC()},
				})
				if err == nil {
					t.Fatal("alpha recorded unit history onto a host belonging to beta")
				}
				history, err := beta.ListUnitTransitions(ctx, betaHostID, 0)
				if err != nil {
					t.Fatalf("reading beta's history: %v", err)
				}
				for _, tr := range history {
					if tr.Unit == "forged.service" {
						t.Fatal("the refused write still landed in beta's history")
					}
				}
			},
			"ListUnitTransitions": func(t *testing.T) {
				// Beta's host has history; alpha asking about it gets nothing rather than beta's.
				history, err := alpha.ListUnitTransitions(ctx, betaHostID, 0)
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				if len(history) != 0 {
					t.Fatalf("alpha read %d transition(s) from beta's host", len(history))
				}
				own, err := alpha.ListUnitTransitions(ctx, alphaHostID, 0)
				if err != nil || len(own) == 0 {
					t.Fatalf("alpha cannot read its own history: %d, %v", len(own), err)
				}
			},
			"CreateAlertRule": func(t *testing.T) {
				if err := alpha.CreateAlertRule(ctx, AlertRule{
					ID: "01JCROSSRULE", Condition: ConditionUnitFailed, Enabled: true,
					CreatedAt: time.Now().UTC(), CreatedBy: "test:alpha",
				}); err != nil {
					t.Fatalf("creating: %v", err)
				}
				rules, err := beta.ListAlertRules(ctx)
				if err != nil {
					t.Fatalf("listing beta's rules: %v", err)
				}
				for _, r := range rules {
					if r.ID == "01JCROSSRULE" {
						t.Fatal("a rule alpha created is listed for beta")
					}
				}
			},
			"ListAlertRules": func(t *testing.T) {
				rules, err := alpha.ListAlertRules(ctx)
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				var mine bool
				for _, r := range rules {
					if r.CreatedBy == "test:"+string(beta.Tenant()) {
						t.Errorf("alpha's rules include one created by %q", r.CreatedBy)
					}
					if r.ID == sharedRuleID {
						mine = true
					}
				}
				if !mine {
					t.Fatalf("alpha's own rule is missing: %+v", rules)
				}
			},
			"UpdateAlertRule": func(t *testing.T) {
				// The colliding id must update the caller's own copy and only it.
				if err := alpha.UpdateAlertRule(ctx, AlertRule{
					ID: sharedRuleID, Threshold: 99, Enabled: true,
				}); err != nil {
					t.Fatalf("alpha updating its own rule: %v", err)
				}
				rules, err := beta.ListAlertRules(ctx)
				if err != nil {
					t.Fatalf("listing beta's rules: %v", err)
				}
				for _, r := range rules {
					if r.ID == sharedRuleID && r.Threshold == 99 {
						t.Fatal("alpha's update rewrote beta's rule")
					}
				}
			},
			"DeleteAlertRule": func(t *testing.T) {
				if err := alpha.DeleteAlertRule(ctx, betaOnlyRuleID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("alpha deleting a rule only beta has: %v", err)
				}
				rules, err := beta.ListAlertRules(ctx)
				if err != nil {
					t.Fatalf("listing beta's rules: %v", err)
				}
				var survived bool
				for _, r := range rules {
					if r.ID == betaOnlyRuleID {
						survived = true
					}
				}
				if !survived {
					t.Fatal("beta's rule did not survive alpha's delete")
				}
			},
			"RecordAlertDelivery": func(t *testing.T) {
				// The delivery report is the one write on a rule that comes from the notification
				// path rather than from an operator, so it is the one most easily written without a
				// tenant in mind. Naming beta's rule must stamp nothing, and stamping the colliding
				// id must reach only the caller's own copy.
				if err := alpha.RecordAlertDelivery(ctx, betaOnlyRuleID, deliveryStamp,
					"alpha's relay refused"); err != nil {
					t.Fatalf("alpha reporting against a rule only beta has: %v", err)
				}
				if err := alpha.RecordAlertDelivery(ctx, sharedRuleID, deliveryStamp,
					"alpha's relay refused"); err != nil {
					t.Fatalf("alpha reporting on its own rule: %v", err)
				}
				rules, err := beta.ListAlertRules(ctx)
				if err != nil {
					t.Fatalf("listing beta's rules: %v", err)
				}
				for _, r := range rules {
					if r.LastDeliveryError != "" {
						t.Fatalf("alpha's delivery report landed on beta's rule %s: %q",
							r.ID, r.LastDeliveryError)
					}
				}
			},
			"ListAlertStates": func(t *testing.T) {
				states, err := alpha.ListAlertStates(ctx)
				if err != nil {
					t.Fatalf("listing: %v", err)
				}
				var mine bool
				for _, st := range states {
					if st.HostID == betaHostID {
						t.Error("alpha's states include one about beta's host")
					}
					if st.RuleID == sharedRuleID && st.HostID == alphaHostID {
						mine = true
					}
				}
				if !mine {
					t.Fatalf("alpha's own state is missing: %+v", states)
				}
			},
			"UpsertAlertState": func(t *testing.T) {
				// Naming a rule only beta holds must be refused — the composite foreign key again —
				// and must leave beta's state alone.
				err := alpha.UpsertAlertState(ctx, AlertState{
					RuleID: betaOnlyRuleID, HostID: alphaHostID, Firing: true,
				})
				if err == nil {
					t.Fatal("alpha recorded state against a rule belonging to beta")
				}
				states, err := beta.ListAlertStates(ctx)
				if err != nil {
					t.Fatalf("listing beta's states: %v", err)
				}
				for _, st := range states {
					if st.RuleID == betaOnlyRuleID && st.Firing {
						t.Fatal("the refused upsert still landed in beta's states")
					}
				}
			},
		}

		// A second job that exists only in beta, for the write probes above to aim at. Beta's host is
		// already there from twoTenants; what is missing is a job alpha has no counterpart for, so that
		// a leak would have to return something alpha could not mistake for its own.
		if err := beta.CreateJob(ctx, NewJob{
			Job: jobFor(betaJobID, "facts.collect"), HostID: betaHostID, CreatedBy: "test:beta",
		}); err != nil {
			t.Fatalf("creating beta's private job: %v", err)
		}

		// A template only beta stores, for the GetTemplateVersion probe's negative half.
		if _, err := beta.CreateTemplateVersion(ctx, TemplateVersion{
			Name:       betaOnlyTemplateName,
			BodySealed: []byte("sealed-only-for-beta"),
			CreatedAt:  time.Now().UTC(),
			CreatedBy:  "test:beta",
		}); err != nil {
			t.Fatalf("creating beta's private template: %v", err)
		}

		// A rule only beta holds, for the delete and state probes that must miss it.
		if err := beta.CreateAlertRule(ctx, AlertRule{
			ID: betaOnlyRuleID, Condition: ConditionUnitFailed, Enabled: true,
			CreatedAt: time.Now().UTC(), CreatedBy: "test:beta",
		}); err != nil {
			t.Fatalf("creating beta's private rule: %v", err)
		}

		// And a claimed job on a host only beta has, for the RecordResult probe. Claimed here, before
		// any probe runs, because the probes run in map order: a probe that depended on the ClaimJobs
		// probe having claimed first would be vacuous in the orders where it had not. On its own host
		// so that no probe's claim can consume it and none of its state can leak into theirs.
		enrolTestHostAs(t, beta, betaClaimedHostID, "web-02.example.org", "sha256:only-beta-has-this")
		if err := beta.CreateJob(ctx, NewJob{
			Job: jobFor(betaClaimedJobID, "facts.collect"), HostID: betaClaimedHostID,
			CreatedBy: "test:beta",
		}); err != nil {
			t.Fatalf("creating beta's claimed job: %v", err)
		}
		if claimed, err := beta.ClaimJobs(ctx, betaClaimedHostID, 1); err != nil || len(claimed) != 1 {
			t.Fatalf("claiming beta's job for the RecordResult probe: %v (%d claimed)", err, len(claimed))
		}

		assertEveryScopedMethodIsProbed(t, probes)

		for name, probe := range probes {
			t.Run(name, probe)
		}
	})
}

// assertDocumentIsNotWritable checks that one tenant cannot write a reported document onto another's
// host.
//
// The three document setters have identical shapes and identical failure modes, so testing them by
// copy would mean three chances to check the wrong digest.
func assertDocumentIsNotWritable(
	t *testing.T,
	write func(context.Context, string, string, []byte) error,
	victim Scoped,
	digestOf func(Host) string,
) {
	t.Helper()
	ctx := t.Context()

	_ = write(ctx, betaHostID, "sha256:forged", []byte(`{"forged":true}`))
	host, err := victim.GetHost(ctx, betaHostID)
	if err != nil {
		t.Fatalf("reading the victim's host: %v", err)
	}
	if digestOf(host) == "sha256:forged" {
		t.Fatal("one tenant wrote a document onto another tenant's host")
	}
}

// assertEveryScopedMethodIsProbed fails when Scoped has grown a method the isolation test does not
// cover.
//
// This is the half that makes the test above hold in a year rather than today. A boundary asserted by a
// list is a boundary that decays by addition: the method somebody forgets to add is the new one, which
// is also the one least likely to have been thought about. Reflecting over the interface makes
// forgetting a build failure instead of a silence.
func assertEveryScopedMethodIsProbed(t *testing.T, probes map[string]func(*testing.T)) {
	t.Helper()

	scoped := reflect.TypeOf((*Scoped)(nil)).Elem()
	var missing []string
	for i := range scoped.NumMethod() {
		if _, covered := probes[scoped.Method(i).Name]; !covered {
			missing = append(missing, scoped.Method(i).Name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("Scoped has %d method(s) with no isolation probe: %s.\n"+
			"Every method that reaches a tenant's data needs one, because the method nobody thought to "+
			"add is the method nobody thought about. Add a case to the map above saying what "+
			"\"isolated\" means for it.",
			len(missing), strings.Join(missing, ", "))
	}

	for name := range probes {
		if _, exists := scoped.MethodByName(name); !exists {
			t.Errorf("the isolation test probes %q, which Scoped no longer has", name)
		}
	}
}

// TestGuaranteeRowLevelSecurityIsTheRuleNotThePredicate proves the database refuses the row, and not
// merely that the queries remember to ask.
//
// Everything else about isolation could be true and this could still be false: every statement in
// postgres.go could carry its tenant predicate, every test above could pass, and the policies could be
// absent — leaving one forgotten WHERE clause between a customer and somebody else's fleet. So this
// runs a statement with no predicate at all, which no production query does, and requires the answer to
// be scoped anyway.
//
// It is PostgreSQL-only because the mechanism is. The in-memory store enforces the same rule in Go and
// is covered by the test above; this asserts the thing that cannot be asserted anywhere but here.
func TestGuaranteeRowLevelSecurityIsTheRuleNotThePredicate(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	alpha, beta := twoTenants(t, pg)

	// The role has to be one the policies apply to. A superuser, or a role with BYPASSRLS, is exempt
	// from every policy in the schema with no symptom whatsoever — so a suite run as one would pass
	// this test while proving the opposite of what it claims. farrier-server refuses to start on such a
	// role for the same reason; here it is a failure rather than a skip, because a guarantee test that
	// quietly opted out would be worse than none.
	var role string
	var superuser, bypass bool
	if err := pg.pool.QueryRow(ctx,
		`SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&role, &superuser, &bypass); err != nil {
		t.Fatalf("reading the current role: %v", err)
	}
	if superuser || bypass {
		t.Fatalf("these tests connect as %q, which bypasses row-level security, so they cannot "+
			"observe it. Run them as an ordinary role: CREATE ROLE farrier_test LOGIN; and grant it "+
			"the schema", role)
	}

	// Both tenants need a row in every table under test, including job_results, which the shared
	// fixture does not populate. Reported here rather than in twoTenants so that adding coverage to
	// this test cannot change the row counts other tests in this file depend on.
	for _, tenant := range []struct {
		scoped Scoped
		hostID string
	}{{alpha, alphaHostID}, {beta, betaHostID}} {
		// Both fixture jobs are queued behind a release, so nothing may claim either until it is
		// approved. Released by a different principal than created it, because that is the rule
		// alpha's row carries; beta's accepts anybody, so the stricter form serves both.
		if err := tenant.scoped.ApproveJob(ctx, sharedJobID, "test:releaser", time.Now().UTC()); err != nil {
			t.Fatalf("approving the job for %s: %v", tenant.scoped.Tenant(), err)
		}
		if _, err := tenant.scoped.ClaimJobs(ctx, tenant.hostID, 10); err != nil {
			t.Fatalf("claiming for %s: %v", tenant.scoped.Tenant(), err)
		}
		if _, err := tenant.scoped.RecordResult(ctx, tenant.hostID, protocol.ResultRequest{
			JobID: sharedJobID, Status: protocol.StatusSucceeded,
		}); err != nil {
			t.Fatalf("recording a result for %s: %v", tenant.scoped.Tenant(), err)
		}
	}

	for _, table := range []string{"hosts", "jobs", "certificates", "enrollment_tokens", "job_results",
		"templates", "events", "unit_transitions", "alert_rules", "alert_states"} {
		t.Run(table, func(t *testing.T) {
			// No tenant set at all. Fail closed: current_setting(…, true) is NULL when unset, and
			// `tenant_id = NULL` is NULL rather than true, so the policy admits nothing.
			var unscoped int
			if err := pg.pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&unscoped); err != nil {
				t.Fatalf("counting %s with no tenant set: %v", table, err)
			}
			if unscoped != 0 {
				t.Errorf("a query against %s with no tenant set returned %d rows; the policy is not "+
					"enabled, or not FORCEd, and the table owner is bypassing it", table, unscoped)
			}

			// One tenant set, and a statement with no predicate of its own. Both tenants have rows
			// here; only one may come back.
			//
			// Asserted by counting the DISTINCT tenant_id values the statement can see, rather than by
			// comparing two row counts. That distinction is the whole point and it was got wrong here
			// once: the earlier version compared `count(*)` against `count(*) … WHERE true`, both run
			// as the same tenant, so the two were equal by construction and the assertion could not
			// fail. A policy that returned every tenant's rows passed it.
			//
			// This shape cannot be satisfied vacuously. A correct policy admits exactly one tenant's
			// rows, so one distinct value; a policy that leaks admits two, whatever the counts are.
			for _, tenant := range []Scoped{alpha, beta} {
				rows, tenants, only, err := visibleAsTenant(ctx, pg, tenant.Tenant(), table)
				if err != nil {
					t.Fatalf("reading %s as %s: %v", table, tenant.Tenant(), err)
				}
				if rows == 0 {
					t.Errorf("%s sees none of its own rows in %s", tenant.Tenant(), table)
				}
				if tenants != 1 {
					t.Errorf("an unpredicated statement against %s as %s saw rows belonging to %d "+
						"tenants; the policy is admitting somebody else's fleet", table,
						tenant.Tenant(), tenants)
				}
				if only != string(tenant.Tenant()) {
					t.Errorf("an unpredicated statement against %s as %s returned rows owned by %q",
						table, tenant.Tenant(), only)
				}
			}
		})
	}

	// And the same for a write: the policy's WITH CHECK must refuse a row addressed to somebody else.
	tx, err := pg.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`SELECT set_config('farrier.tenant', $1, true)`, string(alpha.Tenant())); err != nil {
		t.Fatalf("setting the tenant: %v", err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO hosts (id, hostname, tenant_id, enrolled_at) VALUES ($1, $2, $3, now())`,
		"01JSTOLEN", "stolen", string(beta.Tenant()))
	if err == nil {
		t.Error("a tenant inserted a host row belonging to another tenant; the policy has no WITH CHECK")
	}
}

// visibleAsTenant reports what an unpredicated statement can see inside a transaction that has set one
// tenant: how many rows, how many distinct owners, and which owner when there is exactly one.
//
// The statement it runs deliberately has no tenant predicate. That is what is being tested: a query
// written by somebody who forgot must return that tenant's rows and no others, because the policy is
// the rule and the predicate is only the query plan.
//
// It returns the owner count rather than a row count because a row count cannot express the property.
// The version this replaced compared two counts that were equal by construction, so it passed against a
// policy showing every tenant every other tenant's rows. Counting distinct owners has no such failure
// mode: correct is one, leaking is more, and neither depends on how many rows the fixture happened to
// create.
func visibleAsTenant(ctx context.Context, pg *Postgres, tenant TenantID, table string) (
	rows, tenants int, only string, err error) {

	tx, beginErr := pg.pool.Begin(ctx)
	if beginErr != nil {
		return 0, 0, "", beginErr
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('farrier.tenant', $1, true)`, string(tenant)); err != nil {
		return 0, 0, "", err
	}
	// No predicate, deliberately: no production query looks like this, and the answer has to be
	// scoped anyway. min(tenant_id) names the owner when exactly one is visible, and is reported so
	// that a policy admitting the *wrong* single tenant fails as loudly as one admitting two.
	err = tx.QueryRow(ctx,
		`SELECT count(*), count(DISTINCT tenant_id), coalesce(min(tenant_id), '') FROM `+table,
	).Scan(&rows, &tenants, &only)
	return rows, tenants, only, err
}

// TestGuaranteeDeletingATenantLeavesNothingBehind is the other half of isolation: what a customer
// leaves behind when they go.
//
// It matters for the same reason the boundary does. A tenant's rows outliving the tenant would mean a
// deleted customer's hostnames, policies and job history sitting in a database somebody has been told
// is empty of them — and, because a job row references a host, it would also be the shape of a
// dangling reference that resurfaces as somebody else's row after an id is reused.
func TestGuaranteeDeletingATenantLeavesNothingBehind(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		alpha, beta := twoTenants(t, s)

		if err := s.DeleteTenant(ctx, alpha.Tenant()); err != nil {
			t.Fatalf("deleting alpha: %v", err)
		}

		if _, err := s.GetTenant(ctx, alpha.Tenant()); !errors.Is(err, ErrNotFound) {
			t.Errorf("the deleted tenant is still readable: %v", err)
		}
		if _, err := alpha.GetHost(ctx, alphaHostID); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted tenant's host is still readable: %v", err)
		}
		if _, err := alpha.GetJob(ctx, sharedJobID); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted tenant's job is still readable: %v", err)
		}
		if jobs, err := alpha.ListJobs(ctx, JobFilter{}); err != nil || len(jobs) != 0 {
			t.Errorf("a deleted tenant lists %d job(s): %v", len(jobs), err)
		}
		if tokens, err := alpha.ListEnrollmentTokens(ctx); err != nil || len(tokens) != 0 {
			t.Errorf("a deleted tenant lists %d token(s): %v", len(tokens), err)
		}
		if _, err := alpha.GetTemplateVersion(ctx, sharedTemplateName, 0); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted tenant's template is still readable: %v", err)
		}

		// The certificate is the one that would still authenticate. An agent presents it on every
		// request, and a row that survived its tenant would let a deleted customer's machine keep
		// talking to the control plane.
		if _, err := s.LookupCertificate(ctx, "fp-"+string(alpha.Tenant())+"-"+alphaHostID); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted tenant's certificate still authenticates: %v", err)
		}

		// And the neighbour is untouched, which is the half that would be missed by a delete that was
		// too enthusiastic rather than too timid.
		if _, err := beta.GetHost(ctx, betaHostID); err != nil {
			t.Errorf("deleting alpha removed beta's host: %v", err)
		}
		if _, err := beta.GetTemplateVersion(ctx, sharedTemplateName, 0); err != nil {
			t.Errorf("deleting alpha removed beta's template: %v", err)
		}
		if _, err := beta.GetJob(ctx, sharedJobID); err != nil {
			t.Errorf("deleting alpha removed beta's job: %v", err)
		}
		if _, err := s.LookupCertificate(ctx, "fp-"+string(beta.Tenant())+"-"+betaHostID); err != nil {
			t.Errorf("deleting alpha removed beta's certificate: %v", err)
		}
	})
}

// TestGuaranteeATenantsApprovalModeCannotRewriteAJobAlreadyQueued is the rule that makes the setting
// safe to expose.
//
// A destructive job records what it required when it was created. Reading the tenant's mode at approval
// time instead would defeat the second-person rule in two API calls: queue the job while the tenant
// requires a second person, relax the setting, release it yourself. That is not a hypothetical — the
// setting is editable through the API by exactly the operator who would benefit.
func TestGuaranteeATenantsApprovalModeCannotRewriteAJobAlreadyQueued(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalSecondPerson)
		enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		job := jobFor("01JREBOOT", "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2ln"
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: "01JHOSTA", CreatedBy: "test:alice",
			ApprovalRequired: true, ApprovalDistinctOperator: true,
		}); err != nil {
			t.Fatalf("creating the job: %v", err)
		}

		// The operator relaxes their own fleet's rule, which is a thing they are allowed to do.
		stored, err := s.GetTenant(ctx, tenant.Tenant())
		if err != nil {
			t.Fatalf("reading the tenant: %v", err)
		}
		stored.ApprovalMode = ApprovalNone
		if err := s.UpdateTenant(ctx, stored); err != nil {
			t.Fatalf("relaxing the tenant: %v", err)
		}

		// And it changes nothing about the job they already queued.
		if err := tenant.ApproveJob(ctx, "01JREBOOT", "test:alice", time.Now().UTC()); !errors.Is(err, ErrConflict) {
			t.Fatalf("the job's creator released it after relaxing the tenant: %v", err)
		}
		rec, err := tenant.GetJob(ctx, "01JREBOOT")
		if err != nil {
			t.Fatalf("reading the job: %v", err)
		}
		if rec.Claimable() {
			t.Fatal("relaxing the tenant made an already-queued job claimable without a release")
		}

		// A second person still releases it, under the rule it was created with.
		if err := tenant.ApproveJob(ctx, "01JREBOOT", "test:bob", time.Now().UTC()); err != nil {
			t.Fatalf("a second operator could not release it: %v", err)
		}
	})
}

// TestGuaranteeATenantThatNeedsNoApprovalStillNeedsASignature is the line the approval setting must
// never cross.
//
// Relaxing approval relaxes a control-plane control. It must not relax the one the guarantee in
// docs/SECURITY.md §1 actually rests on: a destructive job carries a signature made offline by a key in
// the host's own trusted-signers, and no tenant setting reaches that. The host is what enforces it, so
// this asserts the half the store is responsible for — that a job created under ApprovalNone arrives at
// the host with its signature intact and its class unchanged, rather than being quietly downgraded to
// something mTLS alone would authorise.
func TestGuaranteeATenantThatNeedsNoApprovalStillNeedsASignature(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)
		enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")

		job := jobFor("01JREBOOT", "host.reboot")
		job.Class = "destructive"
		job.Signature = "c2lnbmF0dXJl"
		job.SignerKeyID = "ops-laptop"
		job.SignerAlgorithm = "ed25519"
		if err := tenant.CreateJob(ctx, NewJob{
			Job: job, HostID: "01JHOSTA", CreatedBy: "test:alice",
		}); err != nil {
			t.Fatalf("creating the job: %v", err)
		}

		claimed, err := tenant.ClaimJobs(ctx, "01JHOSTA", 10)
		if err != nil {
			t.Fatalf("claiming: %v", err)
		}
		if len(claimed) != 1 {
			t.Fatalf("a tenant requiring no release did not deliver its job: %+v", claimed)
		}
		switch {
		case claimed[0].Signature != "c2lnbmF0dXJl":
			t.Error("the signature did not survive a tenant that requires no approval")
		case claimed[0].SignerKeyID != "ops-laptop":
			t.Error("the signer identity did not survive")
		case claimed[0].Class != "destructive":
			t.Errorf("the class arrived as %q; a host takes the class from its own catalogue, but a "+
				"control plane that relabelled one is a control plane worth failing here",
				claimed[0].Class)
		}
	})
}

// TestGuaranteeAnUnusableTokenResolvesToNoTenant closes the gap between resolving a token and
// redeeming it.
//
// Enrolment resolves the token first, to find out which tenant's machine-id claim to check against, and
// redeems it afterwards. If the resolver answered for a token that could never be redeemed, an expired
// or already-used token would still steer a stranger's machine at a real tenant's rows for the length
// of one request — and the two implementations disagreed about this, which is the drift the shared
// suite exists to catch.
func TestGuaranteeAnUnusableTokenResolvesToNoTenant(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)
		now := time.Now().UTC()

		if err := tenant.CreateEnrollmentToken(ctx, EnrollmentToken{
			Hash: "hash-expired", Label: "expired", CreatedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("creating an expired token: %v", err)
		}
		if err := tenant.CreateEnrollmentToken(ctx, EnrollmentToken{
			Hash: "hash-live", Label: "live", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("creating a live token: %v", err)
		}

		if _, err := s.TenantForEnrollmentToken(ctx, "hash-live"); err != nil {
			t.Fatalf("a live token does not resolve: %v", err)
		}
		for _, hash := range []string{"hash-expired", "hash-never-existed"} {
			if _, err := s.TenantForEnrollmentToken(ctx, hash); !errors.Is(err, ErrTokenUnusable) {
				t.Errorf("%s resolved to a tenant, producing %v; want ErrTokenUnusable", hash, err)
			}
		}

		// And a token stops resolving the moment it is redeemed, rather than on the next expiry.
		enrolTestHost(t, tenant, "01JHOSTA", "a.example.org")
		if _, err := tenant.ConsumeEnrollmentToken(ctx, "hash-live", "01JHOSTA", now); err != nil {
			t.Fatalf("redeeming: %v", err)
		}
		if _, err := s.TenantForEnrollmentToken(ctx, "hash-live"); !errors.Is(err, ErrTokenUnusable) {
			t.Errorf("a redeemed token still resolves to its tenant: %v", err)
		}
	})
}
