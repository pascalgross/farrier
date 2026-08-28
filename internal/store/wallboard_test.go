package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// publishShare stores one wallboard link with the fields every row needs, and returns it.
//
// The creation time is fixed by the caller rather than left to the store, because these tests assert
// on ordering and on "never polled", and a value the store filled in would make a failure read as a
// clock problem rather than as the behaviour under test.
func publishShare(t *testing.T, tenant Scoped, id, secret string, expires time.Time) WallboardShare {
	t.Helper()

	share := WallboardShare{
		ID:         id,
		SecretHash: secret,
		Label:      "Board " + id,
		CreatedAt:  time.Now().UTC().Truncate(time.Microsecond),
		CreatedBy:  "local-account:alice@example.org",
		ExpiresAt:  expires,
	}
	if err := tenant.CreateWallboardShare(context.Background(), share); err != nil {
		t.Fatalf("publishing %s: %v", id, err)
	}
	return share
}

// listedShare returns one share out of a tenant's listing, failing the test when it is not there.
//
// Every assertion below reads a share back through the listing, because that is the only way an
// operator ever sees one — the store has no per-id getter, since the interface's other reader is a
// screen resolving a secret it holds.
func listedShare(t *testing.T, tenant Scoped, id string) WallboardShare {
	t.Helper()

	shares, err := tenant.ListWallboardShares(context.Background())
	if err != nil {
		t.Fatalf("listing published links: %v", err)
	}
	for _, share := range shares {
		if share.ID == id {
			return share
		}
	}
	t.Fatalf("%s is not in the listing of %d link(s)", id, len(shares))
	return WallboardShare{}
}

// TestAPublishedLinkReadsBackAsItWasPublished covers the round trip every other test here assumes.
//
// The fields it checks are the ones the operator's page renders and the ones a revocation depends on:
// what the link was called, who published it, when it stops answering, and that nothing has polled it
// yet. That last one is the field the two stores can most easily disagree about — PostgreSQL has NULL
// and Go has the zero time — so it is asserted rather than taken on trust.
func TestAPublishedLinkReadsBackAsItWasPublished(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		expires := time.Now().UTC().Truncate(time.Microsecond).Add(90 * 24 * time.Hour)
		published := publishShare(t, tenant, "01JBOARD1", "secret-hash-1", expires)

		read := listedShare(t, tenant, "01JBOARD1")
		if read.Label != published.Label || read.CreatedBy != published.CreatedBy {
			t.Errorf("read back %+v, want the label and author of %+v", read, published)
		}
		if !read.ExpiresAt.Equal(expires) {
			t.Errorf("the link expires at %s, want %s", read.ExpiresAt, expires)
		}
		if !read.CreatedAt.Equal(published.CreatedAt) {
			t.Errorf("the link was published at %s, want %s", read.CreatedAt, published.CreatedAt)
		}
		if !read.LastSeenAt.IsZero() {
			t.Errorf("a link nothing has polled reports having been seen at %s", read.LastSeenAt)
		}
		if read.SecretHash != "secret-hash-1" {
			t.Errorf("the stored digest is %q", read.SecretHash)
		}
	})
}

// TestAScreensSecretResolvesToItsOwnLink is the lookup the public poll runs on every request.
//
// Three live links in one fleet, because the failure worth ruling out is not "no row came back" but
// "the wrong row did": a fleet's shares differ in nothing an unlocked screen would notice except the
// heading, so a lookup keyed loosely would publish the wrong board with no visible symptom.
func TestAScreensSecretResolvesToItsOwnLink(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Microsecond)
		for _, id := range []string{"01JBOARD1", "01JBOARD2", "01JBOARD3"} {
			publishShare(t, tenant, id, "secret-hash-"+id, now.Add(time.Hour))
		}

		found, err := tenant.WallboardShareBySecret(ctx, "secret-hash-01JBOARD2", now)
		if err != nil {
			t.Fatalf("resolving a live secret: %v", err)
		}
		if found.ID != "01JBOARD2" {
			t.Errorf("the secret of 01JBOARD2 resolved to %+v", found)
		}
		if _, err := tenant.WallboardShareBySecret(ctx, "secret-hash-nothing", now); !errors.Is(err, ErrNotFound) {
			t.Errorf("a digest naming nothing returned %v, want ErrNotFound", err)
		}
	})
}

// TestAnExpiredLinkStopsAnsweringAndStaysListed is the two halves of an expiry, which pull apart.
//
// The screen must stop — an expired share is refused by the same path and with the same error as one
// that never existed, so that a stranger cannot tell the two apart. The operator must still see it,
// because "the board in the corridor has gone dark" is answered by finding the row and reading its
// date, and a listing that hid it would answer "there is no such link" to the person holding one.
func TestAnExpiredLinkStopsAnsweringAndStaysListed(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Microsecond)
		publishShare(t, tenant, "01JLIVE", "secret-hash-live", now.Add(time.Hour))
		publishShare(t, tenant, "01JEXPIRED", "secret-hash-expired", now.Add(-time.Minute))

		if _, err := tenant.WallboardShareBySecret(ctx, "secret-hash-expired", now); !errors.Is(err, ErrNotFound) {
			t.Errorf("an expired link answered with %v, want the same ErrNotFound an unknown one gets", err)
		}
		if _, err := tenant.WallboardShareBySecret(ctx, "secret-hash-live", now); err != nil {
			t.Errorf("a live link stopped answering: %v", err)
		}

		expired := listedShare(t, tenant, "01JEXPIRED")
		if expired.Live(now) {
			t.Errorf("the listed link reports itself live, expiring at %s", expired.ExpiresAt)
		}
	})
}

// TestAShareIsLiveByTheSameRuleInBothStores pins WallboardShare.Live to what the lookups actually do.
//
// The rule lives in three places that cannot see each other: a Go method, a WHERE clause against the
// database's own comparison, and the in-memory store's filter. Two of them disagreeing by one instant
// would show up as a screen that kept working for a second after its link expired — invisible, and
// exactly the kind of drift that makes an expiry date something nobody trusts. So the boundary itself
// is asserted, on both sides and on the instant.
func TestAShareIsLiveByTheSameRuleInBothStores(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		expires := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
		publishShare(t, tenant, "01JBOUNDARY", "secret-hash-boundary", expires)

		for _, at := range []time.Time{
			expires.Add(-time.Second),
			expires,
			expires.Add(time.Second),
		} {
			_, err := tenant.WallboardShareBySecret(ctx, "secret-hash-boundary", at)
			answered := err == nil
			if !answered && !errors.Is(err, ErrNotFound) {
				t.Fatalf("resolving at %s: %v", at, err)
			}
			if live := (WallboardShare{ExpiresAt: expires}).Live(at); live != answered {
				t.Errorf("at %s the store answers %t and Live reports %t", at, answered, live)
			}
		}
	})
}

// TestAFleetCannotPublishPastItsCap is the bound on how many live links one fleet may hold.
//
// It is asserted through the store rather than through a handler because that is where it is enforced:
// two operators publishing at once would both read "nineteen" if the count were a separate statement.
// The error is ErrConflict rather than an error of its own, because the caller's answer is the same as
// for a colliding id — publish nothing, and say why.
func TestAFleetCannotPublishPastItsCap(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		expires := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
		for i := range MaxWallboardSharesPerTenant {
			id := fmt.Sprintf("01JBOARD%02d", i)
			publishShare(t, tenant, id, "secret-hash-"+id, expires)
		}

		err := tenant.CreateWallboardShare(ctx, WallboardShare{
			ID: "01JBOARDTOOMANY", SecretHash: "secret-hash-too-many", Label: "One too many",
			CreatedAt: time.Now().UTC(), ExpiresAt: expires,
		})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("publishing past the cap returned %v, want ErrConflict", err)
		}

		// The refusal has to be about *live* links, or a fleet that has published and revoked all year
		// would be locked out by rows that answer nothing. Revoking one makes room immediately.
		if err := tenant.DeleteWallboardShare(ctx, "01JBOARD00"); err != nil {
			t.Fatalf("revoking to make room: %v", err)
		}
		if err := tenant.CreateWallboardShare(ctx, WallboardShare{
			ID: "01JBOARDTOOMANY", SecretHash: "secret-hash-too-many", Label: "Room again",
			CreatedAt: time.Now().UTC(), ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("publishing after revoking one: %v", err)
		}
	})
}

// TestRevokingALinkTwiceIsRefusedTheSecondTime is what makes "that link is gone" mean something.
//
// A delete that reported success for a row it did not remove would say the same thing whether the link
// had been withdrawn or was still on a wall, which is the one report an operator revoking in a hurry
// must be able to believe.
func TestRevokingALinkTwiceIsRefusedTheSecondTime(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Microsecond)
		publishShare(t, tenant, "01JBOARD1", "secret-hash-1", now.Add(time.Hour))

		if err := tenant.DeleteWallboardShare(ctx, "01JBOARD1"); err != nil {
			t.Fatalf("revoking: %v", err)
		}
		if err := tenant.DeleteWallboardShare(ctx, "01JBOARD1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoking a link that has already gone returned %v, want ErrNotFound", err)
		}
		if _, err := tenant.WallboardShareBySecret(ctx, "secret-hash-1", now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a revoked link still answers: %v", err)
		}
		shares, err := tenant.ListWallboardShares(ctx)
		if err != nil || len(shares) != 0 {
			t.Fatalf("a revoked link is still listed: %+v, %v", shares, err)
		}
	})
}

// TestPollingStampsWhenAScreenWasLastSeen covers the field that answers "is anybody still watching".
//
// It has to be answerable before somebody revokes a link and waits to see who complains, which is why
// the stamp exists at all. The second half is the deliberate silence: stamping a link that has been
// revoked is not an error, because the poll carrying it is about to be refused anyway and a second
// refusal would be one log line per dead screen per fifteen seconds.
func TestPollingStampsWhenAScreenWasLastSeen(t *testing.T) {
	eachScoped(t, func(t *testing.T, _ Store, tenant Scoped) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Microsecond)
		publishShare(t, tenant, "01JBOARD1", "secret-hash-1", now.Add(time.Hour))

		polled := now.Add(3 * time.Minute)
		if err := tenant.TouchWallboardShare(ctx, "01JBOARD1", polled); err != nil {
			t.Fatalf("stamping a poll: %v", err)
		}
		if seen := listedShare(t, tenant, "01JBOARD1").LastSeenAt; !seen.Equal(polled) {
			t.Errorf("the link was last seen at %s, want %s", seen, polled)
		}

		if err := tenant.DeleteWallboardShare(ctx, "01JBOARD1"); err != nil {
			t.Fatalf("revoking: %v", err)
		}
		if err := tenant.TouchWallboardShare(ctx, "01JBOARD1", polled.Add(time.Minute)); err != nil {
			t.Fatalf("stamping a link that has gone should be a no-op: %v", err)
		}
	})
}
