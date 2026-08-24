package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestTemplateVersionsAccumulate proves that saving is superseding, never overwriting.
//
// The property under test is the one the Tier 2 bootstrap record depends on: a version, once written,
// resolves to the same bytes for ever, and a change arrives as the next number.
func TestTemplateVersionsAccumulate(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		first, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("sealed-v1"),
			CreatedAt: time.Now().UTC(), CreatedBy: "test:alice",
		})
		if err != nil || first != 1 {
			t.Fatalf("first version: %d, %v", first, err)
		}
		second, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("sealed-v2"),
			Signature: "c2ln", SignerKeyID: "ops-laptop", SignerAlgorithm: "ed25519",
			CreatedAt: time.Now().UTC(), CreatedBy: "test:bob",
		})
		if err != nil || second != 2 {
			t.Fatalf("second version: %d, %v", second, err)
		}

		v1, err := tenant.GetTemplateVersion(ctx, "standard-server", 1)
		if err != nil || string(v1.BodySealed) != "sealed-v1" {
			t.Fatalf("version 1 did not survive being superseded: %+v, %v", v1, err)
		}
		if v1.Signed() {
			t.Fatal("version 1 reports itself signed with no signature")
		}
		latest, err := tenant.GetTemplateVersion(ctx, "standard-server", 0)
		if err != nil || latest.Version != 2 || string(latest.BodySealed) != "sealed-v2" {
			t.Fatalf("latest is not version 2: %+v, %v", latest, err)
		}
		if !latest.Signed() || latest.SignerKeyID != "ops-laptop" {
			t.Fatalf("the signature did not survive storage: %+v", latest)
		}
	})
}

// TestTemplateListingShowsTheLatestVersionPerName proves the listing is a summary, not a history.
func TestTemplateListingShowsTheLatestVersionPerName(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		base := time.Now().UTC().Add(-time.Hour)
		for i, save := range []TemplateVersion{
			{Name: "standard-server", BodySealed: []byte("a1"), CreatedBy: "test:alice"},
			{Name: "database", BodySealed: []byte("b1"), CreatedBy: "test:alice"},
			{Name: "standard-server", BodySealed: []byte("a2"), CreatedBy: "test:bob",
				Signature: "c2ln", SignerKeyID: "ops-laptop", SignerAlgorithm: "ed25519"},
		} {
			save.CreatedAt = base.Add(time.Duration(i) * time.Minute)
			if _, err := tenant.CreateTemplateVersion(ctx, save); err != nil {
				t.Fatalf("saving %s: %v", save.Name, err)
			}
		}

		listed, err := tenant.ListTemplates(ctx)
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 2 {
			t.Fatalf("listed %d templates, want 2: %+v", len(listed), listed)
		}
		// Newest latest-version first: standard-server's v2 postdates database's v1.
		if listed[0].Name != "standard-server" || listed[0].LatestVersion != 2 ||
			!listed[0].Signed || listed[0].CreatedBy != "test:bob" {
			t.Fatalf("first summary is wrong: %+v", listed[0])
		}
		if listed[1].Name != "database" || listed[1].LatestVersion != 1 || listed[1].Signed {
			t.Fatalf("second summary is wrong: %+v", listed[1])
		}
	})
}

// TestTemplateLookupMissesAreErrNotFound proves the sentinel, which is what handlers map to a 404.
func TestTemplateLookupMissesAreErrNotFound(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		if _, err := tenant.GetTemplateVersion(ctx, "absent", 0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a missing name returned %v", err)
		}
		if _, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("v1"), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("saving: %v", err)
		}
		if _, err := tenant.GetTemplateVersion(ctx, "standard-server", 7); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a missing version returned %v", err)
		}
	})
}
