package server

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/pascalgross/farrier/internal/auth"
	"github.com/pascalgross/farrier/internal/store"
)

// MaxTenantRequestBytes bounds a tenant-administration request body.
//
// A tenant is four short strings. This is generous by three orders of magnitude and exists so the body
// is bounded before it is in memory, like every other body this server reads.
const MaxTenantRequestBytes = 16 << 10

// slugPattern is the shape a tenant's handle may take.
//
// Lower-case letters, digits and hyphens, starting with a letter or digit. It appears in URLs, in log
// lines and in support tickets, and it is chosen by whoever runs the installation rather than by a
// customer — so the constraint costs nothing and saves an argument about whether a tenant may be called
// "../admin".
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// tenantRequest is the body of POST and PATCH on /api/v1/tenants.
//
// The pointer fields are what makes PATCH a patch: a field that was not sent is nil and is left alone,
// where a field sent as "" is an explicit instruction to clear it. Without the distinction, an
// administrator changing an approval mode would silently erase a webhook they never mentioned.
type tenantRequest struct {
	// Slug is the short stable handle. Required on create, immutable afterwards.
	Slug string `json:"slug,omitempty"`

	// DisplayName is what the tenant is called in the interface.
	DisplayName *string `json:"displayName,omitempty"`

	// ApprovalMode is how this tenant releases a destructive job.
	ApprovalMode *string `json:"approvalMode,omitempty"`

	// WebhookURL is where this tenant's events are posted.
	WebhookURL *string `json:"webhookUrl,omitempty"`
}

// tenantView is what the API renders for a tenant.
type tenantView struct {
	// ID is the identifier every scoped row carries.
	ID string `json:"id"`

	// Slug is the short stable handle.
	Slug string `json:"slug"`

	// DisplayName is what the tenant is called in the interface.
	DisplayName string `json:"displayName"`

	// CreatedAt is when the tenant was created.
	CreatedAt time.Time `json:"createdAt"`

	// ApprovalMode is how this tenant releases a destructive job.
	ApprovalMode string `json:"approvalMode"`

	// WebhookURL is where this tenant's events go, empty for nowhere.
	WebhookURL string `json:"webhookUrl"`
}

// toTenantView renders a stored tenant.
func toTenantView(t store.Tenant) tenantView {
	return tenantView{
		ID:           string(t.ID),
		Slug:         t.Slug,
		DisplayName:  t.DisplayName,
		CreatedAt:    t.CreatedAt,
		ApprovalMode: string(t.ApprovalMode),
		WebhookURL:   t.WebhookURL,
	}
}

// handleListTenants returns every tenant on this installation.
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	tenants, err := s.cfg.Store.ListTenants(r.Context())
	if err != nil {
		slog.Error("could not list tenants", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant list")
		return
	}
	views := make([]tenantView, 0, len(tenants))
	for _, t := range tenants {
		views = append(views, toTenantView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": views})
}

// handleGetTenant returns one tenant.
func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	tenant, err := s.cfg.Store.GetTenant(r.Context(), store.TenantID(r.PathValue("id")))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	case err != nil:
		slog.Error("could not read a tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}
	writeJSON(w, http.StatusOK, toTenantView(tenant))
}

// handleCreateTenant provisions a new fleet.
//
// This is the operation a hosting provider automates, and it deliberately does not also mint an
// operator credential. Issuing a fleet's credential is the identity provider's job — auth.Provider is
// the seam for that — and a tenant API that handed out tokens would make the platform administrator
// able to authenticate as any customer, which is the exact separation the platform role exists to keep.
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	var req tenantRequest
	if err := decodeJSON(w, r, MaxTenantRequestBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}
	if !slugPattern.MatchString(req.Slug) {
		writeError(w, http.StatusBadRequest, "malformed",
			"a tenant needs a slug of lower-case letters, digits and hyphens, starting with a letter "+
				"or a digit: it appears in URLs and in log lines")
		return
	}

	mode := store.ApprovalNone
	if req.ApprovalMode != nil {
		mode = store.ApprovalMode(*req.ApprovalMode)
		if !mode.Valid() {
			writeError(w, http.StatusBadRequest, "malformed",
				`approvalMode is one of "none", "self" or "second_person"; see docs/SECURITY.md §3`)
			return
		}
	}

	id, err := NewID()
	if err != nil {
		slog.Error("could not generate a tenant id", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not allocate a tenant id")
		return
	}

	tenant := store.Tenant{
		ID:           store.TenantID(id),
		Slug:         req.Slug,
		DisplayName:  valueOr(req.DisplayName, req.Slug),
		CreatedAt:    time.Now().UTC(),
		ApprovalMode: mode,
		WebhookURL:   valueOr(req.WebhookURL, ""),
	}
	switch err := s.cfg.Store.CreateTenant(r.Context(), tenant); {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "duplicate", "a tenant with this slug already exists")
		return
	case err != nil:
		slog.Error("could not create a tenant", "error", err, "slug", req.Slug)
		writeError(w, http.StatusInternalServerError, "internal", "could not create the tenant")
		return
	}

	slog.Info("tenant created",
		"tenant", tenant.ID, "slug", tenant.Slug, "approval_mode", tenant.ApprovalMode,
		"platform_operator", who.Principal())
	writeJSON(w, http.StatusCreated, toTenantView(tenant))
}

// handleUpdateTenant changes a tenant's name, approval mode or webhook.
//
// A changed approval mode applies to jobs created afterwards and to nothing already queued. That is the
// same rule migration 0002 wrote down for approval_required and it matters more here, because this
// setting is one an operator can edit: without it, queueing a job under the two-person rule and then
// relaxing the tenant would release work that nobody agreed to under the rule it was created with.
func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	var req tenantRequest
	if err := decodeJSON(w, r, MaxTenantRequestBytes, &req); err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed", "the request body could not be read")
		return
	}

	id := store.TenantID(r.PathValue("id"))
	tenant, err := s.cfg.Store.GetTenant(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	case err != nil:
		slog.Error("could not read a tenant", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}

	if req.Slug != "" && req.Slug != tenant.Slug {
		// Immutable, and refused rather than ignored. The slug is what logs, tickets and any external
		// system refer to this tenant by, and a silent rename would leave every one of those pointing
		// at something that no longer answers to that name.
		writeError(w, http.StatusConflict, "immutable",
			"a tenant's slug cannot be changed: it is what logs and support tickets refer to")
		return
	}
	if req.DisplayName != nil {
		tenant.DisplayName = *req.DisplayName
	}
	if req.WebhookURL != nil {
		tenant.WebhookURL = *req.WebhookURL
	}
	if req.ApprovalMode != nil {
		mode := store.ApprovalMode(*req.ApprovalMode)
		if !mode.Valid() {
			writeError(w, http.StatusBadRequest, "malformed",
				`approvalMode is one of "none", "self" or "second_person"; see docs/SECURITY.md §3`)
			return
		}
		tenant.ApprovalMode = mode
	}

	if err := s.cfg.Store.UpdateTenant(r.Context(), tenant); err != nil {
		slog.Error("could not update a tenant", "error", err, "tenant", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not update the tenant")
		return
	}

	slog.Info("tenant updated",
		"tenant", tenant.ID, "slug", tenant.Slug, "approval_mode", tenant.ApprovalMode,
		"platform_operator", who.Principal())
	writeJSON(w, http.StatusOK, toTenantView(tenant))
}

// handleDeleteTenant removes a tenant and everything belonging to it.
//
// Everything means everything: hosts, certificates, enrolment tokens, jobs and results. The agents
// themselves are not told and cannot be — there is no path from this control plane to a host — so they
// keep running on their own local policy and their next request is refused as an unknown certificate.
// That is the correct end state for a customer who has left, and it is worth saying out loud that
// deleting a tenant does not uninstall anything.
func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	id := store.TenantID(r.PathValue("id"))
	switch err := s.cfg.Store.DeleteTenant(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	case err != nil:
		slog.Error("could not delete a tenant", "error", err, "tenant", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not delete the tenant")
		return
	}

	slog.Warn("tenant deleted", "tenant", id, "platform_operator", who.Principal())
	w.WriteHeader(http.StatusNoContent)
}

// handleWhoami tells a caller who the control plane thinks they are and which fleet they are in.
//
// The interface needs it for the same reason a shell prompt shows the hostname: an operator with access
// to two fleets, in two browser tabs, needs the page itself to say which one they are looking at before
// they queue a reboot in it.
//
// It is the one route that answers both credentials, and that is a fix rather than a convenience. It
// used to be behind requireOperator, so a platform credential got the 403 every fleet route gives it —
// which left the application able to say only that the credential it had been handed was unusable here,
// with no way to say what it was for. Somebody who pasted the wrong one of an installation's two tokens
// saw an empty console and the words "identity unknown".
//
// A platform credential still gets no tenant, because it has none. The `platform` flag is what the
// interface reads to decide which of two interfaces to render, and `tenant` is null beside it rather
// than an empty object, so a client that forgot to look at the flag fails on the field it needs rather
// than rendering a fleet called "".
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request, who auth.Identity) {
	answer := map[string]any{
		"subject":   who.Subject,
		"display":   who.Display,
		"provider":  who.Provider,
		"principal": who.Principal(),
		"platform":  who.Platform,
		"tenant":    nil,
	}
	if who.Platform || who.Tenant == "" {
		writeJSON(w, http.StatusOK, answer)
		return
	}

	tenant, err := s.cfg.Store.GetTenant(r.Context(), store.TenantID(who.Tenant))
	if err != nil {
		slog.Error("could not read the operator's tenant", "error", err, "tenant", who.Tenant)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the tenant")
		return
	}
	answer["tenant"] = toTenantView(tenant)
	writeJSON(w, http.StatusOK, answer)
}

// valueOr returns a pointer's value, or a fallback when it is nil.
//
// It exists because the tenant request distinguishes "not sent" from "sent empty", and writing that
// check inline four times would make the two cases look like one.
func valueOr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}
