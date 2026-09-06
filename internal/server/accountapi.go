package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pascalgross/hostseal/internal/auth"
	"github.com/pascalgross/hostseal/internal/store"
)

// MaxAccountRequestBytes bounds a request to the account routes.
//
// A password, a label and a number of days. Generous by two orders of magnitude, and here for the same
// reason every other body limit is: the bound applies before the body is in memory.
const MaxAccountRequestBytes = 4 << 10

// MaxAPITokenLabel bounds what an operator may call a token.
//
// Bounded because it is stored, returned to a listing and rendered in an audit-trail display name, and
// an unbounded string that reaches all three is a row that grows with what somebody sends.
const MaxAPITokenLabel = 100

// The bounds on password changes, per account.
//
// Generous, because the honest use is somebody typing their current password wrong once or twice: five
// at a time and one back every thirty seconds is a limit a person never meets. What it stops is a loop,
// which at 64 MiB of Argon2id per attempt is a way to spend the control plane's memory from the least
// privileged credential the system issues — and a way to guess the password of an account whose session
// cookie somebody has stolen.
const (
	// passwordBurst is how many changes one account may attempt at once.
	passwordBurst = 5

	// passwordRefill is how long one attempt takes to come back.
	passwordRefill = 30 * time.Second
)

// MaxAPITokenDays bounds how far ahead a token may be dated.
//
// Two years. Not a security boundary — a token with no expiry is allowed, and is the honest choice for
// a CI runner nobody will remember to rotate — but a `expiresInDays: 100000` is a typo rather than an
// intention, and one that reads as "never" without saying so.
const MaxAPITokenDays = 730

// accountCaller is a request that arrived holding a signed-in browser's session.
//
// It carries the account itself rather than just the identity, because every route behind it acts on
// that account's own rows and the account id is what names them. Resolving it once in the middleware is
// what keeps each handler from repeating a lookup that must not be got wrong.
type accountCaller struct {
	// Identity is who the control plane decided this is.
	Identity auth.Identity

	// Account is the row that identity came from.
	Account store.Account

	// Scope reaches this account's own rows, on whichever side of the tenant boundary it lives.
	Scope store.AccountScope

	// SessionHash identifies the session this request presented, so a listing can mark it.
	SessionHash string
}

// requireAccount authenticates a browser session and resolves the account behind it.
//
// It refuses an API token, and that refusal is the reason this exists rather than requireIdentity. A
// token acts as the account that owns it — same provider, same subject, same principal — which is what
// keeps the second-person approval rule honest, and it means a token presented here would be able to
// mint another token, one with no expiry, that survives the first being revoked. So the account routes
// are the one place where what the caller was holding matters as much as who they are.
//
// It also refuses a control plane with no accounts provider, with 404 rather than 501: on such an
// installation the route genuinely does not exist, and a client told 501 would keep offering the page.
func (s *Server) requireAccount(next func(http.ResponseWriter, *http.Request, accountCaller)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.accounts == nil {
			writeError(w, http.StatusNotFound, "not_found", "this control plane has no accounts")
			return
		}
		identity, err := s.cfg.Auth.Authenticate(r.Context(), r)
		if identity == nil && err == nil {
			err = auth.ErrUnauthenticated
		}
		if refuseOrFail(w, err, "a signed-in session is required") {
			return
		}
		if identity.Credential != auth.CredentialSession {
			writeError(w, http.StatusForbidden, "session_required",
				"this is an API token. The account page is reachable only from a signed-in browser, so "+
					"that a token cannot issue or revoke another one.")
			return
		}

		account, err := s.cfg.Store.AccountByEmail(r.Context(), auth.EmailKey(identity.Subject))
		if err != nil {
			// The session authenticated a moment ago, so this is an account deleted between the two
			// lookups or a database that has stopped answering. Neither is the caller's doing.
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusUnauthorized, "unauthenticated", "a signed-in session is required")
				return
			}
			slog.Error("could not read the signed-in account", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "could not read the account")
			return
		}

		who := accountCaller{
			Identity:    *identity,
			Account:     account,
			Scope:       s.accountScope(account),
			SessionHash: presentedSessionHash(r),
		}
		// Every one of these responses describes a credential. None of them may be cached, by a browser
		// or by anything between.
		noStore(w)
		next(w, r, who)
	})
}

// accountScope returns the handle through which one account's own rows are reached.
//
// The choice is the account's tenant being empty or not, exactly as in internal/auth, and it is here
// rather than imported because the field it reads is the store's. A platform account reached through
// In("") would be a handle whose row-level security matches nothing, and the symptom would be an
// administrator whose sessions silently do not exist.
func (s *Server) accountScope(account store.Account) store.AccountScope {
	if account.TenantID == "" {
		return s.cfg.Store.Platform()
	}
	return s.cfg.Store.In(account.TenantID)
}

// presentedSessionHash returns the stored form of the session token a request carried.
//
// It is used only to mark one row in a listing as "this one". A request that somehow reaches here with
// no cookie gets an empty string, which matches no row — the listing is then simply unmarked, which is
// a better failure than marking the wrong one.
func presentedSessionHash(r *http.Request) string {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return auth.HashSessionToken(cookie.Value)
}

// handleGetAccount describes the signed-in account to itself.
func (s *Server) handleGetAccount(w http.ResponseWriter, _ *http.Request, who accountCaller) {
	writeJSON(w, http.StatusOK, map[string]any{
		"email":        who.Account.Email,
		"displayName":  who.Account.DisplayName,
		"createdAt":    who.Account.CreatedAt.UTC(),
		"lastSignedIn": timeOrNull(who.Account.LastSignedInAt),
		"platform":     who.Account.TenantID == "",
		"principal":    who.Identity.Principal(),
	})
}

// handleChangePassword replaces the signed-in account's own password.
//
// The current password is required and is verified here, even though the request already carries a
// session that authenticated. That is not belt and braces for its own sake: a session is a credential
// somebody else may be holding — a borrowed laptop, a copied cookie — and a password change is the one
// operation that would lock the owner out of their own account. Asking for the password is what makes
// holding the session insufficient.
//
// Sessions are deliberately not ended. A password change is usually a routine one, and signing every
// device out for it is how people learn not to do it. `POST /api/v1/account/sessions/revoke` is beside
// it for the case where that is the point.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, who accountCaller) {
	// Before the body is read and long before anything is hashed: the derivation below is the expensive
	// part, so a limiter that ran after it would meter the thing it was meant to prevent.
	if !s.passwordLimiter.allow(who.Account.ID, time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.passwordLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many password changes")
		return
	}

	var req struct {
		// CurrentPassword is what the operator is signing in with today.
		CurrentPassword string `json:"currentPassword"`

		// NewPassword is what they want instead. Neither is logged, stored or echoed.
		NewPassword string `json:"newPassword"`
	}
	if err := decodeJSON(w, r, MaxAccountRequestBytes, &req); err != nil {
		writeDecodeError(w, err, "the request body holds more than one value; send one password change")
		return
	}

	if !auth.VerifyPassword(who.Account.PasswordHash, req.CurrentPassword) {
		slog.Info("password change refused", "operator", who.Account.Email, "source", auth.RequestSource(r))
		writeError(w, http.StatusUnauthorized, "wrong_password", "that is not the current password")
		return
	}
	// auth.MinPasswordLength rather than a copy, and characters rather than bytes for the same reason
	// HashPassword counts them: `len` on a string is UTF-8 bytes, so three four-byte emoji would pass a
	// twelve-"character" rule. This check exists only to produce a better message than the one
	// HashPassword's error carries — that call is the authority, and it applies the same rule.
	if utf8.RuneCountInString(req.NewPassword) < auth.MinPasswordLength {
		writeError(w, http.StatusBadRequest, "password_too_short",
			fmt.Sprintf("a password must be at least %d characters. There is no rule about digits or "+
				"symbols: length is the property those rules fail to produce.", auth.MinPasswordLength))
		return
	}
	if len(req.NewPassword) > auth.MaxPasswordLength {
		// In bytes, matching the bound it stands for: this one is about what gets copied and hashed.
		writeError(w, http.StatusBadRequest, "password_too_long",
			fmt.Sprintf("a password may be at most %d bytes", auth.MaxPasswordLength))
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeError(w, http.StatusBadRequest, "password_unchanged", "that is the current password")
		return
	}

	hashed, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		slog.Error("could not hash a new password", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not change the password")
		return
	}
	if err := who.Scope.UpdateAccountPassword(r.Context(), who.Account.ID, hashed); err != nil {
		slog.Error("could not change a password", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not change the password")
		return
	}

	slog.Info("password changed", "operator", who.Account.Email)
	w.WriteHeader(http.StatusNoContent)
}

// handleListSessions lists the browsers this account is signed in on.
//
// No token and no token hash is returned, which is why the current session is marked by a flag the
// server computed rather than by an identifier the client compares. There is nothing in this response
// that authenticates anybody, which is the property that makes it safe to render on a page.
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, who accountCaller) {
	sessions, err := who.Scope.ListSessions(r.Context(), who.Account.ID)
	if err != nil {
		slog.Error("could not list sessions", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not list the sessions")
		return
	}

	now := time.Now()
	out := make([]map[string]any, 0, len(sessions))
	for _, held := range sessions {
		out = append(out, map[string]any{
			"createdAt": held.CreatedAt.UTC(),
			"expiresAt": held.ExpiresAt.UTC(),
			"lastUsed":  timeOrNull(held.LastUsedAt),
			"userAgent": held.UserAgent,
			"source":    held.Source,
			"expired":   !held.Valid(now),
			"current":   held.TokenHash == who.SessionHash && who.SessionHash != "",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleRevokeSessions ends every session this account holds, including the one asking.
//
// Including it, deliberately. "Sign out everywhere" is what somebody presses after a laptop goes
// missing, and a version that quietly kept the current session would be a version that has to be
// explained — worse, one whose explanation is "everywhere except here" at the moment somebody is least
// able to reason about which "here" they mean. The browser lands back on the sign-in form, which is
// itself the confirmation that it worked.
func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request, who accountCaller) {
	ended, err := who.Scope.DeleteSessionsFor(r.Context(), who.Account.ID)
	if err != nil {
		slog.Error("could not end an account's sessions", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not end the sessions")
		return
	}

	// The cookie goes too. Without this the browser keeps presenting a token whose row has gone, which
	// authenticates nobody and looks, from the interface, like being signed in until the next request.
	if err := s.accounts.SignOut(r.Context(), w, r); err != nil {
		slog.Warn("could not clear the session cookie", "error", err)
	}
	slog.Info("signed out everywhere", "operator", who.Account.Email, "sessions", ended)
	writeJSON(w, http.StatusOK, map[string]any{"ended": ended})
}

// handleListAPITokens lists this account's tokens.
//
// The id in the listing is the token's SHA-256, which is what the store keys on. Returning it is safe
// and is worth saying why: it is a one-way function of 256 bits of randomness, so it cannot be turned
// back into a credential, and every route that accepts it is already scoped to the account that owns
// the row. What it buys is that revoking one needs no second identifier to keep in step with the first.
func (s *Server) handleListAPITokens(w http.ResponseWriter, r *http.Request, who accountCaller) {
	tokens, err := who.Scope.ListAPITokens(r.Context(), who.Account.ID)
	if err != nil {
		slog.Error("could not list API tokens", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not list the tokens")
		return
	}

	now := time.Now()
	out := make([]map[string]any, 0, len(tokens))
	for _, held := range tokens {
		out = append(out, map[string]any{
			"id":        held.Hash,
			"label":     held.Label,
			"createdAt": held.CreatedAt.UTC(),
			"expiresAt": timeOrNull(held.ExpiresAt),
			"lastUsed":  timeOrNull(held.LastUsedAt),
			"usable":    held.Usable(now),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// handleCreateAPIToken mints a token acting as this account, and returns it exactly once.
//
// Once, because only the SHA-256 is stored. That is the same discipline as an enrolment token and it
// has the same consequence for the interface: the response is the only time the value exists anywhere
// but in whoever copied it, so the page that renders it has to say so.
func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request, who accountCaller) {
	var req struct {
		// Label is what to call it, so that revoking the right one is possible later.
		Label string `json:"label"`

		// ExpiresInDays is how long it lasts; zero or absent means it does not expire.
		ExpiresInDays int `json:"expiresInDays"`
	}
	if err := decodeJSON(w, r, MaxAccountRequestBytes, &req); err != nil {
		writeDecodeError(w, err, "the request body holds more than one value; send one token")
		return
	}

	label := strings.TrimSpace(req.Label)
	if label == "" {
		// Required rather than defaulted. A list of six tokens called "token" is a list nobody revokes
		// from, and the moment to ask what this one is for is the moment somebody is creating it.
		writeError(w, http.StatusBadRequest, "label_required",
			"give the token a label saying what it is for; a token nobody can tell from the others is "+
				"a token nobody revokes")
		return
	}
	if len([]rune(label)) > MaxAPITokenLabel {
		writeError(w, http.StatusBadRequest, "label_too_long", "a label may be at most 100 characters")
		return
	}
	if req.ExpiresInDays < 0 || req.ExpiresInDays > MaxAPITokenDays {
		writeError(w, http.StatusBadRequest, "bad_expiry",
			"expiresInDays must be between 0 and 730; 0 means the token does not expire")
		return
	}

	token, err := auth.GenerateAPIToken()
	if err != nil {
		slog.Error("could not generate an API token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not create the token")
		return
	}
	now := time.Now().UTC()
	record := store.APIToken{
		Hash:      auth.HashAPIToken(token),
		AccountID: who.Account.ID,
		Label:     label,
		CreatedAt: now,
	}
	if req.ExpiresInDays > 0 {
		record.ExpiresAt = now.AddDate(0, 0, req.ExpiresInDays)
	}
	if err := who.Scope.CreateAPIToken(r.Context(), record); err != nil {
		slog.Error("could not record an API token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not create the token")
		return
	}

	slog.Info("API token issued", "operator", who.Account.Email, "label", label,
		"expires", record.ExpiresAt)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        record.Hash,
		"label":     record.Label,
		"createdAt": record.CreatedAt,
		"expiresAt": timeOrNull(record.ExpiresAt),
		"token":     token,
	})
}

// handleDeleteAPIToken revokes one of this account's tokens.
//
// A token that is not this account's is 404 rather than 403, which is the answer every scoped route in
// this server gives: whether a row exists elsewhere is not something a caller who cannot reach it may
// find out.
func (s *Server) handleDeleteAPIToken(w http.ResponseWriter, r *http.Request, who accountCaller) {
	id := r.PathValue("id")
	err := who.Scope.DeleteAPIToken(r.Context(), who.Account.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such token")
		return
	}
	if err != nil {
		slog.Error("could not revoke an API token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not revoke the token")
		return
	}

	slog.Info("API token revoked", "operator", who.Account.Email)
	w.WriteHeader(http.StatusNoContent)
}

// timeOrNull renders a time for JSON, with the zero value as null rather than as a date in year one.
//
// It exists because "never signed in" and "does not expire" are both the zero value here, and both read
// as a wrong answer if they are serialised: `0001-01-01T00:00:00Z` is a date, and an interface that
// received one would render it as one.
func timeOrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
