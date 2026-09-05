package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pascalgross/hostseal/internal/auth"
	"github.com/pascalgross/hostseal/internal/store"
)

// MaxWallboardRequestBytes bounds a share-publication request body.
//
// A label, a passphrase and a number. Generous by two orders of magnitude, and here for the reason
// every other bound in this server is: a body is bounded before it is in memory, and a passphrase field
// is somewhere a caller would otherwise be free to put a megabyte.
const MaxWallboardRequestBytes = 4 << 10

// MaxWallboardLabel bounds what a share may be called.
//
// It is rendered as the heading of a screen laid out to be read from three metres, so a label longer
// than this is not a label — it is a paragraph that would push the fleet off the page. Refused rather
// than truncated: an operator who typed it should be told, not shown something they did not write.
const MaxWallboardLabel = 60

// The bounds on a share's lifetime.
//
// There is no "never" option, and that is the point rather than an omission: a shared credential that
// does not expire is the one docs/SECURITY.md §4.5 removed, wearing a different name. Ninety days by
// default because a screen in a corridor is a thing somebody sets up once and forgets, and a year is
// long enough that renewing it is an annual chore rather than a weekly interruption — but it is a
// deadline, and somebody has to look at the fleet's share list to pass it.
const (
	// DefaultWallboardDays is how long a share lives when the request does not say.
	DefaultWallboardDays = 90

	// MaxWallboardDays is the longest life a share may be given.
	MaxWallboardDays = 365
)

// The bounds on unlocking a passphrase-protected share.
//
// Keyed on the share rather than on the source address, which is the opposite of every other limiter in
// this server and is deliberate. A wallboard is reached from a corridor, over a corporate NAT, or
// through the reverse proxy the deployment guide recommends — all of which collapse many sources to one
// — so a source-keyed bucket here is one bucket for everybody, which one screen can exhaust for the
// whole internet. The share is the identifier the caller does not choose, which is what
// renewLimiter (per host) and passwordLimiter (per account) already key on for the same reason.
//
// Five and one back every thirty seconds: somebody who cannot remember which of two passphrases the
// team uses will not notice, and a script will.
const (
	// unlockBurst is how many passphrase attempts one share admits at once.
	unlockBurst = 5

	// unlockRefill is how long one attempt takes to come back.
	unlockRefill = 30 * time.Second
)

// The bounds on polling a share.
//
// The summary reads the whole fleet, so this is the expensive half of the feature and the half a leaked
// key could be pointed at in a loop. Keyed on the presented key's digest rather than the source, for the
// reason above, and set from what an honest screen does: one request every WallboardPollSeconds. Twenty
// at once and one back per second is two orders of magnitude above a wall of screens sharing one link
// and still turns a loop into a refusal.
const (
	// pollBurst is how many summaries one link may fetch at once.
	pollBurst = 20

	// pollRefill is how long one fetch takes to come back.
	pollRefill = time.Second
)

// The coarse bound on the published routes, before any link has been resolved.
//
// Source-keyed, and it is the one limit here that is, because it guards the thing the key-keyed limits
// cannot guard: their own buckets. A bucket keyed on a value the caller chooses is a bucket the caller
// can mint, and the limiter sweeps its map only on the path that creates one — and only once it holds a
// thousand entries, none of which it drops for an hour. So a flood of syntactically valid nonsense
// scans an ever-growing map once per request, on top of a database round trip each, which is a
// quadratic way to spend a control plane's afternoon. Bounding bucket creation is what closes it.
//
// Generous on purpose, because the reason the fine limits are not source-keyed still holds: a corridor,
// a corporate NAT and a terminating reverse proxy all report as one address. A hundred and twenty at
// once with one back per second is far above a building's worth of screens polling every fifteen
// seconds, and far below what it takes to make the map above worth anything to an attacker.
const (
	// boardBurst is how many published-route requests one source may make at once.
	boardBurst = 120

	// boardRefill is how long one request takes to come back.
	boardRefill = time.Second
)

// wallboardTouchInterval is how stale a share's last-seen stamp is allowed to get.
//
// Fifteen minutes, the same throttle and the same reasoning as an API token's last-used stamp: it is a
// write on the path of every poll of every screen, and nothing reads it more precisely than "somebody
// is still showing this". Without the throttle a wall of four screens is four writes every fifteen
// seconds, for ever, to record a fact that changes nothing.
const wallboardTouchInterval = 15 * time.Minute

// shareView is one published link as an operator sees it afterwards.
//
// The key is not on it and cannot be: only its digest is stored. What an operator gets back is enough to
// recognise which screen this is and decide whether to withdraw it, which is the only decision the list
// exists to support.
type shareView struct {
	// ID names the share in the route that withdraws it.
	ID string `json:"id"`

	// Label is what it was called, and the heading the screen shows.
	Label string `json:"label"`

	// CreatedAt is when it was published.
	CreatedAt time.Time `json:"createdAt"`

	// CreatedBy is the principal of whoever published it.
	CreatedBy string `json:"createdBy"`

	// ExpiresAt is when it stops answering.
	ExpiresAt time.Time `json:"expiresAt"`

	// LastSeenAt is when a screen last polled it, null for never.
	//
	// A pointer so that "never polled" is null rather than a zero time that renders as 1970. It is the
	// closest thing a share has to an access record and it is emphatically not one: it says a screen
	// polled, not which, and not from where.
	LastSeenAt *time.Time `json:"lastSeenAt"`

	// Passphrase reports whether a screen must prove one before it sees anything.
	Passphrase bool `json:"passphrase"`

	// Expired reports that the deadline has passed, computed here so no client has to compare clocks.
	Expired bool `json:"expired"`
}

// toShareView renders one stored share for the operator's list.
func toShareView(share store.WallboardShare, now time.Time) shareView {
	view := shareView{
		ID:         share.ID,
		Label:      share.Label,
		CreatedAt:  share.CreatedAt,
		CreatedBy:  share.CreatedBy,
		ExpiresAt:  share.ExpiresAt,
		Passphrase: share.PasswordHash != "",
		Expired:    !share.Live(now),
	}
	if !share.LastSeenAt.IsZero() {
		seen := share.LastSeenAt
		view.LastSeenAt = &seen
	}
	return view
}

// handleWallboard returns the fleet summary for a signed-in operator.
//
// The same builder and the same payload the published screen gets, differing only in the heading. The
// difference between this route and the public one is not what is on the screen but what you can do
// next, which is docs/SECURITY.md §5.3's own argument one level down: an operator has a toolbar and a
// fleet list behind it, and a share has nothing, because there is no route behind a share that would
// answer.
func (s *Server) handleWallboard(w http.ResponseWriter, r *http.Request, who operator) {
	hosts, err := who.Store.ListHosts(r.Context())
	if err != nil {
		slog.Error("could not read the fleet for the wallboard", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the fleet")
		return
	}
	writeJSON(w, http.StatusOK, s.buildWallboard(hosts, "", time.Now()))
}

// handlePublicWallboard returns the fleet summary to a screen holding a share key.
//
// It answers all-or-nothing. A read that half succeeded would render as three correct tiles and one
// silently zero, at HTTP 200, on a screen nobody is examining — which is the worst outcome this feature
// has available, and worse than the screen going dark.
func (s *Server) handlePublicWallboard(w http.ResponseWriter, r *http.Request, who viewer) {
	hosts, err := who.Store.ListHosts(r.Context())
	if err != nil {
		slog.Error("could not read the fleet for a published wallboard", "error", err,
			"share", who.Share.ID)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the fleet")
		return
	}
	writeJSON(w, http.StatusOK, s.buildWallboard(hosts, who.Share.Label, time.Now()))
}

// handleListShares returns the links this fleet has published.
//
// Expired shares are listed rather than hidden. A share that stopped working is the first thing
// somebody looks for when the screen in the corridor has gone dark, and a list that omitted it would
// answer "there is no such link" to the person holding it.
func (s *Server) handleListShares(w http.ResponseWriter, r *http.Request, who operator) {
	shares, err := who.Store.ListWallboardShares(r.Context())
	if err != nil {
		slog.Error("could not list wallboard shares", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not read the published links")
		return
	}

	now := time.Now()
	views := make([]shareView, 0, len(shares))
	for _, share := range shares {
		views = append(views, toShareView(share, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"shares":     views,
		"serverTime": now.UTC(),
		"maxShares":  store.MaxWallboardSharesPerTenant,
	})
}

// handleCreateShare publishes a link to this fleet's status screen.
//
// The key is returned exactly once, here, and is not recoverable afterwards because only its digest is
// stored — the same property an enrolment token and an API token have, and worth the same sentence in
// the response, so a client can tell the operator rather than leaving them to discover it later.
//
// It is behind requireOperator, which refuses a platform credential. That is what keeps
// docs/SECURITY.md §9's refusal true: what §9 forbids is a mechanism whose subject is somebody else's
// fleet and whose authoriser is the hosting provider, and the only credential that can publish a fleet
// here is one that belongs to it.
func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request, who operator) {
	var req struct {
		// Label is what to call it, and the heading the screen will show.
		Label string `json:"label"`

		// Days is how long it should live. Zero takes DefaultWallboardDays.
		Days int `json:"days"`

		// Passphrase is the optional second factor. Empty publishes a link that needs nothing else.
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(w, r, MaxWallboardRequestBytes, &req); err != nil {
		writeDecodeError(w, err, "the request body holds more than one value; publish one link")
		return
	}

	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, "invalid",
			"a link needs a name: it is the heading the screen shows, and it is how you tell four "+
				"published links apart when you come to withdraw one")
		return
	}
	// Characters rather than bytes, because that is what the refusal below promises and what somebody
	// naming a fleet is counting. `len` on a string counts UTF-8 bytes, under which "Zürich — Rechenzentrum"
	// is longer than it looks and an operator is refused a name that fits.
	if utf8.RuneCountInString(req.Label) > MaxWallboardLabel {
		writeError(w, http.StatusBadRequest, "invalid",
			"a name may be at most "+strconv.Itoa(MaxWallboardLabel)+" characters; it is rendered as a "+
				"heading on a screen read from across a room")
		return
	}
	days := req.Days
	if days == 0 {
		days = DefaultWallboardDays
	}
	if days < 1 || days > MaxWallboardDays {
		writeError(w, http.StatusBadRequest, "invalid",
			"a link lives between 1 and "+strconv.Itoa(MaxWallboardDays)+" days. There is deliberately "+
				"no option for a link that never expires")
		return
	}

	// The passphrase is hashed before anything is written, so a passphrase this build will not store —
	// too short, or too long to be one — refuses the whole request rather than leaving behind a share
	// somebody has published and nobody can unlock.
	var passwordHash string
	if req.Passphrase != "" {
		hashed, err := auth.HashPassword(req.Passphrase)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
		passwordHash = hashed
	}

	shareID, err := NewID()
	if err != nil {
		slog.Error("could not generate a wallboard share id", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not publish the link")
		return
	}
	key, keyHash, err := NewWallboardKey(who.Store.Tenant())
	if err != nil {
		slog.Error("could not generate a wallboard key", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not publish the link")
		return
	}

	now := time.Now()
	share := store.WallboardShare{
		ID:           shareID,
		SecretHash:   keyHash,
		PasswordHash: passwordHash,
		Label:        req.Label,
		CreatedAt:    now,
		CreatedBy:    who.Principal(),
		ExpiresAt:    now.Add(time.Duration(days) * 24 * time.Hour),
	}
	switch err := who.Store.CreateWallboardShare(r.Context(), share); {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "too_many",
			"this fleet already has "+strconv.Itoa(store.MaxWallboardSharesPerTenant)+" live links. "+
				"Withdraw one you no longer recognise before publishing another")
		return
	case err != nil:
		slog.Error("could not publish a wallboard link", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not publish the link")
		return
	}

	// A credential in the body, so no cache may keep it.
	noStore(w)
	slog.Info("wallboard link published", "share", shareID, "label", req.Label,
		"operator", who.Principal(), "tenant", who.Store.Tenant(), "expires", share.ExpiresAt)

	writeJSON(w, http.StatusCreated, map[string]any{
		"share": toShareView(share, now),
		"key":   key,
		"link":  "https://" + r.Host + "/board#" + key,
		"note": "This link is shown once and cannot be recovered — only its digest is stored. The " +
			"secret is after the # and is never sent to the control plane by the browser, so it is in " +
			"no access log; it is still in the address bar, so treat a photograph of the screen as a " +
			"copy of the link.",
	})
}

// handleRevokeShare withdraws one published link.
//
// A delete rather than a flag, exactly as revoking an API token is. It takes effect at the next poll —
// which is within WallboardPollSeconds — because the row is read on every request rather than cached
// anywhere, and it takes the unlock secret with it, so a screen that had proved the passphrase stops
// too.
func (s *Server) handleRevokeShare(w http.ResponseWriter, r *http.Request, who operator) {
	id := r.PathValue("id")
	switch err := who.Store.DeleteWallboardShare(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such published link")
		return
	case err != nil:
		slog.Error("could not withdraw a wallboard link", "error", err, "share", id)
		writeError(w, http.StatusInternalServerError, "internal", "could not withdraw the link")
		return
	}
	slog.Info("wallboard link withdrawn", "share", id, "operator", who.Principal(),
		"tenant", who.Store.Tenant())
	w.WriteHeader(http.StatusNoContent)
}

// handleUnlock exchanges a share's passphrase for the cookie a screen then holds.
//
// Unauthenticated by construction, in the same sense as signing in: it is where the credential comes
// from. So it is rate limited, its body is bounded, and every failure is one answer — an unknown key, an
// expired share, a share with no passphrase and a wrong passphrase are indistinguishable from here.
//
// The exchange exists because a browser cannot hold a password and a wallboard cannot re-derive
// Argon2id every fifteen seconds: one derivation allocates 64 MiB and at most four run at once, so a
// handful of screens polling would be the whole sign-in path's memory budget. Verifying once and handing
// back something cheap to check is the same trade a session makes, for the same reason.
//
// What the screen receives is the share's own second secret rather than a per-viewer one, and that is a
// named limit rather than an oversight: a television has no identity to revoke, so per-viewer
// revocation would be a mechanism with nothing to point at. Changing the passphrase regenerates the
// secret and drops every screen; withdrawing the link drops them too.
func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	presented := wallboardBearer(r)
	tenant, ok := splitWallboardKey(presented)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such published link")
		return
	}
	// The coarse, source-keyed limit first, for the reason requireShare gives at length: a bucket keyed
	// on a value the caller invents is a bucket the caller can mint, and minting them is the attack.
	if !s.boardLimiter.allow(auth.RequestSource(r), time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.boardLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	var req struct {
		// Passphrase is what somebody typed on the screen.
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(w, r, MaxWallboardRequestBytes, &req); err != nil {
		writeDecodeError(w, err, "the request body holds more than one value; send one passphrase")
		return
	}

	noStore(w)

	share, err := s.cfg.Store.In(tenant).WallboardShareBySecret(r.Context(), HashToken(presented), time.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such published link")
		return
	case err != nil:
		// Not a refusal: the link may be perfectly good and the database was not reachable. Answering
		// 404 here would put "this link has been withdrawn" on a screen during an outage, and somebody
		// would go and delete a share that was working.
		slog.Error("could not read a wallboard share", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not check the link")
		return
	}
	// The per-link limit, keyed on a share that exists, and placed here rather than at the top for two
	// reasons. It cannot be minted by a caller inventing keys, because there are at most
	// MaxWallboardSharesPerTenant real ones per fleet; and it is the last thing before an Argon2id
	// derivation, which allocates 64 MiB and of which at most four run at once — so this is what stops
	// somebody who holds one leaked link from spending the whole sign-in path's memory budget guessing
	// its passphrase.
	//
	// A 429 here does say the link is real, where an invented one gets a 404. That is a fact whoever is
	// holding the link already has, and it costs five wrong guesses to learn.
	if !s.unlockLimiter.allow(share.ID, time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.unlockLimiter.retryAfter().Seconds())))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts on this link")
		return
	}

	if share.PasswordHash == "" || !auth.VerifyPassword(share.PasswordHash, req.Passphrase) {
		writeError(w, http.StatusNotFound, "not_found", "no such published link")
		return
	}

	http.SetCookie(w, unlockCookie(share, unlockProof(presented, share)))
	w.WriteHeader(http.StatusNoContent)
}

// unlockProof returns the value a screen holds once it has proved a share's passphrase.
//
// Derived rather than stored, which is what keeps "only a digest is ever written down" true of this
// credential as well as of every other one. It is the digest of the key the screen already holds
// together with the stored password hash, so producing it needs *both* halves and the row carries
// neither in a usable form: whoever leaked the link cannot compute it without the database, and whoever
// has the database cannot compute it without the link — which is precisely the pair of failures the
// passphrase exists to separate.
//
// It also gets one property for free that a stored secret would have needed a column and a rotation
// path for: changing a share's passphrase changes its hash, so every screen unlocked under the old one
// stops at its next poll. The corollary is that this build deliberately does not rehash a passphrase on
// a successful unlock the way a sign-in rehashes a password below the current cost. That would be a
// silent rotation, and the visible effect would be every wallboard in the building going dark at once.
func unlockProof(key string, share store.WallboardShare) string {
	sum := sha256.Sum256([]byte(key + "\x00" + share.PasswordHash))
	return hex.EncodeToString(sum[:])
}

// unlockCookieName is where a screen keeps the secret it received for proving a share's passphrase.
//
// Named per share rather than once for the whole origin, so that an operator with two published boards
// open in two tabs does not have each unlock evict the other's.
func unlockCookieName(shareID string) string {
	return "hostseal_board_" + shareID
}

// unlockCookie builds the credential a screen holds after it has proved a passphrase.
//
// SameSite=Strict rather than the Lax a session cookie uses, and the difference is that the case Lax
// exists for does not arise here: a session cookie has to survive an operator following a link to a host
// page from a chat message, which is a top-level navigation. A screen reaches this cookie only from a
// page already on this origin, so Strict costs nothing and is the stronger of the two.
//
// Path-scoped to the published routes, so it is not attached to any request an operator's own browser
// makes to the administrative API, and expiring with the share, so a browser drops it at the same
// moment the control plane stops honouring it.
func unlockCookie(share store.WallboardShare, proof string) *http.Cookie {
	return &http.Cookie{
		Name:     unlockCookieName(share.ID),
		Value:    proof,
		Path:     "/api/v1/wallboard/public",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  share.ExpiresAt,
	}
}

// wallboardBearer reads a presented wallboard key out of the Authorization header.
//
// The key is in the URL's fragment rather than its path, so the page reads it from the address bar and
// puts it here. A fragment is never transmitted, which keeps the secret out of this control plane's
// access log, out of any reverse proxy's, out of Referer on any link the page follows, and out of a
// link-preview crawler's fetch. What it does not do is keep it out of browser history or off a
// photograph of the screen, and docs/SECURITY.md §4.6 says so rather than implying otherwise.
func wallboardBearer(r *http.Request) string {
	scheme, value, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// viewer is a published wallboard link together with the store handle that reaches its fleet.
//
// The same shape as operator and caller, and for the same reason: a handler behind requireShare is
// handed the scoped store rather than the whole one, so "which tenant may this request touch" is
// answered once, in the middleware, and a handler that forgot to ask has nothing in reach to forget
// with. That is what keeps docs/SECURITY.md §5.2's second layer — "middleware hands a handler a store
// handle already scoped to the request's tenant" — literally true of this credential as well.
type viewer struct {
	// Share is the row the presented key resolved to.
	Share store.WallboardShare

	// Store reaches that share's fleet and nothing else.
	Store store.Scoped
}

// requireShare authenticates a screen by the key it presents, and the passphrase if the share has one.
//
// A share key is a credential like any other — 256 bits of randomness naming one fleet — so this reads
// like the middleware beside it rather than like an exception. Three things about it are deliberate.
//
// Every refusal is the same 404. A key that is not shaped like one, a key no row matches, a share whose
// deadline has passed and a screen that has not proved the passphrase are indistinguishable from
// outside, and the liveness half of that is in the SQL predicate rather than in a branch here — which is
// what stops the four from drifting apart into four refusals somebody has to keep matched.
//
// The rate limit is keyed on the presented key rather than on the source address. Every other limiter in
// this server keys on a source because the caller there is a machine with an address; a wallboard is
// reached from a corridor, over a corporate NAT, or through the reverse proxy the deployment guide
// recommends, all of which collapse many callers into one bucket that a single screen can exhaust for
// everybody. The key is the identifier the caller does not choose, which is the same reasoning that puts
// renewLimiter on a host id and passwordLimiter on an account id.
//
// The tenant comes from inside the key, which is the one place this differs from requireOperator, and
// it is safe for a reason worth stating: the digest covers the whole key including that segment, so a
// key edited to name another fleet hashes to a value no row holds. The tenant is refused by the lookup
// before the predicate and the row-level security policy are reached, and both of those still stand
// behind it.
func (s *Server) requireShare(next func(http.ResponseWriter, *http.Request, viewer)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every response here carries a fleet's state and is reached by a credential in a browser, so
		// none of it may sit in a shared cache. Set before the first refusal rather than after the
		// success, because a 404 that a proxy cached would outlive the share it was about.
		noStore(w)

		presented := wallboardBearer(r)
		tenant, ok := splitWallboardKey(presented)
		if !ok {
			writeError(w, http.StatusNotFound, "not_found", "no such published link")
			return
		}
		// The coarse limit comes first, and it is keyed on the source rather than on the key, which is
		// the opposite of the limit below. Both are needed, and the reason is that they bound different
		// things. A key-scoped bucket cannot be the first gate: the key is a value the caller invents,
		// so a flood of syntactically valid nonsense would allocate a fresh bucket with a full burst
		// every time — and because the bucket map is only swept on the path that creates one, and only
		// once it holds a thousand, that is a scan of the whole map per request against a map nothing
		// removes from for an hour. An unauthenticated caller could spend the control plane's CPU
		// quadratically by typing rubbish, which is not a rate limit, it is the shape of one.
		if !s.boardLimiter.allow(auth.RequestSource(r), time.Now()) {
			w.Header().Set("Retry-After", strconv.Itoa(int(s.boardLimiter.retryAfter().Seconds())))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}

		hash := HashToken(presented)
		scoped := s.cfg.Store.In(tenant)
		share, err := scoped.WallboardShareBySecret(r.Context(), hash, time.Now())
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such published link")
			return
		case err != nil:
			// Not a refusal, and the distinction matters more here than anywhere else in this server: a
			// screen told 404 clears itself and stops polling, which is the correct response to a
			// withdrawn link and the wrong one to a database that is down for ten minutes.
			slog.Error("could not read a wallboard share", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "could not check the link")
			return
		}

		// And now the fine limit, keyed on a share that exists. This is the one that matters — the
		// summary reads the whole fleet, so it is the expensive half of the feature — and keying it on
		// the resolved share's id rather than on the presented key is what makes it safe to key at all:
		// there are at most MaxWallboardSharesPerTenant of those per fleet, so the bucket map is bounded
		// by what operators have published rather than by what a stranger can type.
		//
		// It is deliberately still not keyed on the source. A corridor, a corporate NAT and the reverse
		// proxy the deployment guide recommends all put many screens behind one address, and a bucket
		// they share is one a single television can spend for the whole building.
		if !s.pollLimiter.allow(share.ID, time.Now()) {
			w.Header().Set("Retry-After", strconv.Itoa(int(s.pollLimiter.retryAfter().Seconds())))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests for this link")
			return
		}

		if share.PasswordHash != "" {
			cookie, cookieErr := r.Cookie(unlockCookieName(share.ID))
			want := unlockProof(presented, share)
			if cookieErr != nil ||
				subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(want)) != 1 {
				// The one refusal that is not a 404, because it is the one a screen can do something
				// about: it names the form to render rather than telling somebody their link is dead.
				// It discloses that the link exists, which is a fact whoever holds the link already has.
				writeError(w, http.StatusUnauthorized, "passphrase_required",
					"this link is protected by a passphrase")
				return
			}
		}

		s.touchShare(r, scoped, share)
		next(w, r, viewer{Share: share, Store: scoped})
	})
}

// touchShare records that a screen is still showing one link, at most every wallboardTouchInterval.
//
// Best effort and never fatal: a stamp that could fail a poll would make an unrelated database hiccup
// blank every wallboard in the building. It runs inline rather than detached because it is one indexed
// UPDATE and the request is already holding a connection — and because a detached write here would need
// its own context and its own place in the shutdown drain for a value nothing reads precisely.
func (s *Server) touchShare(r *http.Request, scoped store.Scoped, share store.WallboardShare) {
	now := time.Now()
	if !share.LastSeenAt.IsZero() && now.Sub(share.LastSeenAt) < wallboardTouchInterval {
		return
	}
	if err := scoped.TouchWallboardShare(r.Context(), share.ID, now); err != nil {
		slog.Warn("could not record a wallboard poll", "error", err, "share", share.ID)
	}
}
