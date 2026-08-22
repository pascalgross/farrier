package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Enrolment rate limits.
//
// They apply to /agent/v1/enroll and to nothing else, because it is the only endpoint reachable without
// a client certificate. Everything else already costs an attacker a certificate this CA issued, and
// rate-limiting an authenticated fleet is a good way to break it during the incident when every host
// reconnects at once.
const (
	// enrollBurst is how many enrolments one source may make before the rate applies.
	//
	// Generous enough for a provisioning run that brings up a rack at once, small enough that guessing
	// tokens is hopeless — a token is 256 bits of uniform randomness, so a limiter is a defence against
	// the load of guessing rather than against its success.
	enrollBurst = 20

	// enrollRefill is how long one attempt takes to come back.
	enrollRefill = 3 * time.Second

	// enrollIdleTTL is how long a source is remembered after its last attempt.
	//
	// Without it the limiter is a map that grows for the process's lifetime, keyed by whatever address
	// anybody connects from — which is a slow leak an attacker controls the rate of.
	enrollIdleTTL = time.Hour
)

// rateLimiter is a per-source token bucket.
//
// It is deliberately in-process and approximate. A control plane running several replicas will allow
// roughly the burst per replica, which is fine for what this defends against — load rather than
// success — and much better than the alternative, which is a shared store on the path of the one
// endpoint that has to work when a fleet is being built.
type rateLimiter struct {
	// mu guards buckets.
	mu sync.Mutex

	// buckets holds one bucket per source.
	buckets map[string]*bucket

	// burst is the bucket size.
	burst float64

	// refill is how long one token takes to return.
	refill time.Duration
}

// bucket is one source's remaining allowance.
type bucket struct {
	// tokens is the allowance remaining, in whole attempts.
	tokens float64

	// last is when the allowance was last recomputed.
	last time.Time
}

// newRateLimiter returns a limiter with the given burst and refill interval.
func newRateLimiter(burst int, refill time.Duration) *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}, burst: float64(burst), refill: refill}
}

// allow reports whether a source may make another attempt, and consumes one if so.
func (l *rateLimiter) allow(source string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, known := l.buckets[source]
	if !known {
		l.buckets[source] = &bucket{tokens: l.burst - 1, last: now}
		l.sweep(now)
		return true
	}

	b.tokens += now.Sub(b.last).Seconds() / l.refill.Seconds()
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// retryAfter reports how long a refused source should wait.
func (l *rateLimiter) retryAfter() time.Duration { return l.refill }

// sweep drops sources that have not been seen for enrollIdleTTL.
//
// It runs on the path that creates a bucket rather than on a timer, so a limiter that is never used
// costs nothing and one under load cleans itself. The caller holds the lock.
func (l *rateLimiter) sweep(now time.Time) {
	if len(l.buckets) < 1024 {
		return
	}
	for source, b := range l.buckets {
		if now.Sub(b.last) > enrollIdleTTL {
			delete(l.buckets, source)
		}
	}
}

// requestSource identifies the origin of a request for rate-limiting purposes.
//
// The peer address is used and no forwarded header is consulted. A header is set by whoever is talking
// to the server, so trusting one would let a single client present a different source on every request
// and defeat the limiter entirely. Behind a proxy this limits per proxy, which is the honest behaviour
// for a control plane that has not been told which proxies to trust.
func requestSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
