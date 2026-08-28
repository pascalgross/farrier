package server

import (
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

// Health-check rate limits.
//
// The endpoint is unauthenticated because a health check that needs a credential is one the load
// balancer cannot perform, and each hit is a round trip to the shared database — so the rate at which
// anybody who can reach the port may spend that is a number this file should state rather than one the
// caller chooses.
//
// The numbers are set from what a prober does. A container health check runs every ten to thirty
// seconds and a load balancer every few; sixty at once and one back per second is far above either and
// far below a loop. A refusal here is a 429 and not an unhealthy verdict, so a source that trips it
// cannot make the process look down to anybody else: buckets are per source.
const (
	// healthBurst is how many probes one source may make before the rate applies.
	healthBurst = 60

	// healthRefill is how long one probe takes to come back.
	healthRefill = time.Second
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
