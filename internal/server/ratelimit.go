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

// Renewal rate limits and the cap that goes with them.
//
// Renewal is authenticated, so it is not the endpoint the limiter above defends — and it is the one
// authenticated endpoint whose cost is unbounded per caller. Every call signs a certificate with the CA
// key and inserts a row into a table every tenant of a hosted installation shares, and a host holding
// one valid certificate can call it in a loop.
//
// The numbers come from what an honest agent does. A certificate lasts ninety days and is renewed at
// two-thirds of that, so a host renews about six times a year: five in a burst and one back per minute
// is four orders of magnitude above any real fleet and still turns a loop into a refusal. The cap is
// the other half — a limiter alone bounds the rate and not the total, and the total is what fills a
// table.
//
// The buckets are per replica, like every other limiter here, so a fleet behind N control planes gets
// roughly N times the burst. Against a renewal cadence measured in months that is not a distinction
// worth building shared state for; the cap is a database question and is exact.
const (
	// renewBurst is how many renewals one host may make at once.
	renewBurst = 5

	// renewRefill is how long one renewal takes to come back.
	renewRefill = time.Minute

	// maxLiveCertificatesPerHost bounds how many of a host's certificates may authenticate at once.
	//
	// Three, and the arithmetic is: the one in use, the one a renewal just issued, and one more for a
	// renewal that was interrupted between obtaining a certificate and promoting it. A host needing a
	// fourth is a host whose renewals are failing, which is a thing to fix rather than to accumulate.
	maxLiveCertificatesPerHost = 3

	// renewalOverlap is how long a renewed-away certificate keeps working.
	//
	// It has to outlast the agent's renewal jitter, which is up to a day, so that a host interrupted
	// between obtaining its new certificate and promoting it is certain to have a working one to come
	// back on. Two days rather than one for that reason: at or below the jitter, this would reintroduce
	// the stranding it exists to avoid.
	renewalOverlap = 48 * time.Hour
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
