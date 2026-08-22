package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRateLimiterAllowsABurstThenRefills covers the shape enrolment needs.
//
// A provisioning run that brings up a rack should not be throttled, and a loop that has gone wrong
// should be. That is a burst followed by a slow refill, rather than a flat rate.
func TestRateLimiterAllowsABurstThenRefills(t *testing.T) {
	limiter := newRateLimiter(3, time.Second)
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	for i := range 3 {
		if !limiter.allow("10.0.0.1", now) {
			t.Fatalf("attempt %d of the burst was refused", i+1)
		}
	}
	if limiter.allow("10.0.0.1", now) {
		t.Error("a fourth attempt inside the burst was allowed")
	}

	// One refill interval later, exactly one more attempt is available.
	if !limiter.allow("10.0.0.1", now.Add(time.Second)) {
		t.Error("no allowance had returned after one refill interval")
	}
	if limiter.allow("10.0.0.1", now.Add(time.Second)) {
		t.Error("two attempts were available after one refill interval")
	}
}

// TestRateLimiterIsPerSource asserts one noisy source does not lock out the fleet.
//
// Enrolment is how a host joins. A limiter that counted globally would mean one misconfigured
// provisioning loop preventing every other machine in the estate from enrolling.
func TestRateLimiterIsPerSource(t *testing.T) {
	limiter := newRateLimiter(2, time.Minute)
	now := time.Now()

	for range 2 {
		limiter.allow("10.0.0.1", now)
	}
	if limiter.allow("10.0.0.1", now) {
		t.Fatal("the first source was not limited")
	}
	if !limiter.allow("10.0.0.2", now) {
		t.Error("a second source was refused because of the first")
	}
}

// TestRequestSourceIgnoresForwardedHeaders is the reason the limiter is worth having at all.
//
// A forwarded header is set by whoever is talking to the server. Trusting one would let a single client
// present a different source on every request and defeat the limiter entirely, which is worse than
// having none: it would look like a defence.
func TestRequestSourceIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/agent/v1/enroll", http.NoBody)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Real-IP", "10.0.0.2")

	if got := requestSource(r); got != "203.0.113.7" {
		t.Errorf("requestSource = %q; it must use the peer address, not a header the client sets", got)
	}
}
