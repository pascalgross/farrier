package agent

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// Backoff computes full-jitter exponential delays.
//
// Full jitter, not equal jitter and not decorrelated: the failure mode being prevented is
// synchronisation, and only full jitter removes it entirely. Five hundred agents reconnecting in the
// same second is the single most common way an agent fleet kills its own control plane, and it happens
// precisely when the control plane has just come back and is least able to absorb it.
//
// The formula is sleep = random(0, min(cap, base * 2^attempt)). The lower bound is genuinely zero,
// which feels wasteful for one client and is the entire point for five hundred.
type Backoff struct {
	// Base is the first interval's ceiling.
	Base time.Duration

	// Cap is the largest ceiling, however many attempts have failed.
	Cap time.Duration

	// attempt counts consecutive failures.
	attempt int
}

// NewBackoff returns a backoff with HostSeal's defaults.
//
// One second to five minutes. The cap matters more than the base: an agent that has been failing for an
// hour should retry every few minutes, not every few hours, because the control plane coming back must
// not require a fleet-wide restart to be noticed.
func NewBackoff() *Backoff {
	return &Backoff{Base: time.Second, Cap: 5 * time.Minute}
}

// Next returns the delay before the next attempt and advances the counter.
func (b *Backoff) Next() time.Duration {
	ceiling := float64(b.Base) * math.Pow(2, float64(b.attempt))
	if ceiling > float64(b.Cap) || math.IsInf(ceiling, 1) {
		ceiling = float64(b.Cap)
	}
	b.attempt++
	// rand/v2's top-level functions are safe for concurrent use and seeded from the runtime, which is
	// what this needs: unpredictability matters less than every agent picking a different number.
	//nolint:gosec // G404. This is load spreading, not a secret. crypto/rand here would cost a syscall
	// per retry across the fleet to defend against an attacker who can already see the traffic anyway.
	return time.Duration(rand.Float64() * ceiling)
}

// Reset clears the failure counter after a success.
func (b *Backoff) Reset() { b.attempt = 0 }

// Attempt reports how many consecutive failures have been recorded, for logging.
func (b *Backoff) Attempt() int { return b.attempt }

// Jitter returns a duration spread uniformly across a fraction of an interval.
//
// It is applied to the heartbeat interval and to certificate renewal. Renewal is the one people forget:
// a fleet enrolled on the same afternoon will otherwise try to renew in the same minute ninety days
// later, and that stampede arrives exactly once, which is to say it is never load-tested.
func Jitter(interval time.Duration, fraction float64) time.Duration {
	if fraction <= 0 || interval <= 0 {
		return 0
	}
	//nolint:gosec // G404, as above: spreading a fleet's requests, not generating a secret.
	return time.Duration(rand.Float64() * fraction * float64(interval))
}

// Sleep waits for a duration or until the context ends, reporting whether it completed.
//
// Every wait in the agent goes through this, so that a SIGTERM during a five-minute backoff stops the
// process immediately rather than five minutes later. systemd's default stop timeout is ninety seconds,
// after which it sends SIGKILL — and a process killed rather than stopped is one that skipped whatever
// it does on the way out.
func Sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
