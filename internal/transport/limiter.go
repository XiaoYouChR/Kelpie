package transport

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
)

// Limiter is a token bucket shared by every peer connection in one direction.
// Their reader and writer goroutines call WaitN before moving n bytes,
// protocol overhead included.
//
// The bucket counts bytes cumulatively: reserved is every byte callers asked
// for, paid is every byte the rate has covered. A caller reserves its bytes
// and returns once paid reaches the end of its reservation, so callers pass in
// order, any n is paced exactly, and a rate change applies to callers already
// waiting.
type Limiter struct {
	clock clock.Clock
	// mu guards the bucket, which ADR-0005 keeps as shared memory: every
	// connection's reader and writer leaf calls WaitN, the hub SetRate.
	mu       sync.Mutex
	rate     float64
	reserved float64
	paid     float64
	last     time.Time
	changed  chan struct{}
}

// BuildLimiter builds a Limiter for rate bytes per second; 0 means unlimited.
func BuildLimiter(c clock.Clock, rate int64) *Limiter {
	return &Limiter{clock: c, rate: float64(rate), last: c.Now(), changed: make(chan struct{})}
}

func (l *Limiter) SetRate(rate int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	if l.rate == 0 {
		l.paid = l.reserved
		l.last = now
	} else {
		l.updatePaid(now)
	}
	l.rate = float64(rate)
	close(l.changed)
	l.changed = make(chan struct{})
}

// WaitN blocks until n bytes may pass. Bytes of a cancelled call stay
// reserved.
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	l.mu.Lock()
	if l.rate == 0 {
		l.mu.Unlock()
		return nil
	}
	l.updatePaid(l.clock.Now())
	l.reserved += float64(n)
	end := l.reserved
	for {
		if l.rate == 0 || l.paid >= end {
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration(math.Ceil((end - l.paid) / l.rate * float64(time.Second)))
		changed := l.changed
		l.mu.Unlock()

		timer := l.clock.CreateTimer(wait)
		select {
		case <-timer.C():
		case <-changed:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		timer.Stop()
		l.mu.Lock()
		l.updatePaid(l.clock.Now())
	}
}

// burst is a quarter second of rate: enough that waiters wake rarely, little
// enough that the burst after an idle spell hardly shows in the observed rate.
func (l *Limiter) burst() float64 {
	return l.rate / 4
}

// updatePaid is called with l.mu held.
func (l *Limiter) updatePaid(now time.Time) {
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.paid = min(l.paid+elapsed*l.rate, l.reserved+l.burst())
	}
	l.last = now
}
