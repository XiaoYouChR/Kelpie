// Package clock is the engine's seam for time.
package clock

import "time"

type Clock interface {
	Now() time.Time
	CreateTicker(d time.Duration) Ticker
	CreateTimer(d time.Duration) Timer
}

type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type Timer interface {
	C() <-chan time.Time
	Stop()
}

// Real is the Clock of the running process.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

func (Real) CreateTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }

func (Real) CreateTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTicker struct{ ticker *time.Ticker }

func (t realTicker) C() <-chan time.Time { return t.ticker.C }

func (t realTicker) Stop() { t.ticker.Stop() }

type realTimer struct{ timer *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.timer.C }

func (t realTimer) Stop() { t.timer.Stop() }
