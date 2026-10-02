package engine

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// runWithClock advances c in steps whenever work is parked on a timer, until
// work returns.
func runWithClock(c *clock.Fake, step time.Duration, work func()) {
	done := make(chan struct{})
	go func() {
		work()
		close(done)
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		if c.Waiters() > 0 {
			c.Advance(step)
		} else {
			time.Sleep(time.Microsecond)
		}
	}
}

func TestLimiterUnlimitedNeverWaits(t *testing.T) {
	c := clock.BuildFake(start)
	l := buildRateLimiter(c, 0)
	for range 1000 {
		l.waitN(context.Background(), 1<<20)
	}
	if c.Waiters() != 0 {
		t.Fatal("unlimited limiter waited")
	}
}

func TestLimiterHoldsRate(t *testing.T) {
	for _, size := range []int{100, 1000, 5000} {
		c := clock.BuildFake(start)
		l := buildRateLimiter(c, 1000)
		runWithClock(c, time.Millisecond, func() {
			for range 20000 / size {
				l.waitN(context.Background(), size)
			}
		})
		elapsed := c.Now().Sub(start)
		if elapsed < 20*time.Second || elapsed > 20010*time.Millisecond {
			t.Errorf("size %d: 20000 bytes at 1000 B/s took %v", size, elapsed)
		}
	}
}

// Time may run ahead while one connection is parked and another is still
// runnable, so only the lower bound is exact.
func TestLimiterSharedByConnections(t *testing.T) {
	c := clock.BuildFake(start)
	l := buildRateLimiter(c, 1000)
	runWithClock(c, time.Millisecond, func() {
		done := make(chan struct{})
		for range 4 {
			go func() {
				for range 25 {
					l.waitN(context.Background(), 100)
				}
				done <- struct{}{}
			}()
		}
		for range 4 {
			<-done
		}
	})
	if elapsed := c.Now().Sub(start); elapsed < 10*time.Second || elapsed > 10500*time.Millisecond {
		t.Fatalf("10000 bytes over 4 connections took %v", elapsed)
	}
}

func TestLimiterSetRateWakesWaiters(t *testing.T) {
	c := clock.BuildFake(start)
	l := buildRateLimiter(c, 1)
	done := make(chan struct{})
	go func() {
		l.waitN(context.Background(), 1000)
		close(done)
	}()
	for c.Waiters() == 0 {
		time.Sleep(time.Microsecond)
	}
	l.setRate(0)
	<-done
}

func TestLimiterSlowsDownLive(t *testing.T) {
	c := clock.BuildFake(start)
	l := buildRateLimiter(c, 0)
	l.waitN(context.Background(), 1<<20)
	l.setRate(100)
	runWithClock(c, time.Millisecond, func() {
		l.waitN(context.Background(), 100)
	})
	if elapsed := c.Now().Sub(start); elapsed < time.Second || elapsed > 1001*time.Millisecond {
		t.Fatalf("100 bytes at 100 B/s right after unlimited took %v", elapsed)
	}
}

func TestLimiterCancel(t *testing.T) {
	c := clock.BuildFake(start)
	l := buildRateLimiter(c, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- l.waitN(ctx, 1000) }()
	for c.Waiters() == 0 {
		time.Sleep(time.Microsecond)
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("want canceled, got %v", err)
	}
	if c.Waiters() != 0 {
		t.Fatal("timer leaked")
	}
}

func TestLimiterControlGoesFirst(t *testing.T) {
	c := clock.BuildFake(start)
	l := buildRateLimiter(c, 1000)
	done := make(chan struct{})
	go func() {
		l.waitN(context.Background(), 1000)
		close(done)
	}()
	for c.Waiters() == 0 {
		time.Sleep(time.Microsecond)
	}
	l.addControl(500)
	runWithClock(c, time.Millisecond, func() { <-done })
	if elapsed := c.Now().Sub(start); elapsed < 1500*time.Millisecond || elapsed > 1510*time.Millisecond {
		t.Fatalf("1000 data bytes after 500 control bytes at 1000 B/s took %v", elapsed)
	}
}

func TestWriterSendsControlBeforeData(t *testing.T) {
	c := clock.BuildFake(start)
	l := buildRateLimiter(c, 1000)
	go l.waitN(context.Background(), 1<<20)
	for c.Waiters() == 0 {
		time.Sleep(time.Microsecond)
	}
	e := &Engine{inbox: make(chan any, 8)}
	ours, theirs := net.Pipe()
	defer theirs.Close()
	control, data := make(chan outItem, 4), make(chan outItem, 4)
	block := outItem{packet: client.SendingPart{Data: make([]byte, 10)}, payload: 10}
	data <- block
	data <- block
	control <- outItem{packet: client.QueueRanking{Rank: 7}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.runWriter(ctx, 1, netip.AddrPort{}, ours, control, data, l)
	frame, err := wire.ParseFrameFrom(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := client.Parse(frame.Protocol, frame.Opcode, frame.Body); p != (client.QueueRanking{Rank: 7}) {
		t.Fatalf("first packet %#v, want the queue ranking", p)
	}
}
