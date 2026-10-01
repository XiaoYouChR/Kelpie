package clock

import (
	"testing"
	"time"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestFakeAdvanceFiresDueTicks(t *testing.T) {
	f := BuildFake(start)
	ticker := f.CreateTicker(time.Second)
	f.Advance(999 * time.Millisecond)
	select {
	case <-ticker.C():
		t.Fatal("ticked early")
	default:
	}
	f.Advance(time.Millisecond)
	if got := <-ticker.C(); !got.Equal(start.Add(time.Second)) {
		t.Fatalf("tick at %v", got)
	}
	if !f.Now().Equal(start.Add(time.Second)) {
		t.Fatalf("now %v", f.Now())
	}
}

func TestFakeDropsTicksNobodyReceived(t *testing.T) {
	f := BuildFake(start)
	ticker := f.CreateTicker(time.Second)
	f.Advance(5 * time.Second)
	if got := <-ticker.C(); !got.Equal(start.Add(time.Second)) {
		t.Fatalf("first tick %v", got)
	}
	select {
	case got := <-ticker.C():
		t.Fatalf("extra tick %v", got)
	default:
	}
	f.Advance(time.Second)
	if got := <-ticker.C(); !got.Equal(start.Add(6 * time.Second)) {
		t.Fatalf("next tick %v", got)
	}
}

func TestFakeFiresTickersInTimeOrder(t *testing.T) {
	f := BuildFake(start)
	slow := f.CreateTicker(3 * time.Second)
	fast := f.CreateTicker(2 * time.Second)
	f.Advance(3 * time.Second)
	if got := <-fast.C(); !got.Equal(start.Add(2 * time.Second)) {
		t.Fatalf("fast %v", got)
	}
	if got := <-slow.C(); !got.Equal(start.Add(3 * time.Second)) {
		t.Fatalf("slow %v", got)
	}
}

func TestFakeStoppedTickerStaysSilent(t *testing.T) {
	f := BuildFake(start)
	ticker := f.CreateTicker(time.Second)
	ticker.Stop()
	if f.Waiters() != 0 {
		t.Fatalf("waiters %d", f.Waiters())
	}
	f.Advance(time.Minute)
	select {
	case <-ticker.C():
		t.Fatal("stopped ticker fired")
	default:
	}
}

func TestFakeTimerFiresOnce(t *testing.T) {
	f := BuildFake(start)
	timer := f.CreateTimer(time.Second)
	if f.Waiters() != 1 {
		t.Fatalf("waiters %d", f.Waiters())
	}
	f.Advance(10 * time.Second)
	if got := <-timer.C(); !got.Equal(start.Add(time.Second)) {
		t.Fatalf("fired at %v", got)
	}
	if f.Waiters() != 0 {
		t.Fatal("fired timer still counted")
	}
	f.Advance(10 * time.Second)
	select {
	case <-timer.C():
		t.Fatal("fired twice")
	default:
	}
}

func TestFakeWaitersSkipsUnreceivedTicks(t *testing.T) {
	f := BuildFake(start)
	ticker := f.CreateTicker(time.Second)
	f.Advance(time.Second)
	if f.Waiters() != 0 {
		t.Fatal("ticker with a pending tick counted as parked")
	}
	<-ticker.C()
	if f.Waiters() != 1 {
		t.Fatal("drained ticker not counted")
	}
}

func TestRealTimerFires(t *testing.T) {
	timer := Real{}.CreateTimer(time.Millisecond)
	defer timer.Stop()
	<-timer.C()
}

func TestRealTickerTicks(t *testing.T) {
	ticker := Real{}.CreateTicker(time.Millisecond)
	defer ticker.Stop()
	<-ticker.C()
}
