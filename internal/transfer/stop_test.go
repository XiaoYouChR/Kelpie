package transfer_test

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
)

// The next Run's Transfer takes over the sources of the stopped one: the
// queued and the asked source keep their reask time, the sending one is
// asked again at once, and a dial in flight is made again.
func TestNextTransferKeepsTheSources(t *testing.T) {
	data := buildData(piece.PartSize + 100)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	var found []transfer.Source
	for i := 1; i <= 4; i++ {
		found = append(found, transfer.Source{Endpoint: endpoint(i)})
	}
	h.run(h.transfer.OnSourcesFound(found, transfer.ChannelServer, start))
	h.tick(transfer.Tick{ConnectBudget: 4})
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, start))
	h.transfer.OnPeerParts(1, piece.Set{true, true})
	h.run(h.transfer.OnQueued(1, 3, start))
	h.connect(2, 2, piece.Set{true, true})
	h.deliver(2, 1, false)
	h.run(h.transfer.OnPeerConnected(3, transfer.Source{Endpoint: endpoint(3), UserHash: userHash(3)}, start))

	stopped := start.Add(time.Minute)
	closed := traces(h.transfer.Stop(stopped), transfer.EventClosed)
	if len(closed) != 3 || slices.ContainsFunc(closed, func(e transfer.TraceEvent) bool { return e.Reason != "run ended" }) {
		t.Fatalf("closed on stop: %+v", closed)
	}
	if got := h.transfer.OnPeerGone(2, "run ended", stopped); len(got) != 0 {
		t.Fatalf("peer still attached after Stop: %+v", got)
	}

	next, started := transfer.Build(transfer.Options{File: buildFile(data, endpoint(1)), Path: path, Random: rand.New(rand.NewPCG(3, 4)), Previous: h.transfer}, stopped)
	if got := traces(started, transfer.EventFound); len(got) != 0 {
		t.Fatalf("known link source found again: %+v", got)
	}
	at := func(d time.Duration) []netip.AddrPort {
		var dialled []netip.AddrPort
		for _, c := range connects(next.OnTick(transfer.Tick{Now: start.Add(d), ConnectBudget: 4})) {
			dialled = append(dialled, c.Endpoint)
		}
		return dialled
	}
	for _, step := range []struct {
		at   time.Duration
		want []netip.AddrPort
	}{
		{time.Minute, []netip.AddrPort{endpoint(2), endpoint(4)}},
		{fileReaskTime - time.Second, nil},
		{fileReaskTime, []netip.AddrPort{endpoint(1), endpoint(3)}},
	} {
		if got := at(step.at); !slices.Equal(got, step.want) {
			t.Fatalf("dialled %v at %v, want %v", got, step.at, step.want)
		}
	}
}

// resumer plays a user who pauses and resumes the file while its only
// source sends, and the source's client, which scores our slot asks as
// aMule and eMule do.
type resumer struct {
	t        *testing.T
	file     link.File
	transfer *transfer.Transfer
	peer     uint64
	// asked is when the client last saw a slot ask, at first one from an
	// earlier Engine Process; aMule and eMule are its scores.
	asked        time.Time
	aMule, eMule int
}

func buildResumer(t *testing.T) *resumer {
	data := buildData(piece.PartSize + 100)
	r := &resumer{t: t, file: buildFile(data, endpoint(1)), asked: start.Add(-time.Minute)}
	r.transfer, _ = transfer.Build(transfer.Options{File: r.file, Path: path, Random: rand.New(rand.NewPCG(3, 4))}, start)
	return r
}

// ask runs the source's turn at now and reports whether it was asked for
// a slot, which it grants.
func (r *resumer) ask(now time.Time) bool {
	r.t.Helper()
	if len(connects(r.transfer.OnTick(transfer.Tick{Now: now, ConnectBudget: 1}))) == 0 {
		return false
	}
	r.peer++
	r.transfer.OnPeerConnected(r.peer, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, now)
	r.transfer.OnPeerParts(r.peer, piece.Set{true, true})
	r.transfer.OnSlotAsked(r.peer, now)
	r.transfer.OnSlotGranted(r.peer, now)
	gap := now.Sub(r.asked)
	if gap < 590*time.Second {
		r.aMule += 3
	} else {
		r.aMule = max(0, r.aMule-1)
	}
	if gap < 10*time.Minute {
		r.eMule++
	} else {
		r.eMule = max(0, r.eMule-1)
	}
	r.asked = now
	if r.aMule >= 10 || r.eMule >= 4 {
		r.t.Fatalf("banned at %v: aMule score %d, eMule count %d", now.Sub(start), r.aMule, r.eMule)
	}
	return true
}

// pause stops the Run and opens the next one.
func (r *resumer) pause(now time.Time) {
	r.transfer.Stop(now)
	r.transfer, _ = transfer.Build(transfer.Options{File: r.file, Path: path, Random: rand.New(rand.NewPCG(3, 4)), Previous: r.transfer}, now)
}

// A sender is asked again at once on resume, as aMule does, until that
// would bring the client's aggressive score near its ban; then it is held,
// as Progress tells, until asking counts as polite. Polite asks, as the
// reask of a queued source, bring the score down again.
func TestResumeAsksTheSenderAtOnceUntilItWouldCountAsAggressive(t *testing.T) {
	const politeGap = 11 * time.Minute
	r := buildResumer(t)
	at := func(d time.Duration) time.Time { return start.Add(d) }
	if !r.ask(start) {
		t.Fatal("the link's source was not asked")
	}
	r.pause(at(time.Minute))
	if !r.ask(at(time.Minute)) {
		t.Fatal("the sender was not asked again at once on the first resume")
	}
	r.pause(at(2 * time.Minute))
	if r.ask(at(2 * time.Minute)) {
		t.Fatal("the sender was asked again at once on the second resume")
	}
	held := at(time.Minute + politeGap)
	p := r.transfer.Progress(at(2 * time.Minute))
	if p.HeldSources != 1 || !p.HeldUntil.Equal(held) {
		t.Fatalf("progress held %d until %v, want 1 until %v", p.HeldSources, p.HeldUntil, held)
	}
	want := []transfer.SourceProgress{{Address: endpoint(1).String(), Status: "held", Channel: "link"}}
	if !slices.Equal(p.Sources, want) {
		t.Fatalf("progress sources %+v, want %+v", p.Sources, want)
	}
	if r.ask(held.Add(-time.Second)) || !r.ask(held) {
		t.Fatal("the held sender was not asked when its ask became polite")
	}
	if p := r.transfer.Progress(held); p.HeldSources != 0 || !p.HeldUntil.IsZero() {
		t.Fatalf("progress still held %d until %v once asked", p.HeldSources, p.HeldUntil)
	}

	asked := held
	for range 2 {
		r.transfer.OnQueued(r.peer, 5, asked.Add(time.Minute))
		r.transfer.OnPeerGone(r.peer, "closed", asked.Add(time.Minute))
		if r.ask(asked.Add(fileReaskTime-time.Second)) || !r.ask(asked.Add(fileReaskTime)) {
			t.Fatal("the queued source was not reasked at its reask time")
		}
		asked = asked.Add(fileReaskTime)
	}
	r.pause(asked.Add(time.Minute))
	if !r.ask(asked.Add(time.Minute)) {
		t.Fatal("the sender was not asked at once after polite asks")
	}
}

// However often the user pauses and resumes, the client never scores us
// near a ban, and the sender is still asked every eleven minutes.
func TestRepeatedResumesNeverGetUsBanned(t *testing.T) {
	for _, every := range []time.Duration{time.Second, 30 * time.Second, 4 * time.Minute, 9 * time.Minute} {
		r := buildResumer(t)
		asks := 0
		for now := start; now.Before(start.Add(3 * time.Hour)); now = now.Add(every) {
			r.pause(now)
			if r.ask(now) {
				asks++
			}
		}
		if want := int(3 * time.Hour / (11*time.Minute + every)); asks < want {
			t.Fatalf("resumed every %v: asked %d times in 3 h, want at least %d", every, asks, want)
		}
	}
}
