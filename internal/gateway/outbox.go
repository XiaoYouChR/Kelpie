package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/XiaoYouChR/Kelpie/internal/engine"
)

// outbox is the engine's non-blocking view of stdout (ADR-0005): progress
// and network are latest-value slots, ended is a queue that is never dropped.
// A single writer drains it; a slow consumer only ever sees the newest
// progress.
type outbox struct {
	mu              sync.Mutex
	network         *engine.Network
	progress        map[engine.RunID]engine.Progress
	progressOrder   []engine.RunID
	ended           []endedLine
	isEnded         map[engine.RunID]bool
	hasPendingWrite chan struct{}
}

func newOutbox() *outbox {
	return &outbox{
		progress:        map[engine.RunID]engine.Progress{},
		isEnded:         map[engine.RunID]bool{},
		hasPendingWrite: make(chan struct{}, 1),
	}
}

func (o *outbox) SetProgress(id engine.RunID, progress engine.Progress) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.isEnded[id] {
		return
	}
	if _, isPending := o.progress[id]; !isPending {
		o.progressOrder = append(o.progressOrder, id)
	}
	o.progress[id] = progress
	o.requestWrite()
}

func (o *outbox) SendEnded(id engine.RunID, err *engine.Error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.isEnded[id] {
		return
	}
	// Run ids are never reused within one Engine Process, so this set only
	// grows by one entry per run.
	o.isEnded[id] = true
	o.ended = append(o.ended, endedLine{Type: "ended", Run: id, Error: toErrorJSON(err)})
	o.requestWrite()
}

func (o *outbox) SetNetwork(network engine.Network) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.network = &network
	o.requestWrite()
}

func (o *outbox) requestWrite() {
	select {
	case o.hasPendingWrite <- struct{}{}:
	default:
	}
}

// run writes pending lines as soon as they arrive, and once isClosed is
// closed writes what is left and returns. After a write error it keeps
// draining into io.Discard so the engine never notices, and returns that
// error.
func (o *outbox) run(out io.Writer, isClosed <-chan struct{}) error {
	var writeErr error
	for {
		select {
		case <-o.hasPendingWrite:
		case <-isClosed:
			return errors.Join(writeErr, o.sendPending(out))
		}
		if err := o.sendPending(out); err != nil {
			writeErr = err
			out = io.Discard
		}
	}
}

// sendPending takes every pending line out of the slots and writes them. A
// run's progress goes before its ended, because the engine set it before
// ending the run.
func (o *outbox) sendPending(out io.Writer) error {
	o.mu.Lock()
	network := o.network
	progress := make([]progressLine, 0, len(o.progressOrder))
	for _, id := range o.progressOrder {
		progress = append(progress, toProgressLine(id, o.progress[id]))
	}
	ended := o.ended
	o.network = nil
	o.progressOrder = nil
	clear(o.progress)
	o.ended = nil
	o.mu.Unlock()

	var lines bytes.Buffer
	encoder := json.NewEncoder(&lines)
	if network != nil {
		encoder.Encode(toNetworkLine(*network))
	}
	for _, line := range progress {
		encoder.Encode(line)
	}
	for _, line := range ended {
		encoder.Encode(line)
	}
	if lines.Len() == 0 {
		return nil
	}
	_, err := out.Write(lines.Bytes())
	return err
}

type progressLine struct {
	Type         string       `json:"type"`
	Run          engine.RunID `json:"run"`
	Hash         string       `json:"hash"`
	Size         int64        `json:"size"`
	Received     int64        `json:"received"`
	DownloadRate int64        `json:"downloadRate"`
	UploadRate   int64        `json:"uploadRate"`
	Uploaded     int64        `json:"uploaded"`
	Peers        int          `json:"peers"`
	ActivePeers  int          `json:"activePeers"`
}

type endedLine struct {
	Type  string       `json:"type"`
	Run   engine.RunID `json:"run"`
	Error *errorJSON   `json:"error"`
}

type networkLine struct {
	Type              string `json:"type"`
	IsServerConnected bool   `json:"isServerConnected"`
	IsHighID          bool   `json:"isHighId"`
	IsKadFirewalled   bool   `json:"isKadFirewalled"`
	KadNodes          int    `json:"kadNodes"`
}

func toProgressLine(id engine.RunID, p engine.Progress) progressLine {
	return progressLine{
		Type:         "progress",
		Run:          id,
		Hash:         p.Hash.String(),
		Size:         p.Size,
		Received:     p.Received,
		DownloadRate: p.DownloadRate,
		UploadRate:   p.UploadRate,
		Uploaded:     p.Uploaded,
		Peers:        p.Peers,
		ActivePeers:  p.ActivePeers,
	}
}

func toNetworkLine(n engine.Network) networkLine {
	return networkLine{
		Type:              "network",
		IsServerConnected: n.IsServerConnected,
		IsHighID:          n.IsHighID,
		IsKadFirewalled:   n.IsKadFirewalled,
		KadNodes:          n.KadNodes,
	}
}
