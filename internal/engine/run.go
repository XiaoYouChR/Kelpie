package engine

import (
	"maps"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/aich"
	"github.com/XiaoYouChR/Kelpie/internal/disk"
	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// run is one open Run. transfer is nil while a seed's file is being
// checked against the link.
type run struct {
	id        RunID
	mode      Mode
	file      link.File
	path      string
	handle    disk.File
	transfer  *transfer.Transfer
	share     peer.Share
	published piece.Set
	progress  Progress
	// asked maps each user we sent the file request to the last time we did.
	asked map[wire.Hash]time.Time
	// isSyncing is set while a complete download is flushed to the device;
	// the run ends when that is done.
	isSyncing bool
	// tree is the AICH tree of a complete file, nil until hashed.
	tree          *aich.Tree
	isTreeHashing bool
}

// fileReaskTime is aMule's FILEREASKTIME (Constants.h:35), the transfer's
// reask interval.
const fileReaskTime = 1300 * time.Second

func (e *Engine) onCommand(command Command) {
	switch c := command.(type) {
	case RunCommand:
		if err := e.startRun(c); err != nil {
			e.events.SendEnded(c.ID, err)
		}
	case StopCommand:
		if r := e.runs[c.ID]; r != nil {
			e.stopRun(r, nil)
		}
	case RemoveCommand:
		if r := e.runByHash[c.Hash]; r != nil {
			e.stopRun(r, nil)
		}
		if _, ok := e.state.Transfers[c.Hash]; ok {
			delete(e.state.Transfers, c.Hash)
			e.requestSave()
		}
	case RateLimitsCommand:
		e.downloadLimiter.SetRate(c.Download)
		e.uploadLimiter.SetRate(c.Upload)
		e.queue.SetRate(c.Upload)
	}
}

// startRun admits a run per docs/protocol.md "Run rules".
func (e *Engine) startRun(c RunCommand) *Error {
	file, err := link.Parse(c.Link)
	if err != nil {
		return &Error{Code: CodeInvalidLink, Message: err.Error()}
	}
	if e.runByHash[file.Hash] != nil {
		return &Error{Code: CodeTransferBusy, Message: "another run is open for " + file.Hash.String()}
	}
	r := &run{id: c.ID, mode: c.Mode, file: file, path: c.File, asked: map[wire.Hash]time.Time{}}
	var state *transfer.State
	if old, ok := e.state.Transfers[file.Hash]; ok && old.File == c.File {
		resume := transfer.State(old)
		state = &resume
	}
	info, err := e.ports.Disk.Probe(c.File)
	if err != nil {
		return toFileError(err)
	}

	if c.Mode == ModeSeed {
		if info == nil || info.IsDir() || info.Size() != file.Size {
			return &Error{Code: CodeFileError, Message: c.File + " is not the complete file of the link"}
		}
		if r.handle, err = e.ports.Disk.Open(c.File, disk.Read); err != nil {
			return toFileError(err)
		}
		e.addRun(r)
		if state != nil && isComplete(state) {
			e.startTransfer(r, state)
		} else {
			e.sendDiskJob(diskJob{kind: jobHashFile, run: r.id, file: r.handle, size: file.Size})
		}
		e.refreshProgress(r, true)
		return nil
	}

	if info != nil && state == nil && (info.IsDir() || info.Size() > 0) {
		return &Error{Code: CodeOutputExists, Message: c.File + " already exists"}
	}
	// Resume data for a file that is gone would claim blocks it no longer has.
	if info == nil {
		state = nil
	}
	if r.handle, err = e.ports.Disk.Open(c.File, disk.Create); err != nil {
		return toFileError(err)
	}
	e.addRun(r)
	e.startTransfer(r, state)
	e.refreshProgress(r, true)
	return nil
}

func toFileError(err error) *Error {
	if disk.IsFull(err) {
		return &Error{Code: CodeDiskFull, Message: err.Error()}
	}
	return &Error{Code: CodeFileError, Message: err.Error()}
}

func isComplete(state *transfer.State) bool {
	return len(state.VerifiedParts) == piece.PartCount(state.Size) && piece.Set(state.VerifiedParts).IsFull()
}

func (e *Engine) addRun(r *run) {
	e.runs[r.id] = r
	e.runByHash[r.file.Hash] = r
	e.runList = append(e.runList, r)
}

func (e *Engine) startTransfer(r *run, state *transfer.State) {
	mode := transfer.ModeDownload
	if r.mode == ModeSeed {
		mode = transfer.ModeSeed
	}
	r.transfer = transfer.Build(transfer.Options{
		File:   r.file,
		Path:   r.path,
		State:  state,
		Mode:   mode,
		Random: e.ports.Rand,
	}, e.now())
	e.refreshShare(r)
	e.queue.AddFile(r.file.Hash)
	for _, src := range r.file.Sources {
		e.addKnownSource(r.file.Hash, transfer.Source{Endpoint: src})
	}
}

// onFileHashed finishes checking a seed's file: a match makes it a
// complete Transfer, anything else ends the run.
func (e *Engine) onFileHashed(r *run, partHashes []wire.Hash, fileHash wire.Hash) {
	if fileHash != r.file.Hash {
		e.stopRun(r, &Error{Code: CodeFileError, Message: r.path + " does not match the link"})
		return
	}
	state := transfer.State{
		Size:          r.file.Size,
		File:          r.path,
		PartHashes:    partHashes,
		VerifiedParts: piece.BuildFullSet(piece.PartCount(r.file.Size)),
		Created:       e.now(),
	}
	if old, ok := e.state.Transfers[r.file.Hash]; ok {
		state.Uploaded = old.Uploaded
		state.Created = old.Created
	}
	e.startTransfer(r, &state)
}

func (e *Engine) refreshShare(r *run) {
	state := r.transfer.ToState()
	r.share = peer.Share{Name: r.file.Name, Size: r.file.Size, Parts: state.VerifiedParts, PartHashes: state.PartHashes, Tree: r.tree}
}

func (e *Engine) shareByHash(file wire.Hash) (peer.Share, bool) {
	r := e.runByHash[file]
	if r == nil || r.transfer == nil || r.share.Parts.Count() == 0 {
		return peer.Share{}, false
	}
	return r.share, true
}

func (e *Engine) downloadByHash(file wire.Hash) *run {
	r := e.runByHash[file]
	if r == nil || r.transfer == nil || r.mode != ModeDownload {
		return nil
	}
	return r
}

// stopRun ends r exactly once and keeps its Durable State.
func (e *Engine) stopRun(r *run, err *Error) {
	h := r.file.Hash
	for _, c := range e.sortedConns() {
		e.removeFile(c, h, "run ended")
	}
	e.releaseA4AF(h)
	e.runQueueActions(e.queue.RemoveFile(h))
	if r.transfer != nil {
		e.refreshProgress(r, false)
		e.state.Transfers[h] = store.Transfer(r.transfer.ToState())
	}
	r.handle.Close()
	delete(e.runs, r.id)
	delete(e.runByHash, h)
	e.runList = slices.DeleteFunc(e.runList, func(other *run) bool { return other == r })
	e.removeKnownSources(h)
	e.events.SendEnded(r.id, err)
	e.requestSave()
}

// refreshRuns ends every run whose Transfer reached its outcome.
func (e *Engine) refreshRuns() {
	for _, r := range slices.Clone(e.runList) {
		if r.transfer == nil {
			continue
		}
		switch outcome := r.transfer.Outcome(); outcome.Status {
		case transfer.StatusFailed:
			code := CodeFileError
			if outcome.IsDiskFull {
				code = CodeDiskFull
			}
			e.stopRun(r, &Error{Code: code, Message: outcome.Message})
		case transfer.StatusComplete:
			if r.mode == ModeDownload && !r.isSyncing {
				r.isSyncing = true
				e.sendDiskJob(diskJob{kind: jobSync, run: r.id, file: r.handle})
			}
		}
	}
}

func (e *Engine) refreshProgress(r *run, isFirst bool) {
	progress := Progress{Hash: r.file.Hash, Size: r.file.Size}
	if r.transfer != nil {
		p := r.transfer.Progress(e.now())
		progress = Progress{
			Hash:         r.file.Hash,
			Size:         p.Size,
			Received:     p.Received,
			DownloadRate: p.DownloadRate,
			UploadRate:   p.UploadRate,
			Uploaded:     p.Uploaded,
			Peers:        p.Peers,
			ActivePeers:  p.ActivePeers,
		}
	}
	if !isFirst && progress == r.progress {
		return
	}
	r.progress = progress
	e.events.SetProgress(r.id, progress)
}

func (e *Engine) runTransfers(now time.Time) {
	budget := e.connectBudget(now)
	n := len(e.runList)
	order := make([]*run, 0, n)
	for i := range n {
		order = append(order, e.runList[(e.budgetCursor+i)%n])
	}
	e.budgetCursor++
	for _, r := range order {
		if r.transfer == nil || e.runs[r.id] != r {
			continue
		}
		actions := r.transfer.OnTick(transfer.Tick{
			Now:           now,
			ConnectBudget: budget,
			Server:        e.serverAddr,
			IsFirewalled:  e.isFirewalled(),
			IsKadRunning:  e.kad != nil,
			PublicIP:      e.publicIP,
			Port:          uint16(e.tcpPort),
			LocalAddrs:    e.config.LocalAddrs,
		})
		for _, action := range actions {
			switch action.(type) {
			case transfer.Connect, transfer.RequestServerCallback, transfer.RequestKadCallback:
				budget--
			}
		}
		e.runTransferActions(r, actions)
	}
}

// connectBudget follows eMule's MaxConnections and MaxConperFive.
func (e *Engine) connectBudget(now time.Time) int {
	e.recentConnects = slices.DeleteFunc(e.recentConnects, func(at time.Time) bool {
		return now.Sub(at) >= newConnectionWindow
	})
	return max(0, min(maxConnections-len(e.conns), maxNewConnections-len(e.recentConnects)))
}

func (e *Engine) runTransferActions(r *run, actions []transfer.Action) {
	now := e.now()
	for _, action := range actions {
		if e.runs[r.id] != r {
			return
		}
		switch a := action.(type) {
		case transfer.Connect:
			if e.deferConnect(r, a) {
				continue
			}
			c := e.connByEndpoint(a.Endpoint)
			if c == nil {
				c = e.openPeerConn(a.Endpoint, a.UserHash, a.CanObfuscate)
			}
			e.addFile(c, r)
		case transfer.ReaskUDP:
			if e.deferUDPReask(r, a.Endpoint) {
				continue
			}
			e.sendPeerDatagram(a.Endpoint, client.ReaskFilePing{
				Hash:               r.file.Hash,
				HasParts:           true,
				Parts:              peer.ToStatus(r.share),
				HasCompleteSources: true,
			}, a.UserHash, a.CanObfuscate)
		case transfer.RequestServerCallback:
			e.requestServerCallback(a.ClientID)
		case transfer.RequestKadCallback:
			switch {
			case e.kad == nil:
			case a.IsDirect:
				e.requestDirectCallback(a.Buddy, a.UserHash, a.CanObfuscate)
			default:
				e.kad.RequestCallback(toKadCallback(a, r.file.Hash))
			}
		case transfer.RequestSources:
			if c := e.conns[a.Peer]; a.Channel == transfer.ChannelExchange && c != nil && c.session != nil {
				e.runSession(c, c.session.RequestSources(r.file.Hash, now))
			}
		case transfer.RequestHashSet:
			if c := e.conns[a.Peer]; c != nil && c.session != nil {
				e.runSession(c, c.session.RequestHashSet(r.file.Hash))
			}
		case transfer.Publish:
			r.published = a.Parts
		case transfer.Write:
			e.sendDiskJob(diskJob{kind: jobWrite, run: r.id, file: r.handle, block: a.Block, data: a.Data})
		case transfer.HashPart:
			e.sendDiskJob(diskJob{kind: jobHashPart, run: r.id, file: r.handle, part: a.Part, block: piece.Block{Begin: a.Begin, End: a.End}})
		case transfer.HashBlocks:
			e.sendDiskJob(diskJob{kind: jobHashBlocks, run: r.id, file: r.handle, part: a.Part, block: piece.Block{Begin: a.Begin, End: a.End}})
		case transfer.RequestRecovery:
			if c := e.conns[a.Peer]; c != nil && c.session != nil {
				e.runSession(c, c.session.RequestRecovery(r.file.Hash, a.Part, a.Root))
			}
		case transfer.Close:
			if c := e.conns[a.Peer]; c != nil {
				e.removeFile(c, r.file.Hash, a.Reason)
				if a.Reason == "corrupt data" || a.Reason == "banned" {
					e.closeConn(c, a.Reason)
				}
			}
		case transfer.TraceEvent:
			e.sendTrace(a)
		}
	}
}

// addSources feeds a transfer and remembers who the sources are, so an
// incoming connection from one of them is recognised.
func (e *Engine) addSources(r *run, sources []transfer.Source, channel transfer.Channel) {
	for _, src := range sources {
		e.addKnownSource(r.file.Hash, src)
	}
	e.runTransferActions(r, r.transfer.OnSourcesFound(sources, channel, e.now()))
}

func (e *Engine) addKnownSource(file wire.Hash, src transfer.Source) {
	if src.UserHash != (wire.Hash{}) {
		addToSet(e.sourceUsers, src.UserHash, file)
	}
	if src.ClientID != 0 && src.Server.IsValid() {
		addToSet(e.sourceLowIDs, lowIDKey{src.ClientID, src.Server}, file)
	}
}

func addToSet[K comparable](sets map[K]map[wire.Hash]bool, key K, file wire.Hash) {
	if sets[key] == nil {
		sets[key] = map[wire.Hash]bool{}
	}
	sets[key][file] = true
}

// refreshKnownSources keeps only the sources running transfers still hold;
// a transfer refuses sources beyond its cap, and these sets follow it.
func (e *Engine) refreshKnownSources() {
	clear(e.sourceUsers)
	clear(e.sourceLowIDs)
	for _, r := range e.runList {
		if r.transfer == nil {
			continue
		}
		for _, src := range r.transfer.Sources() {
			e.addKnownSource(r.file.Hash, src)
		}
	}
}

// refreshAsked forgets file requests older than the reask time, which no
// longer hold back a request on an incoming connection.
func (e *Engine) refreshAsked() {
	now := e.now()
	for _, r := range e.runList {
		maps.DeleteFunc(r.asked, func(_ wire.Hash, asked time.Time) bool {
			return now.Sub(asked) >= fileReaskTime
		})
	}
}

func (e *Engine) removeKnownSources(file wire.Hash) {
	for user, files := range e.sourceUsers {
		if delete(files, file); len(files) == 0 {
			delete(e.sourceUsers, user)
		}
	}
	for key, files := range e.sourceLowIDs {
		if delete(files, file); len(files) == 0 {
			delete(e.sourceLowIDs, key)
		}
	}
}

// matchKnownSource lists the downloads that know the peer as a source, in
// run order.
func (e *Engine) matchKnownSource(user wire.Hash, caps peer.Capabilities) []wire.Hash {
	var files []wire.Hash
	for _, r := range e.runList {
		h := r.file.Hash
		if e.downloadByHash(h) != nil && (e.sourceUsers[user][h] || e.sourceLowIDs[lowIDKey{caps.ClientID, caps.Server}][h]) {
			files = append(files, h)
		}
	}
	return files
}
