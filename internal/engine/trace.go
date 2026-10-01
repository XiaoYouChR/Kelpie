package engine

import (
	"encoding/json"
	"log"
	"os"

	"github.com/XiaoYouChR/Kelpie/internal/transfer"
)

// traceLine is one line of the trace file (docs/protocol.md Trace).
type traceLine map[string]any

func toTraceLine(ev transfer.TraceEvent) traceLine {
	line := traceLine{
		"time":   ev.Time.UnixMilli(),
		"hash":   ev.Hash.String(),
		"source": ev.Source,
		"event":  string(ev.Event),
	}
	switch ev.Event {
	case transfer.EventFound:
		line["channel"] = string(ev.Channel)
	case transfer.EventConnected:
		line["isIpv6"] = ev.IsIPv6
	case transfer.EventFailed, transfer.EventClosed:
		line["reason"] = ev.Reason
	case transfer.EventQueued:
		line["rank"] = ev.Rank
	case transfer.EventReceived:
		line["bytes"] = ev.Bytes
	}
	return line
}

// runTraceWriter is the trace file's leaf; it appends each line and reports
// it written so the hub can send the next.
func (e *Engine) runTraceWriter(file *os.File, lines <-chan traceLine) {
	defer file.Close()
	isBroken := false
	for {
		select {
		case line := <-lines:
			if !isBroken {
				raw, _ := json.Marshal(line)
				if _, err := file.Write(append(raw, '\n')); err != nil {
					log.Printf("engine: trace: %v", err)
					isBroken = true
				}
			}
			if !e.send(e.ctx, traceWritten{}) {
				return
			}
		case <-e.ctx.Done():
			return
		}
	}
}
