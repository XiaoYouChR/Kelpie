// Package gateway is the stateless leaf between the stdio NDJSON protocol
// (docs/protocol.md) and the Engine.
package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/XiaoYouChR/Kelpie/internal/engine"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

const protocolVersion = 1

type Engine interface {
	// Post hands a command to the engine's inbox; it never blocks for long.
	Post(command engine.Command)
	// Close saves Durable State, stops the engine, and returns when done.
	Close() error
}

// Run answers hello with the engine start builds, posts every later command
// to it, and writes the engine's events to out until in reaches EOF.
func Run(in io.Reader, out io.Writer, version string, start func(engine.Config, engine.Events) (Engine, error)) error {
	reader := bufio.NewReader(in)
	line, readErr := reader.ReadBytes('\n')
	if len(bytes.TrimSpace(line)) == 0 {
		return fmt.Errorf("read hello: %w", errors.Join(readErr, io.ErrUnexpectedEOF))
	}
	config, err := parseHello(line, version)
	if err != nil {
		return sendFailed(out, &engine.Error{Code: engine.CodeStartFailed, Message: err.Error()})
	}
	box := newOutbox()
	eng, err := start(config, box)
	if err != nil {
		var engineErr *engine.Error
		if !errors.As(err, &engineErr) {
			engineErr = &engine.Error{Code: engine.CodeStartFailed, Message: err.Error()}
		}
		return sendFailed(out, engineErr)
	}
	if err := sendLine(out, readyLine{Type: "ready", Version: version, Protocol: protocolVersion}); err != nil {
		return errors.Join(err, eng.Close())
	}

	isClosed := make(chan struct{})
	writeErr := make(chan error, 1)
	go func() { writeErr <- box.run(out, isClosed) }()

	for readErr == nil {
		line, readErr = reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		command, err := parseCommand(line)
		if err != nil {
			log.Printf("gateway: ignore line %q: %v", bytes.TrimSpace(line), err)
			continue
		}
		eng.Post(command)
	}
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	closeErr := eng.Close()
	close(isClosed)
	return errors.Join(readErr, closeErr, <-writeErr)
}

type helloLine struct {
	DataFolder string `json:"dataFolder"`
	settingsLine
}

// settingsLine is the part hello and update share.
type settingsLine struct {
	Settings struct {
		Port        int      `json:"port"`
		EnableKad   bool     `json:"enableKad"`
		EnableUpnp  bool     `json:"enableUpnp"`
		ServerLists []string `json:"serverLists"`
		NodeLists   []string `json:"nodeLists"`
		TraceFile   string   `json:"traceFile"`
		Proxy       string   `json:"proxy"`
	} `json:"settings"`
	RateLimits rateLimits `json:"rateLimits"`
}

type rateLimits struct {
	Download int64 `json:"download"`
	Upload   int64 `json:"upload"`
}

func parseHello(line []byte, version string) (engine.Config, error) {
	var kind struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &kind); err != nil {
		return engine.Config{}, fmt.Errorf("hello: %w", err)
	}
	if kind.Type != "hello" {
		return engine.Config{}, fmt.Errorf("first message is %q, want hello", kind.Type)
	}
	var hello helloLine
	if err := json.Unmarshal(line, &hello); err != nil {
		return engine.Config{}, fmt.Errorf("hello: %w", err)
	}
	if hello.DataFolder == "" {
		return engine.Config{}, errors.New("hello: dataFolder is empty")
	}
	if hello.Settings.Port < 0 || hello.Settings.Port > 65535 {
		return engine.Config{}, fmt.Errorf("hello: port %d out of range", hello.Settings.Port)
	}
	settings, err := toSettings(hello.settingsLine)
	if err != nil {
		return engine.Config{}, fmt.Errorf("hello: %w", err)
	}
	return engine.Config{
		Version:     version,
		DataFolder:  hello.DataFolder,
		Port:        hello.Settings.Port,
		ServerLists: hello.Settings.ServerLists,
		NodeLists:   hello.Settings.NodeLists,
		TraceFile:   hello.Settings.TraceFile,
		Settings:    settings,
	}, nil
}

type commandLine struct {
	Type string `json:"type"`
	Run  int64  `json:"run"`
	Mode string `json:"mode"`
	Link string `json:"link"`
	File string `json:"file"`
	Hash string `json:"hash"`
	settingsLine
}

func parseCommand(line []byte) (engine.Command, error) {
	var c commandLine
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	switch c.Type {
	case "run":
		if c.Run <= 0 {
			return nil, fmt.Errorf("run id %d is not positive", c.Run)
		}
		if c.File == "" {
			return nil, errors.New("run file is empty")
		}
		mode, err := parseMode(c.Mode)
		if err != nil {
			return nil, err
		}
		return engine.RunCommand{ID: engine.RunID(c.Run), Mode: mode, Link: c.Link, File: c.File}, nil
	case "stop":
		if c.Run <= 0 {
			return nil, fmt.Errorf("run id %d is not positive", c.Run)
		}
		return engine.StopCommand{ID: engine.RunID(c.Run)}, nil
	case "remove":
		hash, err := wire.ParseHash(c.Hash)
		if err != nil {
			return nil, err
		}
		return engine.RemoveCommand{Hash: hash}, nil
	case "update":
		return toSettings(c.settingsLine)
	default:
		return nil, fmt.Errorf("unknown message type %q", c.Type)
	}
}

func parseMode(text string) (engine.Mode, error) {
	switch text {
	case "download":
		return engine.ModeDownload, nil
	case "seed":
		return engine.ModeSeed, nil
	}
	return 0, fmt.Errorf("unknown run mode %q", text)
}

func toSettings(line settingsLine) (engine.Settings, error) {
	limits := line.RateLimits
	if limits.Download < 0 || limits.Upload < 0 {
		return engine.Settings{}, fmt.Errorf("negative rate limit %+v", limits)
	}
	return engine.Settings{
		EnableKad:     line.Settings.EnableKad,
		EnableUPnP:    line.Settings.EnableUpnp,
		DownloadLimit: limits.Download,
		UploadLimit:   limits.Upload,
		Proxy:         line.Settings.Proxy,
	}, nil
}

type readyLine struct {
	Type     string `json:"type"`
	Version  string `json:"version"`
	Protocol int    `json:"protocol"`
}

type failedLine struct {
	Type  string     `json:"type"`
	Error *errorJSON `json:"error"`
}

type errorJSON struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// codeNames is the wire name of each engine.Code, from docs/protocol.md
// "Error codes".
var codeNames = map[engine.Code]string{
	engine.CodeInternal:     "INTERNAL",
	engine.CodeInvalidLink:  "INVALID_LINK",
	engine.CodeOutputExists: "OUTPUT_EXISTS",
	engine.CodeTransferBusy: "TRANSFER_BUSY",
	engine.CodeDiskFull:     "DISK_FULL",
	engine.CodeFileError:    "FILE_ERROR",
	engine.CodeStartFailed:  "START_FAILED",
}

func sendFailed(out io.Writer, err *engine.Error) error {
	sendErr := sendLine(out, failedLine{Type: "failed", Error: toErrorJSON(err)})
	return errors.Join(err, sendErr)
}

func sendLine(out io.Writer, message any) error {
	line, err := json.Marshal(message)
	if err != nil {
		return err
	}
	_, err = out.Write(append(line, '\n'))
	return err
}

func toErrorJSON(err *engine.Error) *errorJSON {
	if err == nil {
		return nil
	}
	return &errorJSON{Code: codeNames[err.Code], Message: err.Message}
}
