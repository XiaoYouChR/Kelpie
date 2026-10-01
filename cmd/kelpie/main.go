// Command kelpie is the Engine Process: it speaks docs/protocol.md on stdin
// and stdout and writes diagnostics to stderr.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/XiaoYouChR/Kelpie/internal/engine"
	"github.com/XiaoYouChR/Kelpie/internal/gateway"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	log.SetOutput(os.Stderr)
	if err := gateway.Run(os.Stdin, os.Stdout, version, start); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func start(config engine.Config, events engine.Events) (gateway.Engine, error) {
	if os.Getenv("KELPIE_DEBUG") == "1" {
		config.PacketLog = os.Stderr
	}
	e, err := engine.Start(config, events)
	if err != nil {
		return nil, err
	}
	return e, nil
}
