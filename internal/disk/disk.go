// Package disk is the engine's seam for the files it downloads and seeds.
package disk

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

type Disk interface {
	Open(path string, mode Mode) (File, error)
	// Probe reports a missing path as an error matching fs.ErrNotExist.
	Probe(path string) (fs.FileInfo, error)
}

type File interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Close() error
}

type Mode int

const (
	// Read opens an existing file for seeding, so a read-only file can be shared.
	Read Mode = iota
	// Write opens an existing file for reading and writing.
	Write
	// Create opens a file for reading and writing, creating it when missing.
	Create
)

// IsFull reports whether err means the disk has no space left.
func IsFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || isWindowsFull(err)
}

// Real is the Disk of the running process.
type Real struct{}

func (Real) Open(path string, mode Mode) (File, error) {
	switch mode {
	case Read:
		return os.Open(path)
	case Write:
		return os.OpenFile(path, os.O_RDWR, 0)
	default:
		return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	}
}

func (Real) Probe(path string) (fs.FileInfo, error) {
	return os.Stat(path)
}
