package disk

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
)

func buildDisks() map[string]func(t *testing.T) (Disk, string) {
	return map[string]func(t *testing.T) (Disk, string){
		"real": func(t *testing.T) (Disk, string) { return Real{}, t.TempDir() },
		"fake": func(t *testing.T) (Disk, string) { return BuildFake(), "/data" },
	}
}

func TestDiskContract(t *testing.T) {
	for name, build := range buildDisks() {
		t.Run(name, func(t *testing.T) {
			d, folder := build(t)
			path := filepath.Join(folder, "a.iso")

			if _, err := d.Open(path, Write); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("open missing for write: %v", err)
			}
			if info, err := d.Probe(path); info != nil || err != nil {
				t.Fatalf("probe missing: %v %v", info, err)
			}

			file, err := d.Open(path, Create)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte("world"), 6); err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte("hello"), 0); err != nil {
				t.Fatal(err)
			}
			if err := file.Sync(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			info, err := d.Probe(path)
			if err != nil || info.Size() != 11 || info.Name() != "a.iso" || info.IsDir() {
				t.Fatalf("probe: %v %v", info, err)
			}

			file, err = d.Open(path, Read)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			got := make([]byte, 11)
			if _, err := file.ReadAt(got, 0); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte("hello\x00world")) {
				t.Fatalf("read %q", got)
			}
			if n, err := file.ReadAt(make([]byte, 4), 9); n != 2 || err != io.EOF {
				t.Fatalf("short read: %d %v", n, err)
			}
			if _, err := file.WriteAt([]byte("x"), 0); err == nil {
				t.Fatal("write through a read-only handle")
			}
		})
	}
}

func TestFakeFaultHitsNextWritesOnly(t *testing.T) {
	d := BuildFake()
	file, _ := d.Open("/a", Create)
	d.AddFault("/a", OpWrite, syscall.ENOSPC, 2)
	for range 2 {
		_, err := file.WriteAt([]byte("x"), 0)
		if !IsFull(err) {
			t.Fatalf("want full disk, got %v", err)
		}
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) || pathErr.Path != "/a" {
			t.Fatalf("want *fs.PathError for /a, got %#v", err)
		}
	}
	if _, err := file.WriteAt([]byte("x"), 0); err != nil {
		t.Fatalf("third write: %v", err)
	}
}

func TestFakeFaultMatchesPath(t *testing.T) {
	d := BuildFake()
	a, _ := d.Open("/a", Create)
	b, _ := d.Open("/b", Create)
	d.AddFault("/a", OpWrite, syscall.EIO, 1)
	if _, err := b.WriteAt([]byte("x"), 0); err != nil {
		t.Fatalf("other path failed: %v", err)
	}
	_, err := a.WriteAt([]byte("x"), 0)
	if !errors.Is(err, syscall.EIO) || IsFull(err) {
		t.Fatalf("want EIO, got %v", err)
	}
}

func TestFakeGlobalFault(t *testing.T) {
	d := BuildFake()
	d.SetData("/a", []byte("abc"))
	d.AddFault("", OpOpen, fs.ErrPermission, 1)
	if _, err := d.Open("/a", Read); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("want permission denied, got %v", err)
	}
	file, err := d.Open("/a", Read)
	if err != nil {
		t.Fatal(err)
	}
	d.AddFault("", OpRead, syscall.EIO, 1)
	if _, err := file.ReadAt(make([]byte, 1), 0); !errors.Is(err, syscall.EIO) {
		t.Fatalf("want EIO, got %v", err)
	}
	d.AddFault("", OpSync, syscall.ENOSPC, 1)
	if err := file.Sync(); !IsFull(err) {
		t.Fatalf("want full on sync, got %v", err)
	}
}

func TestFakeDeleteMakesPathMissing(t *testing.T) {
	d := BuildFake()
	file, _ := d.Open("/a", Create)
	file.WriteAt([]byte("abc"), 0)
	d.Delete("/a")
	if _, err := d.Open("/a", Read); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want missing, got %v", err)
	}
	if _, ok := d.DataByPath("/a"); ok {
		t.Fatal("data still there")
	}
}

func TestFakeClosedFileFails(t *testing.T) {
	d := BuildFake()
	file, _ := d.Open("/a", Create)
	file.Close()
	if _, err := file.WriteAt([]byte("x"), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("want closed, got %v", err)
	}
}

func TestIsFull(t *testing.T) {
	wrapped := &fs.PathError{Op: "write", Path: "/a", Err: syscall.ENOSPC}
	if !IsFull(wrapped) {
		t.Fatal("ENOSPC not full")
	}
	if IsFull(&fs.PathError{Op: "write", Path: "/a", Err: syscall.EIO}) || IsFull(nil) {
		t.Fatal("EIO is full")
	}
}

func TestFakeIsRaceFree(t *testing.T) {
	d := BuildFake()
	file, _ := d.Open("/a", Create)
	done := make(chan struct{})
	for i := range 4 {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := range 100 {
				file.WriteAt([]byte{byte(j)}, int64(i*100+j))
				file.ReadAt(make([]byte, 1), int64(j))
				d.Probe("/a")
			}
		}()
	}
	for range 4 {
		<-done
	}
	if data, _ := d.DataByPath("/a"); len(data) != 400 {
		t.Fatalf("size %d", len(data))
	}
}
