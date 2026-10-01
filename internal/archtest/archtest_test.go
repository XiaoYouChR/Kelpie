// Package archtest checks the import graph against ADR-0005 and the Go rules
// in CLAUDE.md, so a new dependency is a reviewed decision, not an accident.
package archtest

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/XiaoYouChR/Kelpie/"

// allowed is every import edge between Kelpie packages in non-test code.
// Adding an edge here is the review point: it must also pass the rules below.
var allowed = map[string][]string{
	"cmd/kelpie":           {"internal/engine", "internal/gateway"},
	"internal/aich":        {"internal/piece", "internal/wire", "internal/wire/client"},
	"internal/clock":       {},
	"internal/disk":        {},
	"internal/fakeserver":  {"internal/clock", "internal/transport", "internal/wire", "internal/wire/server"},
	"internal/gateway":     {"internal/engine", "internal/wire"},
	"internal/identity":    {"internal/wire"},
	"internal/kad":         {"internal/clock", "internal/obfuscation", "internal/store", "internal/transport", "internal/wire", "internal/wire/kad"},
	"internal/link":        {"internal/piece", "internal/wire"},
	"internal/nat":         {},
	"internal/obfuscation": {"internal/wire"},
	"internal/peer":        {"internal/aich", "internal/identity", "internal/piece", "internal/wire", "internal/wire/client"},
	"internal/piece":       {"internal/wire"},
	"internal/server":      {"internal/wire", "internal/wire/server"},
	"internal/store":       {"internal/piece", "internal/wire"},
	"internal/transfer":    {"internal/aich", "internal/link", "internal/piece", "internal/wire", "internal/wire/client"},
	"internal/transport":   {"internal/clock"},
	"internal/upload":      {"internal/identity", "internal/piece", "internal/wire"},
	"internal/wire":        {},
	"internal/wire/client": {"internal/wire", "internal/wire/kad"},
	"internal/wire/kad":    {"internal/wire"},
	"internal/wire/server": {"internal/wire"},
	"internal/engine": {
		"internal/aich", "internal/clock", "internal/disk", "internal/identity", "internal/kad",
		"internal/link", "internal/nat", "internal/obfuscation", "internal/peer", "internal/piece",
		"internal/server", "internal/store", "internal/transfer", "internal/transport", "internal/upload",
		"internal/wire", "internal/wire/client", "internal/wire/kad", "internal/wire/server",
	},
}

// exceptions are edges that break a rule today. Each one is debt: the test
// fails once the edge is gone, so the cleanup that removes it removes the
// entry too.
var exceptions = map[edge]string{
	// The engine takes connections from the transport seam as net.Conn, and
	// matches net.ErrClosed and *net.TCPAddr on them; it opens nothing itself.
	{"internal/engine", "net"}: "engine uses the transport seam's net.Conn",
	// Allowed, not debt: the store is a leaf I/O actor (ADR-0005) whose only
	// job is the atomic write of state.json; tests point it at a temp folder.
	{"internal/store", "os"}:    "store is a leaf I/O actor",
	{"internal/store", "io/fs"}: "store is a leaf I/O actor",
	// Allowed, not debt: nat is its own seam to the router, reached only
	// through Start and tested against httptest/UDP fakes; the eD2k fakes
	// never need it.
	{"internal/nat", "net"}:        "nat is the router seam",
	{"internal/nat", "net/http"}:   "nat is the router seam",
	{"internal/nat", "os/exec"}:    "nat is the router seam",
	{"internal/nat", "wall clock"}: "nat is the router seam",
}

type edge struct{ from, to string }

// pure lists the state machines that consume events and return actions
// (CLAUDE.md "Go", ADR-0005): no I/O, no goroutines, no hubs, no seams.
var pure = []string{
	"internal/aich", "internal/identity", "internal/link", "internal/peer", "internal/piece",
	"internal/server", "internal/transfer", "internal/upload",
	"internal/wire", "internal/wire/client", "internal/wire/kad", "internal/wire/server",
}

// notForPure are the Kelpie packages that own goroutines, sockets, files or
// time.
var notForPure = []string{
	"internal/clock", "internal/disk", "internal/engine", "internal/fakeserver", "internal/gateway",
	"internal/kad", "internal/nat", "internal/obfuscation", "internal/store", "internal/transport",
}

// ioStd are standard packages that reach the outside world or synchronise
// goroutines.
var ioStd = []string{"context", "io/fs", "log", "net", "net/http", "os", "os/exec", "path/filepath", "sync", "sync/atomic", "syscall"}

// seams may use ioStd and the wall clock: they are the outside world's
// only entry (CLAUDE.md "Go"). obfuscation wraps a net.Conn; fakeserver is a
// test peer.
var seams = []string{"cmd/kelpie", "internal/clock", "internal/disk", "internal/transport", "internal/fakeserver"}

var wallClock = []string{"Now", "Since", "Until", "After", "AfterFunc", "Sleep", "NewTimer", "NewTicker", "Tick"}

type listed struct {
	ImportPath   string
	Dir          string
	GoFiles      []string
	Imports      []string
	TestImports  []string
	XTestImports []string
}

func loadPackages(t *testing.T) []listed {
	t.Helper()
	readTree(t)
	cmd := exec.Command("go", "list", "-json", module+"...")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	var packages []listed
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listed
		if err := decoder.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		p.ImportPath = strings.TrimPrefix(p.ImportPath, module)
		packages = append(packages, p)
	}
	return packages
}

// readTree reads every folder and Go file of the module itself, because go
// test caches a result by the files the test binary opened and does not see
// what go list read.
func readTree(t *testing.T) {
	t.Helper()
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "testdata"):
			return filepath.SkipDir
		case entry.IsDir():
			_, err = os.ReadDir(path)
		case strings.HasSuffix(path, ".go"):
			_, err = os.ReadFile(path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func toLocal(imports []string) []string {
	var local []string
	for _, path := range imports {
		if strings.HasPrefix(path, module) {
			local = append(local, strings.TrimPrefix(path, module))
		}
	}
	return local
}

func isWire(path string) bool {
	return path == "internal/wire" || strings.HasPrefix(path, "internal/wire/")
}

// matchRule names the rule an edge breaks, or "" if it breaks none. to is
// a Kelpie package, a standard package, or "wall clock".
func matchRule(from, to string) string {
	isLocal := strings.HasPrefix(to, "internal/") || strings.HasPrefix(to, "cmd/")
	switch {
	case strings.HasPrefix(to, "cmd/"):
		return "no package imports cmd"
	case to == "internal/gateway" && from != "cmd/kelpie":
		return "only cmd/kelpie imports gateway"
	case to == "internal/fakeserver":
		return "fakeserver is for tests only"
	case isWire(from) && isLocal && !isWire(to):
		return "wire imports only wire and the standard library"
	case to == "internal/engine" && from != "internal/gateway" && from != "cmd/kelpie":
		return "only gateway and cmd/kelpie import engine"
	case from == "internal/kad" && slices.Contains([]string{"internal/peer", "internal/transfer", "internal/upload", "internal/server"}, to):
		return "kad meets the engine's state machines only through messages"
	case slices.Contains(pure, from) && (slices.Contains(notForPure, to) || slices.Contains(ioStd, to) || to == "wall clock"):
		return "pure state machines do no I/O and import no hub or seam"
	case slices.Contains([]string{"internal/clock", "internal/disk", "internal/transport"}, from) && isLocal && to != "internal/clock":
		return "seams import only clock and the standard library"
	case !isLocal && (slices.Contains([]string{"net", "net/http", "os", "os/exec", "io/fs", "syscall"}, to) || to == "wall clock") &&
		!slices.Contains(seams, from) && !(from == "internal/obfuscation" && to == "net"):
		return "outside world only through transport, disk and clock"
	}
	return ""
}

func TestImportsMatchAllowList(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range loadPackages(t) {
		if p.ImportPath == "internal/archtest" {
			continue
		}
		seen[p.ImportPath] = true
		want, isListed := allowed[p.ImportPath]
		if !isListed {
			t.Errorf("%s is not in the allow-list; add it with its imports", p.ImportPath)
			continue
		}
		got := toLocal(p.Imports)
		for _, to := range got {
			if !slices.Contains(want, to) {
				t.Errorf("new import edge %s -> %s; review it and add it to allowed", p.ImportPath, to)
			}
		}
		for _, to := range want {
			if !slices.Contains(got, to) {
				t.Errorf("%s no longer imports %s; remove it from allowed", p.ImportPath, to)
			}
		}
	}
	for path := range allowed {
		if !seen[path] {
			t.Errorf("%s is in the allow-list but no longer exists", path)
		}
	}
}

func TestRules(t *testing.T) {
	used := map[edge]bool{}
	check := func(from, to string) {
		rule := matchRule(from, to)
		if rule == "" {
			return
		}
		e := edge{from, to}
		if _, isException := exceptions[e]; isException {
			used[e] = true
			return
		}
		t.Errorf("%s -> %s breaks %q", from, to, rule)
	}
	for from, tos := range allowed {
		for _, to := range tos {
			check(from, to)
		}
	}
	for _, p := range loadPackages(t) {
		for _, to := range p.Imports {
			if !strings.HasPrefix(to, module) {
				check(p.ImportPath, to)
			}
		}
		for _, to := range toLocal(append(p.TestImports, p.XTestImports...)) {
			if strings.HasPrefix(to, "cmd/") || (to == "internal/gateway" && p.ImportPath != "internal/gateway") {
				t.Errorf("test of %s imports %s", p.ImportPath, to)
			}
		}
		source := scanSource(t, p)
		if source.hasWallClock {
			check(p.ImportPath, "wall clock")
		}
		if source.hasGo && slices.Contains(pure, p.ImportPath) {
			t.Errorf("%s starts a goroutine; pure state machines do not", p.ImportPath)
		}
		if source.hasStdio && p.ImportPath != "cmd/kelpie" {
			t.Errorf("%s touches os.Stdin/Stdout/Stderr; only cmd/kelpie wires stdio to the gateway", p.ImportPath)
		}
		if source.hasJSONTag && p.ImportPath != "internal/gateway" && p.ImportPath != "internal/store" {
			t.Errorf("%s has json struct tags; the Python-facing protocol lives only in gateway", p.ImportPath)
		}
	}
	for e := range exceptions {
		if !used[e] {
			t.Errorf("exception %s -> %s no longer applies; remove it", e.from, e.to)
		}
	}
}

type source struct {
	hasWallClock bool
	hasGo        bool
	hasStdio     bool
	hasJSONTag   bool
}

func scanSource(t *testing.T, p listed) source {
	t.Helper()
	var s source
	files := token.NewFileSet()
	for _, name := range p.GoFiles {
		file, err := parser.ParseFile(files, filepath.Join(p.Dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GoStmt:
				s.hasGo = true
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok {
					s.hasWallClock = s.hasWallClock || (x.Name == "time" && slices.Contains(wallClock, n.Sel.Name))
					s.hasStdio = s.hasStdio || (x.Name == "os" && strings.HasPrefix(n.Sel.Name, "Std"))
				}
			case *ast.Field:
				s.hasJSONTag = s.hasJSONTag || (n.Tag != nil && strings.Contains(n.Tag.Value, `json:"`))
			}
			return true
		})
	}
	return s
}
