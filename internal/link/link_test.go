package link_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

type vector struct {
	Link  string `json:"link"`
	Valid bool   `json:"valid"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Hash  string `json:"hash"`
}

func TestParseSharedVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/links.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Link, func(t *testing.T) {
			file, err := link.Parse(v.Link)
			if !v.Valid {
				if !errors.Is(err, link.ErrInvalid) {
					t.Fatalf("Parse = %+v, %v; want ErrInvalid", file, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if file.Name != v.Name || file.Size != v.Size || file.Hash.String() != v.Hash {
				t.Fatalf("Parse = %q %d %s, want %q %d %s", file.Name, file.Size, file.Hash, v.Name, v.Size, v.Hash)
			}
		})
	}
}

func TestParseKeepsMatchingPartHashes(t *testing.T) {
	const parts = "D7DEF262A127CD79096A108E7A9FC138:47C61A0FA8738BA77308A8A600F88E4B"
	file, err := link.Parse("ed2k://|file|a|9728001|06329E9DBA1373512C06386FE29E3C65|p=" + parts + "|/")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.PartHashes) != 2 || file.PartHashes[1].String() != "47C61A0FA8738BA77308A8A600F88E4B" {
		t.Fatalf("PartHashes = %v", file.PartHashes)
	}

	file, err = link.Parse("ed2k://|file|a|9728001|31D6CFE0D16AE931B73C59D7E0C089C0|p=" + parts + "|/")
	if err != nil {
		t.Fatal(err)
	}
	if file.PartHashes != nil {
		t.Fatalf("kept a hash set that does not match the file hash: %v", file.PartHashes)
	}
}

func TestParseReadsIPSources(t *testing.T) {
	file, err := link.Parse("ed2k://|file|a|5|31D6CFE0D16AE931B73C59D7E0C089C0|/|sources,1.2.3.4:4662,example.com:4662,[2001:db8::1]:4672,5.6.7.8:0|/")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("1.2.3.4:4662"),
		netip.MustParseAddrPort("[2001:db8::1]:4672"),
	}
	if !slices.Equal(file.Sources, want) {
		t.Fatalf("Sources = %v, want %v", file.Sources, want)
	}
}

func TestParseReadsAICHHash(t *testing.T) {
	file, err := link.Parse("ed2k://|file|a|5|31D6CFE0D16AE931B73C59D7E0C089C0|h=dztdjp5oxqbuqkmbawjd2dzg4r5kgp7v|/")
	if err != nil {
		t.Fatal(err)
	}
	if got := file.AICHHash.String(); got != "DZTDJP5OXQBUQKMBAWJD2DZG4R5KGP7V" {
		t.Fatalf("AICHHash = %s", got)
	}

	file, err = link.Parse("ed2k://|file|a|5|31D6CFE0D16AE931B73C59D7E0C089C0|h=NOTBASE32!|/")
	if err != nil {
		t.Fatal(err)
	}
	if file.AICHHash != (wire.AICHHash{}) {
		t.Fatalf("kept a malformed AICH hash: %s", file.AICHHash)
	}
}
