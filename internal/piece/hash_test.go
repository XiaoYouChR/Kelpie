package piece_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

func md4Of(data []byte) wire.Hash {
	var hasher piece.MD4
	hasher.Write(data)
	return hasher.Digest()
}

func TestMD4MatchesRFC1320(t *testing.T) {
	vectors := map[string]string{
		"":                           "31D6CFE0D16AE931B73C59D7E0C089C0",
		"a":                          "BDE52CB31DE33E46245E05FBDBD6FB24",
		"abc":                        "A448017AAF21D8525FC10AE87AA6729D",
		"message digest":             "D9130A8164549FE818874806E1C7014B",
		"abcdefghijklmnopqrstuvwxyz": "D79E1C308AA5BBCDEEA8ED63DF412DA9",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":                   "043F8582F241DB351CE627E153E7F0E4",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "E33B4DDC9C38F2199C3E7B164FCC0536",
	}
	for data, want := range vectors {
		if got := md4Of([]byte(data)).String(); got != want {
			t.Errorf("MD4(%q) = %s, want %s", data, got, want)
		}
	}
}

func TestMD4IsIncremental(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 37)
	want := md4Of(data)

	var hasher piece.MD4
	for i := range data {
		hasher.Write(data[i : i+1])
		hasher.Digest()
	}
	if got := hasher.Digest(); got != want {
		t.Fatalf("byte-wise digest = %s, want %s", got, want)
	}
}

func fileHashOf(t *testing.T, data []byte) (wire.Hash, []wire.Hash) {
	t.Helper()
	var hasher piece.FileHasher
	for chunk := range slices.Chunk(data, 1_000_003) {
		hasher.Write(chunk)
	}
	return hasher.FileHash(), hasher.PartHashes()
}

func TestFileHash(t *testing.T) {
	// Expected values were computed independently with LibreSSL's MD4.
	cases := []struct {
		name       string
		size       int64
		want       string
		hashCount  int
		lastPartIs string
	}{
		{"empty", 0, "31D6CFE0D16AE931B73C59D7E0C089C0", 0, ""},
		{"one byte below a part", piece.PartSize - 1, "AC44B93FC9AFF773AB0005C911F8396F", 0, ""},
		{"exactly one part", piece.PartSize, "FC21D9AF828F92A8DF64BEAC3357425D", 2, "31D6CFE0D16AE931B73C59D7E0C089C0"},
		{"one byte over a part", piece.PartSize + 1, "06329E9DBA1373512C06386FE29E3C65", 2, "47C61A0FA8738BA77308A8A600F88E4B"},
		{"exactly two parts", 2 * piece.PartSize, "114B21C63A74B6CA922291A11177DD5C", 3, "31D6CFE0D16AE931B73C59D7E0C089C0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fileHash, partHashes := fileHashOf(t, make([]byte, tc.size))
			if fileHash.String() != tc.want {
				t.Errorf("file hash = %s, want %s", fileHash, tc.want)
			}
			if len(partHashes) != tc.hashCount || piece.HashCount(tc.size) != tc.hashCount {
				t.Fatalf("hash set has %d hashes, HashCount says %d, want %d", len(partHashes), piece.HashCount(tc.size), tc.hashCount)
			}
			if tc.hashCount == 0 {
				return
			}
			if got := partHashes[len(partHashes)-1].String(); got != tc.lastPartIs {
				t.Errorf("last part hash = %s, want %s", got, tc.lastPartIs)
			}
			if got := piece.BuildFileHash(partHashes); got != fileHash {
				t.Errorf("BuildFileHash = %s, want %s", got, fileHash)
			}
		})
	}
}

func TestPartAndBlockCounts(t *testing.T) {
	cases := []struct {
		size      int64
		parts     int
		lastPart  int
		lastCount int
	}{
		{0, 0, 0, 0},
		{1, 1, 0, 1},
		{piece.BlockSize, 1, 0, 1},
		{piece.BlockSize + 1, 1, 0, 2},
		{piece.PartSize, 1, 0, 53},
		{piece.PartSize + 1, 2, 1, 1},
		{5 * piece.PartSize / 2, 3, 2, 27},
	}
	for _, tc := range cases {
		if got := piece.PartCount(tc.size); got != tc.parts {
			t.Errorf("PartCount(%d) = %d, want %d", tc.size, got, tc.parts)
		}
		if tc.parts == 0 {
			continue
		}
		if got := piece.BlockCount(tc.size, 0); tc.parts > 1 && got != 53 {
			t.Errorf("BlockCount(%d, 0) = %d, want 53", tc.size, got)
		}
		if got := piece.BlockCount(tc.size, tc.lastPart); got != tc.lastCount {
			t.Errorf("BlockCount(%d, %d) = %d, want %d", tc.size, tc.lastPart, got, tc.lastCount)
		}
	}
}
