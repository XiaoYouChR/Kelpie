package wire

import "testing"

func TestHashRoundTrip(t *testing.T) {
	hash, err := ParseHash("31d6cfe0d16ae931b73c59d7e0c089c0")
	if err != nil {
		t.Fatal(err)
	}
	if got := hash.String(); got != "31D6CFE0D16AE931B73C59D7E0C089C0" {
		t.Fatalf("String() = %s", got)
	}
}

func TestParseHashRejectsWrongLength(t *testing.T) {
	if _, err := ParseHash("31D6"); err == nil {
		t.Fatal("want error")
	}
}
