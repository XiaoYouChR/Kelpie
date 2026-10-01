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

func TestAICHHashRoundTrip(t *testing.T) {
	const text = "DZTDJP5OXQBUQKMBAWJD2DZG4R5KGP7V"
	hash, err := ParseAICHHash("dztdjp5oxqbuqkmbawjd2dzg4r5kgp7v")
	if err != nil {
		t.Fatal(err)
	}
	if got := hash.String(); got != text {
		t.Fatalf("String() = %s, want %s", got, text)
	}
	for _, bad := range []string{"", "DZTDJP5OXQBUQKMBAWJD2DZG4R5KGP7", "DZTDJP5OXQBUQKMBAWJD2DZG4R5KGP71", "DZTDJP5OXQBUQKMBAWJD2DZG4R5KGP7VA"} {
		if _, err := ParseAICHHash(bad); err == nil {
			t.Errorf("ParseAICHHash(%q): want error", bad)
		}
	}
}
