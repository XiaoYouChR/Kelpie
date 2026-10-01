package identity

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Fixture made once with LibreSSL 3.3.6:
//
//	openssl genrsa -out key.pem 384
//	openssl rsa -in key.pem -outform DER -out key.der
//	openssl rsa -in key.pem -pubout -outform DER -out pub.der
//	{ cat pub.der; printf '\x78\x56\x34\x12\xc0\x00\x02\x07\x14'; } > msg.bin
//	openssl dgst -sha1 -sign key.pem -out sig.bin msg.bin
//
// msg.bin is the v2 message for verifier key = pub.der, challenge 0x12345678,
// IP 192.0.2.7, kind ipKindSigner.
const (
	fixturePrivateKey = "3081f3020100023100c9b63e24e6b3ab50a97d86b490f76d825b8441c4933c813f1aa12a0fcdda22d469c60e495cdf18f1fd485fd15f13e32102030100010230673d5e8b3685090eece0f17c23a2702b4339eb0b78ac841d6570ddd25c9f6a59f3260981ca0cac91cbdf2f26ca75acdd021900fb541d1ac2100e5ddf519727e725d1db3795c9b69b489ccf021900cd760a40f546d52cfec05a5819c70e6ce9453e19a74cdd0f021900d4093be0c656fb77f11f89d22d6e37e5a5b8a68c7be7bffb02180183a431b45d1047239d814cf2ebafa487d795cc949a116b021900c0d19491465f07c4cd355a85722a185e688f44fc6a465135"
	fixturePublicKey  = "304c300d06092a864886f70d0101010500033b003038023100c9b63e24e6b3ab50a97d86b490f76d825b8441c4933c813f1aa12a0fcdda22d469c60e495cdf18f1fd485fd15f13e3210203010001"
	fixtureSignature  = "0836bc211dabb2618a0acd42fe9c396a75b60662dca68aa317ff9a77c0808d882262c3a1067c9e6888e6e7dd713eee40"
)

var fixtureChallenge = Challenge{Value: 0x12345678, IPKind: ipKindSigner, SignerIP: netip.MustParseAddr("192.0.2.7")}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadFixture(t *testing.T) Self {
	t.Helper()
	self, err := LoadSelf(wire.Hash{}, mustHex(t, fixturePrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	return self
}

func TestLoadSelfMatchesOpenSSLPublicKey(t *testing.T) {
	if got := loadFixture(t).PublicKey(); !bytes.Equal(got, mustHex(t, fixturePublicKey)) {
		t.Fatalf("PublicKey() = %x", got)
	}
}

func TestBuildSignatureMatchesOpenSSL(t *testing.T) {
	self := loadFixture(t)
	got := self.BuildSignature(self.PublicKey(), fixtureChallenge)
	if !bytes.Equal(got, mustHex(t, fixtureSignature)) {
		t.Fatalf("signature = %x", got)
	}
}

func TestMatchSignatureAcceptsOpenSSL(t *testing.T) {
	key := mustHex(t, fixturePublicKey)
	if !MatchSignature(key, mustHex(t, fixtureSignature), key, fixtureChallenge) {
		t.Fatal("openssl signature rejected")
	}
}

func TestMatchSignatureRejectsTampering(t *testing.T) {
	key := mustHex(t, fixturePublicKey)
	signature := mustHex(t, fixtureSignature)
	cases := map[string]func() bool{
		"challenge": func() bool {
			c := fixtureChallenge
			c.Value++
			return MatchSignature(key, signature, key, c)
		},
		"ip": func() bool {
			c := fixtureChallenge
			c.SignerIP = netip.MustParseAddr("192.0.2.8")
			return MatchSignature(key, signature, key, c)
		},
		"kind": func() bool {
			c := fixtureChallenge
			c.IPKind = ipKindVerifier
			return MatchSignature(key, signature, key, c)
		},
		"v1": func() bool {
			return MatchSignature(key, signature, key, Challenge{Value: fixtureChallenge.Value})
		},
		"flipped bit": func() bool {
			bad := bytes.Clone(signature)
			bad[20] ^= 1
			return MatchSignature(key, bad, key, fixtureChallenge)
		},
		"leading zero": func() bool {
			return MatchSignature(key, append([]byte{0}, signature...), key, fixtureChallenge)
		},
		"truncated": func() bool {
			return MatchSignature(key, signature[1:], key, fixtureChallenge)
		},
		"garbage key": func() bool {
			return MatchSignature(key[:40], signature, key, fixtureChallenge)
		},
	}
	for name, match := range cases {
		if match() {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCreateSelfRoundTrip(t *testing.T) {
	alice, err := CreateSelf()
	if err != nil {
		t.Fatal(err)
	}
	if alice.UserHash[5] != 14 || alice.UserHash[14] != 111 {
		t.Fatalf("user hash %s lacks eMule markers", alice.UserHash)
	}
	if got := len(alice.PublicKey()); got != 76 {
		t.Fatalf("public key is %d bytes, want 76", got)
	}
	loaded, err := LoadSelf(alice.UserHash, alice.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.PublicKey(), alice.PublicKey()) {
		t.Fatal("public key changed across PrivateKey/LoadSelf")
	}

	bob, err := CreateSelf()
	if err != nil {
		t.Fatal(err)
	}
	challenge := Challenge{Value: 7, IPKind: ipKindVerifier, VerifierIP: netip.MustParseAddr("203.0.113.9")}
	signature := loaded.BuildSignature(bob.PublicKey(), challenge)
	if len(signature) != 48 {
		t.Fatalf("signature is %d bytes, want 48", len(signature))
	}
	if !MatchSignature(alice.PublicKey(), signature, bob.PublicKey(), challenge) {
		t.Fatal("own signature rejected")
	}
	if MatchSignature(bob.PublicKey(), signature, bob.PublicKey(), challenge) {
		t.Fatal("signature accepted under the wrong key")
	}
}

func TestLoadSelfRejectsBrokenKey(t *testing.T) {
	der := mustHex(t, fixturePrivateKey)
	der[80] ^= 1
	if _, err := LoadSelf(wire.Hash{}, der); err == nil {
		t.Fatal("want error")
	}
}

// TestSignatureBindsAddressByKind: a signature covers only the address its
// kind names.
func TestSignatureBindsAddressByKind(t *testing.T) {
	self := loadFixture(t)
	signer := netip.MustParseAddr("192.0.2.1")
	verifier := netip.MustParseAddr("192.0.2.2")
	other := netip.MustParseAddr("192.0.2.3")
	cases := []struct {
		kind                           IPKind
		isSignerBound, isVerifierBound bool
	}{
		{ipKindNone, false, false},
		{ipKindSigner, true, false},
		{ipKindVerifier, false, true},
		{ipKindZero, false, false},
	}
	for _, c := range cases {
		challenge := Challenge{Value: 1, IPKind: c.kind, SignerIP: signer, VerifierIP: verifier}
		signature := self.BuildSignature(self.PublicKey(), challenge)
		movedSigner, movedVerifier := challenge, challenge
		movedSigner.SignerIP, movedVerifier.VerifierIP = other, other
		if got := MatchSignature(self.PublicKey(), signature, self.PublicKey(), movedSigner); got == c.isSignerBound {
			t.Errorf("kind %d: other signer address matches = %v", c.kind, got)
		}
		if got := MatchSignature(self.PublicKey(), signature, self.PublicKey(), movedVerifier); got == c.isVerifierBound {
			t.Errorf("kind %d: other verifier address matches = %v", c.kind, got)
		}
	}
}

func TestBuildReply(t *testing.T) {
	cases := []struct {
		name        string
		state       State
		peerSupport byte
		isLowID     bool
		want        Reply
	}{
		{"none", stateNone, 3, false, Reply{}},
		{"unknown state", 9, 3, false, Reply{}},
		{"signature", stateSignatureNeeded, 3, false, Reply{ShouldSign: true}},
		{"key and signature", stateKeyAndSignatureNeeded, 3, false, Reply{ShouldSendKey: true, ShouldSign: true}},
		{"v2 only highid", stateSignatureNeeded, 2, false, Reply{ShouldSign: true, IPKind: ipKindSigner}},
		{"v2 only lowid", stateSignatureNeeded, 2, true, Reply{ShouldSign: true, IPKind: ipKindVerifier}},
	}
	for _, c := range cases {
		if got := BuildReply(c.state, c.peerSupport, c.isLowID); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}
