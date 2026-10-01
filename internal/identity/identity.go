// Package identity implements eMule Secure User Identification (SUI) and the
// credits ledger. It does no I/O.
//
// Handshake, as eMule and aMule run it on each peer connection once both hello
// packets are in: each side whose peer advertised SUI support sends
// OP_SECIDENTSTATE with a fresh nonzero challenge, asking for
// StateKeyAndSignatureNeeded when it knows no public key for the peer's user
// hash and StateSignatureNeeded otherwise. The receiver answers per
// BuildReply: OP_PUBLICKEY if asked, then OP_SIGNATURE over the asker's public
// key and challenge. A signature that cannot be built yet because the asker's
// key has not arrived is sent when OP_PUBLICKEY arrives. The asker checks the
// signature with MatchSignature and reports the outcome to the Ledger.
package identity

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Support is the SecIdent bit set advertised in hello misc options:
// bit 0 = signature v1, bit 1 = signature v2.
const Support = 3

// State is the request carried by OP_SECIDENTSTATE.
type State byte

const (
	StateNone                  State = 0
	StateSignatureNeeded       State = 1
	StateKeyAndSignatureNeeded State = 2
)

// IPKind tells the verifier which IPv4 address the signer appended to the
// signed message (signature v2). Zero means v1: no address appended.
type IPKind byte

const (
	IPKindNone IPKind = 0
	// IPKindVerifier: the signer did not know its own address (LowID), so it
	// signed the verifier's address as the signer sees it.
	IPKindVerifier IPKind = 10
	// IPKindSigner: the signer signed its own server-assigned HighID address.
	IPKindSigner IPKind = 20
	// IPKindZero: the signed address is 0.0.0.0.
	IPKindZero IPKind = 30
)

// Challenge is everything besides the verifier's public key that the signature
// covers. Value is the 4-byte random challenge from OP_SECIDENTSTATE.
type Challenge struct {
	Value  uint32
	IPKind IPKind
	IP     netip.Addr
}

// BuildChallenge picks the address that goes with kind. Both sides call it
// with the same roles: the signer passes its own server-assigned address and
// the peer's address; the verifier passes the peer's address and its own
// public address.
func BuildChallenge(value uint32, kind IPKind, signerIP, verifierIP netip.Addr) Challenge {
	challenge := Challenge{Value: value, IPKind: kind}
	switch kind {
	case IPKindSigner:
		challenge.IP = signerIP
	case IPKindVerifier:
		challenge.IP = verifierIP
	}
	return challenge
}

// buildMessage lays out what is signed: verifier's public key || challenge
// (uint32 LE) [|| IPv4 octets in network order || kind]. eMule pokes its
// network-order IP as a little-endian uint32, which yields the octets as-is.
func buildMessage(verifierKey []byte, challenge Challenge) []byte {
	message := binary.LittleEndian.AppendUint32(append([]byte(nil), verifierKey...), challenge.Value)
	if challenge.IPKind == IPKindNone {
		return message
	}
	var ip [4]byte
	if challenge.IP.Is4() {
		ip = challenge.IP.As4()
	}
	return append(append(message, ip[:]...), byte(challenge.IPKind))
}

// Self is our own identity: the user hash and the SUI key pair.
type Self struct {
	UserHash wire.Hash
	key      privateKey
}

// CreateSelf makes a new random user hash, marked as an eMule hash by bytes 5
// and 14, and a new 384-bit key pair.
func CreateSelf() (Self, error) {
	var hash wire.Hash
	if _, err := rand.Read(hash[:]); err != nil {
		return Self{}, err
	}
	hash[5] = 14
	hash[14] = 111
	key, err := createKey()
	if err != nil {
		return Self{}, err
	}
	return Self{hash, key}, nil
}

// LoadSelf rebuilds Self from a user hash and a PKCS#1 DER private key, as
// produced by PrivateKey.
func LoadSelf(userHash wire.Hash, keyDER []byte) (Self, error) {
	key, err := parsePKCS1(keyDER)
	if err != nil {
		return Self{}, err
	}
	if len(toSubjectPublicKeyInfo(key.publicKey)) > maxKeySize {
		return Self{}, errors.New("private key: public key too large for OP_PUBLICKEY")
	}
	return Self{userHash, key}, nil
}

// PublicKey is our key as sent in OP_PUBLICKEY: X.509 SubjectPublicKeyInfo DER.
func (s Self) PublicKey() []byte {
	return toSubjectPublicKeyInfo(s.key.publicKey)
}

// PrivateKey is the PKCS#1 DER form that LoadSelf reads.
func (s Self) PrivateKey() []byte {
	return toPKCS1(s.key)
}

// BuildSignature signs peerKey and challenge for OP_SIGNATURE (RSASSA-PKCS1-v1_5
// with SHA-1).
func (s Self) BuildSignature(peerKey []byte, challenge Challenge) []byte {
	return buildPKCS1v15Signature(s.key, buildMessage(peerKey, challenge))
}

// MatchSignature reports whether signature, made by the holder of peerKey,
// covers ourKey and challenge.
func MatchSignature(peerKey, signature, ourKey []byte, challenge Challenge) bool {
	key, err := parseSubjectPublicKeyInfo(peerKey)
	if err != nil {
		return false
	}
	return matchPKCS1v15Signature(key, buildMessage(ourKey, challenge), signature)
}

// Reply is what to send after receiving OP_SECIDENTSTATE.
type Reply struct {
	ShouldSendKey       bool
	ShouldSendSignature bool
	// IsSignaturePending: send the signature once the peer's OP_PUBLICKEY arrives.
	IsSignaturePending bool
	IPKind             IPKind
}

// BuildReply follows eMule: signatures are v1 unless the peer supports only
// v2; a v2 signer that is LowID does not know its own address and signs the
// peer's instead.
func BuildReply(state State, peerSupport byte, isLowID, hasPeerKey bool) Reply {
	if state != StateSignatureNeeded && state != StateKeyAndSignatureNeeded {
		return Reply{}
	}
	reply := Reply{
		ShouldSendKey:       state == StateKeyAndSignatureNeeded,
		ShouldSendSignature: hasPeerKey,
		IsSignaturePending:  !hasPeerKey,
	}
	if peerSupport&1 == 0 {
		reply.IPKind = IPKindSigner
		if isLowID {
			reply.IPKind = IPKindVerifier
		}
	}
	return reply
}

// BuildStatePayload builds OP_SECIDENTSTATE: <state u8><challenge u32 LE>.
func BuildStatePayload(state State, challenge uint32) []byte {
	return binary.LittleEndian.AppendUint32([]byte{byte(state)}, challenge)
}

func ParseStatePayload(payload []byte) (State, uint32, error) {
	if len(payload) != 5 {
		return 0, 0, fmt.Errorf("secident state: %d bytes, want 5", len(payload))
	}
	state := State(payload[0])
	if state > StateKeyAndSignatureNeeded {
		return 0, 0, fmt.Errorf("secident state: unknown state %d", state)
	}
	return state, binary.LittleEndian.Uint32(payload[1:]), nil
}

// BuildKeyPayload builds OP_PUBLICKEY: <len u8><key>.
func BuildKeyPayload(key []byte) []byte {
	return append([]byte{byte(len(key))}, key...)
}

func ParseKeyPayload(payload []byte) ([]byte, error) {
	if len(payload) < 2 || int(payload[0]) != len(payload)-1 {
		return nil, errors.New("public key: length prefix mismatch")
	}
	if len(payload)-1 > maxKeySize {
		return nil, fmt.Errorf("public key: %d bytes, max %d", len(payload)-1, maxKeySize)
	}
	return payload[1:], nil
}

// BuildSignaturePayload builds OP_SIGNATURE: <len u8><signature>[<kind u8>],
// the kind byte present only for v2 signatures.
func BuildSignaturePayload(signature []byte, kind IPKind) []byte {
	payload := append([]byte{byte(len(signature))}, signature...)
	if kind != IPKindNone {
		payload = append(payload, byte(kind))
	}
	return payload
}

// ParseSignaturePayload accepts the v2 form only from peers that advertised v2.
func ParseSignaturePayload(payload []byte, peerSupport byte) ([]byte, IPKind, error) {
	if len(payload) < 2 {
		return nil, 0, errors.New("signature: too short")
	}
	size := int(payload[0])
	switch {
	case size == len(payload)-1:
		return payload[1:], IPKindNone, nil
	case size == len(payload)-2 && peerSupport&2 != 0:
		return payload[1 : 1+size], IPKind(payload[len(payload)-1]), nil
	}
	return nil, 0, errors.New("signature: length prefix mismatch")
}
