// Package shadowlemoncrypto implements the byte-level cryptographic primitives
// of ShadowLemon V0.2 (wire version 4), mirroring the authoritative Rust crate
// shadowlemon-crypto. All algorithms and constants here are part of the wire
// protocol and must stay in lockstep with the Rust implementation.
package shadowlemoncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// ProtocolVersion is the V0.2 wire protocol version.
	ProtocolVersion = 4

	// Suite identifiers carried on the wire.
	SuiteXChaCha20Poly1305 = 0
	SuiteAes256Gcm         = 1
	SuiteAes128Gcm         = 2

	// WireNonceLen is the length of the nonce on the wire for every suite.
	WireNonceLen = 24
	// TagLen is the AEAD authentication tag length for every suite.
	TagLen = 16
	// KeyLen is the length of a PBKDF2 / X25519 / SHA-256 key.
	KeyLen = 32
	// SaltLen is the length of the client and server handshake salts.
	SaltLen = 16
	// EphKeyLen is the length of an X25519 public key or shared secret.
	EphKeyLen = 32
	// HintLen is the length of the keyed user hint.
	HintLen = 4

	// Pbkdf2Iterations is the frozen static-key iteration count.
	Pbkdf2Iterations = 4096
	// MaxHandshakeSuites is the maximum number of suites in a handshake request.
	MaxHandshakeSuites = 4

	// HandshakeRequestFixedLen is the request length without the suite list.
	HandshakeRequestFixedLen = 51
	// HandshakeResponseLen is the exact response length.
	HandshakeResponseLen = 51

	// HintNoncePrefixLen is the number of leading wire-nonce bytes in the hint.
	HintNoncePrefixLen = 16
	// PayloadNonceIndex is the wire-nonce byte flipped for UDP payloads.
	PayloadNonceIndex = 16
	// PayloadNonceMask is the value XORed into the payload nonce byte.
	PayloadNonceMask = 0x01

	// replayDomainC2S and replayDomainS2C separate the two replay-cache flows.
	replayDomainC2S = 1
	replayDomainS2C = 2

	// FNV1A64OffsetBasis and FNV1A64Prime are the spec's FNV-1a 64 constants.
	FNV1A64OffsetBasis = uint64(0xcbf29ce484222325)
	FNV1A64Prime       = uint64(0x00000100000001b3)

	// EnvelopeSecretEnv is the environment variable holding the deployment
	// secret shared by both peers. There is deliberately no default.
	EnvelopeSecretEnv = "SHADOWLEMON_ENVELOPE_SECRET"
)

// Frozen domain-separation strings. Do not reformat.
var (
	staticKeySaltInfo = []byte("ShadowLemon V0.2 static key salt")
	c2sInfo           = []byte("ShadowLemon V0.2 c2s")
	s2cInfo           = []byte("ShadowLemon V0.2 s2c")
	earlyC2SInfo      = []byte("ShadowLemon V0.2 0rtt c2s")
	earlyS2CInfo      = []byte("ShadowLemon V0.2 0rtt s2c")
)

// SuiteKeyLen returns the AEAD key length of a wire suite identifier.
func SuiteKeyLen(suite uint8) (int, error) {
	switch suite {
	case SuiteXChaCha20Poly1305, SuiteAes256Gcm:
		return 32, nil
	case SuiteAes128Gcm:
		return 16, nil
	default:
		return 0, fmt.Errorf("unknown cipher suite id %d", suite)
	}
}

// SuiteNonceLen returns the AEAD nonce length of a wire suite identifier.
func SuiteNonceLen(suite uint8) (int, error) {
	switch suite {
	case SuiteXChaCha20Poly1305:
		return WireNonceLen, nil
	case SuiteAes256Gcm, SuiteAes128Gcm:
		return 12, nil
	default:
		return 0, fmt.Errorf("unknown cipher suite id %d", suite)
	}
}

// HashPassword computes SHA256(password || 0x00 || username) and returns the
// 32-byte credential. Callers whose password is already a 32-byte credential
// (for example from a hashedPassword config field) should pass it through
// unchanged rather than hashing it a second time.
func HashPassword(password, username []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte{0x00})
	h.Write(username)
	return h.Sum(nil)
}

// CredentialFromPassword is the string convenience wrapper of HashPassword.
func CredentialFromPassword(password, username string) []byte {
	return HashPassword([]byte(password), []byte(username))
}

// staticKeySalt returns SHA256("ShadowLemon V0.2 static key salt").
func staticKeySalt() []byte {
	s := sha256.Sum256(staticKeySaltInfo)
	return s[:]
}

// DeriveStaticKey derives the envelope static key from a credential:
//
//	salt      = SHA256("ShadowLemon V0.2 static key salt")
//	staticKey = PBKDF2-HMAC-SHA256(credential, salt, 4096, 32)[0:suite.KeyLen()]
//
// The credential must be the output of HashPassword (32 bytes).
func DeriveStaticKey(credential []byte, suite uint8) ([]byte, error) {
	keyLen, err := SuiteKeyLen(suite)
	if err != nil {
		return nil, err
	}
	if len(credential) != KeyLen {
		return nil, fmt.Errorf("credential length %d is invalid (want %d)", len(credential), KeyLen)
	}
	salt := staticKeySalt()
	out := pbkdf2.Key(credential, salt, Pbkdf2Iterations, KeyLen, sha256.New)
	return out[:keyLen], nil
}

// CredentialFromPasswordDouble mirrors the Rust peer's effective credential.
// The Rust server stores SHA256(password || 0x00 || username) and its
// derive_static_key() hashes that value a second time before PBKDF2; the Rust
// client follows the same path. DeriveStaticKey consumes this double-hashed
// value directly.
func CredentialFromPasswordDouble(password, username string) []byte {
	first := CredentialFromPassword(password, username)
	return HashPassword(first, []byte(username))
}

// DeriveStaticKeyFromPassword derives the wire static key from a plain-text
// password using the Rust peer's double-hash credential path.
func DeriveStaticKeyFromPassword(username, password string, suite uint8) ([]byte, error) {
	return DeriveStaticKey(CredentialFromPasswordDouble(password, username), suite)
}

// hkdfSha256 performs HKDF-SHA256 with the given salt, info and output length.
func hkdfSha256(secret, salt, info []byte, outLen int) ([]byte, error) {
	r := hkdf.New(func() hash.Hash { return sha256.New() }, secret, salt, info)
	out := make([]byte, outLen)
	if _, err := readFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// readFull reads len(buf) bytes from r or returns an error.
func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// sessionInfo builds the HKDF info of a directional key:
// prefix || version(0x04) || suite.
func sessionInfo(prefix []byte, suite uint8) []byte {
	info := make([]byte, 0, len(prefix)+2)
	info = append(info, prefix...)
	info = append(info, ProtocolVersion, suite)
	return info
}

// DeriveSessionKeys derives the two directional session keys of an
// established X25519 exchange:
//
//	salt  = SHA256(staticKey || clientSalt || serverSalt)
//	c2s   = HKDF-SHA256(shared, salt, "ShadowLemon V0.2 c2s" || 0x04 || suite, keyLen)
//	s2c   = HKDF-SHA256(shared, salt, "ShadowLemon V0.2 s2c" || 0x04 || suite, keyLen)
//
// The caller supplies the X25519 shared secret from X25519Shared.
func DeriveSessionKeys(staticKey, clientSalt, serverSalt, shared []byte, suite uint8) (c2s, s2c []byte, err error) {
	keyLen, err := SuiteKeyLen(suite)
	if err != nil {
		return nil, nil, err
	}
	if len(staticKey) == 0 || len(staticKey) > KeyLen {
		return nil, nil, fmt.Errorf("static key length %d is invalid (want %d)", len(staticKey), KeyLen)
	}
	if len(clientSalt) != SaltLen {
		return nil, nil, fmt.Errorf("client salt length %d is invalid (want %d)", len(clientSalt), SaltLen)
	}
	if len(serverSalt) != SaltLen {
		return nil, nil, fmt.Errorf("server salt length %d is invalid (want %d)", len(serverSalt), SaltLen)
	}
	if len(shared) != KeyLen {
		return nil, nil, fmt.Errorf("shared secret length %d is invalid (want %d)", len(shared), KeyLen)
	}

	h := sha256.New()
	h.Write(staticKey)
	h.Write(clientSalt)
	h.Write(serverSalt)
	salt := h.Sum(nil)

	c2s, err = hkdfSha256(shared, salt, sessionInfo(c2sInfo, suite), keyLen)
	if err != nil {
		return nil, nil, err
	}
	s2c, err = hkdfSha256(shared, salt, sessionInfo(s2cInfo, suite), keyLen)
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// DeriveEarlyKeys derives the two directional 0-RTT early keys from the static
// key and session id alone:
//
//	salt = SHA256(staticKey || u32be(sessionID))
//	c2s  = HKDF-SHA256(staticKey, salt, "ShadowLemon V0.2 0rtt c2s" || 0x04 || suite, keyLen)
//	s2c  = HKDF-SHA256(staticKey, salt, "ShadowLemon V0.2 0rtt s2c" || 0x04 || suite, keyLen)
func DeriveEarlyKeys(staticKey []byte, sessionID uint32, envelopeSuite uint8) (c2s, s2c []byte, err error) {
	keyLen, err := SuiteKeyLen(envelopeSuite)
	if err != nil {
		return nil, nil, err
	}
	if len(staticKey) == 0 || len(staticKey) > KeyLen {
		return nil, nil, fmt.Errorf("static key length %d is invalid (want %d)", len(staticKey), KeyLen)
	}

	h := sha256.New()
	h.Write(staticKey)
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], sessionID)
	h.Write(sid[:])
	salt := h.Sum(nil)

	c2s, err = hkdfSha256(staticKey, salt, sessionInfo(earlyC2SInfo, envelopeSuite), keyLen)
	if err != nil {
		return nil, nil, err
	}
	s2c, err = hkdfSha256(staticKey, salt, sessionInfo(earlyS2CInfo, envelopeSuite), keyLen)
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// DeploymentSecret reads the process-wide deployment secret from
// SHADOWLEMON_ENVELOPE_SECRET. An unset or empty value is an error: a
// published fallback would let an observer derive routing keystreams.
func DeploymentSecret() ([]byte, error) {
	v := os.Getenv(EnvelopeSecretEnv)
	if v == "" {
		return nil, fmt.Errorf("%s must be set to the same high-entropy value on both peers", EnvelopeSecretEnv)
	}
	return []byte(v), nil
}

// UserHint computes the four-byte keyed user hint:
// SHA256(deploymentSecret || username || wireNonce[0:16])[0:4].
// The caller supplies the deployment secret obtained from DeploymentSecret.
func UserHint(deploymentSecret, username, wireNonce []byte) [HintLen]byte {
	var hint [HintLen]byte
	if len(wireNonce) < HintNoncePrefixLen {
		return hint
	}
	h := sha256.New()
	h.Write(deploymentSecret)
	h.Write(username)
	h.Write(wireNonce[:HintNoncePrefixLen])
	digest := h.Sum(nil)
	copy(hint[:], digest[:HintLen])
	return hint
}

// fnv1a64 computes the 64-bit FNV-1a hash of data using the spec constants.
func fnv1a64(data []byte) uint64 {
	hash := FNV1A64OffsetBasis
	for _, b := range data {
		hash ^= uint64(b)
		hash *= FNV1A64Prime
	}
	return hash
}

// ReplaySig computes the 64-bit replay-cache signature of one message:
// FNV1a64(u32be(inputLen) || byte(domain) || wireNonce[0:24]).
// Domain 1 is UDP client-to-server and domain 2 is UDP server-to-client.
func ReplaySig(inputLen uint32, domain uint8, wireNonce24 []byte) (uint64, error) {
	if len(wireNonce24) != WireNonceLen {
		return 0, fmt.Errorf("nonce length %d is invalid (want %d)", len(wireNonce24), WireNonceLen)
	}
	if domain != replayDomainC2S && domain != replayDomainS2C {
		return 0, fmt.Errorf("unknown replay domain %d", domain)
	}
	msg := make([]byte, 4+1+WireNonceLen)
	binary.BigEndian.PutUint32(msg[:4], inputLen)
	msg[4] = domain
	copy(msg[5:], wireNonce24)
	return fnv1a64(msg), nil
}

// ReplaySigC2S is ReplaySig with the client-to-server domain (1).
func ReplaySigC2S(inputLen uint32, wireNonce24 []byte) (uint64, error) {
	return ReplaySig(inputLen, replayDomainC2S, wireNonce24)
}

// ReplaySigS2C is ReplaySig with the server-to-client domain (2).
func ReplaySigS2C(inputLen uint32, wireNonce24 []byte) (uint64, error) {
	return ReplaySig(inputLen, replayDomainS2C, wireNonce24)
}

// NewAEAD constructs the AEAD for a wire suite and key. The key must be
// exactly suite.KeyLen() bytes. XChaCha20-Poly1305 uses a 24-byte nonce;
// both AES-GCM suites use a 12-byte nonce.
func NewAEAD(suite uint8, key []byte) (cipher.AEAD, error) {
	keyLen, err := SuiteKeyLen(suite)
	if err != nil {
		return nil, err
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("key length %d is invalid for suite %d (want %d)", len(key), suite, keyLen)
	}
	switch suite {
	case SuiteXChaCha20Poly1305:
		return chacha20poly1305.NewX(key)
	case SuiteAes256Gcm, SuiteAes128Gcm:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unknown cipher suite id %d", suite)
	}
}

// AeadNonce derives the AEAD nonce from a 24-byte wire nonce: XChaCha uses
// the full 24 bytes, AES-GCM uses the **last** 12 bytes. The leading 12 bytes
// may be a deterministic traffic pattern and must never reach AES-GCM.
func AeadNonce(wireNonce24 []byte, suite uint8) ([]byte, error) {
	nonceLen, err := SuiteNonceLen(suite)
	if err != nil {
		return nil, err
	}
	if len(wireNonce24) != WireNonceLen {
		return nil, fmt.Errorf("nonce length %d is invalid (want %d)", len(wireNonce24), WireNonceLen)
	}
	return wireNonce24[WireNonceLen-nonceLen:], nil
}

// PayloadNonce derives the wire nonce used to protect a UDP payload: a copy
// of the metadata nonce with byte 16 XORed with 0x01.
func PayloadNonce(wireNonce24 []byte) ([]byte, error) {
	if len(wireNonce24) != WireNonceLen {
		return nil, fmt.Errorf("nonce length %d is invalid (want %d)", len(wireNonce24), WireNonceLen)
	}
	out := make([]byte, WireNonceLen)
	copy(out, wireNonce24)
	out[PayloadNonceIndex] ^= PayloadNonceMask
	return out, nil
}

// Seal encrypts plaintext with the AEAD using the nonce derived from the
// wire nonce and an empty AAD. The result is ciphertext followed by the tag.
func Seal(aead cipher.AEAD, wireNonce24, plaintext []byte) ([]byte, error) {
	nonce, err := AeadNonce(wireNonce24, aeadSuite(aead))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// Open decrypts ciphertext sealed by Seal, authenticating with an empty AAD.
func Open(aead cipher.AEAD, wireNonce24, ciphertext []byte) ([]byte, error) {
	nonce, err := AeadNonce(wireNonce24, aeadSuite(aead))
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

// aeadSuite maps an AEAD instance back to its wire suite identifier by nonce
// size; it is used internally by Seal and Open.
func aeadSuite(aead cipher.AEAD) uint8 {
	switch aead.NonceSize() {
	case WireNonceLen:
		return SuiteXChaCha20Poly1305
	case 12:
		return SuiteAes256Gcm
	default:
		return 255
	}
}

// GenerateX25519 generates a fresh ephemeral X25519 key pair. The private key
// is 32 bytes and the public key is 32 bytes.
func GenerateX25519() (priv, pub []byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key.Bytes(), key.PublicKey().Bytes(), nil
}

// X25519Shared computes the raw X25519 shared secret between a private key and
// a peer public key. All-zero (non-contributory) results from low-order points
// are rejected.
func X25519Shared(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != EphKeyLen {
		return nil, fmt.Errorf("private key length %d is invalid (want %d)", len(priv), EphKeyLen)
	}
	if len(peerPub) != EphKeyLen {
		return nil, fmt.Errorf("peer public key length %d is invalid (want %d)", len(peerPub), EphKeyLen)
	}
	privKey, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	shared, err := privKey.ECDH(peerKey)
	if err != nil {
		return nil, err
	}
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("X25519 shared secret is all zero (peer public key is not usable)")
	}
	return shared, nil
}
