package shadowlemoncrypto

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestConstants(t *testing.T) {
	if ProtocolVersion != 4 {
		t.Fatalf("version = %d, want 4", ProtocolVersion)
	}
	if SuiteKeyLenForTest(SuiteXChaCha20Poly1305) != 32 ||
		SuiteKeyLenForTest(SuiteAes256Gcm) != 32 ||
		SuiteKeyLenForTest(SuiteAes128Gcm) != 16 {
		t.Fatal("suite key lengths")
	}
}

// SuiteKeyLenForTest just wraps SuiteKeyLen into a plain int for the test.
func SuiteKeyLenForTest(suite uint8) int {
	n, _ := SuiteKeyLen(suite)
	return n
}

func TestHashPassword(t *testing.T) {
	// SHA256("password" || 0x00 || "alice")
	want := "1667598d5eb7956356b4ce60f60a2d2c43c34e994760b8855ac579cdefb4fc89"
	got := CredentialFromPassword("password", "alice")
	if hex.EncodeToString(got) != want {
		t.Fatalf("credential = %x, want %s", got, want)
	}
	// The byte-slice form must agree.
	got2 := HashPassword([]byte("password"), []byte("alice"))
	if !bytes.Equal(got, got2) {
		t.Fatal("HashPassword and CredentialFromPassword disagree")
	}
}

func TestDeriveStaticKey(t *testing.T) {
	cred := mustHex(t, "1667598d5eb7956356b4ce60f60a2d2c43c34e994760b8855ac579cdefb4fc89")
	want32 := "ca297d3c97611700b97323e846a309ea0771a0885c7c261fb0c580175fb9c68b"
	want16 := "ca297d3c97611700b97323e846a309ea"

	k32, err := DeriveStaticKey(cred, SuiteAes256Gcm)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k32) != want32 {
		t.Fatalf("static key(32) = %x, want %s", k32, want32)
	}
	k16, err := DeriveStaticKey(cred, SuiteAes128Gcm)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k16) != want16 {
		t.Fatalf("static key(16) = %x, want %s", k16, want16)
	}
	// Suite 0 and suite 1 share the full 32 bytes.
	k0, err := DeriveStaticKey(cred, SuiteXChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k0, k32) {
		t.Fatal("suite 0 and suite 1 static keys differ")
	}
	// Truncation must be a strict prefix.
	if !bytes.Equal(k16, k32[:16]) {
		t.Fatal("aes-128 key is not the prefix of aes-256 key")
	}
	// Bad credential length.
	if _, err := DeriveStaticKey([]byte{1, 2, 3}, SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for short credential")
	}
}

func TestStaticKeySalt(t *testing.T) {
	want := "84f639c5046c5b169311f5657ff659b2f8646e4816ea863167ce13369c9429fe"
	if got := hex.EncodeToString(staticKeySalt()); got != want {
		t.Fatalf("static key salt = %s, want %s", got, want)
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	staticKey := mustHex(t, "ca297d3c97611700b97323e846a309ea0771a0885c7c261fb0c580175fb9c68b")
	clientSalt := bytes.Repeat([]byte{0x01}, 16)
	serverSalt := bytes.Repeat([]byte{0x02}, 16)
	shared := bytes.Repeat([]byte{0x07}, 32)

	c2s, s2c, err := DeriveSessionKeys(staticKey, clientSalt, serverSalt, shared, SuiteXChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	wantC2S := "cc41f77200cf8f513c476c65c66210a6e8259433b550e42200970561946428e3"
	wantS2C := "b7a90a272fb39cb7ee83f1aae9fa863fb99ef30819b0ddfeeb1696316921e306"
	if hex.EncodeToString(c2s) != wantC2S {
		t.Fatalf("c2s = %x, want %s", c2s, wantC2S)
	}
	if hex.EncodeToString(s2c) != wantS2C {
		t.Fatalf("s2c = %x, want %s", s2c, wantS2C)
	}
	if bytes.Equal(c2s, s2c) {
		t.Fatal("directional keys must differ")
	}
	// Determinism.
	c2s2, s2c2, _ := DeriveSessionKeys(staticKey, clientSalt, serverSalt, shared, SuiteXChaCha20Poly1305)
	if !bytes.Equal(c2s, c2s2) || !bytes.Equal(s2c, s2c2) {
		t.Fatal("session keys are not deterministic")
	}
	// Suite 2 produces a 16-byte key.
	c2s128, _, err := DeriveSessionKeys(staticKey, clientSalt, serverSalt, shared, SuiteAes128Gcm)
	if err != nil {
		t.Fatal(err)
	}
	if len(c2s128) != 16 {
		t.Fatalf("aes-128 session key length = %d, want 16", len(c2s128))
	}
	// Changing the version byte in info must change the key (v3 vs v4).
	// We exercise this by directly expanding with a v3 info string.
	v3Info := append([]byte("ShadowLemon V0.2 c2s"), 3, SuiteXChaCha20Poly1305)
	h := newSHA256()
	h.Write(staticKey)
	h.Write(clientSalt)
	h.Write(serverSalt)
	salt := h.Sum(nil)
	v3Key, err := hkdfSha256(shared, salt, v3Info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(v3Key, c2s) {
		t.Fatal("version byte not bound into HKDF info")
	}
	// Bad inputs.
	if _, _, err := DeriveSessionKeys(nil, clientSalt, serverSalt, shared, SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for empty static key")
	}
	if _, _, err := DeriveSessionKeys(staticKey, clientSalt[:15], serverSalt, shared, SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for short client salt")
	}
	longServerSalt := append(append([]byte(nil), serverSalt...), 0x03)
	if _, _, err := DeriveSessionKeys(staticKey, clientSalt, longServerSalt, shared, SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for long server salt")
	}
	if _, _, err := DeriveSessionKeys(staticKey, clientSalt, serverSalt, shared[:31], SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for short shared secret")
	}
}

func TestDeriveEarlyKeys(t *testing.T) {
	staticKey := mustHex(t, "ca297d3c97611700b97323e846a309ea0771a0885c7c261fb0c580175fb9c68b")
	c2s, s2c, err := DeriveEarlyKeys(staticKey, 0x01020304, SuiteXChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	wantC2S := "e33f0ed0ab2da1ff9cbf4eac8608fb2827386846d3804a797b4c5d5baacc1981"
	wantS2C := "6c09ca150f1e0a487a8f5c866b523e698f1fd50f0702e5b8b415219ad68d2ce7"
	if hex.EncodeToString(c2s) != wantC2S {
		t.Fatalf("early c2s = %x, want %s", c2s, wantC2S)
	}
	if hex.EncodeToString(s2c) != wantS2C {
		t.Fatalf("early s2c = %x, want %s", s2c, wantS2C)
	}
	// Session id binding.
	c2s2, _, _ := DeriveEarlyKeys(staticKey, 0x01020305, SuiteXChaCha20Poly1305)
	if bytes.Equal(c2s, c2s2) {
		t.Fatal("early keys must bind the session id")
	}
	// Different from X25519 session keys.
	skC2S, _, _ := DeriveSessionKeys(staticKey, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{7}, 32), SuiteXChaCha20Poly1305)
	if bytes.Equal(c2s, skC2S) {
		t.Fatal("early and session keys must differ")
	}
	// Bad inputs.
	if _, _, err := DeriveEarlyKeys(nil, 1, SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for empty static key")
	}
	if _, _, err := DeriveEarlyKeys(make([]byte, 33), 1, SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for overlong static key")
	}
}

func TestDeploymentSecret(t *testing.T) {
	old, had := lookupEnv(EnvelopeSecretEnv)
	defer func() {
		if had {
			setEnv(EnvelopeSecretEnv, old)
		} else {
			unsetEnv(EnvelopeSecretEnv)
		}
	}()

	unsetEnv(EnvelopeSecretEnv)
	if _, err := DeploymentSecret(); err == nil {
		t.Fatal("expected error when secret is unset")
	}
	setEnv(EnvelopeSecretEnv, "")
	if _, err := DeploymentSecret(); err == nil {
		t.Fatal("expected error when secret is empty")
	}
	setEnv(EnvelopeSecretEnv, "test-deployment-secret")
	got, err := DeploymentSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "test-deployment-secret" {
		t.Fatalf("secret = %q", got)
	}
}

func TestUserHint(t *testing.T) {
	secret := []byte("test-deployment-secret")
	nonce := bytes.Repeat([]byte{0x11}, 24)
	want := "f7ffe585"
	got := UserHint(secret, []byte("alice"), nonce)
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("hint = %x, want %s", got, want)
	}
	// Definition check: first four bytes of SHA256(secret||user||nonce[:16]).
	h := newSHA256()
	h.Write(secret)
	h.Write([]byte("alice"))
	h.Write(nonce[:16])
	digest := h.Sum(nil)
	if !bytes.Equal(got[:], digest[:4]) {
		t.Fatal("hint does not match SHA256 definition")
	}
	// Binds to nonce prefix only: changing byte 20 has no effect.
	nonce2 := append([]byte(nil), nonce...)
	nonce2[20] = 9
	got2 := UserHint(secret, []byte("alice"), nonce2)
	if got != got2 {
		t.Fatal("hint must not depend on nonce bytes beyond index 15")
	}
	nonce3 := append([]byte(nil), nonce...)
	nonce3[0] = 9
	got3 := UserHint(secret, []byte("alice"), nonce3)
	if got == got3 {
		t.Fatal("hint must bind to nonce prefix")
	}
	// Different user yields different hint.
	if got == UserHint(secret, []byte("bob"), nonce) {
		t.Fatal("hint must bind to username")
	}
}

func TestFNV1A64(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{"", 0xcbf29ce484222325},
		{"a", 0xaf63dc4c8601ec8c},
		{"foobar", 0x85944171f73967e8},
	}
	for _, tt := range tests {
		if got := fnv1a64([]byte(tt.in)); got != tt.want {
			t.Fatalf("fnv1a64(%q) = %016x, want %016x", tt.in, got, tt.want)
		}
	}
}

func TestReplaySig(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, 24)
	// Published golden vector: m = u32be(72) || 0x01 || 0x42*24.
	got, err := ReplaySigC2S(72, nonce)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(0x4bd6ad18f9578274)
	if got != want {
		t.Fatalf("replay sig = %016x, want %016x", got, want)
	}
	// Direct form agrees.
	got2, err := ReplaySig(72, 1, nonce)
	if err != nil || got2 != got {
		t.Fatalf("ReplaySig = %016x, err=%v", got2, err)
	}
	// Domain and length separation.
	s2c, _ := ReplaySigS2C(72, nonce)
	if got == s2c {
		t.Fatal("replay sig must separate domains")
	}
	otherLen, _ := ReplaySigC2S(73, nonce)
	if got == otherLen {
		t.Fatal("replay sig must separate lengths")
	}
	changed := append([]byte(nil), nonce...)
	changed[23] ^= 1
	otherNonce, _ := ReplaySigC2S(72, changed)
	if got == otherNonce {
		t.Fatal("replay sig must bind the full nonce")
	}
	// Bad inputs.
	if _, err := ReplaySigC2S(72, nonce[:23]); err == nil {
		t.Fatal("expected error for short nonce")
	}
	if _, err := ReplaySig(72, 3, nonce); err == nil {
		t.Fatal("expected error for unknown domain")
	}
}

func TestNewAEADAndKeyLengths(t *testing.T) {
	for _, suite := range []uint8{SuiteXChaCha20Poly1305, SuiteAes256Gcm, SuiteAes128Gcm} {
		keyLen, _ := SuiteKeyLen(suite)
		aead, err := NewAEAD(suite, bytes.Repeat([]byte{0x03}, keyLen))
		if err != nil {
			t.Fatalf("suite %d: %v", suite, err)
		}
		wantNonce, _ := SuiteNonceLen(suite)
		if aead.NonceSize() != wantNonce {
			t.Fatalf("suite %d nonce size = %d, want %d", suite, aead.NonceSize(), wantNonce)
		}
		if aead.Overhead() != TagLen {
			t.Fatalf("suite %d tag = %d, want %d", suite, aead.Overhead(), TagLen)
		}
		if _, err := NewAEAD(suite, []byte{1, 2, 3}); err == nil {
			t.Fatalf("suite %d: expected error for bad key length", suite)
		}
	}
	if _, err := NewAEAD(99, make([]byte, 32)); err == nil {
		t.Fatal("expected error for unknown suite")
	}
}

func TestAeadNonceSelection(t *testing.T) {
	wire := bytes.Repeat([]byte{0xAA}, 24)
	copy(wire, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})

	// AES uses the LAST twelve bytes.
	for _, suite := range []uint8{SuiteAes256Gcm, SuiteAes128Gcm} {
		nonce, err := AeadNonce(wire, suite)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(nonce, wire[12:24]) {
			t.Fatalf("suite %d: AES nonce = %x, want last 12 bytes %x", suite, nonce, wire[12:24])
		}
		if bytes.Equal(nonce, wire[:12]) {
			t.Fatalf("suite %d: AES nonce must not be the first 12 bytes", suite)
		}
	}
	// XChaCha uses all 24 bytes.
	nonce, err := AeadNonce(wire, SuiteXChaCha20Poly1305)
	if err != nil || !bytes.Equal(nonce, wire) {
		t.Fatalf("xchacha nonce = %x, err=%v", nonce, err)
	}
	// Bad inputs.
	if _, err := AeadNonce(wire[:23], SuiteAes256Gcm); err == nil {
		t.Fatal("expected error for short wire nonce")
	}
	if _, err := AeadNonce(wire, 99); err == nil {
		t.Fatal("expected error for unknown suite")
	}
}

func TestPayloadNonce(t *testing.T) {
	metadata := bytes.Repeat([]byte{0x10}, 24)
	out, err := PayloadNonce(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if out[16] != 0x11 {
		t.Fatalf("byte 16 = %02x, want 0x11", out[16])
	}
	if !bytes.Equal(out[:16], metadata[:16]) || !bytes.Equal(out[17:], metadata[17:]) {
		t.Fatal("payload nonce must only flip byte 16")
	}
	// Flipping twice restores the original.
	back, _ := PayloadNonce(out)
	if !bytes.Equal(back, metadata) {
		t.Fatal("double flip must restore metadata nonce")
	}
	// Input must not be modified.
	if metadata[16] != 0x10 {
		t.Fatal("PayloadNonce mutated its input")
	}
	if _, err := PayloadNonce(metadata[:23]); err == nil {
		t.Fatal("expected error for short nonce")
	}
}

func TestSealOpenRoundTripAndNonceUsage(t *testing.T) {
	for _, suite := range []uint8{SuiteXChaCha20Poly1305, SuiteAes256Gcm, SuiteAes128Gcm} {
		keyLen, _ := SuiteKeyLen(suite)
		aead, _ := NewAEAD(suite, bytes.Repeat([]byte{0x05}, keyLen))
		wire := bytes.Repeat([]byte{0x42}, 24)
		ct, err := Seal(aead, wire, []byte("payload"))
		if err != nil {
			t.Fatalf("suite %d seal: %v", suite, err)
		}
		if len(ct) != len("payload")+TagLen {
			t.Fatalf("suite %d ciphertext length = %d", suite, len(ct))
		}
		pt, err := Open(aead, wire, ct)
		if err != nil {
			t.Fatalf("suite %d open: %v", suite, err)
		}
		if !bytes.Equal(pt, []byte("payload")) {
			t.Fatalf("suite %d plaintext = %q", suite, pt)
		}
		// Tampering is detected.
		bad := append([]byte(nil), ct...)
		bad[0] ^= 1
		if _, err := Open(aead, wire, bad); err == nil {
			t.Fatalf("suite %d: tampered ciphertext accepted", suite)
		}
	}

	// Changing only the leading 12 wire bytes must not affect AES-GCM, but
	// must change XChaCha20-Poly1305.
	key := bytes.Repeat([]byte{0x03}, 32)
	aes, _ := NewAEAD(SuiteAes256Gcm, key)
	xchacha, _ := NewAEAD(SuiteXChaCha20Poly1305, key)
	a := bytes.Repeat([]byte{0x09}, 24)
	b := append([]byte(nil), a...)
	b[0] ^= 0xff
	aesA, _ := Seal(aes, a, []byte("msg"))
	aesB, _ := Seal(aes, b, []byte("msg"))
	if !bytes.Equal(aesA, aesB) {
		t.Fatal("AES-GCM must depend only on the last 12 wire bytes")
	}
	xA, _ := Seal(xchacha, a, []byte("msg"))
	xB, _ := Seal(xchacha, b, []byte("msg"))
	if bytes.Equal(xA, xB) {
		t.Fatal("XChaCha20-Poly1305 must use all 24 wire bytes")
	}
}

// AES-GCM NIST test case 13 (empty plaintext) via the wire-nonce (last-12)
// convention. Key and IV are all zero; wire nonce has 0xAA in the first 12.
func TestAESGCMGoldenVector(t *testing.T) {
	wire := append(bytes.Repeat([]byte{0xAA}, 12), make([]byte, 12)...)
	aead, err := NewAEAD(SuiteAes256Gcm, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Seal(aead, wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "530f8afbc74536b9a963b4f1c4cb738b"
	if hex.EncodeToString(ct) != want {
		t.Fatalf("AES-256-GCM empty = %x, want %s", ct, want)
	}
	pt, err := Open(aead, wire, ct)
	if err != nil || len(pt) != 0 {
		t.Fatalf("open failed: %v, %x", err, pt)
	}

	// AES-128-GCM NIST case 13.
	aead128, err := NewAEAD(SuiteAes128Gcm, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	ct128, err := Seal(aead128, wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	want128 := "58e2fccefa7e3061367f1d57a4e7455a"
	if hex.EncodeToString(ct128) != want128 {
		t.Fatalf("AES-128-GCM empty = %x, want %s", ct128, want128)
	}
}

func TestGenerateX25519(t *testing.T) {
	privA, pubA, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	privB, pubB, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	if len(privA) != 32 || len(pubA) != 32 || len(privB) != 32 || len(pubB) != 32 {
		t.Fatal("key lengths")
	}
	if bytes.Equal(pubA, pubB) {
		t.Fatal("generated public keys must differ")
	}
	sharedA, err := X25519Shared(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	sharedB, err := X25519Shared(privB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedA, sharedB) {
		t.Fatal("X25519 shared secrets must agree")
	}
	if len(sharedA) != 32 {
		t.Fatal("shared secret length")
	}
}

func TestX25519SharedGoldenVector(t *testing.T) {
	// RFC 7748 section 6.1, Alice and Bob.
	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPub := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	want := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	shared, err := X25519Shared(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(shared) != want {
		t.Fatalf("shared = %x, want %s", shared, want)
	}
	// The exchanged public key derived from alicePriv must match RFC.
	// (ecdh derives it from the private bytes.)
	key, err := ecdhFromPrivate(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(key, alicePub) {
		t.Fatalf("alice public = %x, want %x", key, alicePub)
	}
}

func TestX25519RejectsLowOrderPoint(t *testing.T) {
	priv := mustHex(t, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	if _, err := X25519Shared(priv, make([]byte, 32)); err == nil {
		t.Fatal("expected error for low-order point")
	}
	if _, err := X25519Shared(priv[:31], make([]byte, 32)); err == nil {
		t.Fatal("expected error for short private key")
	}
}

// TestDoubleHashCredentialMatchesRust pins the credential path used by the
// Rust peers: the server stores SHA256(password || 0x00 || username) and its
// derive_static_key() hashes that value once more before PBKDF2. The Rust
// client follows the same path, so a Go peer must reproduce the double hash
// to authenticate against either side.
func TestDoubleHashCredentialMatchesRust(t *testing.T) {
	cred := CredentialFromPasswordDouble("password1", "user1")
	sk, err := DeriveStaticKey(cred, SuiteXChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	want := "bb10a96b217d76184ff17e5acfb447e54bde715e27fdad250e3f3e9d1cc760b6"
	if got := hex.EncodeToString(sk); got != want {
		t.Fatalf("double-hash static key = %s, want %s", got, want)
	}
}
