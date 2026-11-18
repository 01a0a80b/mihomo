package shadowlemonwire

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
)

func newTestAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func TestMetadataRoundTrip(t *testing.T) {
	cases := []struct {
		typ uint8
		m   *Metadata
	}{
		{TypeOpenSessionRequest, &Metadata{Type: 2, SessionID: 0x01020304, Seq: 42, PayloadLen: 256, SuffixLen: 7}},
		{TypeOpenSessionResponse, &Metadata{Type: 3, SessionID: 9, Seq: 1, PayloadLen: 1236, SuffixLen: 32}},
		{TypeCloseSessionReq, &Metadata{Type: 4, SessionID: 77, Seq: 0}},
		{TypeCloseSessionResp, &Metadata{Type: 5, SessionID: 77, Seq: 0, SuffixLen: 3}},
		{TypeDataC2S, &Metadata{Type: 6, SessionID: 0x0a0b0c0d, Seq: 256, Unack: 240, Window: 1024, Fragment: 3, PrefixLen: 5, PayloadLen: 2048, SuffixLen: 9}},
		{TypeDataS2C, &Metadata{Type: 7, SessionID: 1, Seq: 2, Unack: 3, Window: 16, Fragment: 0, PrefixLen: 2, PayloadLen: 4, SuffixLen: 1}},
		{TypeAckC2S, &Metadata{Type: 8, SessionID: 1, Unack: 9, Window: 64}},
		{TypeAckS2C, &Metadata{Type: 9, SessionID: 1, Unack: 9, Window: 64, PrefixLen: 1, SuffixLen: 1}},
	}
	for _, tc := range cases {
		raw := MarshalMetadata(tc.m)
		if len(raw) != MetadataLen {
			t.Fatalf("type %d: encoded length %d", tc.typ, len(raw))
		}
		got, err := UnmarshalMetadata(raw)
		if err != nil {
			t.Fatalf("type %d: unmarshal: %v", tc.typ, err)
		}
		if *got != *tc.m {
			t.Errorf("type %d: round trip mismatch: got %+v want %+v", tc.typ, got, tc.m)
		}
	}
}

func TestMetadataGoldenOffsets(t *testing.T) {
	// Golden vectors copied from Rust metadata.rs spec §6.
	session := []byte{
		0x02, 0x00,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x00, 0x00, 0x2a,
		0x01, 0x00,
		0x07,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	m, err := UnmarshalMetadata(session)
	if err != nil {
		t.Fatal(err)
	}
	want := &Metadata{Type: 2, SessionID: 0x01020304, Seq: 42, PayloadLen: 256, SuffixLen: 7}
	if *m != *want {
		t.Fatalf("session golden: got %+v want %+v", m, want)
	}
	if !bytes.Equal(MarshalMetadata(m), session) {
		t.Error("session golden re-encode mismatch")
	}

	data := []byte{
		0x07, 0x00,
		0x0a, 0x0b, 0x0c, 0x0d,
		0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0xf0,
		0x04, 0x00,
		0x03,
		0x05,
		0x08, 0x00,
		0x09,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	m, err = UnmarshalMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	want = &Metadata{Type: 7, SessionID: 0x0a0b0c0d, Seq: 256, Unack: 240, Window: 1024, Fragment: 3, PrefixLen: 5, PayloadLen: 2048, SuffixLen: 9}
	if *m != *want {
		t.Fatalf("data golden: got %+v want %+v", m, want)
	}
	if !bytes.Equal(MarshalMetadata(m), data) {
		t.Error("data golden re-encode mismatch")
	}
}

func TestMetadataReservedAndValidation(t *testing.T) {
	// Reserved bytes are ignored on receive.
	noisy := MarshalMetadata(&Metadata{Type: 2, SessionID: 1, Seq: 2, PayloadLen: 3, SuffixLen: 4})
	noisy[13] = 0xab
	noisy[31] = 0xcd
	if _, err := UnmarshalMetadata(noisy); err != nil {
		t.Fatalf("noisy session: %v", err)
	}

	if _, err := UnmarshalMetadata(make([]byte, 31)); !errors.Is(err, ErrMetadataLength) {
		t.Errorf("short metadata: got %v", err)
	}
	if _, err := UnmarshalMetadata(append([]byte{1}, make([]byte, 31)...)); !errors.Is(err, ErrInvalidProtocolType) {
		t.Errorf("bad type: got %v", err)
	}
	if IsLowEntropy(10) != true || IsLowEntropy(11) != true || IsLowEntropy(9) != false {
		t.Error("IsLowEntropy")
	}
	if _, err := UnmarshalMetadata(append([]byte{10}, make([]byte, 31)...)); !errors.Is(err, ErrLowEntropyDisabled) {
		t.Errorf("low entropy: got %v", err)
	}

	tooLong := MarshalMetadata(&Metadata{Type: 2, PayloadLen: MaxSessionPayload + 1})
	if _, err := UnmarshalMetadata(tooLong); !errors.Is(err, ErrSessionPayloadLong) {
		t.Errorf("session payload limit: got %v", err)
	}
	tooLong = MarshalMetadata(&Metadata{Type: 7, PayloadLen: 0xffff})
	if _, err := UnmarshalMetadata(tooLong); !errors.Is(err, ErrDataPayloadLong) {
		t.Errorf("data payload limit: got %v", err)
	}
}

func TestFrameLen(t *testing.T) {
	m := &Metadata{Type: 7, PrefixLen: 2, PayloadLen: 4, SuffixLen: 1}
	if got := FrameLen(m); got != 24+32+16+2+4+16+1 {
		t.Fatalf("frame len %d", got)
	}
	m = &Metadata{Type: 4, SuffixLen: 3}
	if got := FrameLen(m); got != 24+32+16+3 {
		t.Fatalf("empty payload frame len %d", got)
	}
	if got := PayloadBlockLen(0); got != 0 {
		t.Errorf("empty payload block %d", got)
	}
	if got := PayloadBlockLen(5); got != 21 {
		t.Errorf("payload block %d", got)
	}
}

func TestIncrementNonce(t *testing.T) {
	n := make([]byte, NonceLen)
	for i := range n {
		n[i] = 0x10
	}
	IncrementNonce(n)
	want := make([]byte, NonceLen)
	copy(want, n)
	want[NonceLen-1] = 0x11
	if !bytes.Equal(n, want) {
		t.Fatalf("simple increment: got %x want %x", n, want)
	}

	carry := make([]byte, NonceLen)
	carry[22] = 0xff
	carry[23] = 0xff
	IncrementNonce(carry)
	want = make([]byte, NonceLen)
	want[21] = 1
	if !bytes.Equal(carry, want) {
		t.Fatalf("carry: got %x want %x", carry, want)
	}

	all := bytes.Repeat([]byte{0xff}, NonceLen)
	IncrementNonce(all)
	if !bytes.Equal(all, make([]byte, NonceLen)) {
		t.Fatalf("wrap: got %x", all)
	}
}

func TestPayloadNonce(t *testing.T) {
	n := bytes.Repeat([]byte{0x10}, NonceLen)
	p := PayloadNonce(n)
	if p[PayloadNonceIndex] != 0x11 || p[17] != 0x10 {
		t.Fatalf("payload nonce: %x", p)
	}
	if n[PayloadNonceIndex] != 0x10 {
		t.Fatal("input nonce mutated")
	}
	if PayloadNonce(make([]byte, 4)) != nil {
		t.Error("short nonce should return nil")
	}
}

func TestChoosePadding(t *testing.T) {
	cases := []struct{ min, max, want int }{
		{8, 8, 7},
		{1, 1, 0},
		{0, 0, 0},
		{3, 6, 3},
	}
	for _, tc := range cases {
		got, err := ChoosePadding(tc.min, tc.max, func(int) int { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("ChoosePadding(%d,%d) = %d, want %d", tc.min, tc.max, got, tc.want)
		}
	}
	got, _ := ChoosePadding(3, 6, func(int) int { return 99 })
	if got != 6 {
		t.Errorf("clamping: got %d", got)
	}
	if _, err := ChoosePadding(5, 4, func(int) int { return 0 }); !errors.Is(err, ErrInvalidPaddingRange) {
		t.Errorf("invalid range: %v", err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	aead := newTestAEAD(t)
	nonce := bytes.Repeat([]byte{0x42}, NonceLen)
	cases := []struct {
		m      *Metadata
		prefix []byte
		body   []byte
		suffix []byte
	}{
		{
			m:      &Metadata{Type: 7, SessionID: 0x01020304, Seq: 7, Unack: 3, Window: 16, Fragment: 0, PrefixLen: 2, PayloadLen: 4, SuffixLen: 1},
			prefix: []byte{0x11, 0x22},
			body:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
			suffix: []byte{0x33},
		},
		{
			m:      &Metadata{Type: 4, SessionID: 1, Seq: 2, SuffixLen: 3},
			suffix: []byte{0x77, 0x77, 0x77},
		},
		{
			m:      &Metadata{Type: 6, SessionID: 9, Seq: 1, Unack: 2, Window: 8, Fragment: 255, PrefixLen: 32, PayloadLen: 1236, SuffixLen: 32},
			prefix: bytes.Repeat([]byte{0x5a}, 32),
			body:   bytes.Repeat([]byte{0xab}, 1236),
			suffix: bytes.Repeat([]byte{0xa5}, 32),
		},
	}
	for _, tc := range cases {
		frame, err := SealSegment(aead, aead, tc.m, tc.body, tc.prefix, tc.suffix, nonce)
		if err != nil {
			t.Fatalf("seal type %d: %v", tc.m.Type, err)
		}
		if len(frame) != FrameLen(tc.m) {
			t.Errorf("type %d: frame length %d want %d", tc.m.Type, len(frame), FrameLen(tc.m))
		}
		gotMeta, gotBody, err := OpenSegment(aead, aead, frame)
		if err != nil {
			t.Fatalf("open type %d: %v", tc.m.Type, err)
		}
		if *gotMeta != *tc.m || !bytes.Equal(gotBody, tc.body) {
			t.Errorf("type %d mismatch: meta %+v body len %d", tc.m.Type, gotMeta, len(gotBody))
		}

		// A single extra or missing byte must be rejected.
		if _, _, err := OpenSegment(aead, aead, append(append([]byte{}, frame...), 0)); !errors.Is(err, ErrFrameLengthMismatch) {
			t.Errorf("type %d: extra byte: %v", tc.m.Type, err)
		}
		if _, _, err := OpenSegment(aead, aead, frame[:len(frame)-1]); !errors.Is(err, ErrFrameLengthMismatch) {
			t.Errorf("type %d: missing byte: %v", tc.m.Type, err)
		}
	}
}

func TestSealOpenRejectsBadInputs(t *testing.T) {
	aead := newTestAEAD(t)
	nonce := bytes.Repeat([]byte{0x42}, NonceLen)
	m := &Metadata{Type: 7, SessionID: 1, PrefixLen: 1, PayloadLen: 2, SuffixLen: 1}

	if _, err := SealSegment(aead, aead, m, []byte{1, 2}, nil, []byte{3}, nonce); !errors.Is(err, ErrPaddingLength) {
		t.Errorf("prefix mismatch: %v", err)
	}
	if _, err := SealSegment(aead, aead, m, []byte{1}, []byte{0}, []byte{3}, nonce); !errors.Is(err, ErrPayloadLength) {
		t.Errorf("payload mismatch: %v", err)
	}
	if _, err := SealSegment(aead, aead, &Metadata{Type: 10}, nil, nil, nil, nonce); !errors.Is(err, ErrLowEntropyDisabled) {
		t.Errorf("low entropy seal: %v", err)
	}
	if _, _, err := OpenSegment(aead, aead, []byte{1, 2, 3}); !errors.Is(err, ErrFrameTooShort) {
		t.Errorf("short frame: %v", err)
	}

	frame, err := SealSegment(aead, aead, m, []byte{1, 2}, []byte{0}, []byte{3}, nonce)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the metadata tag.
	bad := append([]byte{}, frame...)
	bad[24+32] ^= 0xff
	if _, _, err := OpenSegment(aead, aead, bad); err == nil {
		t.Error("tampered metadata tag accepted")
	}
	// Tamper with the payload ciphertext.
	bad = append([]byte{}, frame...)
	bad[NonceAndMetaLen+1] ^= 0xff
	if _, _, err := OpenSegment(aead, aead, bad); err == nil {
		t.Error("tampered payload accepted")
	}
}

// TestAESNonceUsesTrailingBytes pins that AES-GCM uses the last 12 bytes of the
// 24-byte wire nonce, not the first 12 (which may be a deterministic pattern).
func TestAESNonceUsesTrailingBytes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	aead, err := crypto.NewAEAD(crypto.SuiteAes256Gcm, key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, NonceLen)
	for i := range nonce {
		nonce[i] = byte(0x80 + i)
	}
	plaintext := []byte("nonce-check")
	got, err := aeadSeal(aead, nonce, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wantTail := aead.Seal(nil, nonce[12:], plaintext, nil)
	wantHead := aead.Seal(nil, nonce[:12], plaintext, nil)
	if !bytes.Equal(got, wantTail) {
		t.Fatal("AES-GCM must use the trailing 12 bytes of the wire nonce")
	}
	if bytes.Equal(got, wantHead) {
		t.Fatal("AES-GCM must not use the leading 12 bytes of the wire nonce")
	}
}
