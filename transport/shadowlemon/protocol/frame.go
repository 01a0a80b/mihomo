package shadowlemonprotocol

import (
	"crypto/cipher"
	"fmt"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
	wire "github.com/metacubex/mihomo/transport/shadowlemon/wire"
)

// sealFrame builds a V0.2 wire frame exactly like Rust's encode_segment: the
// metadata and payload are sealed with crypto.Seal, which derives the AEAD
// nonce from the full 24-byte wire nonce (XChaCha) or its LAST 12 bytes
// (AES-GCM). The Go wire package uses the FIRST 12 bytes for AES-GCM, so it
// cannot be used here without breaking Rust interoperability.
//
// Layout: [nonce 24][encrypted meta 32 + tag 16][prefix][payload + tag][suffix].
func sealV2Frame(metaAEAD, payloadAEAD cipher.AEAD, meta *wire.Metadata, payload, prefix, suffix, nonce []byte) ([]byte, error) {
	if len(nonce) != wire.NonceLen {
		return nil, fmt.Errorf("shadowlemon: nonce length %d", len(nonce))
	}
	if len(prefix) != int(meta.PrefixLen) || len(suffix) != int(meta.SuffixLen) {
		return nil, wire.ErrPaddingLength
	}
	if len(payload) != int(meta.PayloadLen) {
		return nil, wire.ErrPayloadLength
	}
	if int(meta.PayloadLen) > wire.MaxSessionPayload && meta.Type >= 2 && meta.Type <= 5 {
		return nil, wire.ErrSessionPayloadLong
	}
	if int(meta.PayloadLen) > wire.MaxFragment && meta.Type >= 6 && meta.Type <= 9 {
		return nil, wire.ErrDataPayloadLong
	}
	if wire.IsLowEntropy(meta.Type) {
		return nil, wire.ErrLowEntropyDisabled
	}
	metaPlain := wire.MarshalMetadata(meta)
	metaSealed, err := crypto.Seal(metaAEAD, nonce, metaPlain)
	if err != nil {
		return nil, err
	}
	var payloadBlock []byte
	if len(payload) > 0 {
		payloadNonce, err := crypto.PayloadNonce(nonce)
		if err != nil {
			return nil, err
		}
		payloadBlock, err = crypto.Seal(payloadAEAD, payloadNonce, payload)
		if err != nil {
			return nil, err
		}
	}
	frame := make([]byte, 0, wire.FrameLen(meta))
	frame = append(frame, nonce...)
	frame = append(frame, metaSealed...)
	frame = append(frame, prefix...)
	frame = append(frame, payloadBlock...)
	frame = append(frame, suffix...)
	return frame, nil
}

// openFrame is the inverse of sealFrame. It never panics on attacker input.
func openV2Frame(metaAEAD, payloadAEAD cipher.AEAD, frame []byte) (*wire.Metadata, []byte, error) {
	if len(frame) < wire.NonceAndMetaLen {
		return nil, nil, wire.ErrFrameTooShort
	}
	nonce := frame[:wire.NonceLen]
	metaPlain, err := crypto.Open(metaAEAD, nonce, frame[wire.NonceLen:wire.NonceAndMetaLen])
	if err != nil {
		return nil, nil, err
	}
	meta, err := wire.UnmarshalMetadata(metaPlain)
	if err != nil {
		return nil, nil, err
	}
	want := wire.FrameLen(meta)
	if len(frame) != want {
		return nil, nil, fmt.Errorf("%w: declared %d, actual %d", wire.ErrFrameLengthMismatch, want, len(frame))
	}
	at := wire.NonceAndMetaLen + int(meta.PrefixLen)
	blockLen := wire.PayloadBlockLen(int(meta.PayloadLen))
	payloadBlock := frame[at : at+blockLen]
	if blockLen == 0 {
		return meta, []byte{}, nil
	}
	payloadNonce, err := crypto.PayloadNonce(nonce)
	if err != nil {
		return nil, nil, err
	}
	payload, err := crypto.Open(payloadAEAD, payloadNonce, payloadBlock)
	if err != nil {
		return nil, nil, err
	}
	return meta, payload, nil
}
