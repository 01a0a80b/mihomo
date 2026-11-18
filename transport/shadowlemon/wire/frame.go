package shadowlemonwire

import (
	"crypto/cipher"
	"fmt"
)

// aeadNonce derives the native AEAD nonce from a 24-byte wire nonce. XChaCha
// consumes all 24 bytes; AES-GCM consumes the last 12 bytes. Using the first
// 12 bytes would break interoperability: those bytes may carry a deterministic
// pattern and are not the AEAD nonce.
func aeadNonce(aead cipher.AEAD, nonce []byte) ([]byte, error) {
	n := aead.NonceSize()
	if len(nonce) < n {
		return nil, ErrAEADNonce
	}
	return nonce[len(nonce)-n:], nil
}

func aeadSeal(aead cipher.AEAD, nonce, plaintext []byte) ([]byte, error) {
	n, err := aeadNonce(aead, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, n, plaintext, nil), nil
}

func aeadOpen(aead cipher.AEAD, nonce, ciphertext []byte) ([]byte, error) {
	n, err := aeadNonce(aead, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, n, ciphertext, nil)
}

// SealSegment builds a complete wire frame:
//
//	[nonce 24] [encrypted meta 32] [meta tag 16] [padding1] [payload] [tag 16] [padding2]
//
// metaAEAD is used with nonce; payloadAEAD is used with PayloadNonce(nonce).
// prefixPad and suffixPad lengths must match meta.PrefixLen/meta.SuffixLen,
// and len(payload) must match meta.PayloadLen. An empty payload produces no
// payload tag, matching the Rust encoder. Low-entropy types are rejected.
func SealSegment(metaAEAD, payloadAEAD cipher.AEAD, meta *Metadata, payload, prefixPad, suffixPad []byte, nonce []byte) ([]byte, error) {
	if meta == nil {
		return nil, fmt.Errorf("shadowlemonwire: nil metadata")
	}
	if err := meta.validate(); err != nil {
		return nil, err
	}
	if len(nonce) != NonceLen {
		return nil, fmt.Errorf("shadowlemonwire: nonce length %d, want %d", len(nonce), NonceLen)
	}
	if len(prefixPad) != int(meta.PrefixLen) {
		return nil, fmt.Errorf("%w: prefix declared %d, actual %d", ErrPaddingLength, meta.PrefixLen, len(prefixPad))
	}
	if len(suffixPad) != int(meta.SuffixLen) {
		return nil, fmt.Errorf("%w: suffix declared %d, actual %d", ErrPaddingLength, meta.SuffixLen, len(suffixPad))
	}
	if len(payload) != int(meta.PayloadLen) {
		return nil, fmt.Errorf("%w: declared %d, actual %d", ErrPayloadLength, meta.PayloadLen, len(payload))
	}

	metaPlain := MarshalMetadata(meta)
	metaSealed, err := aeadSeal(metaAEAD, nonce, metaPlain)
	if err != nil {
		return nil, err
	}
	if len(metaSealed) != MetaBlockLen {
		return nil, fmt.Errorf("shadowlemonwire: metadata ciphertext length %d, want %d", len(metaSealed), MetaBlockLen)
	}

	var payloadBlock []byte
	if len(payload) > 0 {
		payloadBlock, err = aeadSeal(payloadAEAD, PayloadNonce(nonce), payload)
		if err != nil {
			return nil, err
		}
		if len(payloadBlock) != len(payload)+TagLen {
			return nil, fmt.Errorf("shadowlemonwire: payload ciphertext length %d, want %d", len(payloadBlock), len(payload)+TagLen)
		}
	}

	frame := make([]byte, 0, FrameLen(meta))
	frame = append(frame, nonce...)
	frame = append(frame, metaSealed...)
	frame = append(frame, prefixPad...)
	frame = append(frame, payloadBlock...)
	frame = append(frame, suffixPad...)
	return frame, nil
}

// OpenSegment decrypts and parses a complete wire frame. The total frame
// length must exactly match the length declared in the metadata; a single
// byte too many or too few is rejected. The function never panics on
// attacker-controlled input.
func OpenSegment(metaAEAD, payloadAEAD cipher.AEAD, frame []byte) (meta *Metadata, payload []byte, err error) {
	if len(frame) < NonceAndMetaLen {
		return nil, nil, fmt.Errorf("%w: got %d, want at least %d", ErrFrameTooShort, len(frame), NonceAndMetaLen)
	}
	nonce := frame[:NonceLen]
	metaPlain, err := aeadOpen(metaAEAD, nonce, frame[NonceLen:NonceAndMetaLen])
	if err != nil {
		return nil, nil, err
	}
	meta, err = UnmarshalMetadata(metaPlain)
	if err != nil {
		return nil, nil, err
	}

	want := FrameLen(meta)
	if len(frame) != want {
		return nil, nil, fmt.Errorf("%w: declared %d, actual %d", ErrFrameLengthMismatch, want, len(frame))
	}

	at := NonceAndMetaLen
	at += int(meta.PrefixLen)
	blockLen := PayloadBlockLen(int(meta.PayloadLen))
	payloadBlock := frame[at : at+blockLen]

	if blockLen == 0 {
		return meta, []byte{}, nil
	}
	payload, err = aeadOpen(payloadAEAD, PayloadNonce(nonce), payloadBlock)
	if err != nil {
		return nil, nil, err
	}
	if len(payload) != int(meta.PayloadLen) {
		return nil, nil, fmt.Errorf("%w: declared %d, actual %d", ErrPayloadLength, meta.PayloadLen, len(payload))
	}
	return meta, payload, nil
}
