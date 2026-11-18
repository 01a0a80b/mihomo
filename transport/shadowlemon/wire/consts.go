// Package shadowlemonwire implements the byte-level framing of ShadowLemon
// V0.2 (wire version 4) as specified by rust/docs/protocol-v0.2.md and the
// authoritative Rust crate shadowlemon-wire. It performs pure byte encoding
// and decoding: confidentiality and integrity are delegated to the AEAD
// instances supplied by the caller.
package shadowlemonwire

import "errors"

const (
	// NonceLen is the length of the wire nonce carried by every segment.
	NonceLen = 24
	// MetadataLen is the exact plaintext metadata length.
	MetadataLen = 32
	// TagLen is the AEAD authentication tag length for every supported suite.
	TagLen = 16

	// MaxSessionPayload is the maximum payload length in session metadata
	// (types 2-5), excluding the AEAD tag.
	MaxSessionPayload = 1236
	// MaxFragment is the maximum application fragment length in data metadata
	// (types 6-11), excluding the AEAD tag.
	MaxFragment = 32768

	// MaxPrefixPadding and MaxSuffixPadding bound the padding length fields.
	MaxPrefixPadding = 32
	MaxSuffixPadding = 32

	// UdpRoutingEnvelopeLen is the length of the UDP routing envelope that
	// precedes a wire frame in UDP datagrams.
	UdpRoutingEnvelopeLen = 5
	// MaxFragmentNumber is the highest fragment number (counting down to zero).
	MaxFragmentNumber = 255

	// PayloadNonceIndex is the wire nonce byte flipped to derive the payload
	// nonce. PayloadNonceMask is the value XORed into that byte.
	PayloadNonceIndex = 16
	PayloadNonceMask  = 0x01

	// META_LEN is the length of encrypted metadata plus its tag (32 + 16).
	MetaBlockLen = MetadataLen + TagLen
	// NonceAndMetaLen is the fixed prefix of a frame that carries a nonce.
	NonceAndMetaLen = NonceLen + MetaBlockLen
)

// Protocol types.
const (
	TypeOpenSessionRequest  uint8 = 2
	TypeOpenSessionResponse uint8 = 3
	TypeCloseSessionReq     uint8 = 4
	TypeCloseSessionResp    uint8 = 5
	TypeDataC2S             uint8 = 6
	TypeDataS2C             uint8 = 7
	TypeAckC2S              uint8 = 8
	TypeAckS2C              uint8 = 9
	TypeLowEntropyC2S       uint8 = 10
	TypeLowEntropyS2C       uint8 = 11
)

// IsLowEntropy reports whether t is one of the low-entropy protocol types.
// The Go implementation recognizes these types but does not encode or decode
// their bodies.
func IsLowEntropy(t uint8) bool {
	return t == TypeLowEntropyC2S || t == TypeLowEntropyS2C
}

var (
	ErrMetadataLength      = errors.New("shadowlemonwire: metadata plaintext length is not 32")
	ErrInvalidProtocolType = errors.New("shadowlemonwire: invalid protocol type")
	ErrSessionPayloadLong  = errors.New("shadowlemonwire: session payload longer than 1236")
	ErrDataPayloadLong     = errors.New("shadowlemonwire: data payload longer than 32768")
	ErrLowEntropyDisabled  = errors.New("shadowlemonwire: low entropy disabled")
	ErrFrameTooShort       = errors.New("shadowlemonwire: frame shorter than fixed prefix")
	ErrFrameLengthMismatch = errors.New("shadowlemonwire: frame length does not match metadata")
	ErrPayloadLength       = errors.New("shadowlemonwire: payload length does not match metadata")
	ErrPaddingLength       = errors.New("shadowlemonwire: padding length does not match metadata")
	ErrAEADNonce           = errors.New("shadowlemonwire: AEAD nonce size larger than wire nonce")
	ErrInvalidPaddingRange = errors.New("shadowlemonwire: invalid padding range")
)
