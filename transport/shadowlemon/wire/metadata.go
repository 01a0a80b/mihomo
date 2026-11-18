package shadowlemonwire

import (
	"encoding/binary"
	"fmt"
)

// Metadata is the parsed representation of the 32-byte plaintext metadata.
// The same struct covers all three layouts (session, data/ack, low entropy);
// fields that do not exist in a given layout are zero for that layout.
type Metadata struct {
	Type       uint8
	Flags      uint8
	SessionID  uint32
	Seq        uint32
	Unack      uint32
	Window     uint16
	Fragment   uint8
	PrefixLen  uint8
	PayloadLen uint16
	SuffixLen  uint8
}

// isSession reports whether the type uses the session metadata layout (2-5).
func (m *Metadata) isSession() bool { return m.Type >= 2 && m.Type <= 5 }

// isData reports whether the type uses the data/ack metadata layout (6-9).
func (m *Metadata) isData() bool { return m.Type >= 6 && m.Type <= 9 }

// validate checks the type-specific constraints. Reserved fields are ignored.
func (m *Metadata) validate() error {
	switch {
	case m.isSession():
		if int(m.PayloadLen) > MaxSessionPayload {
			return fmt.Errorf("%w: %d", ErrSessionPayloadLong, m.PayloadLen)
		}
	case m.isData():
		if int(m.PayloadLen) > MaxFragment {
			return fmt.Errorf("%w: %d", ErrDataPayloadLong, m.PayloadLen)
		}
	case IsLowEntropy(m.Type):
		return ErrLowEntropyDisabled
	default:
		return fmt.Errorf("%w: %d", ErrInvalidProtocolType, m.Type)
	}
	return nil
}

// MarshalMetadata encodes m into the exact 32-byte plaintext layout. Every
// reserved byte (including the flags byte for non-low-entropy types) is
// written as zero. Low-entropy types (10/11) are rejected because the Go side
// does not implement their transform.
func MarshalMetadata(m *Metadata) []byte {
	out := make([]byte, MetadataLen)
	out[0] = m.Type
	if m.isSession() {
		// type(1) flags(1) sessionID(4be) seq(4be) payloadLen(2be) suffixLen(1)
		// reserved(19) -- prefixLen is implicitly zero for session types.
		out[1] = m.Flags
		binary.BigEndian.PutUint32(out[2:6], m.SessionID)
		binary.BigEndian.PutUint32(out[6:10], m.Seq)
		binary.BigEndian.PutUint16(out[10:12], m.PayloadLen)
		out[12] = m.SuffixLen
		return out
	}
	// types 6-9: type(1) flags(1) sessionID(4) seq(4) unack(4) window(2be)
	// fragment(1) prefixLen(1) payloadLen(2be) suffixLen(1) reserved(11).
	out[1] = m.Flags
	binary.BigEndian.PutUint32(out[2:6], m.SessionID)
	binary.BigEndian.PutUint32(out[6:10], m.Seq)
	binary.BigEndian.PutUint32(out[10:14], m.Unack)
	binary.BigEndian.PutUint16(out[14:16], m.Window)
	out[16] = m.Fragment
	out[17] = m.PrefixLen
	binary.BigEndian.PutUint16(out[18:20], m.PayloadLen)
	out[20] = m.SuffixLen
	return out
}

// UnmarshalMetadata parses a 32-byte metadata plaintext, ignoring all
// reserved bytes. Low-entropy types are recognized but rejected with
// ErrLowEntropyDisabled; their body transform is not implemented on the Go
// side. The function never panics on arbitrary input.
func UnmarshalMetadata(b []byte) (*Metadata, error) {
	if len(b) != MetadataLen {
		return nil, fmt.Errorf("%w: %d", ErrMetadataLength, len(b))
	}
	m := &Metadata{Type: b[0], Flags: b[1]}
	switch {
	case m.isSession():
		m.SessionID = binary.BigEndian.Uint32(b[2:6])
		m.Seq = binary.BigEndian.Uint32(b[6:10])
		m.PayloadLen = binary.BigEndian.Uint16(b[10:12])
		m.SuffixLen = b[12]
	case m.isData():
		m.SessionID = binary.BigEndian.Uint32(b[2:6])
		m.Seq = binary.BigEndian.Uint32(b[6:10])
		m.Unack = binary.BigEndian.Uint32(b[10:14])
		m.Window = binary.BigEndian.Uint16(b[14:16])
		m.Fragment = b[16]
		m.PrefixLen = b[17]
		m.PayloadLen = binary.BigEndian.Uint16(b[18:20])
		m.SuffixLen = b[20]
	case IsLowEntropy(m.Type):
		return nil, ErrLowEntropyDisabled
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidProtocolType, m.Type)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// PayloadBlockLen returns the length of the encrypted payload block: zero for
// an empty payload (no tag), otherwise payloadLen + TagLen.
func PayloadBlockLen(payloadLen int) int {
	if payloadLen == 0 {
		return 0
	}
	return payloadLen + TagLen
}

// FrameLen returns the expected total frame length implied by m. The frame
// always carries an explicit 24-byte nonce in this package.
func FrameLen(m *Metadata) int {
	return NonceLen + MetaBlockLen + int(m.PrefixLen) + PayloadBlockLen(int(m.PayloadLen)) + int(m.SuffixLen)
}
