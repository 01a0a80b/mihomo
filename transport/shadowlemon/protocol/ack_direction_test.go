package shadowlemonprotocol

import (
	"bytes"
	"testing"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
	wire "github.com/metacubex/mihomo/transport/shadowlemon/wire"
)

// TestACKFrameDirection pins that a peer sends ACK frames of its own direction.
// The client must emit TYPE_ACK_C2S (8) and the server TYPE_ACK_S2C (9); using a
// data type or the peer's ACK type makes the remote side reject the frame as
// "wrong direction" and stalls the sliding window.
func TestACKFrameDirection(t *testing.T) {
	cases := []struct {
		name      string
		direction byte
		wantACK   byte
	}{
		{"client", directionClient, wire.TypeAckC2S},
		{"server", directionServer, wire.TypeAckS2C},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x33}, 32)
			s, err := NewSession(1, tc.direction, key, key, crypto.SuiteXChaCha20Poly1305, EmptySourceTag, false)
			if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			if err := s.encodeACKLocked(); err != nil {
				s.mu.Unlock()
				t.Fatal(err)
			}
			frames := s.outgoing
			s.mu.Unlock()
			if len(frames) == 0 {
				t.Fatal("no ACK frame produced")
			}
			meta, _, err := openV2Frame(s.sendAEAD, s.sendAEAD, frames[0])
			if err != nil {
				t.Fatal(err)
			}
			if meta.Type != tc.wantACK {
				t.Fatalf("ACK frame type = %d, want %d", meta.Type, tc.wantACK)
			}
		})
	}
}
