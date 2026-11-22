package udpkey

import (
	"net/netip"
	"testing"
)

func TestMakeUnmap(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:1000")
	mapped := netip.AddrPortFrom(netip.AddrFrom16(src.Addr().As16()), src.Port())

	plain := Make(7, src)
	fromMapped := Make(7, mapped)

	if plain != fromMapped {
		t.Fatalf("v4 and v4-mapped v6 must normalize to the same FlowKey: %v != %v", plain, fromMapped)
	}
	if !plain.Src.Addr().Is4() {
		t.Fatalf("Src must be unmapped v4, got %v", plain.Src.Addr())
	}
}

func TestDifferentInboundDifferentFlowKey(t *testing.T) {
	src := netip.MustParseAddrPort("198.51.100.9:5353")
	a := Make(1, src)
	b := Make(2, src)

	if a == b {
		t.Fatal("same source with different inbound must produce distinct FlowKey")
	}
	if a.Src != b.Src {
		t.Fatal("Src must remain identical when only Inbound differs")
	}
	if a.Hash() == b.Hash() {
		t.Fatal("different inbound should produce a different hash shard")
	}
}

func TestHashStable(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.5:443")
	key := Make(42, src)

	first := key.Hash()
	for i := 0; i < 100; i++ {
		if key.Hash() != first {
			t.Fatal("FlowKey.Hash changed between calls")
		}
	}

	mapped := netip.AddrPortFrom(netip.AddrFrom16(src.Addr().As16()), src.Port())
	if Make(42, mapped).Hash() != first {
		t.Fatal("v4 and v4-mapped v6 must hash identically")
	}
}

func TestNextInboundUnique(t *testing.T) {
	seen := make(map[uint32]struct{})
	for i := 0; i < 100; i++ {
		id := NextInbound()
		if id == 0 {
			t.Fatal("NextInbound must never return 0")
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("NextInbound returned duplicate id %d", id)
		}
		seen[id] = struct{}{}
	}
}
