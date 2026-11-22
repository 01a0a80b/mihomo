package nat

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/common/net/udpkey"
	C "github.com/metacubex/mihomo/constant"
)

type stubSender struct {
	C.PacketSender
}

func TestTableDistinguishesFlowKeys(t *testing.T) {
	tbl := New()
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	keyA := udpkey.Make(11, src)
	keyB := udpkey.Make(22, src)
	keyAClone := udpkey.Make(11, src)

	created := 0
	maker := func() C.PacketSender {
		created++
		return &stubSender{}
	}

	senderA, loaded := tbl.GetOrCreate(keyA, maker)
	if loaded || senderA == nil {
		t.Fatalf("first GetOrCreate must create a new entry (loaded=%v)", loaded)
	}
	senderB, loaded := tbl.GetOrCreate(keyB, maker)
	if loaded || senderB == nil {
		t.Fatalf("second inbound with same src must create a new entry (loaded=%v)", loaded)
	}
	if senderA == senderB {
		t.Fatal("same src with different inbound must not share a NAT entry")
	}
	if created != 2 {
		t.Fatalf("expected 2 newly created senders, got %d", created)
	}

	senderAgain, loaded := tbl.GetOrCreate(keyAClone, maker)
	if !loaded || senderAgain != senderA {
		t.Fatal("identical FlowKey must reuse the existing NAT entry")
	}
	if created != 2 {
		t.Fatalf("reusing an entry must not call maker (created=%d)", created)
	}

	tbl.Delete(keyA)
	_, loaded = tbl.GetOrCreate(keyA, maker)
	if loaded {
		t.Fatal("deleted FlowKey must be recreated")
	}
	_, loaded = tbl.GetOrCreate(keyB, maker)
	if !loaded {
		t.Fatal("deleting one inbound must not remove the other inbound's entry")
	}
}
