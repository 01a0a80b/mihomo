package udpkey

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"net/netip"
	"sync/atomic"
)

type FlowKey struct {
	Inbound uint32
	Src     netip.AddrPort
}

var seed = maphash.MakeSeed()

var nextInbound atomic.Uint32

func unmap(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return ap
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func Make(inbound uint32, src netip.AddrPort) FlowKey {
	return FlowKey{Inbound: inbound, Src: unmap(src)}
}

func NextInbound() uint32 {
	for {
		id := nextInbound.Add(1)
		if id != 0 {
			return id
		}
	}
}

func (k FlowKey) Hash() uint64 {
	var b [22]byte
	binary.LittleEndian.PutUint32(b[0:4], k.Inbound)
	ap := unmap(k.Src)
	copy(b[4:], ap.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[20:22], ap.Port())
	return maphash.Bytes(seed, b[:])
}

func (k FlowKey) String() string {
	if k.Inbound == 0 {
		return k.Src.String()
	}
	return fmt.Sprintf("%d|%s", k.Inbound, k.Src)
}
