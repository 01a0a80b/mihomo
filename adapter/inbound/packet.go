package inbound

import (
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

func NewPacket(target socks5.Addr, packet C.UDPPacketPeer, source C.Type, additions ...Addition) (C.UDPPacketPeer, *C.Metadata) {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.UDP
	metadata.Type = source
	src := net.UDPAddrFromAddrPort(packet.FlowKey().Src)
	metadata.RawSrcAddr = src
	metadata.RawDstAddr = net.UDPAddrFromAddrPort(metadata.AddrPort())
	ApplyAdditions(metadata, WithSrcAddr(src), WithInAddr(src))
	ApplyAdditions(metadata, additions...)

	return packet, metadata
}
