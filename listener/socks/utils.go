package socks

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/net/udpkey"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/sing/common/buf"
)

type packet struct {
	Buffer  *buf.Buffer
	pc      net.PacketConn
	rAddr   net.Addr
	flowKey udpkey.FlowKey
}

func (c *packet) FlowKey() udpkey.FlowKey {
	return c.flowKey
}

func (c *packet) WriteBack(b *buf.Buffer, src netip.AddrPort) (int, error) {
	packet, err := socks5.EncodeUDPPacket(socks5.AddrFromStdAddrPort(src), b.Bytes())
	if err != nil {
		return 0, err
	}
	return c.pc.WriteTo(packet, c.rAddr)
}
