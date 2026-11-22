package tunnel

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/net/udpkey"

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
	return c.pc.WriteTo(b.Bytes(), c.rAddr)
}
