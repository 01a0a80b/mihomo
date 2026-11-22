package trojan

import (
	"errors"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/net/udpkey"

	"github.com/metacubex/sing/common/buf"
)

type packet struct {
	Buffer  *buf.Buffer
	pc      net.PacketConn
	flowKey udpkey.FlowKey
}

func (c *packet) FlowKey() udpkey.FlowKey {
	return c.flowKey
}

func (c *packet) WriteBack(b *buf.Buffer, src netip.AddrPort) (int, error) {
	if !src.IsValid() {
		return 0, errors.New("address is invalid")
	}
	return c.pc.WriteTo(b.Bytes(), net.UDPAddrFromAddrPort(src))
}
