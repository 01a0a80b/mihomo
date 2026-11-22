package shadowsocks

import (
	"bytes"
	"errors"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/net/udpkey"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/mhurl"
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
	if !src.IsValid() {
		return 0, errors.New("address is invalid")
	}
	packet := bytes.Join([][]byte{socks5.AddrFromStdAddrPort(src), b.Bytes()}, []byte{})
	return c.pc.WriteTo(packet, c.rAddr)
}

func ParseSSURL(s string) (addr, cipher, password string, err error) {
	u, err := mhurl.Parse(s) // we need multiple hosts url supports
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
