package shadowsocks

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/net/udpkey"
	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/sing/common/buf"
)

type UDPListener struct {
	packetConn net.PacketConn
	closed     bool
	inboundID  uint32
}

func NewUDP(addr string, lc C.InboundListenConfig, pickCipher core.Cipher, tunnel C.Tunnel, additions ...inbound.Addition) (*UDPListener, error) {
	l, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}

	if err := sockopt.UDPReuseaddr(l); err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}

	sl := &UDPListener{packetConn: l, closed: false, inboundID: udpkey.NextInbound()}
	conn := pickCipher.PacketConn(N.NewEnhancePacketConn(l))
	go func() {
		for {
			data, put, remoteAddr, err := conn.WaitReadFrom()
			if err != nil {
				if put != nil {
					put()
				}
				if sl.closed {
					break
				}
				continue
			}
			b := buf.NewPacket()
			b.Write(data)
			if put != nil {
				put()
			}
			handleSocksUDP(conn, tunnel, b, remoteAddr, sl.inboundID, additions...)
		}
	}()

	return sl, nil
}

func (l *UDPListener) Close() error {
	l.closed = true
	return l.packetConn.Close()
}

func (l *UDPListener) LocalAddr() net.Addr {
	return l.packetConn.LocalAddr()
}

func handleSocksUDP(pc net.PacketConn, tunnel C.Tunnel, b *buf.Buffer, addr net.Addr, inboundID uint32, additions ...inbound.Addition) {
	tgtAddr := socks5.SplitAddr(b.Bytes())
	if tgtAddr == nil {
		b.Release()
		return
	}
	b.Advance(len(tgtAddr))
	pkt := &packet{
		Buffer:  b,
		pc:      pc,
		rAddr:   addr,
		flowKey: udpkey.Make(inboundID, addr.(*net.UDPAddr).AddrPort()),
	}
	_, metadata := inbound.NewPacket(tgtAddr, pkt, C.SHADOWSOCKS, additions...)
	up := C.NewUDPPacket(pkt.Buffer, metadata, pkt.FlowKey(), pkt)
	tunnel.HandleUDPPacket(up, metadata)
}
