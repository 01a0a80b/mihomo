package socks

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/net/udpkey"
	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/sing/common/buf"
)

type UDPListener struct {
	packetConn net.PacketConn
	addr       string
	closed     bool
	inboundID  uint32
}

// RawAddress implements C.Listener
func (l *UDPListener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *UDPListener) Address() string {
	return l.packetConn.LocalAddr().String()
}

// Close implements C.Listener
func (l *UDPListener) Close() error {
	l.closed = true
	return l.packetConn.Close()
}

func NewUDP(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*UDPListener, error) {
	return NewUDPWithConfig(defaultConfig(addr), inbound.NewListenConfig(), tunnel, additions...)
}

func NewUDPWithConfig(config LC.AuthServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*UDPListener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SOCKS"),
			inbound.WithSpecialRules(""),
		}
	}
	l, err := lc.ListenPacket(context.Background(), "udp", config.Listen)
	if err != nil {
		return nil, err
	}

	if err := sockopt.UDPReuseaddr(l); err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}

	sl := &UDPListener{
		packetConn: l,
		addr:       config.Listen,
		inboundID:  udpkey.NextInbound(),
	}
	conn := N.NewEnhancePacketConn(l)
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
			handleSocksUDP(l, tunnel, b, remoteAddr, sl.inboundID, additions...)
		}
	}()

	return sl, nil
}

func handleSocksUDP(pc net.PacketConn, tunnel C.Tunnel, b *buf.Buffer, addr net.Addr, inboundID uint32, additions ...inbound.Addition) {
	target, payload, err := socks5.DecodeUDPPacket(b.Bytes())
	if err != nil {
		b.Release()
		return
	}
	b.Advance(len(b.Bytes()) - len(payload))
	pkt := &packet{
		Buffer:  b,
		pc:      pc,
		rAddr:   addr,
		flowKey: udpkey.Make(inboundID, addr.(*net.UDPAddr).AddrPort()),
	}
	_, metadata := inbound.NewPacket(target, pkt, C.SOCKS5, additions...)
	up := C.NewUDPPacket(pkt.Buffer, metadata, pkt.FlowKey(), pkt)
	tunnel.HandleUDPPacket(up, metadata)
}
