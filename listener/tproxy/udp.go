package tproxy

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/net/udpkey"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/sing/common/buf"
	"golang.org/x/exp/slices"
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
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TPROXY"),
			inbound.WithSpecialRules(""),
		}
	}
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	rl := &UDPListener{
		packetConn: l,
		addr:       addr,
		inboundID:  udpkey.NextInbound(),
	}

	c := l.(*net.UDPConn)

	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	err = setsockopt(rc, addr)
	if err != nil {
		return nil, err
	}

	go func() {
		oob := make([]byte, 1024)
		for {
			b := buf.NewPacket()
			n, oobn, _, lAddr, err := c.ReadMsgUDPAddrPort(b.FreeBytes(), oob)
			if err != nil {
				b.Release()
				if rl.closed {
					break
				}
				continue
			}

			rAddr, err := getOrigDst(oob[:oobn])
			if err != nil {
				b.Release()
				continue
			}

			dscp, _ := getDSCP(oob[:oobn])
			additions := append(slices.Clip(additions), inbound.WithDSCP(dscp)) // don't change outside additions

			if rAddr.Addr().Is4() {
				// try to unmap 4in6 address
				lAddr = netip.AddrPortFrom(lAddr.Addr().Unmap(), lAddr.Port())
			}
			b.Truncate(n)
			handlePacketConn(l, tunnel, b, lAddr, rAddr, rl.inboundID, additions...)
		}
	}()

	return rl, nil
}

func handlePacketConn(pc net.PacketConn, tunnel C.Tunnel, b *buf.Buffer, lAddr, rAddr netip.AddrPort, inboundID uint32, additions ...inbound.Addition) {
	target := socks5.AddrFromStdAddrPort(rAddr)
	pkt := &packet{
		Buffer:    b,
		pc:        pc,
		lAddr:     lAddr,
		tunnel:    tunnel,
		additions: additions,
		flowKey:   udpkey.Make(inboundID, lAddr),
	}
	_, metadata := inbound.NewPacket(target, pkt, C.TPROXY, additions...)
	up := C.NewUDPPacket(pkt.Buffer, metadata, pkt.FlowKey(), pkt)
	tunnel.HandleUDPPacket(up, metadata)
}
