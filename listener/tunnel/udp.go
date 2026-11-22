package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/net/udp/batch"
	"github.com/metacubex/mihomo/common/net/udpkey"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	T "github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/sing/common/buf"
)

type PacketConn struct {
	conn      net.PacketConn
	addr      string
	target    socks5.Addr
	proxy     string
	closed    bool
	inboundID uint32
}

// RawAddress implements C.Listener
func (l *PacketConn) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *PacketConn) Address() string {
	return l.conn.LocalAddr().String()
}

// Close implements C.Listener
func (l *PacketConn) Close() error {
	l.closed = true
	return l.conn.Close()
}

func NewUDP(addr, target, proxy string, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*PacketConn, error) {
	l, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}

	targetAddr := socks5.ParseAddr(target)
	if targetAddr == nil {
		return nil, fmt.Errorf("invalid target address %s", target)
	}

	sl := &PacketConn{
		conn:      l,
		target:    targetAddr,
		proxy:     proxy,
		addr:      addr,
		inboundID: udpkey.NextInbound(),
	}

	if proxy != "" {
		additions = append([]inbound.Addition{inbound.WithSpecialProxy(proxy)}, additions...)
	}

	go func() {
		r := batch.NewReader(l)
		buffers := make([]*buf.Buffer, batch.BatchSize)
		for {
			n, addrs, err := r.ReadBatch(buffers)
			T.AddBatchCalls(1)
			if n > 0 {
				T.AddBatchPackets(uint64(n))
				for i := 0; i < n; i++ {
					b := buffers[i]
					buffers[i] = nil
					sl.handleUDP(l, tunnel, b, addrs[i], additions...)
				}
			}
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
		}
	}()

	return sl, nil
}

func (l *PacketConn) handleUDP(pc net.PacketConn, tunnel C.Tunnel, b *buf.Buffer, addrPort netip.AddrPort, additions ...inbound.Addition) {
	pkt := &packet{
		Buffer:  b,
		pc:      pc,
		rAddr:   net.UDPAddrFromAddrPort(addrPort),
		flowKey: udpkey.Make(l.inboundID, addrPort),
	}

	_, metadata := inbound.NewPacket(l.target, pkt, C.TUNNEL, additions...)
	up := C.NewUDPPacket(pkt.Buffer, metadata, pkt.FlowKey(), pkt)
	tunnel.HandleUDPPacket(up, metadata)
}
