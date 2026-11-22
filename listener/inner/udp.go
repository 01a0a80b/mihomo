package inner

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/common/net/udpkey"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/sing/common/buf"
)

const innerUDPQueueSize = 128

var innerUDPConnID atomic.Uint64

type innerUDPAddr struct {
	network string
	address string
}

func (a innerUDPAddr) Network() string { return a.network }
func (a innerUDPAddr) String() string  { return a.address }

type innerUDPDatagram struct {
	data *buf.Buffer
	addr netip.AddrPort
}

type innerUDPPacketConn struct {
	tunnel    C.Tunnel
	proxy     string
	localAddr net.Addr
	readChan  chan innerUDPDatagram
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	inboundID uint32

	readDeadline  deadline.PipeDeadline
	writeDeadline deadline.PipeDeadline
}

func HandleUdp(tunnel C.Tunnel, network, address, proxy string) (net.PacketConn, net.Addr, error) {
	if tunnel == nil {
		return nil, nil, fmt.Errorf("tunnel uninitialized")
	}
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, nil, fmt.Errorf("unsupported network %s", network)
	}
	if socks5.ParseAddr(address) == nil {
		return nil, nil, fmt.Errorf("invalid target address %s", address)
	}

	id := innerUDPConnID.Add(1)
	conn := &innerUDPPacketConn{
		tunnel:        tunnel,
		proxy:         proxy,
		localAddr:     innerUDPAddr{network: network, address: fmt.Sprintf("inner-udp-%d", id)},
		readChan:      make(chan innerUDPDatagram, innerUDPQueueSize),
		done:          make(chan struct{}),
		inboundID:     udpkey.NextInbound(),
		readDeadline:  deadline.MakePipeDeadline(),
		writeDeadline: deadline.MakePipeDeadline(),
	}
	return conn, innerUDPAddr{network: network, address: address}, nil
}

func (c *innerUDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case datagram := <-c.readChan:
		n := copy(p, datagram.data.Bytes())
		short := n < datagram.data.Len()
		addr := net.UDPAddrFromAddrPort(datagram.addr)
		datagram.data.Release()
		if short {
			return n, addr, io.ErrShortBuffer
		}
		return n, addr, nil
	}
}

func (c *innerUDPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("missing target address")
	}
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}

	target := socks5.ParseAddr(addr.String())
	if target == nil {
		return 0, fmt.Errorf("invalid target address %s", addr)
	}
	b := buf.NewPacket()
	b.Write(p)
	udpPacket := &innerUDPPacket{
		Buffer:  b,
		conn:    c,
		flowKey: udpkey.Make(c.inboundID, flowAddrPort(addr)),
	}
	_, metadata := inbound.NewPacket(target, udpPacket, C.INNER)
	metadata.DNSMode = C.DNSNormal
	metadata.Process = C.MihomoName
	metadata.SpecialProxy = c.proxy
	up := C.NewUDPPacket(udpPacket.Buffer, metadata, udpPacket.FlowKey(), udpPacket)
	c.tunnel.HandleUDPPacket(up, metadata)
	return len(p), nil
}

func (c *innerUDPPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.done)
		for {
			select {
			case datagram := <-c.readChan:
				datagram.data.Release()
			default:
				c.mu.Unlock()
				return
			}
		}
	})
	return nil
}

func (c *innerUDPPacketConn) LocalAddr() net.Addr { return c.localAddr }

func (c *innerUDPPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *innerUDPPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *innerUDPPacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

func (c *innerUDPPacketConn) writeBack(b *buf.Buffer, src netip.AddrPort) (int, error) {
	payload := buf.NewPacket()
	payload.Write(b.Bytes())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		payload.Release()
		return 0, net.ErrClosed
	}
	select {
	case c.readChan <- innerUDPDatagram{data: payload, addr: src}:
		return payload.Len(), nil
	default:
		payload.Release()
		return b.Len(), nil
	}
}

type innerUDPPacket struct {
	Buffer  *buf.Buffer
	conn    *innerUDPPacketConn
	flowKey udpkey.FlowKey
}

func flowAddrPort(addr net.Addr) netip.AddrPort {
	if a, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		return a.AddrPort()
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return netip.AddrPortFrom(ip, uint16(a.Port))
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return netip.AddrPortFrom(ip, 0)
	}
	return netip.AddrPort{}
}

func (p *innerUDPPacket) FlowKey() udpkey.FlowKey {
	return p.flowKey
}

func (p *innerUDPPacket) WriteBack(b *buf.Buffer, src netip.AddrPort) (int, error) {
	return p.conn.writeBack(b, src)
}

var _ net.PacketConn = (*innerUDPPacketConn)(nil)
