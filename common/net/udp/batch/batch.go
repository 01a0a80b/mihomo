package batch

import (
	"net"
	"net/netip"

	"github.com/metacubex/sing/common/buf"
)

const BatchSize = 32

type Reader interface {
	ReadBatch([]*buf.Buffer) (int, []netip.AddrPort, error)
}

type Writer interface {
	WriteBatch([]*buf.Buffer, netip.AddrPort) error
}

type MultiDestWriter interface {
	WriteBatchMulti([]*buf.Buffer, []netip.AddrPort) error
}

type packetReader struct {
	pc    net.PacketConn
	addrs [BatchSize]netip.AddrPort
}

func (r *packetReader) ReadBatch(buffers []*buf.Buffer) (int, []netip.AddrPort, error) {
	limit := len(buffers)
	if limit > BatchSize {
		limit = BatchSize
	}
	var n int
	for i := 0; i < limit; i++ {
		b := buf.NewPacket()
		nr, addr, err := r.pc.ReadFrom(b.FreeBytes())
		if err != nil {
			b.Release()
			return n, r.addrs[:n], err
		}
		b.Extend(int(nr))
		buffers[i] = b
		r.addrs[i] = netAddrToAddrPort(addr)
		n++
	}
	return n, r.addrs[:n], nil
}

type packetWriter struct {
	pc net.PacketConn
}

func (w *packetWriter) WriteBatch(buffers []*buf.Buffer, addr netip.AddrPort) error {
	return writeByPacket(w.pc, buffers, nil, addr)
}

func (w *packetWriter) WriteBatchMulti(buffers []*buf.Buffer, addrs []netip.AddrPort) error {
	return writeByPacket(w.pc, buffers, addrs, netip.AddrPort{})
}

func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return ap
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func writeByPacket(pc net.PacketConn, buffers []*buf.Buffer, addrs []netip.AddrPort, fallback netip.AddrPort) error {
	for i, b := range buffers {
		addr := fallback
		if addrs != nil && i < len(addrs) {
			addr = addrs[i]
		}
		if _, err := pc.WriteTo(b.Bytes(), addrPortToNetAddr(addr)); err != nil {
			return err
		}
	}
	return nil
}

func netAddrToAddrPort(addr net.Addr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPort{}
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		ip, ok := netip.AddrFromSlice(ua.IP)
		if !ok {
			return netip.AddrPort{}
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port))
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return unmapAddrPort(ap)
}

func addrPortToNetAddr(ap netip.AddrPort) net.Addr {
	return net.UDPAddrFromAddrPort(ap)
}

var emptyByte byte
