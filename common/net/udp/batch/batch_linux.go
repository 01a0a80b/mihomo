//go:build linux

package batch

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/metacubex/sing/common/buf"
	"golang.org/x/sys/unix"
)

const (
	sizeofSockaddrInet6 = 28
	maxGSOPacket        = 65507
)

type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

var (
	nativeEndian = detectEndian()
	gsoState     atomic.Int32
	mmsgState    atomic.Int32
)

func detectEndian() binary.ByteOrder {
	v := uint16(1)
	if *(*byte)(unsafe.Pointer(&v)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func socketRaw(pc net.PacketConn) (syscall.RawConn, bool) {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return nil, false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, false
	}
	return rc, true
}

type linuxReader struct {
	pc    net.PacketConn
	raw   syscall.RawConn
	addrs [BatchSize]netip.AddrPort
}

func NewReader(pc net.PacketConn) Reader {
	if raw, ok := socketRaw(pc); ok {
		return &linuxReader{pc: pc, raw: raw}
	}
	return &packetReader{pc: pc}
}

func (r *linuxReader) ReadBatch(buffers []*buf.Buffer) (int, []netip.AddrPort, error) {
	limit := len(buffers)
	if limit > BatchSize {
		limit = BatchSize
	}
	if limit == 0 {
		return 0, r.addrs[:0], nil
	}

	var msgs [BatchSize]mmsghdr
	var iovs [BatchSize]unix.Iovec
	var names [BatchSize][sizeofSockaddrInet6]byte
	var holds [BatchSize]*buf.Buffer
	var caps [BatchSize]int
	for i := 0; i < limit; i++ {
		b := buf.NewPacket()
		holds[i] = b
		space := b.FreeBytes()
		caps[i] = len(space)
		if len(space) == 0 {
			iovs[i].Base = &emptyByte
		} else {
			iovs[i].Base = &space[0]
		}
		iovs[i].SetLen(len(space))
		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = sizeofSockaddrInet6
		msgs[i].Hdr.Iov = &iovs[i]
		msgs[i].Hdr.Iovlen = 1
	}

	var got int
	var errno syscall.Errno
	err := r.raw.Read(func(fd uintptr) bool {
		n, _, e := unix.Syscall6(unix.SYS_RECVMMSG, fd,
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(limit),
			uintptr(unix.MSG_WAITFORONE),
			0, 0)
		if e != 0 {
			if e == unix.EAGAIN || e == unix.EWOULDBLOCK || e == unix.EINTR {
				return false
			}
			errno = e
			return true
		}
		got = int(n)
		return true
	})
	if err != nil || errno != 0 {
		for i := 0; i < limit; i++ {
			holds[i].Release()
		}
		if err != nil {
			return 0, r.addrs[:0], err
		}
		return 0, r.addrs[:0], errno
	}
	if got <= 0 {
		for i := 0; i < limit; i++ {
			holds[i].Release()
		}
		return 0, r.addrs[:0], nil
	}
	if got > limit {
		got = limit
	}
	for i := 0; i < got; i++ {
		n := int(msgs[i].Len)
		if n < 0 {
			n = 0
		}
		if n > caps[i] {
			n = caps[i]
		}
		holds[i].Extend(n)
		buffers[i] = holds[i]
		r.addrs[i] = parseSockaddr(names[i][:])
	}
	for i := got; i < limit; i++ {
		holds[i].Release()
	}
	return got, r.addrs[:got], nil
}

type linuxWriter struct {
	pc  net.PacketConn
	raw syscall.RawConn
}

func NewWriter(pc net.PacketConn) Writer {
	if raw, ok := socketRaw(pc); ok {
		return &linuxWriter{pc: pc, raw: raw}
	}
	return &packetWriter{pc: pc}
}

func (w *linuxWriter) WriteBatch(buffers []*buf.Buffer, addr netip.AddrPort) error {
	if len(buffers) == 0 {
		return nil
	}
	if len(buffers) == 1 {
		_, err := w.pc.WriteTo(buffers[0].Bytes(), addrPortToNetAddr(addr))
		return err
	}
	if gsoState.Load() != 2 && gsoEligible(buffers) {
		if err := w.tryGSO(buffers, addr); err == nil {
			return nil
		}
	}
	return w.sendmmsg(buffers, nil, addr)
}

func (w *linuxWriter) WriteBatchMulti(buffers []*buf.Buffer, addrs []netip.AddrPort) error {
	if len(buffers) == 0 {
		return nil
	}
	return w.sendmmsg(buffers, addrs, netip.AddrPort{})
}

func gsoEligible(buffers []*buf.Buffer) bool {
	seg := len(buffers[0].Bytes())
	if seg == 0 || seg > 65535 {
		return false
	}
	total := seg * len(buffers)
	if total == 0 || total > maxGSOPacket {
		return false
	}
	for _, b := range buffers[1:] {
		if b.Len() != seg {
			return false
		}
	}
	return true
}

func (w *linuxWriter) tryGSO(buffers []*buf.Buffer, addr netip.AddrPort) error {
	seg := uint16(len(buffers[0].Bytes()))
	total := int(seg) * len(buffers)
	big := buf.NewSize(total)
	defer big.Release()
	for _, b := range buffers {
		copy(big.Extend(b.Len()), b.Bytes())
	}

	var iov unix.Iovec
	iov.Base = &big.Bytes()[0]
	iov.SetLen(total)

	var control [64]byte
	ch := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	ch.SetLen(unix.CmsgLen(2))
	ch.Level = unix.SOL_UDP
	ch.Type = unix.UDP_SEGMENT
	nativeEndian.PutUint16(control[unix.CmsgLen(0):], seg)

	var name [sizeofSockaddrInet6]byte
	nl := writeSockaddr(name[:], addr)
	var msg unix.Msghdr
	msg.Name = &name[0]
	msg.Namelen = uint32(nl)
	msg.Iov = &iov
	msg.Iovlen = 1
	msg.Control = &control[0]
	msg.SetControllen(unix.CmsgSpace(2))
	var mm mmsghdr
	mm.Hdr = msg

	var sent int
	var errno syscall.Errno
	err := w.raw.Write(func(fd uintptr) bool {
		n, _, e := unix.Syscall6(unix.SYS_SENDMMSG, fd,
			uintptr(unsafe.Pointer(&mm)),
			1, 0, 0, 0)
		if e != 0 {
			if e == unix.EAGAIN || e == unix.EWOULDBLOCK || e == unix.EINTR {
				return false
			}
			errno = e
			return true
		}
		sent = int(n)
		return true
	})
	if err != nil {
		return err
	}
	if errno != 0 {
		if gsoUnsupported(errno) {
			gsoState.Store(2)
		}
		return errno
	}
	if sent != 1 {
		gsoState.Store(2)
		return syscall.EIO
	}
	gsoState.Store(1)
	return nil
}

func gsoUnsupported(errno syscall.Errno) bool {
	return errno == syscall.EINVAL ||
		errno == syscall.EOPNOTSUPP ||
		errno == syscall.ENOPROTOOPT ||
		errno == syscall.EPROTONOSUPPORT ||
		errno == syscall.ENOSYS
}

func (w *linuxWriter) sendmmsg(buffers []*buf.Buffer, addrs []netip.AddrPort, fallback netip.AddrPort) error {
	limit := len(buffers)
	if limit > BatchSize {
		limit = BatchSize
	}
	if limit == 0 {
		return nil
	}
	if mmsgState.Load() == 2 {
		return writeByPacket(w.pc, buffers[:limit], addrs, fallback)
	}

	var msgs [BatchSize]mmsghdr
	var iovs [BatchSize]unix.Iovec
	var names [BatchSize][sizeofSockaddrInet6]byte
	for i := 0; i < limit; i++ {
		data := buffers[i].Bytes()
		if len(data) == 0 {
			iovs[i].Base = &emptyByte
		} else {
			iovs[i].Base = &data[0]
		}
		iovs[i].SetLen(len(data))
		addr := fallback
		if addrs != nil && i < len(addrs) {
			addr = addrs[i]
		}
		nl := writeSockaddr(names[i][:], addr)
		msgs[i].Hdr.Name = &names[i][0]
		msgs[i].Hdr.Namelen = uint32(nl)
		msgs[i].Hdr.Iov = &iovs[i]
		msgs[i].Hdr.Iovlen = 1
	}

	for sentTotal := 0; sentTotal < limit; {
		var sent int
		var errno syscall.Errno
		err := w.raw.Write(func(fd uintptr) bool {
			n, _, e := unix.Syscall6(unix.SYS_SENDMMSG, fd,
				uintptr(unsafe.Pointer(&msgs[sentTotal])),
				uintptr(limit-sentTotal),
				0, 0, 0)
			if e != 0 {
				if e == unix.EAGAIN || e == unix.EWOULDBLOCK || e == unix.EINTR {
					return false
				}
				errno = e
				return true
			}
			sent = int(n)
			return true
		})
		if err != nil {
			if mmsgUnsupported(err) {
				mmsgState.Store(2)
				return writeByPacket(w.pc, buffers[:limit], addrs, fallback)
			}
			return err
		}
		if errno != 0 {
			if mmsgUnsupported(errno) {
				mmsgState.Store(2)
				return writeByPacket(w.pc, buffers[:limit], addrs, fallback)
			}
			return errno
		}
		if sent <= 0 {
			return syscall.EIO
		}
		sentTotal += sent
		mmsgState.Store(1)
	}
	return nil
}

func mmsgUnsupported(err error) bool {
	errno, ok := err.(syscall.Errno)
	if !ok {
		return false
	}
	return errno == syscall.ENOSYS ||
		errno == syscall.EINVAL ||
		errno == syscall.EOPNOTSUPP ||
		errno == syscall.ENOTSUP
}

func parseSockaddr(b []byte) netip.AddrPort {
	if len(b) < 8 {
		return netip.AddrPort{}
	}
	family := nativeEndian.Uint16(b[0:2])
	port := binary.BigEndian.Uint16(b[2:4])
	switch family {
	case unix.AF_INET:
		var a4 [4]byte
		copy(a4[:], b[4:8])
		return unmapAddrPort(netip.AddrPortFrom(netip.AddrFrom4(a4), port))
	case unix.AF_INET6:
		if len(b) < 24 {
			return netip.AddrPort{}
		}
		var a16 [16]byte
		copy(a16[:], b[8:24])
		return unmapAddrPort(netip.AddrPortFrom(netip.AddrFrom16(a16), port))
	}
	return netip.AddrPort{}
}

func writeSockaddr(dst []byte, ap netip.AddrPort) uint32 {
	if !ap.IsValid() {
		return 0
	}
	port := ap.Port()
	addr := ap.Addr()
	if addr.Is4() {
		nativeEndian.PutUint16(dst[0:2], unix.AF_INET)
		binary.BigEndian.PutUint16(dst[2:4], port)
		a4 := addr.As4()
		copy(dst[4:8], a4[:])
		return 16
	}
	nativeEndian.PutUint16(dst[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(dst[2:4], port)
	a16 := addr.As16()
	copy(dst[8:24], a16[:])
	return sizeofSockaddrInet6
}
