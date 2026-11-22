package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/net/udp/batch"
	"github.com/metacubex/mihomo/common/net/udpkey"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/sing/common/buf"
)

type packetSender struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan *C.UDPPacket
	writer batch.Writer

	originToTarget map[netip.Addr]netip.Addr
	targetToOrigin map[netip.Addr]netip.Addr
	mappingMutex   sync.RWMutex

	writeAddr   net.UDPAddr
	writeAddrIP [16]byte
}

func newPacketSender() C.PacketSender {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *C.UDPPacket, senderCapacity)
	return &packetSender{
		ctx:            ctx,
		cancel:         cancel,
		ch:             ch,
		originToTarget: make(map[netip.Addr]netip.Addr),
		targetToOrigin: make(map[netip.Addr]netip.Addr),
	}
}

func (s *packetSender) setWriteAddr(ap netip.AddrPort) *net.UDPAddr {
	a := ap.Addr()
	if a.Is4() {
		ip := a.As4()
		copy(s.writeAddrIP[:4], ip[:])
		s.writeAddr.IP = s.writeAddrIP[:4]
	} else {
		ip := a.As16()
		copy(s.writeAddrIP[:], ip[:])
		s.writeAddr.IP = s.writeAddrIP[:]
	}
	s.writeAddr.Port = int(ap.Port())
	s.writeAddr.Zone = a.Zone()
	return &s.writeAddr
}

func (s *packetSender) AddMapping(originMetadata *C.Metadata, metadata *C.Metadata) {
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	originKey := originMetadata.DstIP.Unmap()
	originAddr := originMetadata.DstIP.Unmap()
	targetAddr := metadata.DstIP.Unmap()
	if addr := s.originToTarget[originKey]; !addr.IsValid() {
		s.originToTarget[originKey] = targetAddr
	}
	if addr := s.targetToOrigin[targetAddr]; !addr.IsValid() {
		s.targetToOrigin[targetAddr] = originAddr
	}
}

func (s *packetSender) RestoreReadFrom(addr netip.Addr) netip.Addr {
	s.mappingMutex.RLock()
	defer s.mappingMutex.RUnlock()
	if originAddr := s.targetToOrigin[addr]; originAddr.IsValid() {
		return originAddr
	}
	return addr
}

func (s *packetSender) processPacket(pc C.PacketConn, packet *C.UDPPacket) {
	defer packet.Drop()
	meta := packet.Meta

	var addr *net.UDPAddr

	s.mappingMutex.RLock()
	targetAddr := s.originToTarget[meta.DstIP.Unmap()]
	s.mappingMutex.RUnlock()

	if targetAddr.IsValid() {
		addr = s.setWriteAddr(netip.AddrPortFrom(targetAddr, meta.DstPort))
	}

	if addr == nil {
		originMetadata := meta
		meta = meta.Clone()

		_ = preHandleMetadata(meta)
		meta = meta.Pure()
		if meta.Host != "" {
			if err := pc.ResolveUDP(s.ctx, meta); err != nil {
				log.Warnln("[UDP] Resolve Ip error: %s", err)
				return
			}
		}

		if !meta.DstIP.IsValid() {
			log.Warnln("[UDP] Destination ip not valid: %#v", meta)
			return
		}
		s.AddMapping(originMetadata, meta)
		addr = net.UDPAddrFromAddrPort(meta.AddrPort())
	}
	_ = handleUDPToRemote(pc, s.writer, packet, addr)
}

func (s *packetSender) Process(pc C.PacketConn, proxy C.WriteBackProxy) {
	s.writer = batch.NewWriter(pc)
	for {
		select {
		case <-s.ctx.Done():
			return
		case packet := <-s.ch:
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			s.processPacket(pc, packet)
		}
	}
}

func (s *packetSender) dropAll() {
	for {
		select {
		case data := <-s.ch:
			data.Drop()
		default:
			return
		}
	}
}

func (s *packetSender) Send(packet *C.UDPPacket) {
	select {
	case <-s.ctx.Done():
		packet.Drop()
		return
	default:
	}

	select {
	case s.ch <- packet:
	case <-s.ctx.Done():
		packet.Drop()
	default:
		AddDroppedSender(1)
		packet.Drop()
	}
}

func (s *packetSender) Close() {
	s.cancel()
	s.dropAll()
}

func (s *packetSender) DoSniff(metadata *C.Metadata) error { return nil }

func handleUDPToRemote(pc C.PacketConn, w batch.Writer, packet *C.UDPPacket, addr *net.UDPAddr) error {
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	addrPort, ok := addrPortFromNetAddr(addr)
	if !ok {
		return errors.New("udp addr invalid")
	}
	buffers := [1]*buf.Buffer{packet.Buffer}
	if err := w.WriteBatch(buffers[:], addrPort); err != nil {
		return err
	}
	AddBatchCalls(1)
	AddBatchPackets(1)
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func addrPortFromNetAddr(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil {
			return netip.AddrPort{}, false
		}
		return a.AddrPort(), true
	case interface{ AddrPort() netip.AddrPort }:
		return a.AddrPort(), true
	default:
		if addr == nil {
			return netip.AddrPort{}, false
		}
		ap, err := netip.ParseAddrPort(addr.String())
		return ap, err == nil
	}
}

func handleUDPToLocal(writeBack C.WriteBack, pc C.PacketConn, sender C.PacketSender, key udpkey.FlowKey, lAddr string, oAddrPort netip.AddrPort) {
	defer func() {
		sender.Close()
		_ = pc.Close()
		closeAllLocalCoon(lAddr)
		natTable.Delete(key)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			return
		}

		fromAddrPort, ok := addrPortFromNetAddr(from)
		if !ok || !fromAddrPort.IsValid() {
			log.Warnln("server return a [%T](%s) which isn't a UDP address, force replace to (%s), this may be caused by a wrongly implemented server", from, from, oAddrPort)
			fromAddrPort = oAddrPort
		}

		fromAddr := sender.RestoreReadFrom(fromAddrPort.Addr().Unmap()).Unmap()
		fromAddrPort = netip.AddrPortFrom(fromAddr, fromAddrPort.Port())

		_, err = writeBack.WriteBack(buf.As(data), fromAddrPort)
		if put != nil {
			put()
		}
		if err != nil {
			return
		}
	}
}

func closeAllLocalCoon(lAddr string) {
	natTable.RangeForLocalConn(lAddr, func(key string, value *net.UDPConn) bool {
		conn := value

		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", lAddr, key)
		return true
	})
}

func handleSocket(inbound, outbound net.Conn) {
	N.Relay(inbound, outbound)
}
