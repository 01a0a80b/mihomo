package mieru

import (
	"errors"
	"io"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/net/udpkey"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"

	"github.com/metacubex/sing/common/buf"
)

func Handle(conn net.Conn, tunnel C.Tunnel, request *mierumodel.Request, additions ...inbound.Addition) {
	// Return a fake response to the client.
	resp := &mierumodel.Response{
		Reply: mieruconstant.Socks5ReplySuccess,
		BindAddr: mierumodel.AddrSpec{
			IP:   net.IPv4zero,
			Port: 0,
		},
	}
	if err := resp.WriteToSocks5(conn); err != nil {
		conn.Close()
		return
	}
	user := conn.(mierucommon.UserContext).UserName()
	// Handle the connection with tunnel.
	switch request.Command {
	case mieruconstant.Socks5ConnectCmd: // TCP
		metadata := &C.Metadata{
			NetWork: C.TCP,
			Type:    C.MIERU,
			DstPort: uint16(request.DstAddr.Port),
		}
		if request.DstAddr.FQDN != "" {
			metadata.Host = request.DstAddr.FQDN
		} else if request.DstAddr.IP != nil {
			metadata.DstIP, _ = netip.AddrFromSlice(request.DstAddr.IP)
			metadata.DstIP = metadata.DstIP.Unmap()
		}
		inbound.ApplyAdditions(
			metadata,
			inbound.WithInUser(user),
			inbound.WithSrcAddr(conn.RemoteAddr()),
			inbound.WithInAddr(conn.LocalAddr()),
		)
		inbound.ApplyAdditions(metadata, additions...)
		tunnel.HandleTCPConn(conn, metadata)
	case mieruconstant.Socks5UDPAssociateCmd: // UDP
		inboundID := udpkey.NextInbound()
		additions = append(additions, inbound.WithInUser(user))
		pc := mierucommon.NewPacketOverStreamTunnel(conn)
		ep := N.NewEnhancePacketConn(pc)
		defer ep.Close()
		for {
			data, put, addr, err := ep.WaitReadFrom()
			if err != nil {
				if put != nil {
					put()
				}
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
					break
				}
				continue
			}
			b := buf.NewPacket()
			b.Write(data)
			if put != nil {
				put()
			}
			target, payload, err := socks5.DecodeUDPPacket(b.Bytes())
			if err != nil {
				b.Release()
				return
			}
			b.Advance(len(b.Bytes()) - len(payload))
			flow := udpkey.Make(inboundID, flowAddrPort(addr))
			pkt := &packet{
				Buffer:  b,
				pc:      ep,
				addr:    addr,
				flowKey: flow,
			}
			_, metadata := inbound.NewPacket(target, pkt, C.MIERU, additions...)
			up := C.NewUDPPacket(pkt.Buffer, metadata, flow, pkt)
			tunnel.HandleUDPPacket(up, metadata)
		}
	}
}

type packet struct {
	Buffer  *buf.Buffer
	pc      net.PacketConn
	addr    net.Addr
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

func (c *packet) FlowKey() udpkey.FlowKey {
	return c.flowKey
}

func (c *packet) WriteBack(b *buf.Buffer, src netip.AddrPort) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.AddrFromStdAddrPort(src), b.Bytes())
	if err != nil {
		return 0, err
	}
	return c.pc.WriteTo(packet, c.addr)
}
