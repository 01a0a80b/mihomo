package tproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/net/udpkey"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing/common/buf"
)

type packet struct {
	Buffer    *buf.Buffer
	pc        net.PacketConn
	lAddr     netip.AddrPort
	tunnel    C.Tunnel
	additions []inbound.Addition
	flowKey   udpkey.FlowKey
}

func (c *packet) FlowKey() udpkey.FlowKey {
	return c.flowKey
}

func (c *packet) WriteBack(b *buf.Buffer, src netip.AddrPort) (int, error) {
	tc, err := createOrGetLocalConn(src, c.lAddr, c.flowKey.Inbound, c.tunnel, c.additions...)
	if err != nil {
		return 0, err
	}
	return tc.Write(b.Bytes())
}

// this function listen at rAddr and write to lAddr
// for here, rAddr is the ip/port client want to access
// lAddr is the ip/port client opened
func createOrGetLocalConn(rAddr, lAddr netip.AddrPort, inboundID uint32, tunnel C.Tunnel, additions ...inbound.Addition) (*net.UDPConn, error) {
	remote := rAddr.String()
	local := lAddr.String()
	natTable := tunnel.NatTable()
	localConn := natTable.GetForLocalConn(local, remote)
	// localConn not exist
	if localConn == nil {
		cond, loaded := natTable.GetOrCreateLockForLocalConn(local, remote)
		if loaded {
			cond.L.Lock()
			cond.Wait()
			// we should get localConn here
			localConn = natTable.GetForLocalConn(local, remote)
			if localConn == nil {
				return nil, fmt.Errorf("localConn is nil, nat entry not exist")
			}
			cond.L.Unlock()
		} else {
			if cond == nil {
				return nil, fmt.Errorf("cond is nil, nat entry not exist")
			}
			defer func() {
				natTable.DeleteLockForLocalConn(local, remote)
				cond.Broadcast()
			}()
			conn, err := listenLocalConn(rAddr, lAddr, inboundID, tunnel, additions...)
			if err != nil {
				log.Errorln("listenLocalConn failed with error: %s, packet loss (rAddr[%T]=%s lAddr[%T]=%s)", err.Error(), rAddr, remote, lAddr, local)
				return nil, err
			}
			natTable.AddForLocalConn(local, remote, conn)
			localConn = conn
		}
	}
	return localConn, nil
}

// this function listen at rAddr
// and send what received to program itself, then send to real remote
func listenLocalConn(rAddr, lAddr netip.AddrPort, inboundID uint32, tunnel C.Tunnel, additions ...inbound.Addition) (*net.UDPConn, error) {
	lc, err := dialUDP("udp", rAddr, lAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Debugln("TProxy listenLocalConn rAddr=%s lAddr=%s", rAddr, lAddr)
		for {
			b := buf.NewPacket()
			br, err := lc.Read(b.FreeBytes())
			if err != nil {
				b.Release()
				if errors.Is(err, net.ErrClosed) {
					log.Debugln("TProxy local conn listener exit.. rAddr=%s lAddr=%s", rAddr, lAddr)
					return
				}
				continue
			}
			b.Truncate(br)
			// since following localPackets are pass through this socket which listen rAddr
			// I choose current listener as packet's packet conn
			handlePacketConn(lc, tunnel, b, lAddr, rAddr, inboundID, additions...)
		}
	}()
	return lc, nil
}
