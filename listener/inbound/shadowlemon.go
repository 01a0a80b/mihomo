package inbound

import (
	"context"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	slcrypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
	slprotocol "github.com/metacubex/mihomo/transport/shadowlemon/protocol"
	"github.com/metacubex/mihomo/transport/socks5"
)

// ShadowLemon is the inbound listener for the ShadowLemon V0.2 encrypted proxy
// protocol. It accepts CONNECT and UDP ASSOCIATE sessions over a single UDP
// socket and hands each one to the mihomo tunnel.
type ShadowLemon struct {
	*Base
	option *ShadowLemonOption
	server *slprotocol.Server
	cancel context.CancelFunc
}

// ShadowLemonOption is the inbound configuration decoded from `listeners:`.
type ShadowLemonOption struct {
	BaseOption
	Users            map[string]string `inbound:"users"`
	MTU              int               `inbound:"mtu,omitempty"`
	DeploymentSecret string            `inbound:"deployment-secret,omitempty"`
}

func NewShadowLemon(option *ShadowLemonOption) (*ShadowLemon, error) {
	base, err := NewBase(&option.BaseOption)
	if err != nil {
		return nil, err
	}

	secret := []byte(option.DeploymentSecret)
	if len(secret) == 0 {
		secret, err = slcrypto.DeploymentSecret()
		if err != nil {
			return nil, err
		}
	}

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1400
	}

	users := make(map[string]slprotocol.User, len(option.Users))
	for username, password := range option.Users {
		users[username] = slprotocol.FromPassword(username, password, nil)
	}

	listenAddr := base.RawAddress()
	server, err := slprotocol.NewServer(listenAddr, users, secret, mtu)
	if err != nil {
		return nil, fmt.Errorf("create shadowlemon server: %w", err)
	}

	return &ShadowLemon{
		Base:   base,
		option: option,
		server: server,
	}, nil
}

func (s *ShadowLemon) Config() C.InboundConfig {
	return s.option
}

func (s *ShadowLemon) Listen(tunnel C.Tunnel) error {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go func() {
		_ = s.server.Serve()
	}()

	additions := s.Additions()
	go func() {
		for {
			accepted, err := s.server.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if accepted.IsUDP {
				go s.handleUDP(accepted, tunnel, additions)
			} else {
				go s.handleTCP(accepted, tunnel, additions)
			}
		}
	}()

	return nil
}

func (s *ShadowLemon) handleTCP(accepted *slprotocol.AcceptedConn, tunnel C.Tunnel, additions []inbound.Addition) {
	_, metadata := inbound.NewSocket(socks5.ParseAddr(accepted.Target), accepted.Conn, C.SHADOWLEMON, additions...)
	tunnel.HandleTCPConn(accepted.Conn, metadata)
}

func (s *ShadowLemon) handleUDP(accepted *slprotocol.AcceptedConn, tunnel C.Tunnel, additions []inbound.Addition) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := accepted.PacketConn.ReadFrom(buf)
		if err != nil {
			return
		}
		target := accepted.Target
		if addr != nil && addr.String() != "" {
			target = addr.String()
		}
		packet := &shadowLemonPacket{
			data: append([]byte(nil), buf[:n]...),
			pc:   accepted.PacketConn,
			addr: accepted.PacketConn.LocalAddr(),
		}
		_, metadata := inbound.NewPacket(socks5.ParseAddr(target), packet, C.SHADOWLEMON, additions...)
		tunnel.HandleUDPPacket(packet, metadata)
	}
}

type shadowLemonPacket struct {
	data []byte
	pc   net.PacketConn
	addr net.Addr
}

func (p *shadowLemonPacket) Data() []byte { return p.data }
func (p *shadowLemonPacket) WriteBack(b []byte, _ net.Addr) (int, error) {
	return p.pc.WriteTo(b, p.addr)
}
func (p *shadowLemonPacket) LocalAddr() net.Addr { return p.pc.LocalAddr() }
func (p *shadowLemonPacket) Drop()               {}

func (s *ShadowLemon) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return s.server.Close()
}

var _ C.InboundListener = (*ShadowLemon)(nil)

func (o ShadowLemonOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}
