package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	slcrypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
	slprotocol "github.com/metacubex/mihomo/transport/shadowlemon/protocol"
)

// ShadowLemon is the outbound adapter for the ShadowLemon V0.2 encrypted
// proxy protocol. The protocol runs over UDP and carries SOCKS5 CONNECT and
// UDP ASSOCIATE requests through a user-space reliable layer.
type ShadowLemon struct {
	*Base
	option *ShadowLemonOption
	client *slprotocol.Client
}

// ShadowLemonOption is the proxy configuration decoded from `proxies:`.
type ShadowLemonOption struct {
	BasicOption
	Name             string   `proxy:"name"`
	Server           string   `proxy:"server"`
	Port             int      `proxy:"port"`
	Username         string   `proxy:"username"`
	Password         string   `proxy:"password"`
	UDP              bool     `proxy:"udp,omitempty"`
	MTU              int      `proxy:"mtu,omitempty"`
	CipherSuites     []string `proxy:"cipher-suites,omitempty"`
	DeploymentSecret string   `proxy:"deployment-secret,omitempty"`
}

func (s *ShadowLemon) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	target := net.JoinHostPort(metadata.String(), strconv.Itoa(int(metadata.DstPort)))
	conn, err := s.client.DialContext(ctx, target)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, s), nil
}

func (s *ShadowLemon) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := s.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, s), nil
}

func (s *ShadowLemon) SupportUDP() bool {
	return s.option.UDP
}

func (s *ShadowLemon) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func (s *ShadowLemon) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func NewShadowLemon(option ShadowLemonOption) (*ShadowLemon, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	secret := []byte(option.DeploymentSecret)
	if len(secret) == 0 {
		var err error
		secret, err = slcrypto.DeploymentSecret()
		if err != nil {
			return nil, err
		}
	}

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1400
	}

	client, err := slprotocol.NewClient(addr, option.Username, option.Password, secret, mtu)
	if err != nil {
		return nil, fmt.Errorf("create shadowlemon client: %w", err)
	}

	outbound := &ShadowLemon{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.ShadowLemon,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		client: client,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
