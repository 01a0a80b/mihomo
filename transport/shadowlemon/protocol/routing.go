package shadowlemonprotocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
)

const (
	UDPKindHandshakeRequest  byte = 1
	UDPKindHandshakeResponse byte = 2
	UDPKindSessionData       byte = 3
	UDPKindSessionReply      byte = 4
	udpEnvelopeLen                = 5
	appFragmentHeaderLen          = 6

	// SOCKS5 constants.
	socksVersion     byte = 5
	socksCmdConnect  byte = 0x01
	socksCmdUDPAssoc byte = 0x03
	atypIPv4         byte = 0x01
	atypDomain       byte = 0x03
	atypIPv6         byte = 0x04
	maxUDPDatagram        = 65536
)

// WrapUDP builds the masked 5-byte routing envelope in front of a wire frame.
// keystream = SHA256(secret || frame[0:4])[:5]; plain = kind||u32be(sessionID).
func WrapUDP(kind byte, sessionID uint32, frame []byte, secret []byte) []byte {
	salt := frame
	if len(salt) > 4 {
		salt = salt[:4]
	}
	ks := envelopeKeystream(secret, salt)
	id := sessionID
	out := make([]byte, 0, udpEnvelopeLen+len(frame))
	out = append(out, kind^ks[0])
	for i := 0; i < 4; i++ {
		out = append(out, byte(id>>(24-8*i))^ks[1+i])
	}
	out = append(out, frame...)
	return out
}

// UnwrapUDP reverses WrapUDP, validating the masked kind.
func UnwrapUDP(datagram []byte, secret []byte) (kind byte, sessionID uint32, frame []byte, ok bool) {
	if len(datagram) < udpEnvelopeLen+4 {
		return 0, 0, nil, false
	}
	ks := envelopeKeystream(secret, datagram[udpEnvelopeLen:udpEnvelopeLen+4])
	k := datagram[0] ^ ks[0]
	var id uint32
	for i := 0; i < 4; i++ {
		id = id<<8 | uint32(datagram[1+i]^ks[1+i])
	}
	if k < UDPKindHandshakeRequest || k > UDPKindSessionReply {
		return 0, 0, nil, false
	}
	return k, id, datagram[udpEnvelopeLen:], true
}

// SplitAppFragment splits a datagram into fragments prefixed with
// [messageID u32be][fragmentNumber][fragmentCount]. Numbers count down to zero.
func SplitAppFragment(data []byte, maxFragment int, id uint32) ([][]byte, error) {
	if maxFragment <= 0 {
		return nil, fmt.Errorf("shadowlemon: no room for application data")
	}
	pieces := (len(data) + maxFragment - 1) / maxFragment
	if pieces == 0 {
		pieces = 1
	}
	if pieces > 256 {
		return nil, fmt.Errorf("shadowlemon: datagram needs too many fragments")
	}
	count := byte(pieces)
	out := make([][]byte, 0, pieces)
	for i := 0; i < pieces; i++ {
		start := i * maxFragment
		end := start + maxFragment
		if end > len(data) {
			end = len(data)
		}
		piece := make([]byte, appFragmentHeaderLen+end-start)
		binary.BigEndian.PutUint32(piece[:4], id)
		piece[4] = count - 1 - byte(i)
		piece[5] = count
		copy(piece[appFragmentHeaderLen:], data[start:end])
		out = append(out, piece)
	}
	return out, nil
}

// FragmentAssembler reassembles descending-numbered application fragments.
type FragmentAssembler struct {
	parts map[uint32]map[byte][]byte
	count map[uint32]byte
}

func NewFragmentAssembler() *FragmentAssembler {
	return &FragmentAssembler{parts: make(map[uint32]map[byte][]byte), count: make(map[uint32]byte)}
}

// Add inserts one fragment and returns the reassembled datagram when complete.
func (a *FragmentAssembler) Add(id uint32, number, count byte, piece []byte) []byte {
	if count == 0 || number >= count {
		return nil
	}
	if a.parts[id] == nil {
		a.parts[id] = make(map[byte][]byte)
	}
	a.parts[id][number] = append([]byte(nil), piece...)
	a.count[id] = count
	parts := a.parts[id]
	if len(parts) != int(count) {
		return nil
	}
	for i := byte(0); i < count; i++ {
		if _, ok := parts[i]; !ok {
			return nil
		}
	}
	var out []byte
	for i := int(count) - 1; i >= 0; i-- {
		out = append(out, parts[byte(i)]...)
	}
	delete(a.parts, id)
	delete(a.count, id)
	return out
}

func splitAppFragment(chunk []byte) (id uint32, number, count byte, piece []byte, ok bool) {
	if len(chunk) < appFragmentHeaderLen {
		return 0, 0, 0, nil, false
	}
	return binary.BigEndian.Uint32(chunk[:4]), chunk[4], chunk[5], chunk[appFragmentHeaderLen:], true
}

// SocksAddress is a SOCKS5 address (IP literal or domain name).
type SocksAddress struct {
	IP     net.IP
	Domain string
}

func (a SocksAddress) encode(out []byte) []byte {
	if a.Domain != "" {
		out = append(out, atypDomain, byte(len(a.Domain)))
		return append(out, []byte(a.Domain)...)
	}
	if ip4 := a.IP.To4(); ip4 != nil {
		out = append(out, atypIPv4)
		return append(out, ip4...)
	}
	out = append(out, atypIPv6)
	return append(out, a.IP.To16()...)
}

// EncodeSocksRequest encodes VERSION COMMAND RSV ATYP ADDR PORT.
func EncodeSocksRequest(command byte, addr SocksAddress, port uint16) []byte {
	out := []byte{socksVersion, command, 0}
	out = addr.encode(out)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(out, p[:]...)
}

// EncodeUDPHeader encodes RSV(0) FRAG(0) ATYP ADDR PORT.
func EncodeUDPHeader(addr SocksAddress, port uint16) []byte {
	out := []byte{0, 0, 0}
	out = addr.encode(out)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(out, p[:]...)
}

// SocksUDPDatagram is a parsed SOCKS5 UDP datagram header plus payload.
type SocksUDPDatagram struct {
	Address SocksAddress
	Port    uint16
	Header  []byte
	Payload []byte
}

// ParseUDPDatagram parses a SOCKS5 UDP datagram; RSV and FRAG must be zero.
func ParseUDPDatagram(packet []byte) (*SocksUDPDatagram, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, fmt.Errorf("%w: bad SOCKS5 UDP header", ErrMalformed)
	}
	pos := 3
	var addr SocksAddress
	switch packet[pos] {
	case atypIPv4:
		pos++
		if len(packet) < pos+4 {
			return nil, fmt.Errorf("%w: truncated IPv4 address", ErrMalformed)
		}
		addr.IP = net.IPv4(packet[pos], packet[pos+1], packet[pos+2], packet[pos+3])
		pos += 4
	case atypIPv6:
		pos++
		if len(packet) < pos+16 {
			return nil, fmt.Errorf("%w: truncated IPv6 address", ErrMalformed)
		}
		addr.IP = append(net.IP(nil), packet[pos:pos+16]...)
		pos += 16
	case atypDomain:
		pos++
		if pos >= len(packet) {
			return nil, fmt.Errorf("%w: missing domain length", ErrMalformed)
		}
		n := int(packet[pos])
		pos++
		if len(packet) < pos+n {
			return nil, fmt.Errorf("%w: truncated domain", ErrMalformed)
		}
		addr.Domain = string(packet[pos : pos+n])
		pos += n
	default:
		return nil, fmt.Errorf("%w: unknown ATYP", ErrMalformed)
	}
	if len(packet) < pos+2 {
		return nil, fmt.Errorf("%w: missing UDP port", ErrMalformed)
	}
	port := binary.BigEndian.Uint16(packet[pos : pos+2])
	pos += 2
	return &SocksUDPDatagram{
		Address: addr, Port: port,
		Header:  append([]byte(nil), packet[:pos]...),
		Payload: append([]byte(nil), packet[pos:]...),
	}, nil
}

// ParseSocksRequest parses a SOCKS5 CONNECT/UDP ASSOCIATE request from the
// handshake piggyback, returning the request and the number of bytes consumed.
func ParseSocksRequest(data []byte) (command byte, addr SocksAddress, port uint16, consumed int, err error) {
	if len(data) < 4 || data[0] != socksVersion {
		return 0, SocksAddress{}, 0, 0, fmt.Errorf("%w: bad SOCKS5 request", ErrMalformed)
	}
	command = data[1]
	pos := 3
	switch data[pos] {
	case atypIPv4:
		pos++
		if len(data) < pos+4 {
			return 0, SocksAddress{}, 0, 0, fmt.Errorf("%w: truncated IPv4", ErrMalformed)
		}
		addr.IP = net.IPv4(data[pos], data[pos+1], data[pos+2], data[pos+3])
		pos += 4
	case atypIPv6:
		pos++
		if len(data) < pos+16 {
			return 0, SocksAddress{}, 0, 0, fmt.Errorf("%w: truncated IPv6", ErrMalformed)
		}
		addr.IP = append(net.IP(nil), data[pos:pos+16]...)
		pos += 16
	case atypDomain:
		pos++
		if pos >= len(data) {
			return 0, SocksAddress{}, 0, 0, fmt.Errorf("%w: missing domain length", ErrMalformed)
		}
		n := int(data[pos])
		pos++
		if len(data) < pos+n {
			return 0, SocksAddress{}, 0, 0, fmt.Errorf("%w: truncated domain", ErrMalformed)
		}
		addr.Domain = string(data[pos : pos+n])
		pos += n
	default:
		return 0, SocksAddress{}, 0, 0, fmt.Errorf("%w: unknown ATYP", ErrMalformed)
	}
	if len(data) < pos+2 {
		return 0, SocksAddress{}, 0, 0, fmt.Errorf("%w: missing port", ErrMalformed)
	}
	port = binary.BigEndian.Uint16(data[pos : pos+2])
	return command, addr, port, pos + 2, nil
}

// AddressString renders a SocksAddress as "host:port".
func AddressString(addr SocksAddress, port uint16) string {
	host := addr.Domain
	if host == "" && addr.IP != nil {
		host = addr.IP.String()
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// zeroNonceHintCheck is a small helper used by tests to check a hint over a
// synthesized nonce; kept here so the deployment secret stays centralized.
func zeroNonceHintCheck(secret, username, hint []byte) bool {
	var nonce [crypto.WireNonceLen]byte
	want := crypto.UserHint(secret, username, nonce[:])
	return bytes.Equal(want[:], hint)
}
