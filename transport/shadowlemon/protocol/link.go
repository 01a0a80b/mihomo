package shadowlemonprotocol

import (
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// frameWriter sends an already-encrypted wire frame on the transport socket.
type frameWriter func(kind byte, sessionID uint32, frame []byte)

// sessionLink drives one Session: it owns a background ticker goroutine that
// pumps outbound frames and a Drop-like shutdown. Data frames leaving the
// session are routed with UDPKindSessionData (client) or UDPKindSessionReply
// (server); ACKs produced by the ticker use the same kind as data on the client
// path (matching Rust) while server ACKs use reply.
type sessionLink struct {
	session   *Session
	sessionID uint32
	write     frameWriter
	outKind   byte
	done      chan struct{}
	closeOnce sync.Once
	wake      chan struct{}
}

func newSessionLink(sessionID uint32, outKind byte, write frameWriter) *sessionLink {
	return &sessionLink{
		sessionID: sessionID, outKind: outKind,
		write: write, done: make(chan struct{}), wake: make(chan struct{}, 1),
	}
}

// attach installs the Session and starts the background ticker exactly once.
func (l *sessionLink) attach(session *Session) {
	l.session = session
	go l.run()
}

func (l *sessionLink) notify() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *sessionLink) flushFrames() {
	for {
		frame := l.session.PollOutput()
		if frame == nil {
			return
		}
		l.write(l.outKind, l.sessionID, frame)
	}
}

func (l *sessionLink) run() {
	for {
		deadline := l.session.NextTimer()
		if deadline.IsZero() {
			deadline = time.Now().Add(50 * time.Millisecond)
		}
		wait := time.NewTimer(time.Until(deadline))
		select {
		case <-l.done:
			if !wait.Stop() {
				<-wait.C
			}
			return
		case <-l.wake:
			if !wait.Stop() {
				<-wait.C
			}
		case <-wait.C:
		}
		if l.session.IsClosed() {
			return
		}
		_ = l.session.Tick(time.Now())
		l.flushFrames()
	}
}

// feed delivers an inbound data/reply frame into the session and flushes ACKs.
func (l *sessionLink) feed(frame []byte) error {
	if err := l.session.OnFrame(frame, time.Now()); err != nil {
		return err
	}
	l.flushFrames()
	l.notify()
	return nil
}

func (l *sessionLink) close() {
	l.closeOnce.Do(func() {
		close(l.done)
	})
}

// streamConn is the net.Conn facade for CONNECT. Application bytes are carried
// in SOCKS5 UDP datagrams (header + payload) over the reliable session, exactly
// like Rust's DatagramStream.
type streamConn struct {
	link         *sessionLink
	local        net.Addr
	remote       net.Addr
	target       SocksAddress
	port         uint16
	assembler    *FragmentAssembler
	pending      chan []byte
	mu           sync.Mutex
	closed       atomic.Bool
	readDeadline time.Time
	writeBuf     []byte
}

func newStreamConn(link *sessionLink, local, remote net.Addr, target SocksAddress, port uint16) *streamConn {
	return &streamConn{
		link: link, local: local, remote: remote, target: target, port: port,
		assembler: NewFragmentAssembler(), pending: make(chan []byte, 256),
	}
}

func (c *streamConn) Read(b []byte) (int, error) {
	for {
		select {
		case chunk := <-c.pending:
			n := copy(b, chunk)
			if n < len(chunk) {
				rest := append([]byte(nil), chunk[n:]...)
				select {
				case c.pending <- rest:
				default:
				}
			}
			return n, nil
		default:
		}
		// Pull decrypted chunks from the session and parse SOCKS5 UDP headers.
		for {
			payload, ok := c.link.session.TryRecv()
			if !ok {
				break
			}
			id, number, count, piece, ok := splitAppFragment(payload)
			if !ok {
				continue
			}
			datagram := c.assembler.Add(id, number, count, piece)
			if datagram == nil {
				continue
			}
			parsed, err := ParseUDPDatagram(datagram)
			if err != nil {
				continue
			}
			select {
			case c.pending <- parsed.Payload:
			default:
			}
		}
		if len(c.pending) > 0 {
			continue
		}
		if c.link.session.IsClosed() {
			return 0, io.EOF
		}
		// Block briefly for inbound frames (fed by the mux reader) or closure.
		select {
		case <-time.After(10 * time.Millisecond):
		case <-c.link.done:
			return 0, io.EOF
		}
	}
}

func (c *streamConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	// Streams are written as one SOCKS5 UDP datagram per Write call, optionally
	// fragmented to the MTU-derived capacity.
	datagram := EncodeUDPHeader(c.target, c.port)
	datagram = append(datagram, b...)
	fragments, err := SplitAppFragment(datagram, c.link.session.maxFragment(), 1)
	if err != nil {
		return 0, err
	}
	for _, frag := range fragments {
		if err := c.link.session.TrySend(frag); err != nil {
			return 0, err
		}
	}
	c.link.notify()
	return len(b), nil
}

func (c *streamConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.link.close()
	return c.link.session.Close(true)
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}
func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

// packetConn is the net.PacketConn facade for UDP ASSOCIATE. Each
// WriteTo/ReadFrom maps to a SOCKS5 UDP datagram over the session.
type packetConn struct {
	link      *sessionLink
	local     net.Addr
	assembler *FragmentAssembler
	pending   chan []byte
	msgID     atomic.Uint32
	closed    atomic.Bool
	maxFrag   int
}

func newPacketConn(link *sessionLink, local net.Addr, maxFrag int) *packetConn {
	return &packetConn{
		link: link, local: local, assembler: NewFragmentAssembler(),
		pending: make(chan []byte, 256), maxFrag: maxFrag,
	}
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 0 || portNum > 65535 {
		return 0, net.InvalidAddrError("bad UDP port")
	}
	pnum := uint16(portNum)
	var target SocksAddress
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip
	} else {
		target.Domain = host
	}
	datagram := EncodeUDPHeader(target, pnum)
	datagram = append(datagram, b...)
	fragments, err := SplitAppFragment(datagram, p.maxFrag, p.msgID.Add(1))
	if err != nil {
		return 0, err
	}
	for _, frag := range fragments {
		if err := p.link.session.TrySend(frag); err != nil {
			return 0, err
		}
	}
	p.link.notify()
	return len(b), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case datagram := <-p.pending:
			parsed, err := ParseUDPDatagram(datagram)
			if err != nil {
				continue
			}
			addr := SocksAddr{address: parsed.Address, port: parsed.Port}
			n := copy(b, parsed.Payload)
			return n, addr, nil
		default:
		}
		for {
			payload, ok := p.link.session.TryRecv()
			if !ok {
				break
			}
			id, number, count, piece, ok := splitAppFragment(payload)
			if !ok {
				continue
			}
			if datagram := p.assembler.Add(id, number, count, piece); datagram != nil {
				select {
				case p.pending <- datagram:
				default:
				}
			}
		}
		if len(p.pending) > 0 {
			continue
		}
		if p.link.session.IsClosed() {
			return 0, nil, io.EOF
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-p.link.done:
			return 0, nil, io.EOF
		}
	}
}

func (p *packetConn) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	p.link.close()
	return p.link.session.Close(true)
}

func (p *packetConn) LocalAddr() net.Addr              { return p.local }
func (p *packetConn) SetDeadline(time.Time) error      { return nil }
func (p *packetConn) SetReadDeadline(time.Time) error  { return nil }
func (p *packetConn) SetWriteDeadline(time.Time) error { return nil }

// SocksAddr implements net.Addr for a decrypted UDP source/destination.
type SocksAddr struct {
	address SocksAddress
	port    uint16
}

func (a SocksAddr) Network() string { return "udp" }
func (a SocksAddr) String() string  { return AddressString(a.address, a.port) }

// maxFragment is defined on Session; add accessors via extension helper.
func (s *Session) maxFragment() int { return maxFragment }
