package shadowlemonprotocol

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
)

// Client is the client-side mux exposed to mihomo outbound adapters. One Client
// owns a UDP socket shared by all sessions to the server.
type Client struct {
	serverAddr string
	server     *net.UDPAddr
	conn       *net.UDPConn
	secret     []byte
	username   string
	credential []byte
	suites     []byte
	maxFrag    int

	mu       sync.Mutex
	sessions map[uint32]*clientSession
	closed   bool
	closeCh  chan struct{}
	wg       sync.WaitGroup
}

type clientSession struct {
	id       uint32
	response chan []byte
	data     chan []byte
	once     sync.Once
}

func (s *clientSession) close() {
	s.once.Do(func() {
		close(s.response)
		close(s.data)
	})
}

// NewClient creates a client. serverAddr is "host:port"; password is hashed
// into the credential unless it is already a 32-byte hashedPassword.
func NewClient(serverAddr, username, password string, deploymentSecret []byte, mtu int) (*Client, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	credential := crypto.CredentialFromPasswordDouble(password, username)
	if len(password) == crypto.KeyLen {
		// A config-supplied hashed password is the Rust credential after the
		// first hash; the Rust key derivation hashes it once more.
		credential = crypto.HashPassword([]byte(password), []byte(username))
	}
	c := &Client{
		serverAddr: serverAddr, server: addr, conn: conn,
		secret: append([]byte(nil), deploymentSecret...), username: username,
		credential: credential,
		suites:     []byte{crypto.SuiteXChaCha20Poly1305, crypto.SuiteAes256Gcm, crypto.SuiteAes128Gcm},
		maxFrag:    mtuPayloadCapacity(mtu),
		sessions:   make(map[uint32]*clientSession), closeCh: make(chan struct{}),
	}
	c.wg.Add(1)
	go c.readLoop()
	return c, nil
}

func mtuPayloadCapacity(mtu int) int {
	if mtu <= 0 {
		mtu = 1400
	}
	// Wire frame: 24 nonce + 48 meta + up to 32 prefix + payload+16 + 32 suffix.
	// Routing envelope adds 5 bytes. Reserve conservatively, minus 6-byte app
	// fragment header.
	capacity := mtu - 24 - 48 - 32 - 16 - 32 - 5 - appFragmentHeaderLen
	if capacity < 128 {
		capacity = 128
	}
	if capacity > maxFragment {
		capacity = maxFragment
	}
	return capacity
}

func (c *Client) allocateSession() (uint32, *clientSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 100; i++ {
		var b [4]byte
		_, _ = rand.Read(b[:])
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		if _, exists := c.sessions[id]; exists {
			continue
		}
		s := &clientSession{id: id, response: make(chan []byte, 4), data: make(chan []byte, 256)}
		c.sessions[id] = s
		return id, s, nil
	}
	return 0, nil, fmt.Errorf("shadowlemon: cannot allocate session id")
}

func (c *Client) removeSession(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.sessions[id]; ok {
		s.close()
		delete(c.sessions, id)
	}
}

func (c *Client) writeFrame(kind byte, sessionID uint32, frame []byte) {
	wire := WrapUDP(kind, sessionID, frame, c.secret)
	_, _ = c.conn.WriteToUDP(wire, c.server)
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.closeCh:
				return
			default:
				continue
			}
		}
		if !from.IP.Equal(c.server.IP) || from.Port != c.server.Port {
			continue
		}
		kind, id, frame, ok := UnwrapUDP(buf[:n], c.secret)
		if !ok {
			continue
		}
		c.mu.Lock()
		s, exists := c.sessions[id]
		c.mu.Unlock()
		if !exists {
			continue
		}
		switch kind {
		case UDPKindHandshakeResponse:
			select {
			case s.response <- append([]byte(nil), frame...):
			default:
			}
		case UDPKindSessionData, UDPKindSessionReply:
			select {
			case s.data <- append([]byte(nil), frame...):
			default:
			}
		}
	}
}

// dialSession performs the common handshake and returns a ready session link.
func (c *Client) dialSession(ctx context.Context, command byte, target SocksAddress, port uint16) (*sessionLink, *clientSession, *Session, error) {
	id, cs, err := c.allocateSession()
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*sessionLink, *clientSession, *Session, error) {
		c.removeSession(id)
		return nil, nil, nil, err
	}
	handshake, err := NewClientHandshake(c.username, c.credential, c.suites, id, c.secret)
	if err != nil {
		return fail(err)
	}
	earlyC2S, earlyS2C, err := handshake.EarlyKeys()
	if err != nil {
		return fail(err)
	}
	piggyback := EncodeSocksRequest(command, target, port)
	request, err := handshake.BuildRequest(piggyback)
	if err != nil {
		return fail(err)
	}
	link := newSessionLink(id, UDPKindSessionData, c.writeFrame)
	session, err := NewSession(id, directionClient, earlyC2S, earlyS2C, c.suites[0], EmptySourceTag, true)
	if err != nil {
		return fail(err)
	}
	link.attach(session)
	c.writeFrame(UDPKindHandshakeRequest, id, request)

	select {
	case response := <-cs.response:
		est, err := handshake.ProcessResponse(response)
		if err != nil {
			return fail(err)
		}
		if err := session.UpgradeKeys(est.C2SKey, est.S2CKey, est.Suite); err != nil {
			return fail(err)
		}
		link.outKind = UDPKindSessionData
	case <-time.After(handshakeTimeout):
		return fail(ErrTimeout)
	case <-ctx.Done():
		return fail(ctx.Err())
	case <-c.closeCh:
		return fail(ErrClosed)
	}
	return link, cs, session, nil
}

// DialContext opens a CONNECT session to "host:port" and returns the decrypted
// byte stream for the mihomo outbound adapter.
func (c *Client) DialContext(ctx context.Context, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	var pnum uint16
	if _, err := fmt.Sscanf(portStr, "%d", &pnum); err != nil {
		return nil, err
	}
	var addr SocksAddress
	if ip := net.ParseIP(host); ip != nil {
		addr.IP = ip
	} else {
		addr.Domain = host
	}
	link, _, session, err := c.dialSession(ctx, socksCmdConnect, addr, pnum)
	if err != nil {
		return nil, err
	}
	conn := newStreamConn(link, c.conn.LocalAddr(), c.server, addr, pnum)
	go c.pumpSession(link, session)
	return conn, nil
}

// ListenPacket opens a UDP ASSOCIATE session and returns a decrypted PacketConn.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	var any SocksAddress
	any.IP = net.IPv4zero
	link, _, session, err := c.dialSession(ctx, socksCmdUDPAssoc, any, 0)
	if err != nil {
		return nil, err
	}
	pc := newPacketConn(link, c.conn.LocalAddr(), c.maxFrag)
	go c.pumpSession(link, session)
	return pc, nil
}

// pumpSession feeds inbound frames into the session until the link closes.
func (c *Client) pumpSession(link *sessionLink, session *Session) {
	csID := session.ID()
	c.mu.Lock()
	cs := c.sessions[csID]
	c.mu.Unlock()
	if cs == nil {
		return
	}
	for {
		select {
		case <-c.closeCh:
			return
		case <-link.done:
			return
		case frame, ok := <-cs.data:
			if !ok {
				return
			}
			_ = link.feed(frame)
		}
	}
}

// Close shuts down the client socket and all sessions.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closeCh)
	sessions := make([]*clientSession, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
		s.close()
	}
	c.sessions = make(map[uint32]*clientSession)
	c.mu.Unlock()
	_ = c.conn.Close()
	c.wg.Wait()
	return nil
}

// AcceptedConn is a connection accepted by Server.Accept, handed to the
// mihomo inbound tunnel. Exactly one of Conn / PacketConn is set.
type AcceptedConn struct {
	Conn       net.Conn
	PacketConn net.PacketConn
	Target     string
	IsUDP      bool
}

// Server is the server-side mux exposed to mihomo inbound adapters. It accepts
// ShadowLemon sessions from clients and places decrypted connections into an
// Accept queue; the adapter (via mihomo tunnel) dials the target itself.
type Server struct {
	listenAddr string
	conn       *net.UDPConn
	secret     []byte
	users      map[string]User
	registry   *UserRegistry
	suites     []byte
	maxFrag    int

	accept   chan *AcceptedConn
	mu       sync.Mutex
	sessions map[serverSessionKey]*serverSession
	closed   bool
	closeCh  chan struct{}
	wg       sync.WaitGroup
}

type serverSessionKey struct {
	source string
	id     uint32
}

type serverSession struct {
	key     serverSessionKey
	session *Session
	link    *sessionLink
	cs      *clientSession // inbound frame queue
	conn    net.Addr
}

// NewServer creates a server bound to listenAddr ("host:port").
func NewServer(listenAddr string, users map[string]User, deploymentSecret []byte, mtu int) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	userList := make([]User, 0, len(users))
	for _, u := range users {
		userList = append(userList, u)
	}
	s := &Server{
		listenAddr: listenAddr, conn: conn,
		secret: append([]byte(nil), deploymentSecret...),
		users:  users, registry: NewUserRegistry(deploymentSecret, userList),
		suites:   []byte{crypto.SuiteXChaCha20Poly1305, crypto.SuiteAes256Gcm, crypto.SuiteAes128Gcm},
		maxFrag:  mtuPayloadCapacity(mtu),
		accept:   make(chan *AcceptedConn, 64),
		sessions: make(map[serverSessionKey]*serverSession),
		closeCh:  make(chan struct{}),
	}
	return s, nil
}

// Serve runs the accept loop until Close is called.
func (s *Server) Serve() error {
	s.wg.Add(1)
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closeCh:
				return nil
			default:
				continue
			}
		}
		kind, id, frame, ok := UnwrapUDP(buf[:n], s.secret)
		if !ok || id == 0 {
			continue
		}
		switch kind {
		case UDPKindHandshakeRequest:
			s.handleHandshake(from, id, frame)
		case UDPKindSessionData, UDPKindSessionReply:
			s.handleSessionData(from, id, frame)
		}
	}
}

// Accept returns the next accepted connection, suitable for a mihomo inbound
// loop: for { ac, err := s.Accept(ctx); go handle(ac) }.
func (s *Server) Accept(ctx context.Context) (*AcceptedConn, error) {
	select {
	case ac := <-s.accept:
		return ac, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closeCh:
		return nil, ErrClosed
	}
}

func (s *Server) replyWriter(from *net.UDPAddr) frameWriter {
	return func(kind byte, sessionID uint32, frame []byte) {
		wire := WrapUDP(kind, sessionID, frame, s.secret)
		_, _ = s.conn.WriteToUDP(wire, from)
	}
}

func sourceTagFor(from *net.UDPAddr) SourceTag {
	if ip4 := from.IP.To4(); ip4 != nil {
		var b [7]byte
		b[0] = 4
		copy(b[1:5], ip4)
		binary.BigEndian.PutUint16(b[5:7], uint16(from.Port))
		return newSourceTag(b[:])
	}
	if ip16 := from.IP.To16(); ip16 != nil {
		var b [19]byte
		b[0] = 6
		copy(b[1:17], ip16)
		binary.BigEndian.PutUint16(b[17:19], uint16(from.Port))
		return newSourceTag(b[:])
	}
	return EmptySourceTag
}

func (s *Server) handleHandshake(from *net.UDPAddr, id uint32, frame []byte) {
	hs, err := NewServerHandshake(s.registry, s.users, s.suites, id, s.secret, sourceTagFor(from))
	if err != nil {
		return
	}
	result, err := hs.Accept(frame)
	if err != nil {
		return
	}
	resp := result.Response
	if result.NoSuite {
		_, _ = s.conn.WriteToUDP(WrapUDP(UDPKindHandshakeResponse, id, resp, s.secret), from)
		return
	}
	command, addr, port, _, err := ParseSocksRequest(result.Piggyback)
	if err != nil || (command != socksCmdConnect && command != socksCmdUDPAssoc) {
		return
	}
	est := result.Established
	session, err := NewSession(id, directionServer, est.C2SKey, est.S2CKey, est.Suite, sourceTagFor(from), true)
	if err != nil {
		return
	}
	link := newSessionLink(id, UDPKindSessionReply, s.replyWriter(from))
	link.attach(session)
	_ = session.UpgradeKeys(est.C2SKey, est.S2CKey, est.Suite)

	key := serverSessionKey{source: from.String(), id: id}
	cs := &clientSession{id: id, response: make(chan []byte, 4), data: make(chan []byte, 256)}
	s.mu.Lock()
	s.sessions[key] = &serverSession{key: key, session: session, link: link, cs: cs, conn: from}
	s.mu.Unlock()

	target := AddressString(addr, port)
	ac := &AcceptedConn{Target: target, IsUDP: command == socksCmdUDPAssoc}
	if ac.IsUDP {
		ac.PacketConn = newPacketConn(link, s.conn.LocalAddr(), s.maxFrag)
	} else {
		ac.Conn = newStreamConn(link, s.conn.LocalAddr(), from, addr, port)
	}
	// Send the handshake response before handing the connection to the adapter.
	_, _ = s.conn.WriteToUDP(WrapUDP(UDPKindHandshakeResponse, id, resp, s.secret), from)
	select {
	case s.accept <- ac:
	case <-s.closeCh:
	}
	go s.pumpSession(key, link, cs)
}

func (s *Server) handleSessionData(from *net.UDPAddr, id uint32, frame []byte) {
	key := serverSessionKey{source: from.String(), id: id}
	s.mu.Lock()
	sess := s.sessions[key]
	s.mu.Unlock()
	if sess == nil {
		return
	}
	select {
	case sess.cs.data <- frame:
	default:
	}
}

func (s *Server) pumpSession(key serverSessionKey, link *sessionLink, cs *clientSession) {
	defer func() {
		link.close()
		s.mu.Lock()
		delete(s.sessions, key)
		s.mu.Unlock()
	}()
	for {
		select {
		case <-s.closeCh:
			return
		case <-link.done:
			return
		case frame, ok := <-cs.data:
			if !ok {
				return
			}
			_ = link.feed(frame)
		}
	}
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	sessions := make([]*serverSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.sessions = make(map[serverSessionKey]*serverSession)
	s.mu.Unlock()
	for _, sess := range sessions {
		sess.link.close()
		_ = sess.session.Close(false)
	}
	_ = s.conn.Close()
	s.wg.Wait()
	return nil
}
