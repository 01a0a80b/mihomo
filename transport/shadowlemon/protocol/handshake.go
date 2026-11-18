package shadowlemonprotocol

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
	wire "github.com/metacubex/mihomo/transport/shadowlemon/wire"
)

const handshakeTimeout = 10 * time.Second

// Established is the result of a completed handshake on either peer.
type Established struct {
	SessionID   uint32
	Suite       byte
	C2SKey      []byte
	S2CKey      []byte
	EarlyC2SKey []byte
	EarlyS2CKey []byte
	Piggyback   []byte
	User        string
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func randomNonce() []byte { return randomBytes(wire.NonceLen) }
func randomSalt() []byte  { return randomBytes(crypto.SaltLen) }

func randomPadding(max int) []byte { return randomBytes(int(randUint(uint64(max + 1)))) }

func randUint(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	var v [8]byte
	_, _ = rand.Read(v[:])
	return binary.LittleEndian.Uint64(v[:]) % n
}

// negotiateSuite returns the first server-preferred suite the client also offered.
func negotiateSuite(client, serverOrder []byte) byte {
	preferred := serverOrder
	if len(preferred) == 0 {
		preferred = []byte{crypto.SuiteXChaCha20Poly1305, crypto.SuiteAes256Gcm, crypto.SuiteAes128Gcm}
	}
	for _, s := range preferred {
		for _, c := range client {
			if s == c {
				return s
			}
		}
	}
	return 255
}

func sealHandshakeFrame(aead cipher.AEAD, typ byte, sessionID uint32, payload, suffix []byte, nonce []byte) ([]byte, error) {
	meta := &wire.Metadata{
		Type:       typ,
		SessionID:  sessionID,
		PayloadLen: uint16(len(payload)),
		SuffixLen:  byte(len(suffix)),
	}
	return sealV2Frame(aead, aead, meta, payload, nil, suffix, nonce)
}

// ClientHandshake is the client-side 1-RTT handshake state machine (datagram mode).
type ClientHandshake struct {
	username   string
	credential []byte
	staticKey  []byte
	suites     []byte
	sessionID  uint32
	deployment []byte
	envelope   cipher.AEAD
	nonce      []byte
	ephPriv    []byte
	clientSalt []byte
	requestAt  time.Time
	state      int // 0 ready, 1 awaiting, 2 established, 3 failed
}

// NewClientHandshake prepares a client handshake. credential is the 32-byte
// user credential; use ClientHandshakeFromPassword for a plain password.
func NewClientHandshake(username string, credential []byte, suites []byte, sessionID uint32, deploymentSecret []byte) (*ClientHandshake, error) {
	if sessionID == 0 || username == "" || len(suites) == 0 || len(suites) > crypto.MaxHandshakeSuites || len(credential) != crypto.KeyLen {
		return nil, fmt.Errorf("%w: invalid client handshake configuration", ErrMalformed)
	}
	seen := map[byte]bool{}
	for _, s := range suites {
		if !validSuite(s) || seen[s] {
			return nil, fmt.Errorf("%w: invalid suite list", ErrMalformed)
		}
		seen[s] = true
	}
	staticKey, err := crypto.DeriveStaticKey(credential, suites[0])
	if err != nil {
		return nil, err
	}
	envelope, err := crypto.NewAEAD(suites[0], staticKey)
	if err != nil {
		return nil, err
	}
	nonce := randomNonce()
	hint := crypto.UserHint(deploymentSecret, []byte(username), nonce)
	copy(nonce[len(nonce)-crypto.HintLen:], hint[:])
	return &ClientHandshake{
		username: username, credential: append([]byte(nil), credential...), staticKey: staticKey,
		suites: append([]byte(nil), suites...), sessionID: sessionID,
		deployment: append([]byte(nil), deploymentSecret...), envelope: envelope, nonce: nonce,
	}, nil
}

// ClientHandshakeFromPassword derives the credential from a plain password.
func ClientHandshakeFromPassword(username, password string, suites []byte, sessionID uint32, deploymentSecret []byte) (*ClientHandshake, error) {
	return NewClientHandshake(username, crypto.CredentialFromPasswordDouble(password, username), suites, sessionID, deploymentSecret)
}

// EarlyKeys derives the 0-RTT directional keys from the static key and session id.
func (c *ClientHandshake) EarlyKeys() (c2s, s2c []byte, err error) {
	return crypto.DeriveEarlyKeys(c.staticKey, c.sessionID, c.suites[0])
}

// BuildRequest builds and encrypts the openSessionRequest frame. A two-byte
// little-endian length prefix precedes the piggyback; the rest of the padded
// region is random. The total payload length is drawn from
// [MaxSessionPayload-PIGGYBACK_SLACK, MaxSessionPayload].
func (c *ClientHandshake) BuildRequest(piggyback []byte) ([]byte, error) {
	if c.state != 0 {
		return nil, fmt.Errorf("%w: a client handshake emits exactly one request", ErrMalformed)
	}
	priv, pub, err := crypto.GenerateX25519()
	if err != nil {
		return nil, err
	}
	salt := randomSalt()
	req := &HandshakeRequest{
		VersionMin: crypto.ProtocolVersion,
		VersionMax: crypto.ProtocolVersion,
		Suites:     c.suites,
		EphPub:     pub,
		ClientSalt: salt,
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	reqBytes := req.marshal()
	capacity := wire.MaxSessionPayload - (crypto.HandshakeRequestFixedLen + len(c.suites)) - int(randUint(uint64(piggybackSlack+1)))
	if capacity < 2 {
		capacity = 2
	}
	usable := capacity - 2
	attached := len(piggyback)
	if attached > usable {
		attached = usable
	}
	payload := make([]byte, 0, len(reqBytes)+capacity)
	payload = append(payload, reqBytes...)
	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(attached))
	payload = append(payload, lenBuf[:]...)
	payload = append(payload, piggyback[:attached]...)
	// Pad the remainder of the region with random bytes.
	for len(payload) < len(reqBytes)+capacity {
		payload = append(payload, byte(randUint(256)))
	}
	suffix := randomPadding(wire.MaxSuffixPadding)
	frame, err := sealHandshakeFrame(c.envelope, wire.TypeOpenSessionRequest, c.sessionID, payload, suffix, c.nonce)
	if err != nil {
		return nil, err
	}
	c.ephPriv, c.clientSalt = priv, salt
	c.state = 1
	c.requestAt = time.Now()
	return frame, nil
}

// ProcessResponse decrypts and validates the openSessionResponse, installing
// the forward-secret session keys. status=2 short-circuits version/suite checks.
func (c *ClientHandshake) ProcessResponse(frame []byte) (*Established, error) {
	if c.state != 1 {
		return nil, fmt.Errorf("%w: no response expected in this state", ErrMalformed)
	}
	if time.Since(c.requestAt) > handshakeTimeout {
		return nil, ErrTimeout
	}
	meta, payload, err := openV2Frame(c.envelope, c.envelope, frame)
	if err != nil {
		return nil, err
	}
	if meta.Type != wire.TypeOpenSessionResponse || meta.SessionID != c.sessionID {
		return nil, fmt.Errorf("%w: unexpected response type or session id", ErrMalformed)
	}
	if len(payload) < crypto.HandshakeResponseLen {
		return nil, fmt.Errorf("%w: short handshake response", ErrMalformed)
	}
	resp, err := parseResponse(payload[:crypto.HandshakeResponseLen])
	if err != nil {
		return nil, err
	}
	if resp.Status == statusNoSuite {
		c.state = 3
		return nil, ErrNoCommonSuite
	}
	found := false
	for _, s := range c.suites {
		if s == resp.Suite {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: server selected unoffered suite %d", ErrMalformed, resp.Suite)
	}
	shared, err := crypto.X25519Shared(c.ephPriv, resp.EphPub)
	if err != nil {
		return nil, err
	}
	c2s, s2c, err := crypto.DeriveSessionKeys(c.staticKey, c.clientSalt, resp.ServerSalt, shared, resp.Suite)
	if err != nil {
		return nil, err
	}
	earlyC2S, earlyS2C, err := c.EarlyKeys()
	if err != nil {
		return nil, err
	}
	c.state = 2
	c.ephPriv, c.clientSalt = nil, nil
	return &Established{
		SessionID: c.sessionID, Suite: resp.Suite, C2SKey: c2s, S2CKey: s2c,
		EarlyC2SKey: earlyC2S, EarlyS2CKey: earlyS2C,
		Piggyback: append([]byte(nil), payload[crypto.HandshakeResponseLen:]...),
	}, nil
}

// ServerHandshake is the server-side handshake state machine.
type ServerHandshake struct {
	registry      *UserRegistry
	users         map[string]User
	allowedSuites []byte
	sessionID     uint32
	deployment    []byte
	source        SourceTag
	state         int
	mu            sync.Mutex
}

// NewServerHandshake prepares a server handshake. users is the authoritative
// user store keyed by name; allowedSuites is the server preference (empty means
// all suites in canonical order).
func NewServerHandshake(registry *UserRegistry, users map[string]User, allowedSuites []byte, sessionID uint32, deploymentSecret []byte, source SourceTag) (*ServerHandshake, error) {
	if sessionID == 0 {
		return nil, fmt.Errorf("%w: session id 0 is reserved", ErrMalformed)
	}
	if len(allowedSuites) == 0 {
		allowedSuites = []byte{crypto.SuiteXChaCha20Poly1305, crypto.SuiteAes256Gcm, crypto.SuiteAes128Gcm}
	}
	return &ServerHandshake{
		registry: registry, users: users, allowedSuites: append([]byte(nil), allowedSuites...),
		sessionID: sessionID, deployment: append([]byte(nil), deploymentSecret...), source: source,
	}, nil
}

// ServerResult is the outcome of accepting a handshake request.
type ServerResult struct {
	Response    []byte // encrypted response frame; nil on silent rejection
	Established *Established
	Piggyback   []byte
	User        string
	NoSuite     bool
}

// Accept authenticates one openSessionRequest frame. Any error is a silent drop.
func (s *ServerHandshake) Accept(frame []byte) (*ServerResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != 0 {
		return nil, fmt.Errorf("%w: server handshake already consumed a request", ErrMalformed)
	}
	if len(frame) < wire.NonceAndMetaLen {
		s.state = 1
		return nil, fmt.Errorf("%w: short handshake frame", ErrMalformed)
	}
	nonce := frame[:wire.NonceLen]
	candidates := s.registry.Candidates(nonce)

	// Try each candidate × each suite; a tag match authenticates the user.
	var (
		matchedUser  User
		matchedSuite byte
		staticKey    []byte
		envelope     cipher.AEAD
		meta         *wire.Metadata
		payload      []byte
	)
	for _, name := range candidates {
		u, ok := s.users[name]
		if !ok || len(u.Credential) != crypto.KeyLen {
			continue
		}
		suites := u.Suites
		if len(suites) == 0 {
			suites = []byte{crypto.SuiteXChaCha20Poly1305, crypto.SuiteAes256Gcm, crypto.SuiteAes128Gcm}
		}
		for _, suite := range suites {
			if !validSuite(suite) {
				continue
			}
			key, err := crypto.DeriveStaticKey(u.Credential, suite)
			if err != nil {
				continue
			}
			aead, err := crypto.NewAEAD(suite, key)
			if err != nil {
				continue
			}
			m, p, err := openV2Frame(aead, aead, frame)
			if err != nil {
				continue
			}
			if m.Type == wire.TypeOpenSessionRequest {
				matchedUser, matchedSuite, staticKey, envelope, meta, payload = u, suite, key, aead, m, p
				break
			}
		}
		if envelope != nil {
			break
		}
	}
	if envelope == nil {
		s.state = 1
		return nil, ErrAuthentication
	}
	if meta.SessionID != s.sessionID {
		s.state = 1
		return nil, fmt.Errorf("%w: unexpected request session id", ErrMalformed)
	}
	// First version byte is checked before the structured parse so legacy peers
	// never receive a single byte back.
	if len(payload) == 0 || payload[0] != crypto.ProtocolVersion {
		s.state = 1
		return nil, fmt.Errorf("%w: %d", ErrVersion, firstByte(payload))
	}
	req, consumed, err := parseRequest(payload)
	if err != nil {
		s.state = 1
		return nil, err
	}
	region := payload[consumed:]
	if len(region) < 2 {
		s.state = 1
		return nil, fmt.Errorf("%w: missing piggyback length prefix", ErrMalformed)
	}
	pbLen := int(binary.LittleEndian.Uint16(region[:2]))
	if len(region) < 2+pbLen {
		s.state = 1
		return nil, fmt.Errorf("%w: piggyback length exceeds region", ErrMalformed)
	}
	piggyback := append([]byte(nil), region[2:2+pbLen]...)

	responseNonce := randomNonce()
	suite := negotiateSuite(req.Suites, s.allowedSuites)
	if suite == 255 {
		failBytes := noSuiteResponse().marshal()
		respFrame, err := sealHandshakeFrame(envelope, wire.TypeOpenSessionResponse, s.sessionID, failBytes[:], randomPadding(wire.MaxSuffixPadding), responseNonce)
		if err != nil {
			return nil, err
		}
		s.state = 2
		return &ServerResult{Response: respFrame, NoSuite: true}, nil
	}

	ephPriv, ephPub, err := crypto.GenerateX25519()
	if err != nil {
		return nil, err
	}
	serverSalt := randomSalt()
	shared, err := crypto.X25519Shared(ephPriv, req.EphPub)
	if err != nil {
		return nil, err
	}
	c2s, s2c, err := crypto.DeriveSessionKeys(staticKey, req.ClientSalt, serverSalt, shared, suite)
	if err != nil {
		return nil, err
	}
	earlyC2S, earlyS2C, err := crypto.DeriveEarlyKeys(staticKey, s.sessionID, matchedSuite)
	if err != nil {
		return nil, err
	}
	resp := &HandshakeResponse{
		Status: statusOK, Version: crypto.ProtocolVersion, Suite: suite,
		EphPub: ephPub, ServerSalt: serverSalt,
	}
	respBytes := resp.marshal()
	respFrame, err := sealHandshakeFrame(envelope, wire.TypeOpenSessionResponse, s.sessionID, respBytes[:], randomPadding(wire.MaxSuffixPadding), responseNonce)
	if err != nil {
		return nil, err
	}
	s.state = 3
	return &ServerResult{
		Response: respFrame,
		Established: &Established{
			SessionID: s.sessionID, Suite: suite, C2SKey: c2s, S2CKey: s2c,
			EarlyC2SKey: earlyC2S, EarlyS2CKey: earlyS2C, User: matchedUser.Name,
		},
		Piggyback: piggyback,
		User:      matchedUser.Name,
	}, nil
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
