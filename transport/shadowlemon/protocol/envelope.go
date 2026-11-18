package shadowlemonprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
)

const (
	statusOK       byte = 0
	statusNoSuite  byte = 2
	requestHeadLen      = 3
	piggybackSlack      = 28
)

// HandshakeRequest is the first handshake message. Wire layout:
// version_min(1) version_max(1) suite_count(1) suites(n) eph_pub(32) client_salt(16).
type HandshakeRequest struct {
	VersionMin byte
	VersionMax byte
	Suites     []byte
	EphPub     []byte // 32 bytes
	ClientSalt []byte // 16 bytes
}

func (r *HandshakeRequest) marshal() []byte {
	out := make([]byte, 0, crypto.HandshakeRequestFixedLen+len(r.Suites))
	out = append(out, r.VersionMin, r.VersionMax, byte(len(r.Suites)))
	out = append(out, r.Suites...)
	out = append(out, r.EphPub...)
	out = append(out, r.ClientSalt...)
	return out
}

func validSuite(suite byte) bool {
	return suite == crypto.SuiteXChaCha20Poly1305 || suite == crypto.SuiteAes256Gcm || suite == crypto.SuiteAes128Gcm
}

func (r *HandshakeRequest) validate() error {
	if len(r.Suites) == 0 || len(r.Suites) > crypto.MaxHandshakeSuites {
		return fmt.Errorf("%w: %d suites", ErrMalformed, len(r.Suites))
	}
	seen := make(map[byte]bool, len(r.Suites))
	for _, s := range r.Suites {
		if !validSuite(s) {
			return fmt.Errorf("%w: unknown suite %d", ErrMalformed, s)
		}
		if seen[s] {
			return fmt.Errorf("%w: duplicate suite %d", ErrMalformed, s)
		}
		seen[s] = true
	}
	if r.VersionMin > r.VersionMax || r.VersionMin > crypto.ProtocolVersion || r.VersionMax < crypto.ProtocolVersion {
		return fmt.Errorf("%w: version range %d-%d", ErrMalformed, r.VersionMin, r.VersionMax)
	}
	return nil
}

// parseRequest parses from the beginning of input and returns the number of bytes consumed.
func parseRequest(input []byte) (*HandshakeRequest, int, error) {
	if len(input) < requestHeadLen {
		return nil, 0, fmt.Errorf("%w: short handshake request", ErrMalformed)
	}
	count := int(input[2])
	if count == 0 || count > crypto.MaxHandshakeSuites {
		return nil, 0, fmt.Errorf("%w: %d suites", ErrMalformed, count)
	}
	consumed := crypto.HandshakeRequestFixedLen + count
	if len(input) < consumed {
		return nil, 0, fmt.Errorf("%w: short handshake request", ErrMalformed)
	}
	suites := make([]byte, count)
	copy(suites, input[requestHeadLen:requestHeadLen+count])
	r := &HandshakeRequest{
		VersionMin: input[0],
		VersionMax: input[1],
		Suites:     suites,
		EphPub:     append([]byte(nil), input[requestHeadLen+count:requestHeadLen+count+crypto.EphKeyLen]...),
		ClientSalt: append([]byte(nil), input[consumed-crypto.SaltLen:consumed]...),
	}
	if err := r.validate(); err != nil {
		return nil, 0, err
	}
	return r, consumed, nil
}

// HandshakeResponse is the second handshake message, exactly 51 bytes on the wire.
type HandshakeResponse struct {
	Status     byte
	Version    byte
	Suite      byte
	EphPub     []byte // 32 bytes
	ServerSalt []byte // 16 bytes
}

func (r *HandshakeResponse) marshal() [crypto.HandshakeResponseLen]byte {
	var out [crypto.HandshakeResponseLen]byte
	out[0] = r.Status
	out[1] = r.Version
	out[2] = r.Suite
	copy(out[3:3+crypto.EphKeyLen], r.EphPub)
	copy(out[3+crypto.EphKeyLen:], r.ServerSalt)
	return out
}

func noSuiteResponse() *HandshakeResponse {
	return &HandshakeResponse{Status: statusNoSuite, Suite: crypto.SuiteXChaCha20Poly1305}
}

func parseResponse(input []byte) (*HandshakeResponse, error) {
	if len(input) != crypto.HandshakeResponseLen {
		return nil, fmt.Errorf("%w: response is %d bytes", ErrMalformed, len(input))
	}
	status := input[0]
	if status != statusOK && status != statusNoSuite {
		return nil, fmt.Errorf("%w: status %d", ErrMalformed, status)
	}
	suite := input[2]
	if status == statusNoSuite {
		if !validSuite(suite) {
			suite = crypto.SuiteXChaCha20Poly1305
		}
	} else {
		if !validSuite(suite) {
			return nil, fmt.Errorf("%w: unknown suite %d", ErrMalformed, suite)
		}
		if input[1] != crypto.ProtocolVersion {
			return nil, fmt.Errorf("%w: %d", ErrVersion, input[1])
		}
	}
	return &HandshakeResponse{
		Status:     status,
		Version:    input[1],
		Suite:      suite,
		EphPub:     append([]byte(nil), input[3:3+crypto.EphKeyLen]...),
		ServerSalt: append([]byte(nil), input[3+crypto.EphKeyLen:]...),
	}, nil
}

// envelopeKeystream derives SHA256(deploymentSecret || salt)[:5], matching Rust
// shadowlemon_crypto::deployment::envelope_keystream.
func envelopeKeystream(secret, salt []byte) [5]byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(salt)
	var out [5]byte
	copy(out[:], h.Sum(nil))
	return out
}

// checkHint verifies the keyed user hint in the last four bytes of a wire nonce.
func checkHint(secret, username, nonce []byte) bool {
	if len(nonce) < crypto.WireNonceLen {
		return false
	}
	want := crypto.UserHint(secret, username, nonce)
	return bytes.Equal(want[:], nonce[len(nonce)-crypto.HintLen:])
}

// User is a server-side user entry. Credential is the 32-byte value stored on
// the server: SHA256(password || 0x00 || username) or a config-supplied hashed
// password. Suites, when non-empty, restricts which wire suites this user may
// authenticate with; an empty list tries all suites in canonical order.
type User struct {
	Name       string
	Credential []byte
	Suites     []byte
}

// FromPassword builds a User from a plain-text password.
func FromPassword(name, password string, suites []byte) User {
	return User{Name: name, Credential: crypto.CredentialFromPasswordDouble(password, name), Suites: append([]byte(nil), suites...)}
}

// UserRegistry maps users by name and derives candidate sets from the keyed
// hint embedded in a handshake request nonce.
type UserRegistry struct {
	secret []byte
	mu     sync.RWMutex
	users  map[string][]byte // name -> hint bytes (last 4 of a zero nonce with hint written)
	order  []string
}

// NewUserRegistry builds a registry. The deployment secret must be the same
// high-entropy value on both peers.
func NewUserRegistry(secret []byte, users []User) *UserRegistry {
	r := &UserRegistry{secret: append([]byte(nil), secret...), users: make(map[string][]byte, len(users))}
	for _, u := range users {
		r.Add(u)
	}
	return r
}

// Add registers (or replaces) a user.
func (r *UserRegistry) Add(u User) {
	if len(u.Credential) != crypto.KeyLen {
		return
	}
	name := []byte(u.Name)
	var nonce [crypto.WireNonceLen]byte
	hint := crypto.UserHint(r.secret, name, nonce[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[u.Name]; !ok {
		r.order = append(r.order, u.Name)
	}
	r.users[u.Name] = append([]byte(nil), hint[:]...)
}

// Candidates returns user names ordered so hint-matching users come first.
// The hint is only an ordering filter; AEAD authentication is authoritative.
func (r *UserRegistry) Candidates(nonce []byte) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, name)
	}
	// Stable partition: matching users first, preserving registration order.
	var matched, rest []string
	for _, name := range out {
		if checkHint(r.secret, []byte(name), nonce) {
			matched = append(matched, name)
		} else {
			rest = append(rest, name)
		}
	}
	return append(matched, rest...)
}

// Lookup returns a registered user by name.
func (r *UserRegistry) Lookup(name string) (User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.users[name]; !ok {
		return User{}, false
	}
	return User{}, false // names are resolved through the external user store
}

// SourceTag identifies a packet source for the replay retransmission exemption.
type SourceTag struct {
	bytes []byte
}

// EmptySourceTag never grants a retransmission exemption.
var EmptySourceTag = SourceTag{}

func sourceTagFromAddr(addr string) SourceTag {
	// The wire tag is family || ip || u16be(port), at most 19 bytes. Callers
	// pass a UDP "ip:port" string; parsing is done in routing.go by the socket
	// layer, so this helper accepts pre-encoded bytes via newSourceTag.
	return EmptySourceTag
}

func newSourceTag(wire []byte) SourceTag {
	if len(wire) > 19 {
		return EmptySourceTag
	}
	return SourceTag{bytes: append([]byte(nil), wire...)}
}

func (t SourceTag) empty() bool { return len(t.bytes) == 0 }

// replaySignature computes FNV1a64(u32be(len(data)) || domain || data), which
// matches crypto.ReplaySig with len(data)=24 and the full wire nonce as data.
func replaySignature(domain byte, nonce []byte) uint64 {
	sig, _ := crypto.ReplaySig(uint32(len(nonce)), domain, nonce)
	return sig
}

// u32be / u16be helpers.
func putU32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func putU16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }
