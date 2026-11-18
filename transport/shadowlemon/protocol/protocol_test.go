package shadowlemonprotocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
	wire "github.com/metacubex/mihomo/transport/shadowlemon/wire"
)

func testSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

// --- handshake envelope round trips ---

func TestHandshakeRequestMarshalRoundTrip(t *testing.T) {
	eph := bytes.Repeat([]byte{1}, crypto.EphKeyLen)
	salt := bytes.Repeat([]byte{2}, crypto.SaltLen)
	r := &HandshakeRequest{
		VersionMin: crypto.ProtocolVersion, VersionMax: crypto.ProtocolVersion,
		Suites: []byte{crypto.SuiteXChaCha20Poly1305, crypto.SuiteAes256Gcm, crypto.SuiteAes128Gcm},
		EphPub: eph, ClientSalt: salt,
	}
	raw := r.marshal()
	if len(raw) != crypto.HandshakeRequestFixedLen+len(r.Suites) {
		t.Fatalf("request length %d", len(raw))
	}
	trailing := []byte("application data")
	got, consumed, err := parseRequest(append(append([]byte(nil), raw...), trailing...))
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed %d want %d", consumed, len(raw))
	}
	if got.VersionMin != r.VersionMin || got.VersionMax != r.VersionMax ||
		!bytes.Equal(got.Suites, r.Suites) || !bytes.Equal(got.EphPub, eph) || !bytes.Equal(got.ClientSalt, salt) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	// Truncation and malformed suite lists must be rejected.
	for n := 0; n < len(raw); n++ {
		if _, _, err := parseRequest(raw[:n]); err == nil {
			t.Fatalf("accepted truncated request of length %d", n)
		}
	}
	bad := append([]byte(nil), raw...)
	bad[2] = 0
	if _, _, err := parseRequest(bad); err == nil {
		t.Fatal("accepted zero suites")
	}
}

func TestHandshakeResponseMarshalRoundTrip(t *testing.T) {
	r := &HandshakeResponse{
		Status: statusOK, Version: crypto.ProtocolVersion, Suite: crypto.SuiteAes128Gcm,
		EphPub: bytes.Repeat([]byte{3}, crypto.EphKeyLen), ServerSalt: bytes.Repeat([]byte{4}, crypto.SaltLen),
	}
	raw := r.marshal()
	if len(raw) != crypto.HandshakeResponseLen {
		t.Fatalf("response length %d", len(raw))
	}
	got, err := parseResponse(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != r.Status || got.Version != r.Version || got.Suite != r.Suite ||
		!bytes.Equal(got.EphPub, r.EphPub) || !bytes.Equal(got.ServerSalt, r.ServerSalt) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	fail := noSuiteResponse().marshal()
	if got, err := parseResponse(fail[:]); err != nil || got.Status != statusNoSuite {
		t.Fatalf("no-suite parse: %+v %v", got, err)
	}
}

// --- routing envelope ---

func TestUDPRoutingEnvelopeRoundTrip(t *testing.T) {
	secret := testSecret(t)
	frame := bytes.Repeat([]byte{0xab}, 40)
	for i := 0; i < 4; i++ {
		wrapped := WrapUDP(byte(i+1), 0x01020304, frame, secret)
		kind, id, got, ok := UnwrapUDP(wrapped, secret)
		if !ok || kind != byte(i+1) || id != 0x01020304 || !bytes.Equal(got, frame) {
			t.Fatalf("round trip %d: %d %d %v %v", i, kind, id, ok, bytes.Equal(got, frame))
		}
	}
	// Masked kind varies across packets; garbage is rejected.
	seen := map[byte]bool{}
	for i := 0; i < 64; i++ {
		nonce := make([]byte, 24)
		nonce[0] = byte(i)
		w := WrapUDP(UDPKindSessionData, 42, nonce, secret)
		seen[w[0]] = true
	}
	if len(seen) < 2 {
		t.Fatal("routing kind byte must not be constant")
	}
	bad := WrapUDP(UDPKindSessionData, 7, bytes.Repeat([]byte{}, 24), secret)
	if _, _, _, ok := UnwrapUDP(bad[:4], secret); ok {
		t.Fatal("accepted short envelope")
	}
}

// --- sequence comparison ---

func TestSeqWrapComparison(t *testing.T) {
	if !seqLT(0xffffffff, 0) || !seqGE(0, 0xffffffff) {
		t.Fatal("wrap comparison failed")
	}
	if !seqLT(1, 2) || seqLT(2, 1) || !seqGE(2, 2) {
		t.Fatal("basic comparison failed")
	}
}

// --- fragmentation ---

func TestFragmentReassembly(t *testing.T) {
	data := make([]byte, 450)
	for i := range data {
		data[i] = byte(i)
	}
	pieces, err := SplitAppFragment(data, 100, 9)
	if err != nil || len(pieces) != 5 {
		t.Fatalf("split: %d pieces, %v", len(pieces), err)
	}
	a := NewFragmentAssembler()
	var rebuilt []byte
	// Feed in reverse (highest number first).
	for i := len(pieces) - 1; i >= 0; i-- {
		id, num, count, piece, ok := splitAppFragment(pieces[i])
		if !ok || id != 9 || count != 5 {
			t.Fatalf("bad fragment header: id=%d num=%d count=%d", id, num, count)
		}
		if r := a.Add(id, num, count, piece); r != nil {
			rebuilt = r
		}
	}
	if !bytes.Equal(rebuilt, data) {
		t.Fatalf("reassembly mismatch: got %d bytes", len(rebuilt))
	}
}

// --- SOCKS5 encoding ---

func TestSocksEncoding(t *testing.T) {
	req := EncodeSocksRequest(socksCmdConnect, SocksAddress{Domain: "example.com"}, 443)
	cmd, addr, port, consumed, err := ParseSocksRequest(req)
	if err != nil || cmd != socksCmdConnect || addr.Domain != "example.com" || port != 443 || consumed != len(req) {
		t.Fatalf("request parse: %d %s %d %d %v", cmd, addr.Domain, port, consumed, err)
	}
	hdr := EncodeUDPHeader(SocksAddress{IP: net.IPv4(1, 2, 3, 4)}, 53)
	dg, err := ParseUDPDatagram(append(append([]byte(nil), hdr...), []byte("payload")...))
	if err != nil || dg.Port != 53 || !bytes.Equal(dg.Payload, []byte("payload")) {
		t.Fatalf("udp datagram: %+v %v", dg, err)
	}
}

// --- ARQ session: basic bidirectional data flow with ACKs and retransmissions ---

func TestSessionDataExchange(t *testing.T) {
	const sid = 77
	key1 := bytes.Repeat([]byte{1}, 32)
	key2 := bytes.Repeat([]byte{2}, 32)
	client, err := NewSession(sid, directionClient, key1, key2, crypto.SuiteXChaCha20Poly1305, EmptySourceTag, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(sid, directionServer, key1, key2, crypto.SuiteXChaCha20Poly1305, EmptySourceTag, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// Client -> server.
	if err := client.TrySend([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := client.Tick(now); err != nil {
		t.Fatal(err)
	}
	frame := client.PollOutput()
	if frame == nil {
		t.Fatal("no outbound frame")
	}
	if err := server.OnFrame(frame, now); err != nil {
		t.Fatal(err)
	}
	chunk, ok := server.TryRecv()
	if !ok || string(chunk) != "hello" {
		t.Fatalf("server recv: %q %v", chunk, ok)
	}

	// Server -> client.
	if err := server.TrySend([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if err := server.Tick(now); err != nil {
		t.Fatal(err)
	}
	frame = server.PollOutput()
	if frame == nil {
		t.Fatal("no server frame")
	}
	if err := client.OnFrame(frame, now); err != nil {
		t.Fatal(err)
	}
	chunk, ok = client.TryRecv()
	if !ok || string(chunk) != "world" {
		t.Fatalf("client recv: %q %v", chunk, ok)
	}

	// Replay is rejected.
	if err := client.OnFrame(frame, now); err != ErrReplay {
		t.Fatalf("replay: %v", err)
	}

	// Retransmission after timeout uses a fresh nonce but the same sequence.
	if err := server.TrySend([]byte("loss")); err != nil {
		t.Fatal(err)
	}
	if err := server.Tick(now); err != nil {
		t.Fatal(err)
	}
	first := server.PollOutput()
	deadline := server.NextTimer()
	var retry []byte
	for i := 0; i < 10 && retry == nil; i++ {
		if err := server.Tick(deadline.Add(time.Duration(i) * time.Second)); err != nil {
			t.Fatal(err)
		}
		for {
			frame := server.PollOutput()
			if frame == nil {
				break
			}
			m, payload, err := openV2Frame(server.sendAEAD, server.sendAEAD, frame)
			if err != nil {
				t.Fatal(err)
			}
			// The first data frame found may be a retransmission of the earlier
			// unacknowledged "world" segment; pick the "loss" retransmission.
			if m.Type == wire.TypeDataS2C && string(payload) == "loss" && !bytes.Equal(frame, first) {
				retry = frame
				break
			}
		}
	}
	if retry == nil {
		t.Fatal("expected a distinct retransmission data frame")
	}
	if err := client.OnFrame(retry, deadline); err != nil {
		t.Fatal(err)
	}
	chunk, ok = client.TryRecv()
	if !ok || string(chunk) != "loss" {
		t.Fatalf("client retry recv: %q %v", chunk, ok)
	}
}

func TestSessionUpgradeKeys(t *testing.T) {
	key1 := bytes.Repeat([]byte{1}, 32)
	key2 := bytes.Repeat([]byte{2}, 32)
	new1 := bytes.Repeat([]byte{9}, 32)
	new2 := bytes.Repeat([]byte{8}, 32)
	s, err := NewSession(1, directionClient, key1, key2, crypto.SuiteXChaCha20Poly1305, EmptySourceTag, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpgradeKeys(new1, new2, crypto.SuiteXChaCha20Poly1305); err != nil {
		t.Fatal(err)
	}
	if !s.ready || !bytes.Equal(s.sendKey, new1) || !bytes.Equal(s.recvKey, new2) {
		t.Fatal("key upgrade failed")
	}
}

// --- end-to-end client/server over UDP with Accept queue ---

func TestClientServerEndToEnd(t *testing.T) {
	secret := testSecret(t)
	// Find a free UDP port for the server.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	_ = probe.Close()

	user := FromPassword("alice", "s3cret", nil)
	server, err := NewServer(addr, map[string]User{"alice": user}, secret, 1400)
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve() }()
	defer server.Close()

	client, err := NewClient(addr, "alice", "s3cret", secret, 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	accepted, err := server.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if accepted.IsUDP || accepted.Conn == nil || accepted.Target != "example.com:80" {
		t.Fatalf("unexpected accepted conn: %+v", accepted)
	}

	// Send a full SOCKS5 UDP datagram payload through the tunnel; the server
	// side streamConn emits it as plaintext for the adapter to consume.
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = accepted.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := accepted.Conn.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch: got %q", buf[:n])
	}

	// Reverse direction.
	if _, err := accepted.Conn.Write([]byte("HTTP/1.1 200 OK")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "HTTP/1.1 200 OK" {
		t.Fatalf("reverse payload mismatch: %q", buf[:n])
	}
}

func TestClientServerUDPAssociate(t *testing.T) {
	secret := testSecret(t)
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	_ = probe.Close()

	user := FromPassword("bob", "password", nil)
	server, err := NewServer(addr, map[string]User{"bob": user}, secret, 1400)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	defer server.Close()

	client, err := NewClient(addr, "bob", "password", secret, 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	accepted, err := server.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !accepted.IsUDP || accepted.PacketConn == nil {
		t.Fatalf("expected UDP association: %+v", accepted)
	}
	if _, err := pc.WriteTo([]byte("dns-query"), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = accepted.PacketConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := accepted.PacketConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server packet read: %v", err)
	}
	if string(buf[:n]) != "dns-query" || from.String() != "8.8.8.8:53" {
		t.Fatalf("packet mismatch: %q from %s", buf[:n], from)
	}
}

func TestAuthenticationFailure(t *testing.T) {
	secret := testSecret(t)
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	_ = probe.Close()

	user := FromPassword("alice", "correct", nil)
	server, err := NewServer(addr, map[string]User{"alice": user}, secret, 1400)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	defer server.Close()

	client, err := NewClient(addr, "alice", "wrong", secret, 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.DialContext(ctx, "example.com:80")
	if err == nil {
		t.Fatal("expected handshake failure with wrong password")
	}
}

// Helper to make compiler happy about unused fmt in alternate builds.
var _ = fmt.Sprintf
var _ io.Reader
var _ = wire.NonceLen
