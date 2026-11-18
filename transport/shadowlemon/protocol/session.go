package shadowlemonprotocol

import (
	"crypto/cipher"
	"io"
	"sync"
	"time"

	crypto "github.com/metacubex/mihomo/transport/shadowlemon/crypto"
	wire "github.com/metacubex/mihomo/transport/shadowlemon/wire"
)

const (
	directionClient byte = 0
	directionServer byte = 1

	minWindowSize            uint32 = minCWND
	maxWindowSize            uint32 = maxCWND
	segmentTreeCapacity             = 4096
	sendQueueCapacity               = 1024
	packetACKDelay                  = time.Millisecond
	heartbeatMinInterval            = 2 * time.Second
	heartbeatMaxInterval            = 15 * time.Second
	ackPaddingMax                   = 255
	ackWindowUpdateThreshold        = 2048
	earlyRetransmission             = 3
	earlyRetransmissionLimit        = 1
	txCountLimit                    = 20
	maxFragment                     = wire.MaxFragment
)

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqGE(a, b uint32) bool { return !seqLT(a, b) }

// Direction returns the data/ACK protocol types for a local role.
func dataTypes(direction byte) (dataType, ackType, peerDataType, peerACKType byte) {
	if direction == directionClient {
		return wire.TypeDataC2S, wire.TypeAckC2S, wire.TypeDataS2C, wire.TypeAckS2C
	}
	return wire.TypeDataS2C, wire.TypeAckS2C, wire.TypeDataC2S, wire.TypeAckC2S
}

// replayDomain returns the domain used to verify frames received by this role.
func replayDomain(direction byte) byte {
	if direction == directionClient {
		return replayDomainS2C
	}
	return replayDomainC2S
}

type sentSegment struct {
	payload   []byte
	fragment  byte
	txCount   uint32
	ackCount  uint32
	txTime    time.Time
	txTimeout time.Duration
}

// Session provides a reliable, ordered datagram-to-byte-stream bridge over UDP.
// The caller drives it with Tick/NextTimer and pumps outbound frames via
// PollOutput. It is used symmetrically by both client and server.
type Session struct {
	mu sync.Mutex

	id        uint32
	direction byte
	sendKey   []byte
	recvKey   []byte
	sendSuite byte
	recvSuite byte
	sendAEAD  cipher.AEAD
	recvAEAD  cipher.AEAD
	nonce     []byte
	recvNonce []byte

	nextSend     uint32
	nextRecv     uint32
	unack        uint32
	remoteUnack  uint32
	remoteWindow uint16

	recvBuf  map[uint32][]byte
	sendBuf  map[uint32]*sentSegment
	queue    []([2]interface{}) // ([]byte payload, byte fragment)
	outgoing [][]byte

	plaintext      chan []byte
	ackDeadline    time.Time
	heartbeatAt    time.Time
	sinceWindowACK uint32
	state          int // 0 active, 1 closing, 2 closed // 0-RTT gate

	cubic  *Cubic
	rtt    *RttStats
	replay *ReplayCache
	source SourceTag

	// upgrade gate: while false, data-plane Write is blocked (0-RTT early keys
	// are installed at construction; callers may still send early data via
	// WriteEarly before the handshake response).
	ready bool
}

// NewSession creates a session with the supplied directional keys.
func NewSession(id uint32, direction byte, c2sKey, s2cKey []byte, suite byte, source SourceTag, early bool) (*Session, error) {
	if id == 0 {
		return nil, ErrMalformed
	}
	s := &Session{
		id: id, direction: direction,
		recvBuf: make(map[uint32][]byte), sendBuf: make(map[uint32]*sentSegment),
		plaintext: make(chan []byte, 512),
		cubic:     newCubic(minCWND, maxCWND), rtt: &RttStats{},
		replay: newReplayCache(replayDomain(direction)), source: source,
		nonce: randomNonce(), recvNonce: randomNonce(),
		remoteWindow: uint16(minWindowSize), heartbeatAt: time.Now().Add(heartbeatJitter()),
	}
	if err := s.installKeys(c2sKey, s2cKey, suite); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Session) installKeys(c2sKey, s2cKey []byte, suite byte) error {
	var sendKey, recvKey []byte
	if s.direction == directionClient {
		sendKey, recvKey = c2sKey, s2cKey
	} else {
		sendKey, recvKey = s2cKey, c2sKey
	}
	sendAEAD, err := crypto.NewAEAD(suite, sendKey)
	if err != nil {
		return err
	}
	recvAEAD, err := crypto.NewAEAD(suite, recvKey)
	if err != nil {
		return err
	}
	s.sendKey, s.recvKey = append([]byte(nil), sendKey...), append([]byte(nil), recvKey...)
	s.sendSuite, s.recvSuite = suite, suite
	s.sendAEAD, s.recvAEAD = sendAEAD, recvAEAD
	return nil
}

// UpgradeKeys swaps in the forward-secret keys after the handshake completes.
func (s *Session) UpgradeKeys(c2sKey, s2cKey []byte, suite byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.installKeys(c2sKey, s2cKey, suite); err != nil {
		return err
	}
	s.ready = true
	return nil
}

// MarkReady unblocks data-plane writes when no key upgrade is needed.
func (s *Session) MarkReady() { s.mu.Lock(); s.ready = true; s.mu.Unlock() }

func (s *Session) ID() uint32 { return s.id }

func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == 2
}

// Close optionally emits a closeSessionRequest frame.
func (s *Session) Close(notify bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == 2 {
		return nil
	}
	s.state = 2
	s.queue = nil
	s.sendBuf = make(map[uint32]*sentSegment)
	s.ackDeadline = time.Time{}
	if notify {
		return s.encodeControlLocked(wire.TypeCloseSessionReq, nil)
	}
	return nil
}

func heartbeatJitter() time.Duration {
	span := int64(heartbeatMaxInterval - heartbeatMinInterval)
	return heartbeatMinInterval + time.Duration(randUint(uint64(span+1)))
}

// TrySend enqueues application bytes, splitting into maxFragment-sized pieces.
func (s *Session) TrySend(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == 2 {
		return ErrClosed
	}
	count := (len(data) + maxFragment - 1) / maxFragment
	if count == 0 {
		return nil
	}
	if len(s.queue)+count > sendQueueCapacity {
		return ErrBackpressure
	}
	for i := 0; i < count; i++ {
		start := i * maxFragment
		end := start + maxFragment
		if end > len(data) {
			end = len(data)
		}
		frag := byte(count - 1 - i)
		s.queue = append(s.queue, [2]interface{}{append([]byte(nil), data[start:end]...), frag})
	}
	return nil
}

// Write is the net.Conn-style writer. It waits for the 0-RTT gate if needed.
func (s *Session) Write(data []byte) (int, error) {
	s.mu.Lock()
	ready := s.ready
	s.mu.Unlock()
	if !ready {
		return 0, io.ErrClosedPipe
	}
	if err := s.TrySend(data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Read reads reassembled, in-order application bytes.
func (s *Session) Read(b []byte) (int, error) {
	chunk, ok := <-s.plaintext
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, chunk)
	if n < len(chunk) {
		// Requeue the remainder; plaintext is consumed in order.
		go func(rest []byte) { s.plaintext <- rest }(chunk[n:])
	}
	return n, nil
}

// NextTimer returns the earliest deadline at which Tick has work.
func (s *Session) NextTimer() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == 2 {
		return time.Time{}
	}
	next := s.heartbeatAt
	if !s.ackDeadline.IsZero() && s.ackDeadline.Before(next) {
		next = s.ackDeadline
	}
	for _, seg := range s.sendBuf {
		deadline := seg.txTime.Add(seg.txTimeout)
		if deadline.Before(next) {
			next = deadline
		}
	}
	return next
}

func (s *Session) canSend() bool {
	if s.state == 2 {
		return false
	}
	inFlight := uint32(len(s.sendBuf))
	available := s.cubic.Cwnd()
	if available <= inFlight {
		return false
	}
	return inFlight < maxWindowSize && s.remoteWindow > 0 && len(s.recvBuf) < segmentTreeCapacity
}

// Tick sends queued data, delayed ACKs, retransmissions and heartbeats.
func (s *Session) Tick(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == 2 {
		return nil
	}
	for s.canSend() && len(s.queue) > 0 {
		item := s.queue[0]
		s.queue = s.queue[1:]
		payload := item[0].([]byte)
		frag := item[1].(byte)
		frame, seq, err := s.encodeDataLocked(payload, frag)
		if err != nil {
			return err
		}
		s.sendBuf[seq] = &sentSegment{
			payload: payload, fragment: frag, txCount: 1,
			txTime: now, txTimeout: retransmissionTimeout(s.rtt.RTO(), 1),
		}
		s.outgoing = append(s.outgoing, frame)
	}
	if !s.ackDeadline.IsZero() && !now.Before(s.ackDeadline) {
		s.ackDeadline = time.Time{}
		if err := s.encodeACKLocked(); err != nil {
			return err
		}
	}

	loss, timeout, overLimit := false, false, false
	var toRetransmit []uint32
	for seq, seg := range s.sendBuf {
		early := seg.ackCount >= earlyRetransmission && seg.txCount <= earlyRetransmissionLimit
		timedOut := !now.Before(seg.txTime.Add(seg.txTimeout))
		if !early && !timedOut {
			continue
		}
		if seg.txCount >= txCountLimit {
			overLimit = true
			break
		}
		if early {
			loss = true
		} else {
			timeout = true
		}
		toRetransmit = append(toRetransmit, seq)
	}
	if overLimit {
		s.state = 2
		return ErrTooManyRetries
	}
	for _, seq := range toRetransmit {
		seg := s.sendBuf[seq]
		seg.txCount++
		seg.ackCount = 0
		seg.txTime = now
		seg.txTimeout = retransmissionTimeout(s.rtt.RTO(), seg.txCount)
		frame, _, err := s.encodeDataSeqLocked(seq, seg.payload, seg.fragment)
		if err != nil {
			return err
		}
		s.outgoing = append(s.outgoing, frame)
	}
	if loss {
		s.cubic.onLoss(now)
	} else if timeout {
		s.cubic.onTimeout()
	}
	if !now.Before(s.heartbeatAt) {
		if err := s.encodeACKLocked(); err != nil {
			return err
		}
		s.heartbeatAt = now.Add(heartbeatJitter())
	}
	return nil
}

// PollOutput pops the next outbound frame.
func (s *Session) PollOutput() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.outgoing) == 0 {
		return nil
	}
	frame := s.outgoing[0]
	s.outgoing = s.outgoing[1:]
	return frame
}

// OnFrame accepts one complete inbound wire frame.
func (s *Session) OnFrame(frame []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == 2 {
		return ErrClosed
	}
	if len(frame) < wire.NonceAndMetaLen {
		return ErrMalformed
	}
	nonce := frame[:wire.NonceLen]
	sig := replaySignature(replayDomain(s.direction), nonce)
	if s.replay.IsReplay(sig, s.source) {
		return ErrReplay
	}
	meta, payload, err := openV2Frame(s.recvAEAD, s.recvAEAD, frame)
	if err != nil {
		return err
	}
	if meta.SessionID != s.id {
		return ErrSessionMismatch
	}
	_, _, peerData, peerACK := dataTypes(s.direction)
	switch meta.Type {
	case wire.TypeCloseSessionReq:
		s.encodeControlLocked(wire.TypeCloseSessionResp, nil)
		s.state = 2
	case wire.TypeCloseSessionResp:
		s.state = 2
	case peerData:
		s.processDataLocked(meta, payload, now)
	case peerACK:
		s.processRemoteWindowLocked(meta.Unack, meta.Window)
		s.processACKLocked(meta.Unack, now)
	default:
		return ErrWrongDirection
	}
	s.replay.Record(sig, s.source)
	return nil
}

func (s *Session) processDataLocked(meta *wire.Metadata, payload []byte, now time.Time) {
	s.processRemoteWindowLocked(meta.Unack, meta.Window)
	s.requestACKLocked(now)
	if len(payload) == 0 {
		return
	}
	seq := meta.Seq
	left := s.nextRecv
	if seqLT(seq, left) || seqGE(seq, left+maxWindowSize) {
		return
	}
	if len(s.recvBuf) >= segmentTreeCapacity {
		return
	}
	if seq == left {
		s.pushUnreadLocked(payload)
		s.nextRecv++
		s.unack = s.nextRecv
		for {
			next, ok := s.recvBuf[s.nextRecv]
			if !ok {
				break
			}
			delete(s.recvBuf, s.nextRecv)
			s.pushUnreadLocked(next)
			s.nextRecv++
			s.unack = s.nextRecv
		}
	} else {
		s.recvBuf[seq] = append([]byte(nil), payload...)
	}
}

func (s *Session) processRemoteWindowLocked(unack uint32, window uint16) {
	if seqGE(unack, s.remoteUnack) {
		s.remoteUnack = unack
		s.remoteWindow = window
	}
}

func (s *Session) processACKLocked(unack uint32, now time.Time) {
	var freed, duplicated []uint32
	for seq := range s.sendBuf {
		if seqLT(seq, unack) {
			freed = append(freed, seq)
		} else if seq == unack {
			duplicated = append(duplicated, seq)
		}
	}
	for _, seq := range freed {
		seg := s.sendBuf[seq]
		delete(s.sendBuf, seq)
		if seg.txCount == 1 {
			s.rtt.UpdateRTT(now.Sub(seg.txTime))
		}
	}
	for _, seq := range duplicated {
		if seg, ok := s.sendBuf[seq]; ok {
			seg.ackCount++
		}
	}
	if len(freed) > 0 {
		s.cubic.onAck(uint32(len(freed)), s.rtt.SmoothedRTT(), now)
	}
}

func (s *Session) requestACKLocked(now time.Time) {
	if s.ackDeadline.IsZero() {
		s.ackDeadline = now.Add(packetACKDelay)
	}
	if s.sinceWindowACK >= ackWindowUpdateThreshold {
		s.sinceWindowACK = 0
		_ = s.encodeACKLocked()
	}
}

func (s *Session) pushUnreadLocked(data []byte) {
	s.sinceWindowACK++
	select {
	case s.plaintext <- data:
	default:
		// The application is slow; drop into a bounded overflow handled by the
		// stream facade. Keeping the wire moving takes precedence.
	}
}

func (s *Session) receiveWindow() uint16 {
	used := uint32(len(s.recvBuf))
	if used >= maxWindowSize {
		return 0
	}
	return uint16(maxWindowSize - used)
}

func (s *Session) encodeDataLocked(payload []byte, fragment byte) ([]byte, uint32, error) {
	seq := s.nextSend
	s.nextSend++
	return s.encodeDataSeqLocked(seq, payload, fragment)
}

func (s *Session) encodeDataSeqLocked(seq uint32, payload []byte, fragment byte) ([]byte, uint32, error) {
	dataType, _, _, _ := dataTypes(s.direction)
	prefix := randomPadding(wire.MaxPrefixPadding)
	suffix := randomPadding(wire.MaxSuffixPadding)
	meta := &wire.Metadata{
		Type: dataType, SessionID: s.id, Seq: seq,
		Unack: s.nextRecv, Window: s.receiveWindow(), Fragment: fragment,
		PrefixLen: byte(len(prefix)), PayloadLen: uint16(len(payload)), SuffixLen: byte(len(suffix)),
	}
	frame, err := s.sealLocked(meta, payload, prefix, suffix)
	return frame, seq, err
}

func (s *Session) encodeACKLocked() error {
	_, ackType, _, _ := dataTypes(s.direction)
	seq := s.nextSend - 1
	prefix := randomPadding(ackPaddingMax)
	suffix := randomPadding(ackPaddingMax)
	meta := &wire.Metadata{
		Type: ackType, SessionID: s.id, Seq: seq,
		Unack: s.nextRecv, Window: s.receiveWindow(),
		PrefixLen: byte(len(prefix)), SuffixLen: byte(len(suffix)),
	}
	frame, err := s.sealLocked(meta, nil, prefix, suffix)
	if err != nil {
		return err
	}
	s.outgoing = append(s.outgoing, frame)
	return nil
}

func (s *Session) encodeControlLocked(typ byte, payload []byte) error {
	suffix := randomPadding(wire.MaxSuffixPadding)
	meta := &wire.Metadata{
		Type: typ, SessionID: s.id, Seq: s.nextSend - 1,
		PayloadLen: uint16(len(payload)), SuffixLen: byte(len(suffix)),
	}
	frame, err := s.sealLocked(meta, payload, nil, suffix)
	if err != nil {
		return err
	}
	s.outgoing = append(s.outgoing, frame)
	return nil
}

func (s *Session) sealLocked(meta *wire.Metadata, payload, prefix, suffix []byte) ([]byte, error) {
	nonce := randomNonce()
	frame, err := sealV2Frame(s.sendAEAD, s.sendAEAD, meta, payload, prefix, suffix, nonce)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// DrainFrames returns all queued outbound frames without ticking timers.
func (s *Session) DrainFrames() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.outgoing
	s.outgoing = nil
	return out
}

// TryRecv returns the next reassembled plaintext chunk, if any.
func (s *Session) TryRecv() ([]byte, bool) {
	select {
	case chunk := <-s.plaintext:
		return chunk, true
	default:
		return nil, false
	}
}

// HandshakeFrame is a helper to read the metadata of a frame for diagnostics.
func (s *Session) HandshakeFrame(frame []byte) (*wire.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta, _, err := openV2Frame(s.recvAEAD, s.recvAEAD, frame)
	return meta, err
}

// bytesJoin is used by the stream facade to concatenate reassembled fragments.
func bytesJoin(chunks [][]byte) []byte {
	var out []byte
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}
