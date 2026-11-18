package shadowlemonprotocol

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	replayDomainC2S          byte = 1
	replayDomainS2C          byte = 2
	replayGenerationCapacity      = 65536
	replayGenerationTTL           = 360 * time.Second
	replayShardCount              = 16
)

// ReplayCache is a two-generation replay cache for one traffic domain.
// check is read-only; record is called only after full authentication.
type ReplayCache struct {
	domain           byte
	base             time.Time
	mu               [replayShardCount]sync.Mutex
	current          [replayShardCount]map[uint64]SourceTag
	previous         [replayShardCount]map[uint64]SourceTag
	count            atomic.Uint64
	expireNS         atomic.Uint64
	expireIntervalNS uint64
}

func newReplayCache(domain byte) *ReplayCache {
	r := &ReplayCache{domain: domain, base: time.Now(), expireIntervalNS: uint64(replayGenerationTTL)}
	r.expireNS.Store(r.expireIntervalNS)
	for i := 0; i < replayShardCount; i++ {
		r.current[i] = make(map[uint64]SourceTag)
		r.previous[i] = make(map[uint64]SourceTag)
	}
	return r
}

func (r *ReplayCache) shard(sig uint64) int { return int((sig >> 60) & (replayShardCount - 1)) }

func (r *ReplayCache) nowNS() uint64 { return uint64(time.Since(r.base)) }

// Check is read-only. It never inserts, refreshes a tag or rotates.
func (r *ReplayCache) Check(sig uint64, tag SourceTag) bool {
	i := r.shard(sig)
	r.mu[i].Lock()
	defer r.mu[i].Unlock()
	if recorded, ok := r.current[i][sig]; ok {
		return canRetransmit(recorded, tag)
	}
	if recorded, ok := r.previous[i][sig]; ok {
		return canRetransmit(recorded, tag)
	}
	return false
}

// IsReplay reports whether sig must be rejected (seen from a different source).
func (r *ReplayCache) IsReplay(sig uint64, tag SourceTag) bool {
	i := r.shard(sig)
	r.mu[i].Lock()
	defer r.mu[i].Unlock()
	if recorded, ok := r.current[i][sig]; ok {
		return !canRetransmit(recorded, tag)
	}
	if recorded, ok := r.previous[i][sig]; ok {
		return !canRetransmit(recorded, tag)
	}
	return false
}

func canRetransmit(recorded, tag SourceTag) bool {
	return !tag.empty() && !recorded.empty() && sameSourceTag(recorded, tag)
}

func sameSourceTag(a, b SourceTag) bool {
	if len(a.bytes) != len(b.bytes) {
		return false
	}
	for i := range a.bytes {
		if a.bytes[i] != b.bytes[i] {
			return false
		}
	}
	return true
}

// Record inserts a signature after successful authentication.
func (r *ReplayCache) Record(sig uint64, tag SourceTag) {
	if r.count.Load() >= replayGenerationCapacity || r.nowNS() > r.expireNS.Load() {
		r.rotate()
	}
	i := r.shard(sig)
	r.mu[i].Lock()
	defer r.mu[i].Unlock()
	if _, ok := r.current[i][sig]; !ok {
		r.count.Add(1)
	}
	r.current[i][sig] = tag
}

func (r *ReplayCache) rotate() {
	now := r.nowNS()
	expireAt := r.expireNS.Load()
	if now > expireAt+r.expireIntervalNS {
		for i := 0; i < replayShardCount; i++ {
			r.mu[i].Lock()
			r.count.Add(uint64(0) - uint64(len(r.current[i])))
			r.current[i] = make(map[uint64]SourceTag)
			r.previous[i] = make(map[uint64]SourceTag)
			r.mu[i].Unlock()
		}
		r.expireNS.Store(now + r.expireIntervalNS)
		return
	}
	if r.count.Load() < replayGenerationCapacity && now <= expireAt {
		return
	}
	for i := 0; i < replayShardCount; i++ {
		r.mu[i].Lock()
		r.count.Add(uint64(0) - uint64(len(r.current[i])))
		r.previous[i] = r.current[i]
		r.current[i] = make(map[uint64]SourceTag)
		r.mu[i].Unlock()
	}
	r.expireNS.Store(now + r.expireIntervalNS)
}
