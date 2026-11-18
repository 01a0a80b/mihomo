package shadowlemonprotocol

import (
	"math"
	"sync"
	"time"
)

const (
	minCWND            uint32 = 16
	maxCWND            uint32 = 4096
	cubicBeta                 = 0.7
	cubicC                    = 0.4
	cubicAIMDAlpha            = 3.0 * (1.0 - cubicBeta) / (1.0 + cubicBeta)
	defaultInitialRTT         = time.Second
	minRTO                    = 200 * time.Millisecond
	maxACKDelay               = time.Millisecond
	txTimeoutBackoff          = 1.5
	maxBackoffDuration        = 10 * time.Second
)

// retransmissionTimeout computes min(RTO * 1.5^txCount, 10s).
func retransmissionTimeout(rto time.Duration, txCount uint32) time.Duration {
	exp := txCount
	if exp > 64 {
		exp = 64
	}
	scaled := time.Duration(float64(rto) * math.Pow(txTimeoutBackoff, float64(exp)))
	if scaled > maxBackoffDuration {
		return maxBackoffDuration
	}
	return scaled
}

// Cubic implements CUBIC congestion control (RFC 8312) in segments.
type Cubic struct {
	mu         sync.Mutex
	slowStart  bool
	minWindow  uint32
	maxWindow  uint32
	cwnd       uint32
	ssthresh   uint32
	wMax       uint32
	epochK     float64
	epochStart time.Time
	lastRTT    time.Duration
}

func newCubic(minWindow, maxWindow uint32) *Cubic {
	return &Cubic{
		slowStart: true, minWindow: minWindow, maxWindow: maxWindow,
		cwnd: minWindow, ssthresh: maxWindow,
	}
}

func (c *Cubic) Cwnd() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cwnd
}

func clampCwnd(v, lo, hi uint32) uint32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (c *Cubic) onAck(acked uint32, rtt time.Duration, now time.Time) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rtt <= 0 {
		rtt = c.lastRTT
	}
	if rtt <= 0 {
		rtt = defaultInitialRTT
	}
	c.lastRTT = rtt
	if c.slowStart {
		if acked < 1 {
			acked = 1
		}
		c.cwnd = clampCwnd(c.cwnd+acked, c.minWindow, c.maxWindow)
		if c.cwnd > c.ssthresh {
			c.slowStart = false
			c.wMax = c.cwnd
			c.epochK = 0
			c.epochStart = now
		}
		return c.cwnd
	}
	t := 0.0
	if !c.epochStart.IsZero() {
		t = now.Sub(c.epochStart).Seconds()
	}
	d := t - c.epochK
	wCubic := cubicC*d*d*d + float64(c.wMax)
	rttSec := rtt.Seconds()
	if rttSec < math.SmallestNonzeroFloat64 {
		rttSec = math.SmallestNonzeroFloat64
	}
	wEst := float64(c.wMax)*cubicBeta + cubicAIMDAlpha*(t/rttSec)
	w := math.Max(math.Max(wCubic, wEst), 0)
	if w > float64(c.maxWindow) {
		w = float64(c.maxWindow)
	}
	c.cwnd = clampCwnd(uint32(math.Round(w)), c.minWindow, c.maxWindow)
	return c.cwnd
}

func (c *Cubic) onLoss(now time.Time) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	wMax := c.cwnd
	reduced := uint32(math.Round(float64(wMax) * cubicBeta))
	if reduced < c.minWindow {
		reduced = c.minWindow
	}
	c.ssthresh = reduced
	c.cwnd = reduced
	c.slowStart = false
	c.wMax = wMax
	c.epochK = math.Cbrt(float64(wMax) * (1 - cubicBeta) / cubicC)
	c.epochStart = now
	return c.cwnd
}

func (c *Cubic) onTimeout() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	half := c.cwnd / 2
	if half < c.minWindow {
		half = c.minWindow
	}
	c.ssthresh = half
	c.cwnd = c.minWindow
	c.slowStart = true
	c.wMax = 0
	c.epochK = 0
	c.epochStart = time.Time{}
	return c.cwnd
}

// RttStats implements RFC 6298 smoothed RTT, deviation and RTO.
type RttStats struct {
	mu             sync.Mutex
	hasMeasurement bool
	latestRTT      time.Duration
	smoothedRTT    time.Duration
	meanDeviation  time.Duration
}

func (r *RttStats) RTO() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.smoothedRTT == 0 {
		return 2 * defaultInitialRTT
	}
	deviation := r.meanDeviation * 4
	if deviation < 10*time.Millisecond {
		deviation = 10 * time.Millisecond
	}
	rto := r.smoothedRTT + deviation + maxACKDelay
	if rto < minRTO {
		rto = minRTO
	}
	return rto
}

func (r *RttStats) SmoothedRTT() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.smoothedRTT
}

func (r *RttStats) UpdateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.latestRTT = sample
	if !r.hasMeasurement {
		r.hasMeasurement = true
		r.smoothedRTT = sample
		r.meanDeviation = sample / 2
		return
	}
	srtt := float64(r.smoothedRTT) / float64(time.Microsecond)
	dev := float64(r.meanDeviation) / float64(time.Microsecond)
	sampleUS := float64(sample) / float64(time.Microsecond)
	diff := math.Abs(srtt - sampleUS)
	r.meanDeviation = time.Duration((0.75*dev + 0.25*diff) * float64(time.Microsecond))
	r.smoothedRTT = time.Duration((0.875*srtt + 0.125*sampleUS) * float64(time.Microsecond))
}
