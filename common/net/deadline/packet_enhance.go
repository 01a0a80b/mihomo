package deadline

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/net/packet"
)

type EnhancePacketConn struct {
	*NetPacketConn
	enhancePacketConn
}

var _ packet.EnhancePacketConn = (*EnhancePacketConn)(nil)

func NewEnhancePacketConn(pc packet.EnhancePacketConn) packet.EnhancePacketConn {
	return NewNetPacketConn(pc).(packet.EnhancePacketConn)
}

type enhanceReadResult struct {
	data []byte
	put  func()
	addr net.Addr
	err  error
}

type enhancePacketConn struct {
	netPacketConn     *NetPacketConn
	enhancePacketConn packet.EnhancePacketConn

	readerOnce  sync.Once
	readerCh    chan enhanceReadResult
	readerStop  chan struct{}
	readerDone  chan struct{}
	readerStart atomic.Bool
	stopOnce    sync.Once

	mu      sync.Mutex
	timer   *time.Timer
	timerCh <-chan time.Time
}

func (c *enhancePacketConn) startReader() {
	c.readerOnce.Do(func() {
		c.readerCh = make(chan enhanceReadResult, 1)
		c.readerStop = make(chan struct{})
		c.readerDone = make(chan struct{})
		c.readerStart.Store(true)
		go c.readLoop()
	})
}

func (c *enhancePacketConn) readLoop() {
	defer close(c.readerDone)
	for {
		data, put, addr, err := c.enhancePacketConn.WaitReadFrom()
		result := enhanceReadResult{data: data, put: put, addr: addr, err: err}
		select {
		case c.readerCh <- result:
		case <-c.readerStop:
			if put != nil {
				put()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *enhancePacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	if c.netPacketConn.disablePipe.Load() {
		return c.enhancePacketConn.WaitReadFrom()
	}
	if !c.readerStart.Load() {
		if c.netPacketConn.deadline.Load().IsZero() {
			c.netPacketConn.inRead.Store(true)
			defer c.netPacketConn.inRead.Store(false)
			return c.enhancePacketConn.WaitReadFrom()
		}
		c.startReader()
	}
	stopCh := c.readerStop
	c.mu.Lock()
	timerCh := c.timerCh
	c.mu.Unlock()
	select {
	case result := <-c.readerCh:
		return result.data, result.put, result.addr, result.err
	case <-timerCh:
		select {
		case result := <-c.readerCh:
			return result.data, result.put, result.addr, result.err
		default:
			return nil, nil, nil, os.ErrDeadlineExceeded
		}
	case <-stopCh:
		return nil, nil, nil, net.ErrClosed
	}
}

func (c *enhancePacketConn) stop() {
	if c.readerStart.Load() {
		c.stopOnce.Do(func() {
			close(c.readerStop)
			<-c.readerDone
			select {
			case result := <-c.readerCh:
				if result.put != nil {
					result.put()
				}
			default:
			}
		})
	}
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timerCh = nil
	c.mu.Unlock()
}

func (c *EnhancePacketConn) SetReadDeadline(t time.Time) error {
	c.NetPacketConn.deadline.Store(t)
	c.mu.Lock()
	if t.IsZero() {
		if c.timer != nil {
			c.timer.Stop()
		}
		c.timerCh = nil
		c.mu.Unlock()
	} else {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		if c.timer == nil {
			c.timer = time.NewTimer(d)
		} else {
			if !c.timer.Stop() {
				select {
				case <-c.timer.C:
				default:
				}
			}
			c.timer.Reset(d)
		}
		c.timerCh = c.timer.C
		c.mu.Unlock()
	}
	return nil
}

func (c *EnhancePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	data, put, addr, err := c.enhancePacketConn.WaitReadFrom()
	if put != nil {
		defer put()
	}
	n = copy(p, data)
	return
}

func (c *EnhancePacketConn) Close() error {
	err := c.NetPacketConn.Close()
	c.enhancePacketConn.stop()
	return err
}
