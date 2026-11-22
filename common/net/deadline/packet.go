package deadline

import (
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/net/packet"
)

type readResult struct {
	data []byte
	addr net.Addr
	err  error
}

type NetPacketConn struct {
	net.PacketConn
	deadline     atomic.TypedValue[time.Time]
	pipeDeadline PipeDeadline
	disablePipe  atomic.Bool
	inRead       atomic.Bool
	resultCh     chan any

	readerOnce  sync.Once
	readerStop  chan struct{}
	readerDone  chan struct{}
	readerStart atomic.Bool
	stopOnce    sync.Once
	closed      atomic.Bool
}

func NewNetPacketConn(pc net.PacketConn) net.PacketConn {
	npc := &NetPacketConn{
		PacketConn:   pc,
		pipeDeadline: MakePipeDeadline(),
		resultCh:     make(chan any, 1),
	}
	npc.resultCh <- nil
	if enhancePC, isEnhance := pc.(packet.EnhancePacketConn); isEnhance {
		epc := &EnhancePacketConn{
			NetPacketConn: npc,
			enhancePacketConn: enhancePacketConn{
				netPacketConn:     npc,
				enhancePacketConn: enhancePC,
			},
		}
		if singPC, isSingPC := pc.(packet.SingPacketConn); isSingPC {
			return &EnhanceSingPacketConn{
				EnhancePacketConn: epc,
				singPacketConn: singPacketConn{
					netPacketConn:  npc,
					singPacketConn: singPC,
				},
			}
		}
		return epc
	}
	if singPC, isSingPC := pc.(packet.SingPacketConn); isSingPC {
		return &SingPacketConn{
			NetPacketConn: npc,
			singPacketConn: singPacketConn{
				netPacketConn:  npc,
				singPacketConn: singPC,
			},
		}
	}
	return npc
}

func (c *NetPacketConn) startReader() {
	c.readerOnce.Do(func() {
		c.readerStop = make(chan struct{})
		c.readerDone = make(chan struct{})
		c.readerStart.Store(true)
		go c.readLoop()
	})
}

func (c *NetPacketConn) readLoop() {
	defer close(c.readerDone)
	buffer := make([]byte, 1<<16)
	result := &readResult{}
	for {
	FOR:
		for {
			select {
			case cached := <-c.resultCh:
				if cached != nil {
					c.resultCh <- cached
					runtime.Gosched()
					continue FOR
				}
				break FOR
			case <-c.readerStop:
				return
			}
		}
		n, addr, err := c.PacketConn.ReadFrom(buffer)
		result.data = buffer[:n]
		result.addr = addr
		result.err = err
		select {
		case c.resultCh <- result:
		case <-c.readerStop:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *NetPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if c.disablePipe.Load() {
		return c.PacketConn.ReadFrom(p)
	}
	if c.deadline.Load().IsZero() && !c.readerStart.Load() {
		c.inRead.Store(true)
		defer c.inRead.Store(false)
		return c.PacketConn.ReadFrom(p)
	}
	c.startReader()
	for {
		select {
		case result := <-c.resultCh:
			if result != nil {
				if result, ok := result.(*readResult); ok {
					n = copy(p, result.data)
					addr = result.addr
					err = result.err
					c.resultCh <- nil
					return
				}
				c.resultCh <- result
				runtime.Gosched()
			} else {
				c.resultCh <- nil
			}
		case <-c.pipeDeadline.Wait():
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.readerStop:
			return 0, nil, net.ErrClosed
		}
	}
}

func (c *NetPacketConn) Close() error {
	c.closed.Store(true)
	err := c.PacketConn.Close()
	if c.readerStart.Load() {
		c.stopOnce.Do(func() {
			close(c.readerStop)
			<-c.readerDone
		})
	}
	return err
}

func (c *NetPacketConn) SetReadDeadline(t time.Time) error {
	if c.disablePipe.Load() {
		return c.PacketConn.SetReadDeadline(t)
	} else if c.inRead.Load() {
		c.disablePipe.Store(true)
		return c.PacketConn.SetReadDeadline(t)
	}
	c.deadline.Store(t)
	c.pipeDeadline.Set(t)
	return nil
}

func (c *NetPacketConn) ReaderReplaceable() bool {
	select {
	case result := <-c.resultCh:
		c.resultCh <- result
		if result != nil {
			return false // cache reading
		} else {
			break
		}
	default:
		return false // pipe reading
	}
	return c.disablePipe.Load() || c.deadline.Load().IsZero()
}

func (c *NetPacketConn) WriterReplaceable() bool {
	return true
}

func (c *NetPacketConn) Upstream() any {
	return c.PacketConn
}

func (c *NetPacketConn) NeedAdditionalReadDeadline() bool {
	return false
}
