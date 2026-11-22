package nat

import (
	"net/netip"

	"github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/sing/common/buf"
)

type writeBackProxy struct {
	wb atomic.TypedValue[C.WriteBack]
}

func (w *writeBackProxy) WriteBack(b *buf.Buffer, src netip.AddrPort) (n int, err error) {
	return w.wb.Load().WriteBack(b, src)
}

func (w *writeBackProxy) UpdateWriteBack(wb C.WriteBack) {
	w.wb.Store(wb)
}

func NewWriteBackProxy(wb C.WriteBack) C.WriteBackProxy {
	w := &writeBackProxy{}
	w.UpdateWriteBack(wb)
	return w
}
