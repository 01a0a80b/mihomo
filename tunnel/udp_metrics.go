package tunnel

import "sync/atomic"

var (
	udpDroppedWorker atomic.Uint64
	udpDroppedSender atomic.Uint64
	udpBatchPackets  atomic.Uint64
	udpBatchCalls    atomic.Uint64
)

type UDPMetricsSnapshot struct {
	DroppedWorker uint64
	DroppedSender uint64
	BatchPackets  uint64
	BatchCalls    uint64
}

func SnapshotUDPMetrics() UDPMetricsSnapshot {
	return UDPMetricsSnapshot{
		DroppedWorker: udpDroppedWorker.Load(),
		DroppedSender: udpDroppedSender.Load(),
		BatchPackets:  udpBatchPackets.Load(),
		BatchCalls:    udpBatchCalls.Load(),
	}
}

func AddDroppedWorker(n uint64) {
	udpDroppedWorker.Add(n)
}

func AddDroppedSender(n uint64) {
	udpDroppedSender.Add(n)
}

func AddBatchPackets(n uint64) {
	udpBatchPackets.Add(n)
}

func AddBatchCalls(n uint64) {
	udpBatchCalls.Add(n)
}
