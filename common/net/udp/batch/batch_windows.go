//go:build windows

package batch

import "net"

func NewReader(pc net.PacketConn) Reader {
	return &packetReader{pc: pc}
}

func NewWriter(pc net.PacketConn) Writer {
	return &packetWriter{pc: pc}
}
