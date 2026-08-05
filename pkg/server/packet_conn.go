package server

import (
	"net"
	"reflect"
)

// isPacketConn checks if c is a packet-oriented connection by verifying
// if the underlying type implements ReadFrom method (net.PacketConn interface).
func isPacketConn(c net.Conn) bool {
	_, ok := reflect.ValueOf(c).Interface().(interface {
		ReadFrom(b []byte) (n int, addr net.Addr, err error)
	})
	return ok
}
