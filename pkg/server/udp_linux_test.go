package server

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"testing"
)

func TestIsPacketConn(t *testing.T) {
	// Test isPacketConn with a unix datagram connection
	dir := t.TempDir()
	sockPath := dir + "/test.sock"

	addr, err := net.ResolveUnixAddr("unixgram", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	c, err := net.DialUnix("unixgram", &net.UnixAddr{Name: dir + "/client.sock", Net: "unixgram"}, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if !isPacketConn(c) {
		t.Error("Unix datagram connection should be a packet conn")
	}
	if !isPacketConn(struct{ *net.UnixConn }{c}) {
		t.Error("Unix datagram connection (wrapped type) should be a packet conn")
	}
}

func TestQueryExternalSocket(t *testing.T) {
	sockPath := os.Getenv("MOSDNS_TEST_SOCK")
	if sockPath == "" {
		t.Skip("MOSDNS_TEST_SOCK not set, skipping external socket test")
	}

	localSock, err := os.CreateTemp("", "mosdns-unixgram-request.sock")
	if err != nil {
		t.Fatal(err)
	}
	filePath := localSock.Name()
	localSock.Close()
	os.Remove(filePath)

	c, err := net.DialUnix("unixgram",
		&net.UnixAddr{Name: filePath, Net: "unixgram"},
		&net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	m := new(dns.Msg)
	m.SetQuestion("openresty.", dns.TypeA)
	m.RecursionDesired = true
	msg, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("query: %v\n", m)

	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}

	in := make([]byte, 512)
	n, err := c.Read(in)
	if err != nil {
		t.Fatal(err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(in[:n]); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("DNS Response: %v\n", resp)
}
