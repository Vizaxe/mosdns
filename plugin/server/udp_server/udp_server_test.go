package udp_server

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/miekg/dns"
)

type testHandler struct{}

func (h *testHandler) Handle(
	ctx context.Context,
	q *dns.Msg,
	meta server.QueryMeta,
	packFn func(m *dns.Msg) (*[]byte, error),
) *[]byte {
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IP{1, 2, 3, 4},
	})

	payload, err := packFn(resp)
	if err != nil {
		return nil
	}
	return payload
}

func TestUDPQuery(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeUDP(c.(*net.UDPConn), &testHandler{}, server.UDPServerOpts{})
	}()

	addr := c.LocalAddr().String()
	client, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	msg, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}

	in := make([]byte, 512)
	n, err := client.Read(in)
	if err != nil {
		t.Fatal(err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(in[:n]); err != nil {
		t.Fatal(err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if !a.A.Equal(net.IP{1, 2, 3, 4}) {
		t.Fatalf("expected 1.2.3.4, got %s", a.A)
	}

	c.Close()
	<-errCh
}

func TestUnixgramQuery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unixgram not supported on windows")
	}

	sockPath := filepath.Join(t.TempDir(), "udp.sock")
	fmt.Println(sockPath)

	c, err := net.ListenPacket("unixgram", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeUnix(c.(*net.UnixConn), &testHandler{}, server.UDPServerOpts{})
	}()

	clientPath := filepath.Join(t.TempDir(), "client.sock")
	client, err := net.DialUnix("unixgram",
		&net.UnixAddr{Name: clientPath, Net: "unixgram"},
		&net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	msg, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}

	in := make([]byte, 512)
	n, err := client.Read(in)
	if err != nil {
		t.Fatal(err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(in[:n]); err != nil {
		t.Fatal(err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if !a.A.Equal(net.IP{1, 2, 3, 4}) {
		t.Fatalf("expected 1.2.3.4, got %s", a.A)
	}
	fmt.Println(a.A)

	c.Close()
	<-errCh
}
