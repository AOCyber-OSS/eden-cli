package daemon

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
)

// startTestProxy starts a proxy with an HTTPS cert provider on ephemeral
// ports and registers its shutdown.
func startTestProxy(t *testing.T, configure func(*Proxy)) *Proxy {
	t.Helper()
	ca, _ := newTestCA(t)
	p := NewProxy(NewState(), ca, "eden.test", 0, 0)
	if configure != nil {
		configure(p)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p
}

func listenerIPs(t *testing.T, p *Proxy) []net.IP {
	t.Helper()
	addrs := p.Addrs()
	if len(addrs) < 2 {
		t.Fatalf("Addrs() = %v, want at least an HTTP and an HTTPS listener", addrs)
	}
	var ips []net.IP
	for _, a := range addrs {
		tcp, ok := a.(*net.TCPAddr)
		if !ok {
			t.Fatalf("listener address %v is %T, want *net.TCPAddr", a, a)
		}
		ips = append(ips, tcp.IP)
	}
	return ips
}

func TestProxyListensOnLoopbackByDefault(t *testing.T) {
	p := startTestProxy(t, nil)
	for _, ip := range listenerIPs(t, p) {
		if !ip.IsLoopback() {
			t.Errorf("proxy listener bound to %v; default must be loopback only", ip)
		}
	}
}

func TestProxyLANOptInListensOnAllInterfaces(t *testing.T) {
	p := startTestProxy(t, func(p *Proxy) { p.AllowLAN = true })
	for _, ip := range listenerIPs(t, p) {
		if !ip.IsUnspecified() {
			t.Errorf("LAN opt-in listener bound to %v; want the unspecified (all-interfaces) address", ip)
		}
	}
}

func TestProxyStartReturnsBindError(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := taken.Addr().(*net.TCPAddr).Port

	p := NewProxy(NewState(), nil, "eden.test", port, 0)
	if err := p.Start(); err == nil {
		_ = p.Shutdown(context.Background())
		t.Fatal("Start succeeded on a port already in use; the bind error must be returned")
	}
}

// fakeConn is a net.Conn with a chosen remote address that records Close.
type fakeConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error         { c.closed = true; return nil }

// fakeListener hands out queued conns, then reports net.ErrClosed.
type fakeListener struct{ conns []*fakeConn }

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, net.ErrClosed
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv6unspecified, Port: 443} }

func tcpConn(ip string) *fakeConn {
	return &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 50000}}
}

func TestLoopbackOnlyListenerDropsRemotePeers(t *testing.T) {
	lan4, lan6 := tcpConn("192.168.1.50"), tcpConn("fe80::1")
	lo4, lo6 := tcpConn("127.0.0.1"), tcpConn("::1")
	ln := loopbackOnlyListener{&fakeListener{conns: []*fakeConn{lan4, lo4, lan6, lo6}}}

	for _, want := range []*fakeConn{lo4, lo6} {
		got, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if got != want {
			t.Errorf("Accept returned peer %v, want %v", got.RemoteAddr(), want.RemoteAddr())
		}
	}
	if _, err := ln.Accept(); err == nil {
		t.Error("Accept after the queue drained returned no error")
	}
	if !lan4.closed || !lan6.closed {
		t.Error("connections from non-loopback peers were not closed")
	}
	if lo4.closed || lo6.closed {
		t.Error("loopback connections were closed")
	}
}

func TestProxyFallsBackToFilteredWildcardWhenLoopbackBindDenied(t *testing.T) {
	var requested []string
	p := NewProxy(NewState(), nil, "eden.test", 80, 0)
	p.listenFn = func(network, addr string) (net.Listener, error) {
		requested = append(requested, addr)
		host, _, _ := net.SplitHostPort(addr)
		if host != "" {
			// What macOS returns to an unprivileged bind of 127.0.0.1:80.
			return nil, &net.OpError{Op: "listen", Net: network, Err: os.NewSyscallError("bind", syscall.EACCES)}
		}
		return &fakeListener{}, nil
	}

	lns, err := p.listen(80)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if got := requested[len(requested)-1]; got != ":80" {
		t.Errorf("fallback bind address = %q, want \":80\"", got)
	}
	if len(lns) != 1 {
		t.Fatalf("listeners = %d, want 1", len(lns))
	}
	if _, ok := lns[0].(loopbackOnlyListener); !ok {
		t.Errorf("fallback listener is %T; a wildcard bind must be wrapped in loopbackOnlyListener", lns[0])
	}
}
