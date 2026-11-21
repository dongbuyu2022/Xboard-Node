package e2e

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// TestKickFlowMuxXUDP opens several mux TCP substreams and one XUDP session
// on a single VLESS mux connection, using xray-core's own mux client from this
// module's replace. sing-box speaks the same mux framing.
func TestKickFlowMuxXUDP(t *testing.T) {
	for _, kernel := range []string{"xray", "singbox"} {
		t.Run(kernel, func(t *testing.T) {
			runMux(t, kernel)
		})
	}
}

func runMux(t *testing.T, kernel string) {
	t.Helper()
	echo := startEcho(t)
	proxyPort := freePort(t)
	panel := newPanel(t, proxyPort)
	node := startNode(t, kernel, panel.URL)
	t.Cleanup(func() {
		if node.Process != nil {
			_ = node.Process.Kill()
		}
	})
	waitListen(t, proxyPort, node)
	proxy := "127.0.0.1:" + itoa(proxyPort)

	worker, raw := dialMux(t, proxy, user1)
	defer raw.Close()
	defer worker.Close()
	s1 := openStream(t, worker, echo, xnet.Network_TCP)
	s2 := openStream(t, worker, echo, xnet.Network_TCP)
	xu := openStream(t, worker, echo, xnet.Network_UDP)
	if err := exchange(s1, "mux-a", 4*time.Second); err != nil {
		t.Fatalf("substream a: %v\n%s", err, nodeLog(node))
	}
	if err := exchange(s2, "mux-b", 4*time.Second); err != nil {
		t.Fatalf("substream b: %v\n%s", err, nodeLog(node))
	}
	if err := exchange(xu, "xudp!!", 4*time.Second); err != nil {
		t.Fatalf("xudp: %v\n%s", err, nodeLog(node))
	}
	ctrl := startTCPFlow(t, proxy, user2, echo)
	waitHealthy(t, ctrl)

	at := time.Now()
	panel.delta("remove", userSpec(1, user1))
	d1 := waitPipe(t, s1, "mux a")
	d2 := waitPipe(t, s2, "mux b")
	dx := waitPipe(t, xu, "xudp")
	t.Logf("%s mux remove a=%s b=%s xudp=%s", kernel, d1.Sub(at).Round(time.Millisecond), d2.Sub(at).Round(time.Millisecond), dx.Sub(at).Round(time.Millisecond))
	if w, c, err := dialMuxQuiet(proxy, user1); err == nil {
		defer c.Close()
		defer w.Close()
		probe := openStream(t, w, echo, xnet.Network_TCP)
		if err := exchange(probe, "nope", time.Second); err == nil {
			t.Fatal("removed user completed a new mux substream")
		}
	}
	assertAlive(t, ctrl, "control during mux remove")

	panel.delta("add", userSpec(1, user1))
	worker2, raw2 := waitMux(t, proxy, user1, echo)
	defer raw2.Close()
	defer worker2.Close()
	back := openStream(t, worker2, echo, xnet.Network_TCP)
	if err := exchange(back, "back!!", 4*time.Second); err != nil {
		t.Fatalf("restored mux: %v", err)
	}

	panel.syncUsers(userSpec(1, user1))
	waitDead(t, ctrl, "control removed by full sync")
	if err := exchange(back, "still!", 4*time.Second); err != nil {
		t.Fatalf("kept mux user died on full sync: %v", err)
	}
	panel.syncUsers(userSpec(1, user1))
	if err := exchange(back, "again!", 4*time.Second); err != nil {
		t.Fatalf("full list resend kicked a user who is still listed: %v", err)
	}
}

type muxStream struct {
	read  *pipe.Reader
	write *pipe.Writer
}

func dialMux(t *testing.T, proxy, id string) (*mux.ClientWorker, net.Conn) {
	t.Helper()
	w, c, err := dialMuxQuiet(proxy, id)
	if err != nil {
		t.Fatalf("mux dial: %v", err)
	}
	return w, c
}

func waitMux(t *testing.T, proxy, id string, echo echoAddr) (*mux.ClientWorker, net.Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		w, c, err := dialMuxQuiet(proxy, id)
		if err != nil {
			last = err
			time.Sleep(40 * time.Millisecond)
			continue
		}
		stream := openStream(t, w, echo, xnet.Network_TCP)
		if err := exchange(stream, "ping", time.Second); err == nil {
			return w, c
		} else {
			last = err
		}
		_ = c.Close()
		_ = w.Close()
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("mux did not return: %v", last)
	return nil, nil
}

func dialMuxQuiet(proxy, id string) (*mux.ClientWorker, net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		return nil, nil, err
	}
	hdr := make([]byte, 0, 19)
	hdr = append(hdr, 0)
	raw := parseUUID(id)
	hdr = append(hdr, raw[:]...)
	hdr = append(hdr, 0, byte(protocol.RequestCommandMux))
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return nil, nil, err
	}
	toSrvR, toSrvW := pipe.New()
	fromSrvR, fromSrvW := pipe.New()
	go func() {
		_ = buf.Copy(toSrvR, buf.NewWriter(conn))
		_ = conn.Close()
	}()
	go func() {
		tmp := make([]byte, 2)
		_, _ = io.ReadFull(conn, tmp)
		_ = buf.Copy(buf.NewReader(conn), fromSrvW)
	}()
	worker, err := mux.NewClientWorker(transport.Link{Reader: fromSrvR, Writer: toSrvW}, mux.ClientStrategy{MaxConcurrency: 16})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return worker, conn, nil
}

func openStream(t *testing.T, worker *mux.ClientWorker, echo echoAddr, network xnet.Network) muxStream {
	t.Helper()
	inR, inW := pipe.New()
	outR, outW := pipe.New()
	dest := xnet.TCPDestination(xnet.IPAddress(echo.ip.To4()), xnet.Port(echo.port))
	ctx := context.Background()
	if network == xnet.Network_UDP {
		dest = xnet.UDPDestination(xnet.IPAddress(echo.ip.To4()), xnet.Port(echo.port))
		ctx = context.WithValue(ctx, "cone", true)
		ctx = session.ContextWithInbound(ctx, &session.Inbound{
			Name:   "socks",
			Source: xnet.UDPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), 40000),
		})
	}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: inR, Writer: outW}) {
		t.Fatal("mux dispatch rejected")
	}
	_ = xudp.GetGlobalID
	return muxStream{read: outR, write: inW}
}

func exchange(s muxStream, payload string, wait time.Duration) error {
	errc := make(chan error, 1)
	go func() {
		got, err := s.read.ReadMultiBuffer()
		if err != nil {
			errc <- err
			return
		}
		if got.Len() == 0 {
			buf.ReleaseMulti(got)
			errc <- io.ErrUnexpectedEOF
			return
		}
		buf.ReleaseMulti(got)
		errc <- nil
	}()
	if err := s.write.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte(payload))}); err != nil {
		return err
	}
	select {
	case err := <-errc:
		return err
	case <-time.After(wait):
		return io.EOF
	}
}

func waitPipe(t *testing.T, s muxStream, label string) time.Time {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if err := exchange(s, "z", 400*time.Millisecond); err != nil {
			return time.Now()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s still passing mux traffic", label)
	return time.Time{}
}

func itoa(n int) string {
	return string(appendInt(nil, n))
}

func appendInt(dst []byte, n int) []byte {
	if n == 0 {
		return append(dst, '0')
	}
	var tmp [16]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(dst, tmp[i:]...)
}
