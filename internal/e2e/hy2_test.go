package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestKickFlowHy2 drives the node binary (this module's sing-box replace) as a
// Hysteria2 server. The client is only a protocol peer built from the same
// go.mod. Mux and XUDP are not part of this case.
func TestKickFlowHy2(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	echo := startEcho(t)
	proxyPort := freePort(t)
	panel := newPanelWithConfig(t, map[string]any{
		"protocol":    "hysteria",
		"version":     2,
		"listen_ip":   "127.0.0.1",
		"server_port": proxyPort,
		"up_mbps":     100,
		"down_mbps":   100,
		"server_name": "127.0.0.1",
		"cert_config": map[string]any{
			"cert_mode":    "content",
			"cert_content": certPEM,
			"key_content":  keyPEM,
		},
	})
	node := startNode(t, "singbox", panel.URL)
	t.Cleanup(func() {
		if node.Process != nil {
			_ = node.Process.Kill()
			_, _ = node.Process.Wait()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c1 := waitHy2(t, ctx, proxyPort, user1)
	c2 := waitHy2(t, ctx, proxyPort, user2)
	defer c1.CloseWithError(io.EOF)
	defer c2.CloseWithError(io.EOF)

	tcp1 := hy2Stream(t, ctx, c1, echo)
	udp1 := hy2Packet(t, ctx, c1, echo)
	tcp2 := hy2Stream(t, ctx, c2, echo)
	udp2 := hy2Packet(t, ctx, c2, echo)

	removedAt := time.Now()
	panel.delta("remove", userSpec(1, user1))
	dt := waitIO(t, tcp1, echo, "hy2 tcp after remove")
	du := waitIO(t, udp1, echo, "hy2 udp after remove")
	t.Logf("hy2 delta-remove stop tcp=%s udp=%s", dt.Sub(removedAt).Round(time.Millisecond), du.Sub(removedAt).Round(time.Millisecond))
	if _, err := dialHy2(ctx, proxyPort, user1); err == nil {
		t.Fatal("removed hy2 user authenticated")
	}
	if err := pingStream(tcp2); err != nil {
		t.Fatalf("control hy2 tcp died: %v", err)
	}
	if err := pingPacket(udp2, echo); err != nil {
		t.Fatalf("control hy2 udp died: %v", err)
	}

	panel.delta("add", userSpec(1, user1))
	c1b := waitHy2(t, ctx, proxyPort, user1)
	defer c1b.CloseWithError(io.EOF)
	tcp1b := hy2Stream(t, ctx, c1b, echo)
	udp1b := hy2Packet(t, ctx, c1b, echo)
	if err := pingStream(tcp1b); err != nil || pingPacket(udp1b, echo) != nil {
		t.Fatalf("restored hy2 user cannot pass traffic: tcp=%v udp=%v", err, pingPacket(udp1b, echo))
	}

	panel.syncUsers(userSpec(1, user1))
	fullAt := time.Now()
	dt2 := waitIO(t, tcp2, echo, "hy2 tcp after full sync")
	t.Logf("hy2 full-sync stop tcp=%s", dt2.Sub(fullAt).Round(time.Millisecond))
	if err := pingStream(tcp1b); err != nil {
		t.Fatalf("kept hy2 user died on full sync: %v", err)
	}
	_ = udp1b
	_ = udp2
}

func selfSignedPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

func waitHy2(t *testing.T, ctx context.Context, port int, password string) *hysteria2.Client {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		client, err := dialHy2(ctx, port, password)
		if err == nil {
			return client
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("hy2 auth for %s: %v", password, last)
	return nil
}

func dialHy2(ctx context.Context, port int, password string) (*hysteria2.Client, error) {
	tlsCfg, err := tls.NewClient(ctx, log.StdLogger(), "127.0.0.1", option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "127.0.0.1",
		ALPN:       []string{"h3"},
	})
	if err != nil {
		return nil, err
	}
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       ctx,
		Dialer:        N.SystemDialer,
		Logger:        logger.NOP(),
		ServerAddress: M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port)),
		Password:      password,
		TLSConfig:     tlsCfg,
	})
	if err != nil {
		return nil, err
	}
	probe, err := client.DialConn(ctx, M.ParseSocksaddr("127.0.0.1:1"))
	if err != nil {
		_ = client.CloseWithError(err)
		return nil, err
	}
	_ = probe.Close()
	return client, nil
}

func hy2Stream(t *testing.T, ctx context.Context, c *hysteria2.Client, echo echoAddr) net.Conn {
	t.Helper()
	conn, err := c.DialConn(ctx, M.ParseSocksaddr(fmt.Sprintf("%s:%d", echo.ip, echo.port)))
	if err != nil {
		t.Fatal(err)
	}
	if err := pingStream(conn); err != nil {
		t.Fatal(err)
	}
	return conn
}

func hy2Packet(t *testing.T, ctx context.Context, c *hysteria2.Client, echo echoAddr) net.PacketConn {
	t.Helper()
	pc, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := pingPacket(pc, echo); err != nil {
		t.Fatal(err)
	}
	return pc
}

func pingStream(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("hy2-tcp")); err != nil {
		return err
	}
	buf := make([]byte, 16)
	_, err := io.ReadFull(conn, buf[:7])
	return err
}

func pingPacket(pc net.PacketConn, echo echoAddr) error {
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	addr := &net.UDPAddr{IP: echo.ip, Port: echo.port}
	if _, err := pc.WriteTo([]byte("hy2-udp"), addr); err != nil {
		return err
	}
	buf := make([]byte, 32)
	_, _, err := pc.ReadFrom(buf)
	return err
}

func waitIO(t *testing.T, closer io.Closer, echo echoAddr, label string) time.Time {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	if pc, ok := closer.(net.PacketConn); ok {
		buf := make([]byte, 32)
		addr := &net.UDPAddr{IP: echo.ip, Port: echo.port}
		for time.Now().Before(deadline) {
			_ = pc.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
			if _, err := pc.WriteTo([]byte("x"), addr); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return time.Now()
			}
			_ = pc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			if _, _, err := pc.ReadFrom(buf); err != nil {
				// Hy2 delivers UDP as QUIC datagrams. Closing the routed
				// packet conn drops the session; the client write can still
				// return nil, but the echo stops. A timeout with no reply
				// means the flow is no longer forwarded.
				return time.Now()
			}
		}
		t.Fatalf("%s still open", label)
	}
	conn := closer.(net.Conn)
	buf := make([]byte, 8)
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := conn.Write([]byte("x")); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return time.Now()
		}
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return time.Now()
		}
	}
	t.Fatalf("%s still open", label)
	return time.Time{}
}

func newPanelWithConfig(t *testing.T, cfg map[string]any) *synthPanel {
	t.Helper()
	p := newPanel(t, cfg["server_port"].(int))
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
	return p
}
