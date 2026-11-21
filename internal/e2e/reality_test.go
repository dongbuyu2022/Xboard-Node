package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// The xray client below is the module replace (cedar2025/Xray-core), not a
// hand-rolled handshake. REALITY+Vision, gRPC and XHTTP only change the
// transport in front of VLESS Process; the node still admits the link in
// LimitDispatcher.DispatchLink. sing-box grpc/reality likewise enter
// vless.Inbound.NewConnectionEx and then ConnTracker.RoutedConnection.
// sing-box has no xhttp transport builder, so that case is xray-only.

const (
	realityPrivate = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
	realityPublic  = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"
	realityShortID = "0123456789abcdef"
	realitySNI     = "www.cloudflare.com"
)

func TestKickFlowRealityVision(t *testing.T) {
	for _, kernel := range []string{"xray", "singbox"} {
		t.Run(kernel, func(t *testing.T) {
			runWrappedKick(t, kernel, map[string]any{
				"network": "tcp",
				"tls":     2,
				"flow":    "xtls-rprx-vision",
				"tls_settings": map[string]any{
					"private_key": realityPrivate,
					"short_id":    realityShortID,
					"dest":        realitySNI + ":443",
					"server_name": realitySNI,
				},
			}, func(proxy string, id string, echo echoAddr) map[string]any {
				return vlessOutbound(proxy, id, echo, map[string]any{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverName":  realitySNI,
						"fingerprint": "chrome",
						"publicKey":   realityPublic,
						"shortId":     realityShortID,
					},
				}, "xtls-rprx-vision")
			})
		})
	}
}

func TestKickFlowGRPC(t *testing.T) {
	for _, kernel := range []string{"xray", "singbox"} {
		t.Run(kernel, func(t *testing.T) {
			runWrappedKick(t, kernel, map[string]any{
				"network":         "grpc",
				"tls":             0,
				"networkSettings": map[string]any{"serviceName": "xboard"},
			}, func(proxy string, id string, echo echoAddr) map[string]any {
				return vlessOutbound(proxy, id, echo, map[string]any{
					"network":      "grpc",
					"grpcSettings": map[string]any{"serviceName": "xboard"},
					"security":     "none",
				}, "")
			})
		})
	}
}

func TestKickFlowXHTTP(t *testing.T) {
	// XHTTP is an xray transport. It still delivers a conn into VLESS Process.
	runWrappedKick(t, "xray", map[string]any{
		"network": "xhttp",
		"tls":     0,
		"networkSettings": map[string]any{
			"path": "/xh",
			"mode": "stream-one",
		},
	}, func(proxy string, id string, echo echoAddr) map[string]any {
		return vlessOutbound(proxy, id, echo, map[string]any{
			"network": "xhttp",
			"xhttpSettings": map[string]any{
				"path": "/xh",
				"mode": "stream-one",
			},
			"security": "none",
		}, "")
	})
}

func runWrappedKick(t *testing.T, kernel string, extra map[string]any, outbound func(proxy, id string, echo echoAddr) map[string]any) {
	t.Helper()
	echo := startEcho(t)
	proxyPort := freePort(t)
	panel := newPanel(t, proxyPort)
	panel.mu.Lock()
	for k, v := range extra {
		panel.cfg[k] = v
	}
	panel.mu.Unlock()
	node := startNode(t, kernel, panel.URL)
	t.Cleanup(func() {
		_ = node.Process.Kill()
		_ = node.Wait()
	})
	waitListen(t, proxyPort, node)
	proxy := fmt.Sprintf("127.0.0.1:%d", proxyPort)

	c1 := startXrayDoor(t, echo, outbound(proxy, user1, echo))
	c2 := startXrayDoor(t, echo, outbound(proxy, user2, echo))
	f1 := startRawFlow(t, c1)
	f2 := startRawFlow(t, c2)
	waitHealthy(t, f1, f2)

	removedAt := time.Now()
	panel.delta("remove", userSpec(1, user1))
	dt := waitDead(t, f1, "user1 after remove")
	t.Logf("%s stop=%s", kernel, dt.Sub(removedAt).Round(time.Millisecond))
	if err := probeEcho(c1); err == nil {
		t.Fatal("removed user still completed an echo")
	}
	assertAlive(t, f2, "control during remove")

	panel.delta("add", userSpec(1, user1))
	f1b := waitRawFlow(t, c1)
	assertAlive(t, f2, "control after restore")
	assertAlive(t, f1b, "restored user")
	stopFlow(f1b)
	stopFlow(f2)
}

func vlessOutbound(proxy, id string, _ echoAddr, stream map[string]any, flow string) map[string]any {
	host, portStr, _ := net.SplitHostPort(proxy)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	user := map[string]any{"id": id, "encryption": "none"}
	if flow != "" {
		user["flow"] = flow
	}
	return map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": host,
				"port":    port,
				"users":   []any{user},
			}},
		},
		"streamSettings": stream,
	}
}

func startXrayDoor(t *testing.T, echo echoAddr, outbound map[string]any) string {
	t.Helper()
	port := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "dokodemo-door",
			"settings": map[string]any{
				"address":        echo.ip.String(),
				"port":           echo.port,
				"network":        "tcp",
				"followRedirect": false,
			},
		}},
		"outbounds": []any{outbound},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("client config: %v\n%s", err, raw)
	}
	inst, err := xcore.New(pb)
	if err != nil {
		t.Fatalf("client new: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func startRawFlow(t *testing.T, addr string) *flow {
	t.Helper()
	f := tryRawFlow(addr)
	if f == nil {
		t.Fatalf("dial %s failed", addr)
	}
	return f
}

func tryRawFlow(addr string) *flow {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	f := &flow{conn: conn, errc: make(chan error, 2)}
	go func() {
		buf := make([]byte, 16)
		for {
			// REALITY's first handshake dials the dest site, so the first
			// echo can take longer than the plain-TCP probe.
			_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				f.errc <- err
				return
			}
			f.mark()
		}
	}()
	go func() {
		payload := []byte("vision-ping!")
		for {
			_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				f.errc <- err
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()
	return f
}

func waitRawFlow(t *testing.T, addr string) *flow {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		f := tryRawFlow(addr)
		if f == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ok := true
		health := time.Now().Add(3 * time.Second)
		for f.age() >= time.Second {
			select {
			case err := <-f.errc:
				last = err
				stopFlow(f)
				ok = false
			default:
			}
			if !ok || time.Now().After(health) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if ok && f.age() < time.Second {
			return f
		}
		stopFlow(f)
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("restored flow did not come up: %v", last)
	return nil
}

func probeEcho(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("nope")
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if !bytes.Equal(buf, payload) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}
