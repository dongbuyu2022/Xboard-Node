package e2e

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// End-to-end check against the node binary produced from this module
// (cedar2025/Xray-core and cedar2025/sing-box replaces, not an upstream
// Xray stand-in). The panel is synthetic and holds no production credentials.
//
// Not covered here: VLESS mux, XUDP, and TLS/REALITY. Those paths share the
// same admission hook but are not exercised with live sockets.

const (
	user1 = "11111111-1111-4111-8111-111111111111"
	user2 = "22222222-2222-4222-8222-222222222222"
)

func TestMain(m *testing.M) {
	if os.Getenv("XBOARD_NODE_BIN") == "" {
		bin := filepath.Join(os.TempDir(), "xboard-node-kickflow-e2e")
		cmd := exec.Command("go", "build",
			"-tags", "with_quic with_utls with_wireguard with_clash_api",
			"-o", bin, "./cmd/xboard-node")
		cmd.Dir = moduleRoot()
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "build node: %v\n%s", err, out)
			os.Exit(1)
		}
		os.Setenv("XBOARD_NODE_BIN", bin)
	}
	os.Exit(m.Run())
}

func TestKickFlow(t *testing.T) {
	for _, kernel := range []string{"xray", "singbox"} {
		t.Run(kernel, func(t *testing.T) {
			runKickFlow(t, kernel)
		})
	}
}

func runKickFlow(t *testing.T, kernel string) {
	t.Helper()
	echo := startEcho(t)
	proxyPort := freePort(t)
	panel := newPanel(t, proxyPort)
	node := startNode(t, kernel, panel.URL)
	t.Cleanup(func() {
		node.Process.Kill()
		_ = node.Wait()
	})

	waitListen(t, proxyPort, node)
	proxy := fmt.Sprintf("127.0.0.1:%d", proxyPort)

	tcp1 := startTCPFlow(t, proxy, user1, echo)
	udp1 := startUDPFlow(t, proxy, user1, echo)
	tcp2 := startTCPFlow(t, proxy, user2, echo)
	udp2 := startUDPFlow(t, proxy, user2, echo)
	waitHealthy(t, tcp1, udp1, tcp2, udp2)

	removedAt := time.Now()
	panel.delta("remove", userSpec(1, user1))
	dt1 := waitDead(t, tcp1, "user1 tcp after delta remove")
	du1 := waitDead(t, udp1, "user1 udp after delta remove")
	t.Logf("%s delta-remove stop tcp=%s udp=%s (from send)", kernel, dt1.Sub(removedAt).Round(time.Millisecond), du1.Sub(removedAt).Round(time.Millisecond))
	if err := dialExpectFail(proxy, user1, echo, "tcp"); err != nil {
		t.Fatalf("removed user still accepted a new tcp flow: %v", err)
	}
	assertAlive(t, tcp2, "control tcp during user1 remove")
	assertAlive(t, udp2, "control udp during user1 remove")

	panel.delta("add", userSpec(1, user1))
	tcp1b := waitNewFlow(t, proxy, user1, echo, "tcp")
	udp1b := waitNewFlow(t, proxy, user1, echo, "udp")
	assertAlive(t, tcp2, "control tcp after user1 restore")

	// Full-list diff drops only user2.
	panel.syncUsers(userSpec(1, user1))
	fullAt := time.Now()
	dt2 := waitDead(t, tcp2, "user2 tcp after full sync")
	du2 := waitDead(t, udp2, "user2 udp after full sync")
	t.Logf("%s full-sync stop tcp=%s udp=%s", kernel, dt2.Sub(fullAt).Round(time.Millisecond), du2.Sub(fullAt).Round(time.Millisecond))
	assertAlive(t, tcp1b, "user1 tcp survives full sync that keeps user1")
	assertAlive(t, udp1b, "user1 udp survives full sync that keeps user1")

	// Repeated remove is a no-op for an already-deleted user and must not kill user1.
	panel.delta("remove", userSpec(2, user2))
	panel.delta("remove", userSpec(2, user2))
	time.Sleep(200 * time.Millisecond)
	assertAlive(t, tcp1b, "user1 after repeated remove of user2")
	if node.ProcessState != nil && node.ProcessState.Exited() {
		t.Fatalf("node exited during repeated remove\n%s", nodeLog(node))
	}

	// Remove and immediate add: the pre-remove flow dies, a post-add flow works.
	panel.delta("remove", userSpec(1, user1))
	panel.delta("add", userSpec(1, user1))
	waitDead(t, tcp1b, "user1 tcp after remove+add")
	waitDead(t, udp1b, "user1 udp after remove+add")
	tcp1c := waitNewFlow(t, proxy, user1, echo, "tcp")
	udp1c := waitNewFlow(t, proxy, user1, echo, "udp")
	stopFlow(tcp1c)
	stopFlow(udp1c)
}

type flow struct {
	conn net.Conn
	errc chan error
	last int64
	mu   sync.Mutex
}

func (f *flow) mark() {
	f.mu.Lock()
	f.last = time.Now().UnixNano()
	f.mu.Unlock()
}

func (f *flow) age() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == 0 {
		return time.Hour
	}
	return time.Since(time.Unix(0, f.last))
}

type echoAddr struct {
	ip   net.IP
	port int
}

func startTCPFlow(t *testing.T, proxy, id string, echo echoAddr) *flow {
	t.Helper()
	f := tryTCPFlow(proxy, id, echo)
	if f == nil {
		t.Fatalf("dial tcp %s failed", id)
	}
	return f
}

func tryTCPFlow(proxy, id string, echo echoAddr) *flow {
	conn, err := dialVLESS(proxy, id, "tcp", echo)
	if err != nil {
		return nil
	}
	f := &flow{conn: conn, errc: make(chan error, 2)}
	go func() {
		buf := make([]byte, 256)
		_, err := io.ReadFull(conn, buf[:2]) // response version + addon length
		if err != nil {
			f.errc <- err
			return
		}
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				f.errc <- err
				return
			}
			f.mark()
		}
	}()
	go func() {
		payload := []byte("abcdefghij")
		for {
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				f.errc <- err
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()
	return f
}

func startUDPFlow(t *testing.T, proxy, id string, echo echoAddr) *flow {
	t.Helper()
	f := tryUDPFlow(proxy, id, echo)
	if f == nil {
		t.Fatalf("dial udp %s failed", id)
	}
	return f
}

func tryUDPFlow(proxy, id string, echo echoAddr) *flow {
	conn, err := dialVLESS(proxy, id, "udp", echo)
	if err != nil {
		return nil
	}
	f := &flow{conn: conn, errc: make(chan error, 2)}
	go func() {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			f.errc <- err
			return
		}
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var n uint16
			if err := binary.Read(conn, binary.BigEndian, &n); err != nil {
				f.errc <- err
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(conn, buf); err != nil {
				f.errc <- err
				return
			}
			f.mark()
		}
	}()
	go func() {
		payload := []byte("udp-ping!!")
		for {
			var pkt bytes.Buffer
			_ = binary.Write(&pkt, binary.BigEndian, uint16(len(payload)))
			pkt.Write(payload)
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(pkt.Bytes()); err != nil {
				f.errc <- err
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()
	return f
}

func waitNewFlow(t *testing.T, proxy, id string, echo echoAddr, kind string) *flow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		var f *flow
		if kind == "udp" {
			f = tryUDPFlow(proxy, id, echo)
		} else {
			f = tryTCPFlow(proxy, id, echo)
		}
		if f == nil {
			time.Sleep(40 * time.Millisecond)
			continue
		}
		ok := true
		health := time.Now().Add(2 * time.Second)
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
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("new %s flow for %s did not come up: %v", kind, id, last)
	return nil
}

func waitHealthy(t *testing.T, flows ...*flow) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for _, f := range flows {
		for {
			if f.age() < time.Second {
				break
			}
			select {
			case err := <-f.errc:
				t.Fatalf("flow died before it became healthy: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("flow did not pass traffic")
			}
			time.Sleep(30 * time.Millisecond)
		}
	}
}

func waitDead(t *testing.T, f *flow, label string) time.Time {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case <-f.errc:
		return time.Now()
	case <-timer.C:
		t.Fatalf("%s still passing traffic", label)
		return time.Time{}
	}
}

func assertAlive(t *testing.T, f *flow, label string) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-f.errc:
		t.Fatalf("%s stopped: %v", label, err)
	default:
	}
	if f.age() > 2*time.Second {
		t.Fatalf("%s is not moving traffic (age %s)", label, f.age())
	}
}

func stopFlow(f *flow) {
	if f != nil && f.conn != nil {
		f.conn.Close()
	}
}

func dialExpectFail(proxy, id string, echo echoAddr, kind string) error {
	conn, err := dialVLESS(proxy, id, kind, echo)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	if kind == "tcp" {
		if _, err := conn.Write([]byte("nope")); err != nil {
			return nil
		}
		if _, err := conn.Read(buf); err != nil {
			return nil
		}
		return fmt.Errorf("read payload from a removed user")
	}
	var pkt bytes.Buffer
	_ = binary.Write(&pkt, binary.BigEndian, uint16(4))
	pkt.WriteString("nope")
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return nil
	}
	if _, err := conn.Read(buf); err != nil {
		return nil
	}
	return fmt.Errorf("udp payload from a removed user")
}

func dialVLESS(proxy, id, kind string, echo echoAddr) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		return nil, err
	}
	var hdr bytes.Buffer
	hdr.WriteByte(0)
	raw := parseUUID(id)
	hdr.Write(raw[:])
	hdr.WriteByte(0)
	if kind == "udp" {
		hdr.WriteByte(2)
	} else {
		hdr.WriteByte(1)
	}
	_ = binary.Write(&hdr, binary.BigEndian, uint16(echo.port))
	hdr.WriteByte(1)
	hdr.Write(echo.ip.To4())
	if _, err := conn.Write(hdr.Bytes()); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func parseUUID(s string) [16]byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		panic(s)
	}
	var out [16]byte
	copy(out[:], raw)
	return out
}

type userSpecBody struct {
	ID   int    `json:"id"`
	UUID string `json:"uuid"`
}

func userSpec(id int, uuid string) userSpecBody {
	return userSpecBody{ID: id, UUID: uuid}
}

type synthPanel struct {
	URL    string
	server *httptest.Server
	mu     sync.Mutex
	users  []userSpecBody
	cfg    map[string]any
	send   chan map[string]any
}

func newPanel(t *testing.T, proxyPort int) *synthPanel {
	t.Helper()
	p := &synthPanel{
		users: []userSpecBody{userSpec(1, user1), userSpec(2, user2)},
		cfg: map[string]any{
			"protocol":    "vless",
			"listen_ip":   "127.0.0.1",
			"server_port": proxyPort,
			"network":     "tcp",
			"tls":         0,
		},
		send: make(chan map[string]any, 16),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/server/handshake", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"websocket": map[string]any{"enabled": true, "ws_url": "ws" + strings.TrimPrefix(p.URL, "http") + "/ws"},
			"settings":  map[string]any{"push_interval": 3600, "pull_interval": 3600},
		})
	})
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(p.cfg)
	})
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"users": p.users})
	})
	mux.HandleFunc("/ws", p.serveWS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	p.server = srv
	p.URL = srv.URL
	t.Cleanup(srv.Close)
	return p
}

func (p *synthPanel) serveWS(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.WriteJSON(map[string]any{"event": "auth.success"})
	p.mu.Lock()
	_ = conn.WriteJSON(map[string]any{"event": "sync.config", "data": map[string]any{"config": p.cfg, "node_id": 1}})
	users := append([]userSpecBody(nil), p.users...)
	p.mu.Unlock()
	_ = conn.WriteJSON(map[string]any{"event": "sync.users", "data": map[string]any{"users": users, "node_id": 1}})
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	for msg := range p.send {
		if err := conn.WriteJSON(msg); err != nil {
			return
		}
	}
}

func (p *synthPanel) delta(action string, users ...userSpecBody) {
	p.mu.Lock()
	switch action {
	case "remove":
		next := p.users[:0]
		drop := map[int]bool{}
		for _, u := range users {
			drop[u.ID] = true
		}
		for _, u := range p.users {
			if !drop[u.ID] {
				next = append(next, u)
			}
		}
		p.users = append([]userSpecBody(nil), next...)
	case "add":
		for _, u := range users {
			replaced := false
			for i := range p.users {
				if p.users[i].ID == u.ID {
					p.users[i] = u
					replaced = true
				}
			}
			if !replaced {
				p.users = append(p.users, u)
			}
		}
	}
	p.mu.Unlock()
	p.send <- map[string]any{
		"event": "sync.user.delta",
		"data":  map[string]any{"action": action, "users": users, "node_id": 1},
	}
}

func (p *synthPanel) syncUsers(users ...userSpecBody) {
	p.mu.Lock()
	p.users = append([]userSpecBody(nil), users...)
	p.mu.Unlock()
	p.send <- map[string]any{
		"event": "sync.users",
		"data":  map[string]any{"users": users, "node_id": 1},
	}
}

func startNode(t *testing.T, kernel, panelURL string) *exec.Cmd {
	t.Helper()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`
log:
  level: info
  output: stdout
panel:
  url: %q
  token: synthetic-token
  node_id: 1
  node_type: vless
kernel:
  type: %q
  config_dir: %q
%s
node:
  push_interval: 3600
  pull_interval: 3600
ws:
  status_interval: 3600
  discovery_interval: 3600
`, panelURL, kernel, dir, loopbackRoute(kernel))
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "node.log")
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logf.Close() })
	cmd := exec.Command(os.Getenv("XBOARD_NODE_BIN"), "-c", path)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.Env = append(os.Environ(), "XBOARD_NODE_LOG="+logPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("node log:\n%s", nodeLog(cmd))
		}
	})
	return cmd
}

func nodeLog(cmd *exec.Cmd) string {
	path := ""
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "XBOARD_NODE_LOG=") {
			path = strings.TrimPrefix(e, "XBOARD_NODE_LOG=")
		}
	}
	b, _ := os.ReadFile(path)
	if len(b) > 8000 {
		return string(b[len(b)-8000:])
	}
	return string(b)
}

func waitListen(t *testing.T, port int, cmd *exec.Cmd) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			t.Fatalf("node exited before listen\n%s", nodeLog(cmd))
		}
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("proxy port %d did not open\n%s", port, nodeLog(cmd))
}

func startEcho(t *testing.T) echoAddr {
	t.Helper()
	// 127.0.0.1 is on the kernel's private-address block list. The node
	// config inserts a more specific direct rule ahead of that block.
	ip := net.ParseIP("127.0.0.1")
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		t.Fatalf("echo udp: %v", err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(buf[:n], addr)
		}
	}()
	return echoAddr{ip: ip, port: port}
}

func loopbackRoute(kernel string) string {
	if kernel == "xray" {
		return `  custom_route:
    - type: field
      ip: ["127.0.0.1/32"]
      outboundTag: direct`
	}
	return `  custom_route:
    - ip_cidr: ["127.0.0.1/32"]
      outbound: direct`
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func moduleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}
