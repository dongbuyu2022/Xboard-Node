package singbox

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/auth"
	singM "github.com/sagernet/sing/common/metadata"
	"golang.org/x/time/rate"
)

func TestSingBoxCapabilities(t *testing.T) {
	s := New(config.KernelConfig{Type: "sing-box"})
	caps := s.Capabilities()
	if !caps.PerUserSpeedLimit || !caps.DeviceLimit || !caps.AliveIPTracking || !caps.ForceCloseUser {
		t.Fatalf("unexpected sing-box capabilities: %+v", caps)
	}
	if caps.BuiltInTrafficStats || caps.ForceCloseConnection {
		t.Fatalf("unexpected sing-box capabilities: %+v", caps)
	}
	protocols := s.Protocols()
	found := false
	for _, protocol := range protocols {
		if protocol == "hysteria" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Protocols() missing hysteria: %v", protocols)
	}
}

type testConn struct {
	mu     sync.Mutex
	closed bool
	reads  [][]byte
	writes [][]byte
}

func (c *testConn) Read(b []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, errors.New("eof")
	}
	chunk := c.reads[0]
	c.reads = c.reads[1:]
	n := copy(b, chunk)
	return n, nil
}

func (c *testConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	c.writes = append(c.writes, cp)
	return len(b), nil
}

func (c *testConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *testConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}
func (c *testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

func testInboundContext(uuid, ip string) adapter.InboundContext {
	return adapter.InboundContext{
		User:   uuid,
		Source: singM.Socksaddr{Addr: netip.MustParseAddr(ip)},
	}
}

func TestConnTrackerRoutedConnectionTracksTrafficAndAliveIPs(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{reads: [][]byte{[]byte("hello")}}

	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)

	buf := make([]byte, 16)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 5 {
		t.Fatalf("Read() bytes = %d, want 5", n)
	}
	if _, err := wrapped.Write([]byte("bye")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	traffic, aliveIPs, connCount := tracker.GetUserTraffic()
	if got := traffic[1]; got != [2]int64{5, 3} {
		t.Fatalf("traffic[1] = %v, want [5 3]", got)
	}
	if !aliveIPs[1]["1.1.1.1"] {
		t.Fatal("expected alive IP to include source address")
	}
	if connCount != 1 {
		t.Fatalf("connCount = %d, want 1", connCount)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, aliveIPs, connCount = tracker.GetUserTraffic()
	if aliveIPs[1] != nil {
		t.Fatalf("aliveIPs after close = %v, want nil", aliveIPs[1])
	}
	if connCount != 0 {
		t.Fatalf("connCount after close = %d, want 0", connCount)
	}
}

func TestConnTrackerRoutedConnectionRejectsWhenDeviceLimitExceeded(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(uuid string) (int, bool) {
		if uuid != "uuid-1" {
			return 0, false
		}
		return 1, true
	})

	first := &testConn{}
	wrapped1 := tracker.RoutedConnection(context.Background(), first, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	if wrapped1 == first {
		t.Fatal("expected first connection to be wrapped")
	}

	second := &testConn{}
	wrapped2 := tracker.RoutedConnection(context.Background(), second, testInboundContext("uuid-1", "2.2.2.2"), nil, nil)
	if wrapped2 != second {
		t.Fatal("expected rejected connection to be returned unwrapped")
	}
	if !second.isClosed() {
		t.Fatal("expected rejected connection to be closed")
	}
}

func TestConnTrackerCheckDeviceGateMergesFreshGlobalDevices(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	us := tracker.users[1]
	us.addConn("1.1.1.1")
	tracker.UpdateGlobalDevices(map[int][]string{1: {"9.9.9.9"}})

	if tracker.checkDeviceGate(us, 1, "2.2.2.2", 2) {
		t.Fatal("expected lexicographically earlier candidate to remain allowed")
	}
	if !tracker.checkDeviceGate(us, 1, "99.99.99.99", 2) {
		t.Fatal("expected merged local+global device state to reject lexicographically later third device")
	}
	if tracker.checkDeviceGate(us, 1, "1.1.1.1", 2) {
		t.Fatal("existing local IP should still be allowed")
	}
	if tracker.checkDeviceGate(us, 1, "9.9.9.9", 2) {
		t.Fatal("existing global IP should still be allowed")
	}
}

func TestConnTrackerCloseByIDClosesTrackedConnection(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{}
	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	tracked, ok := wrapped.(*trackedConn)
	if !ok {
		t.Fatalf("wrapped type = %T, want *trackedConn", wrapped)
	}
	if !tracker.CloseByID(tracked.connID) {
		t.Fatal("CloseByID() = false, want true")
	}
	if !base.isClosed() {
		t.Fatal("expected underlying connection to be closed")
	}
}

func TestConnTrackerRateLimitHonorsContextCancellation(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetSpeedLimitFunc(func(uuid string) *rate.Limiter {
		if uuid != "uuid-1" {
			return nil
		}
		return rate.NewLimiter(rate.Limit(1), 1)
	})

	readCtx, cancelRead := context.WithCancel(context.Background())
	readBase := &testConn{reads: [][]byte{[]byte("a"), []byte("a")}}
	readTracked := tracker.RoutedConnection(readCtx, readBase, testInboundContext("uuid-1", "1.1.1.1"), nil, nil).(*trackedConn)
	buf := make([]byte, 8)
	if n, err := readTracked.Read(buf); err != nil || n != 1 {
		t.Fatalf("first Read() = (%d, %v), want (1, nil)", n, err)
	}
	cancelRead()
	if n, err := readTracked.Read(buf); !errors.Is(err, context.Canceled) || n != 1 {
		t.Fatalf("second Read() = (%d, %v), want (1, context canceled)", n, err)
	}

	writeCtx, cancelWrite := context.WithCancel(context.Background())
	writeBase := &testConn{}
	writeTracked := tracker.RoutedConnection(writeCtx, writeBase, testInboundContext("uuid-1", "1.1.1.2"), nil, nil).(*trackedConn)
	if n, err := writeTracked.Write([]byte("a")); err != nil || n != 1 {
		t.Fatalf("first Write() = (%d, %v), want (1, nil)", n, err)
	}
	cancelWrite()
	if n, err := writeTracked.Write([]byte("a")); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("second Write() = (%d, %v), want (0, context canceled)", n, err)
	}
}

func commitUsers(t *testing.T, tracker *ConnTracker, users []model.UserSpec) []func() {
	t.Helper()
	_, next, gen := tracker.PlanSlots(users)
	return tracker.CommitSlots(next, gen)
}

func TestConnTrackerSlotRevokeClosesOnlyThatUser(t *testing.T) {
	tracker := NewConnTracker(0)
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1"}, {ID: 2, UUID: "uuid-2"}}
	commitUsers(t, tracker, users)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})

	ctx1 := auth.ContextWithUser(context.Background(), 0)
	ctx2 := auth.ContextWithUser(context.Background(), 1)
	c1 := &testConn{}
	c2 := &testConn{}
	if got := tracker.RoutedConnection(ctx1, c1, testInboundContext("uuid-1", "1.1.1.1"), nil, nil); got == c1 {
		t.Fatal("user 1 should be tracked")
	}
	if got := tracker.RoutedConnection(ctx2, c2, testInboundContext("uuid-2", "2.2.2.2"), nil, nil); got == c2 {
		t.Fatal("user 2 should be tracked")
	}

	closers := commitUsers(t, tracker, []model.UserSpec{{ID: 2, UUID: "uuid-2"}})
	for _, closeFn := range closers {
		closeFn()
	}
	if !c1.isClosed() {
		t.Fatal("removed user's TCP flow should be closed")
	}
	if c2.isClosed() {
		t.Fatal("other user's flow must stay open")
	}

	late := &testConn{}
	if got := tracker.RoutedConnection(ctx1, late, testInboundContext("uuid-1", "1.1.1.9"), nil, nil); got != late || !late.isClosed() {
		t.Fatal("auth index from the removed generation must be closed on registration")
	}

	closers = commitUsers(t, tracker, []model.UserSpec{{ID: 2, UUID: "uuid-2"}})
	for _, closeFn := range closers {
		closeFn()
	}
	if c2.isClosed() {
		t.Fatal("repeated removal must not close the remaining user")
	}

	commitUsers(t, tracker, users)
	ctxNew := auth.ContextWithUser(context.Background(), 2)
	fresh := &testConn{}
	if got := tracker.RoutedConnection(ctxNew, fresh, testInboundContext("uuid-1", "1.1.1.3"), nil, nil); got == fresh || fresh.isClosed() {
		t.Fatal("re-added user must accept a new slot")
	}
	stale := &testConn{}
	if got := tracker.RoutedConnection(ctx1, stale, testInboundContext("uuid-1", "1.1.1.4"), nil, nil); got != stale || !stale.isClosed() {
		t.Fatal("old slot must stay dead after the user is added again")
	}
	if _, _, n := tracker.GetUserTraffic(); n != 2 {
		t.Fatalf("connCount = %d, want 2 (user 2 + re-added user)", n)
	}
}

func TestConnTrackerCloseByUUIDReleasesRefs(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
	a := &testConn{}
	b := &testConn{}
	tracker.RoutedConnection(context.Background(), a, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	wrappedB := tracker.RoutedConnection(context.Background(), b, testInboundContext("uuid-2", "2.2.2.2"), nil, nil)
	if n := tracker.CloseByUUID("uuid-1"); n != 1 {
		t.Fatalf("CloseByUUID() = %d, want 1", n)
	}
	if !a.isClosed() || b.isClosed() {
		t.Fatalf("close flags a=%v b=%v", a.isClosed(), b.isClosed())
	}
	if n := tracker.CloseByUUID("uuid-1"); n != 0 {
		t.Fatalf("repeated CloseByUUID() = %d, want 0", n)
	}
	if tracker.trackedRefs() != 1 {
		t.Fatalf("tracked refs = %d, want 1", tracker.trackedRefs())
	}
	if err := wrappedB.Close(); err != nil {
		t.Fatal(err)
	}
	if tracker.trackedRefs() != 0 {
		t.Fatalf("tracked refs after natural close = %d, want 0", tracker.trackedRefs())
	}
	if _, _, n := tracker.GetUserTraffic(); n != 0 {
		t.Fatalf("connCount = %d, want 0", n)
	}
}

func TestOldSlotStaysDeadAfterClockPassesFormerReuseWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := start
	prev := admissionNow
	admissionNow = func() time.Time { return clock }
	t.Cleanup(func() { admissionNow = prev })

	tracker := NewConnTracker(0)
	commitUsers(t, tracker, []model.UserSpec{{ID: 1, UUID: "uuid-1"}})
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	oldCtx := auth.ContextWithUser(context.Background(), 0)
	old := &testConn{}
	if got := tracker.RoutedConnection(oldCtx, old, testInboundContext("uuid-1", "1.1.1.1"), nil, nil); got == old {
		t.Fatal("original generation should be tracked")
	}

	for _, closeFn := range commitUsers(t, tracker, nil) {
		closeFn()
	}
	if !old.isClosed() {
		t.Fatal("removed user's flow should close")
	}
	clock = clock.Add(31 * time.Second)
	commitUsers(t, tracker, []model.UserSpec{{ID: 1, UUID: "uuid-1"}})

	tracker.usersMu.RLock()
	if len(tracker.slots) < 2 || tracker.slots[0].alive || tracker.slots[0].gen == tracker.slots[1].gen {
		t.Fatalf("index 0 was recycled or generations collided: %+v", tracker.slots)
	}
	newIdx := -1
	for i, slot := range tracker.slots {
		if slot.alive && slot.uuid == "uuid-1" {
			newIdx = i
		}
	}
	tracker.usersMu.RUnlock()
	if newIdx != 1 {
		t.Fatalf("restored user index = %d, want a new slot", newIdx)
	}

	late := &testConn{}
	if got := tracker.RoutedConnection(oldCtx, late, testInboundContext("uuid-1", "1.1.1.2"), nil, nil); got != late || !late.isClosed() {
		t.Fatal("auth context older than 30s was accepted as the reused user")
	}
	fresh := &testConn{}
	freshCtx := auth.ContextWithUser(context.Background(), newIdx)
	if got := tracker.RoutedConnection(freshCtx, fresh, testInboundContext("uuid-1", "1.1.1.3"), nil, nil); got == fresh || fresh.isClosed() {
		t.Fatal("new slot should accept the restored user")
	}
}

func TestPlanSlotsKeepsFreshTombstone(t *testing.T) {
	tracker := NewConnTracker(0)
	commitUsers(t, tracker, []model.UserSpec{{ID: 1, UUID: "uuid-1"}, {ID: 2, UUID: "uuid-2"}})
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
	ctx1 := auth.ContextWithUser(context.Background(), 0)
	c1 := &testConn{}
	tracker.RoutedConnection(ctx1, c1, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	c2 := &testConn{}
	tracker.RoutedConnection(auth.ContextWithUser(context.Background(), 1), c2, testInboundContext("uuid-2", "2.2.2.2"), nil, nil)

	closers := commitUsers(t, tracker, []model.UserSpec{{ID: 1, UUID: "uuid-1"}, {ID: 2, UUID: "uuid-2"}})
	if len(closers) != 0 || c1.isClosed() || c2.isClosed() {
		t.Fatal("resending the same user list must not close anyone")
	}

	closers = commitUsers(t, tracker, []model.UserSpec{{ID: 2, UUID: "uuid-2"}})
	for _, closeFn := range closers {
		closeFn()
	}
	commitUsers(t, tracker, []model.UserSpec{{ID: 1, UUID: "uuid-1"}, {ID: 2, UUID: "uuid-2"}})
	tracker.usersMu.RLock()
	n := len(tracker.slots)
	tracker.usersMu.RUnlock()
	if n < 3 {
		t.Fatalf("fresh tombstone was reused, slots=%d", n)
	}
	late := &testConn{}
	if got := tracker.RoutedConnection(ctx1, late, testInboundContext("uuid-1", "9.9.9.9"), nil, nil); got != late || !late.isClosed() {
		t.Fatal("index captured before remove must not join the restored user")
	}
	if c2.isClosed() {
		t.Fatal("control user was closed")
	}
}

func TestConnTrackerReserveRacesSlotRevoke(t *testing.T) {
	tracker := NewConnTracker(0)
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1"}}
	commitUsers(t, tracker, users)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	ctx := auth.ContextWithUser(context.Background(), 0)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			c := &testConn{}
			got := tracker.RoutedConnection(ctx, c, testInboundContext("uuid-1", "10.1.1.1"), nil, nil)
			if got != c {
				_ = got.Close()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			closers := commitUsers(t, tracker, nil)
			for _, closeFn := range closers {
				closeFn()
			}
			commitUsers(t, tracker, users)
		}
	}()
	wg.Wait()
	closers := commitUsers(t, tracker, nil)
	for _, closeFn := range closers {
		closeFn()
	}
	if _, _, n := tracker.GetUserTraffic(); n != 0 {
		t.Fatalf("connCount = %d, want 0", n)
	}
	if tracker.trackedRefs() != 0 {
		t.Fatalf("tracked refs = %d, want 0", tracker.trackedRefs())
	}
}
