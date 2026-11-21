package xray

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Access xray's internal config creator registry so we can replace the
// default dispatcher factory with ours. This runs AFTER xray's init()
// functions because our package imports xray (dependency order guarantee).
//
//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

// globalLimitDispatcher is set when the factory creates a LimitDispatcher.
// The Xray kernel reads it to configure limits and get connections.
var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:      orig,
		innerDisp:  inner,
		limitedIPs: make(map[string]map[string]int),
		byEmail:    make(map[string]map[*trackedLink]struct{}),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

// LimitDispatcher wraps xray's DefaultDispatcher to enforce per-user
// admission checks before a request is dispatched into xray-core.
//
// It intentionally does NOT mutate transport.Link.Reader/Writer. Xray's
// mux/XUDP close path requires the original concrete *pipe.Reader to remain
// intact, so the dispatcher is limited to gate-keeping and safe connection
// lifecycle bookkeeping.
type LimitDispatcher struct {
	inner     interface{}        // original DefaultDispatcher (Feature + Dispatcher)
	innerDisp routing.Dispatcher // same object, typed as Dispatcher

	// limitedUsers: users with device limit > 0, protected by mu.
	// Needs deterministic IP ordering for kick decisions.
	mu           sync.RWMutex
	limitedIPs   map[string]map[string]int // email → sourceIP → refcount
	deviceLimits map[string]int            // email → max devices
	emailToUID   map[string]int            // email → panel user ID

	// unlimitedIPs: users without device limit — sync.Map for lock-free access.
	// Each entry is *ipCounter{ips sync.Map}.
	unlimitedIPs sync.Map // email → *ipCounter

	connCount atomic.Int64 // total active connections tracked by dispatcher

	// connMu guards the admission generation and the closable-link index.
	// It is never held while a connection or link writer is closed.
	connMu  sync.Mutex
	live    map[string]*admission // email → generation authenticated against the current MemoryUser
	byEmail map[string]map[*trackedLink]struct{}
	genSeq  uint64
}

// admission is one user generation. The MemoryUser pointer is the token
// captured by xray at authentication time (validator.Get returns that pointer).
// Removing the user drops it; adding the user back installs a new pointer.
// A flow that authenticated against an older pointer is closed even if it
// reaches trackLink only after the user has been added again.
type admission struct {
	user *protocol.MemoryUser
	gen  uint64
}

// trackedLink is one dispatched flow. Reader is intentionally not wrapped:
// mux and XUDP type-assert the concrete pipe reader. Closing the inbound
// net.Conn (and interrupting the wrapped writer) stops TCP and the UDP
// sessions carried on that VLESS/VMess connection.
type trackedLink struct {
	email  string
	user   *protocol.MemoryUser
	gen    uint64
	conn   net.Conn
	writer *closeTrackingWriter
}

// ipCounter tracks IPs for unlimited users without any lock.
type ipCounter struct {
	ips sync.Map // sourceIP → *atomic.Int64 (refcount)
}

// aliveIPs returns a snapshot of distinct IPs.
func (ic *ipCounter) aliveIPs() map[string]bool {
	result := make(map[string]bool)
	ic.ips.Range(func(key, _ interface{}) bool {
		if rv, ok := ic.ips.Load(key); ok && rv.(*atomic.Int64).Load() > 0 {
			result[key.(string)] = true
		}
		return true
	})
	return result
}

// ─── routing.Dispatcher ──────────────────────────────────────────────────────

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	email, sourceIP, isTCP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return nil, err
	}

	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if email != "" && isTCP {
			d.delConn(email, sourceIP)
		}
		return nil, err
	}

	if email != "" && !d.trackLink(ctx, link, email, sourceIP, isTCP) {
		return nil, errors.New("user revoked")
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	email, sourceIP, isTCP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return err
	}

	if email != "" && !d.trackLink(ctx, link, email, sourceIP, isTCP) {
		return errors.New("user revoked")
	}
	return d.innerDisp.DispatchLink(ctx, dest, link)
}

// identifyAndCheck extracts user identity from the session context, enforces
// device limits, and returns the user's email, source IP, and TCP flag.
// Returns a non-nil error only when the connection should be rejected.
func (d *LimitDispatcher) identifyAndCheck(ctx context.Context, dest xnet.Destination) (email, sourceIP string, isTCP bool, err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return "", "", false, nil
	}
	email = si.User.Email
	sourceIP = si.Source.Address.IP().String()
	isTCP = dest.Network == xnet.Network_TCP

	if d.checkDeviceLimit(email, sourceIP, isTCP) {
		nlog.Core().Debug("xray: device limit exceeded", "email", email, "ip", sourceIP)
		return "", "", false, errors.New("device limit exceeded for " + email)
	}
	return email, sourceIP, isTCP, nil
}

// trackLink records connection lifecycle without mutating xray-core owned
// transport primitives. This keeps mux/XUDP compatible while still allowing
// the dispatcher to release device-limit state when the link closes.
func (d *LimitDispatcher) trackLink(ctx context.Context, link *transport.Link, email, sourceIP string, isTCP bool) bool {
	d.connCount.Add(1)

	tl := &trackedLink{email: email}
	if si := session.InboundFromContext(ctx); si != nil {
		tl.user = si.User
		tl.conn = si.Conn
	}
	onClose := func() {
		d.unlink(tl)
		if isTCP {
			d.delConn(email, sourceIP)
		}
		d.connCount.Add(-1)
	}
	cw := &closeTrackingWriter{Writer: link.Writer, onClose: onClose}
	tl.writer = cw
	link.Writer = cw

	if !d.admit(tl) {
		// Interrupt releases device-limit and connCount exactly once.
		// Close the accepted socket outside connMu so a late-registered
		// flow cannot outlive revocation, including remove-then-add.
		cw.Interrupt()
		if tl.conn != nil {
			_ = tl.conn.Close()
		}
		return false
	}
	return true
}

// admit records tl under the current user generation, or rejects it when the
// flow authenticated against a user object that is no longer live.
// A nil live map means admissions have not been installed yet (startup or
// unit tests); the link is still tracked so a later SetLiveUsers can drop it.
func (d *LimitDispatcher) admit(tl *trackedLink) bool {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if d.live == nil {
		d.trackLocked(tl)
		return true
	}
	adm := d.live[tl.email]
	if adm == nil || tl.user == nil || adm.user != tl.user {
		return false
	}
	tl.gen = adm.gen
	d.trackLocked(tl)
	return true
}

func (d *LimitDispatcher) trackLocked(tl *trackedLink) {
	if d.byEmail == nil {
		d.byEmail = make(map[string]map[*trackedLink]struct{})
	}
	set := d.byEmail[tl.email]
	if set == nil {
		set = make(map[*trackedLink]struct{})
		d.byEmail[tl.email] = set
	}
	set[tl] = struct{}{}
}

func (d *LimitDispatcher) unlink(tl *trackedLink) {
	if tl == nil {
		return
	}
	d.connMu.Lock()
	if set := d.byEmail[tl.email]; set != nil {
		delete(set, tl)
		if len(set) == 0 {
			delete(d.byEmail, tl.email)
		}
	}
	d.connMu.Unlock()
}

func (tl *trackedLink) kick() {
	if tl == nil {
		return
	}
	if tl.writer != nil {
		tl.writer.Interrupt()
	}
	if tl.conn != nil {
		_ = tl.conn.Close()
	}
}

// SetLiveUsers installs the MemoryUser pointers currently stored in the
// xray user manager. Pointers that are unchanged keep their generation and
// their open flows. A replaced or removed user closes every older flow.
func (d *LimitDispatcher) SetLiveUsers(users []*protocol.MemoryUser) {
	if d == nil {
		return
	}
	var closers []func()
	d.connMu.Lock()
	next := make(map[string]*admission, len(users))
	for _, user := range users {
		if user == nil || user.Email == "" {
			continue
		}
		if old := d.live[user.Email]; old != nil && old.user == user {
			next[user.Email] = old
			continue
		}
		d.genSeq++
		next[user.Email] = &admission{user: user, gen: d.genSeq}
		closers = append(closers, d.takeClosersLocked(user.Email, user, nil)...)
	}
	if d.live != nil {
		for email := range d.live {
			if _, ok := next[email]; ok {
				continue
			}
			closers = append(closers, d.takeClosersLocked(email, nil, nil)...)
		}
	}
	d.live = next
	d.connMu.Unlock()
	runClosers(closers)
}

// Allow publishes one authenticated user generation. Re-allowing the same
// MemoryUser pointer does not disturb its flows. A new pointer (remove then
// add) closes flows that still carry the previous pointer.
func (d *LimitDispatcher) Allow(user *protocol.MemoryUser) {
	if d == nil || user == nil || user.Email == "" {
		return
	}
	var closers []func()
	d.connMu.Lock()
	if d.live == nil {
		d.live = make(map[string]*admission)
	}
	if old := d.live[user.Email]; old != nil && old.user == user {
		d.connMu.Unlock()
		return
	}
	d.genSeq++
	d.live[user.Email] = &admission{user: user, gen: d.genSeq}
	closers = d.takeClosersLocked(user.Email, user, nil)
	d.connMu.Unlock()
	runClosers(closers)
}

// RevokeEmails drops whatever generation is currently live for each email and
// closes its flows. Prefer RevokePointer when the caller still has the
// MemoryUser it removed: a concurrent add may already have installed a newer
// pointer, and this call must not delete that generation.
func (d *LimitDispatcher) RevokeEmails(emails []string) {
	if d == nil || len(emails) == 0 {
		return
	}
	var closers []func()
	d.connMu.Lock()
	if d.live == nil {
		d.live = make(map[string]*admission)
	}
	for _, email := range emails {
		closers = append(closers, d.revokeLocked(email, nil)...)
	}
	d.connMu.Unlock()
	runClosers(closers)
}

// RevokePointer retires one authenticated user object. Flows and the live
// admission are removed only when they still point at that object. A newer
// Allow of the same email is left in place, including flows it already accepted.
func (d *LimitDispatcher) RevokePointer(user *protocol.MemoryUser) {
	if d == nil || user == nil || user.Email == "" {
		return
	}
	d.connMu.Lock()
	if d.live == nil {
		d.live = make(map[string]*admission)
	}
	closers := d.revokeLocked(user.Email, user)
	d.connMu.Unlock()
	runClosers(closers)
}

// revokeLocked closes flows for email. only, when non-nil, limits the revoke
// to that MemoryUser so a generation installed by a later add survives.
func (d *LimitDispatcher) revokeLocked(email string, only *protocol.MemoryUser) []func() {
	if email == "" {
		return nil
	}
	if only != nil {
		if adm := d.live[email]; adm != nil && adm.user == only {
			delete(d.live, email)
		}
		return d.takeClosersLocked(email, nil, only)
	}
	current := d.live[email]
	delete(d.live, email)
	if current == nil {
		return d.takeClosersLocked(email, nil, nil)
	}
	// Email-wide revoke still must not take flows that already belong to a
	// pointer other than the one we just unpublished. Re-read: we deleted
	// current, so every tracked flow of this email was authenticated as
	// current or as an older object. Close all of them.
	return d.takeClosersLocked(email, nil, nil)
}

// CloseEmail closes currently tracked flows without removing the user.
// Newly authenticated flows of the same generation stay allowed.
func (d *LimitDispatcher) CloseEmail(email string) int {
	if d == nil || email == "" {
		return 0
	}
	d.connMu.Lock()
	closers := d.takeClosersLocked(email, nil, nil)
	d.connMu.Unlock()
	runClosers(closers)
	return len(closers)
}

// takeClosersLocked detaches flows for email. keepUser, when non-nil, leaves
// flows authenticated as that exact user object in place. onlyUser, when
// non-nil, detaches only flows authenticated as that object.
func (d *LimitDispatcher) takeClosersLocked(email string, keepUser, onlyUser *protocol.MemoryUser) []func() {
	set := d.byEmail[email]
	if len(set) == 0 {
		return nil
	}
	var closers []func()
	for tl := range set {
		if keepUser != nil && tl.user == keepUser {
			continue
		}
		if onlyUser != nil && tl.user != onlyUser {
			continue
		}
		delete(set, tl)
		closers = append(closers, tl.kick)
	}
	if len(set) == 0 {
		delete(d.byEmail, email)
	}
	return closers
}

func runClosers(closers []func()) {
	for _, closeFn := range closers {
		if closeFn != nil {
			closeFn()
		}
	}
}

// ─── features.Feature (delegated) ───────────────────────────────────────────

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}

func (d *LimitDispatcher) Close() error {
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ─── Limit management (called by Xray kernel) ──────────────────────────────

func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits, _ map[string]int) {
	d.mu.Lock()
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.mu.Unlock()

}

func (d *LimitDispatcher) ResetConns() {
	d.mu.Lock()
	d.limitedIPs = make(map[string]map[string]int)
	d.mu.Unlock()

	// Clear unlimited IPs
	d.unlimitedIPs.Range(func(key, _ interface{}) bool {
		d.unlimitedIPs.Delete(key)
		return true
	})

	d.connCount.Store(0)
}

// GetConnectionState returns dispatcher-tracked alive IPs and connection count.
// Traffic bytes are intentionally left to xray's built-in stats pipeline.
func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	d.mu.RLock()
	emailToUID := d.emailToUID
	limitedIPs := d.limitedIPs
	d.mu.RUnlock()

	aliveIPs = make(map[int]map[string]bool)

	// Collect IPs from limited users (under RLock snapshot).
	for email, ipsMap := range limitedIPs {
		uid := emailToUID[email]
		if uid == 0 {
			continue
		}
		ipSet := make(map[string]bool, len(ipsMap))
		for ip := range ipsMap {
			ipSet[ip] = true
		}
		if len(ipSet) > 0 {
			aliveIPs[uid] = ipSet
		}
	}

	// Collect IPs from unlimited users (lock-free).
	d.unlimitedIPs.Range(func(key, value interface{}) bool {
		email := key.(string)
		uid := emailToUID[email]
		if uid == 0 {
			return true
		}
		ic := value.(*ipCounter)
		if ips := ic.aliveIPs(); len(ips) > 0 {
			// Merge with limited IPs if any
			if existing, ok := aliveIPs[uid]; ok {
				for ip := range ips {
					existing[ip] = true
				}
			} else {
				aliveIPs[uid] = ips
			}
		}
		return true
	})

	connCount = int(d.connCount.Load())
	return
}

// ─── Internal helpers ───────────────────────────────────────────────────────

// checkDeviceLimit enforces per-user device limits.
// Fast path: unlimited users use lock-free sync.Map.
// Slow path: limited users use RWMutex with deterministic IP ordering.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string, isTCP bool) bool {
	d.mu.RLock()
	limit, hasLimit := d.deviceLimits[email]
	d.mu.RUnlock()

	// Fast path: no device limit — use lock-free sync.Map.
	if !hasLimit || limit <= 0 {
		if isTCP {
			v, _ := d.unlimitedIPs.LoadOrStore(email, &ipCounter{})
			ic := v.(*ipCounter)

			// Increment IP refcount atomically.
			rv, _ := ic.ips.LoadOrStore(sourceIP, &atomic.Int64{})
			rv.(*atomic.Int64).Add(1)
		}
		return false
	}

	// Slow path: user has device limit — need deterministic ordering.
	d.mu.RLock()
	ips := d.limitedIPs[email]
	if ips != nil && ips[sourceIP] > 0 {
		d.mu.RUnlock()
		if isTCP {
			d.mu.Lock()
			d.limitedIPs[email][sourceIP]++
			d.mu.Unlock()
		}
		return false
	}

	if ips != nil && len(ips) < limit {
		d.mu.RUnlock()
		if isTCP {
			d.mu.Lock()
			if d.limitedIPs[email] == nil {
				d.limitedIPs[email] = make(map[string]int)
			}
			d.limitedIPs[email][sourceIP]++
			d.mu.Unlock()
		}
		return false
	}
	d.mu.RUnlock()

	// Over limit — need write lock for deterministic check.
	d.mu.Lock()
	defer d.mu.Unlock()

	// Re-check under write lock.
	ips = d.limitedIPs[email]
	if ips == nil {
		ips = make(map[string]int)
		d.limitedIPs[email] = ips
	}

	if ips[sourceIP] > 0 {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	if len(ips) < limit {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	// Over limit — deterministic: allow lowest IPs lexicographically.
	ipList := make([]string, 0, len(ips)+1)
	for ip := range ips {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			if isTCP {
				ips[sourceIP]++
			}
			return false
		}
	}
	return true
}

// delConn decrements the IP refcount when a connection closes.
func (d *LimitDispatcher) delConn(email, sourceIP string) {
	// Check if this is an unlimited user first (lock-free).
	if v, ok := d.unlimitedIPs.Load(email); ok {
		ic := v.(*ipCounter)
		if rv, ok := ic.ips.Load(sourceIP); ok {
			counter := rv.(*atomic.Int64)
			if counter.Add(-1) <= 0 {
				ic.ips.Delete(sourceIP)
			}
		}
		return
	}

	// Limited user — use write lock.
	d.mu.Lock()
	defer d.mu.Unlock()
	if ips, ok := d.limitedIPs[email]; ok {
		ips[sourceIP]--
		if ips[sourceIP] <= 0 {
			delete(ips, sourceIP)
		}
		if len(ips) == 0 {
			delete(d.limitedIPs, email)
		}
	}
}

type closeTrackingWriter struct {
	buf.Writer
	onClose func()
	closed  atomic.Bool
}

func (w *closeTrackingWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	return common.Close(w.Writer)
}

func (w *closeTrackingWriter) Interrupt() {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	common.Interrupt(w.Writer)
}
