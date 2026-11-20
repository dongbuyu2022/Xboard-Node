package singbox

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync/atomic"

	"github.com/sagernet/sing/common/auth"

	"github.com/cedar2025/xboard-node/internal/model"
)

var nextGenFallback atomic.Uint64

// admissionSlot is one sing-box user index. The index is the value sing-box
// stores in the connection context at authentication time, so it must not be
// reused for a later generation. A removed user becomes a tombstone at the
// same index; a later add appends a new index.
type admissionSlot struct {
	id    int
	uuid  string
	gen   uint64
	alive bool
	spec  model.UserSpec
}

// reserve records ref if its auth-time slot (when present) is still the live
// generation. The check and insert share usersMu with SyncSlots/CommitSlots,
// so a revocation cannot snapshot a moment that misses this flow.
func (t *ConnTracker) reserve(ctx context.Context, ref *connRef) bool {
	if ref == nil {
		return false
	}
	idx, hasIdx := auth.UserFromContext[int](ctx)
	t.usersMu.Lock()
	defer t.usersMu.Unlock()
	if hasIdx {
		if !t.slotAliveLocked(idx) {
			return false
		}
		ref.slot = idx
		ref.gen = t.slots[idx].gen
	}
	if t.refs == nil {
		t.refs = make(map[*connRef]struct{})
	}
	t.refs[ref] = struct{}{}
	return true
}

func (t *ConnTracker) slotAliveLocked(idx int) bool {
	return idx >= 0 && idx < len(t.slots) && t.slots[idx].alive
}

func (t *ConnTracker) unlink(ref *connRef) {
	if t == nil || ref == nil {
		return
	}
	t.usersMu.Lock()
	delete(t.refs, ref)
	t.usersMu.Unlock()
}

// PlanSlots computes the next stable user list without mutating tracker state.
// ordered is what the kernel config must emit, including tombstones, so
// in-flight authentications keep their original index.
func (t *ConnTracker) PlanSlots(users []model.UserSpec) (ordered []model.UserSpec, next []admissionSlot, nextGen uint64) {
	t.usersMu.RLock()
	current := append([]admissionSlot(nil), t.slots...)
	nextGen = t.nextGen
	t.usersMu.RUnlock()
	ordered, next, nextGen = planSlots(current, users, nextGen)
	return ordered, next, nextGen
}

// CommitSlots installs a previously planned slot table and detaches flows
// whose slot was revoked. Closers run outside the lock.
func (t *ConnTracker) CommitSlots(next []admissionSlot, nextGen uint64) []func() {
	t.usersMu.Lock()
	var closers []func()
	for i := range t.slots {
		old := t.slots[i]
		var neu admissionSlot
		if i < len(next) {
			neu = next[i]
		}
		if old.alive && (!neu.alive || neu.uuid != old.uuid || neu.id != old.id) {
			closers = append(closers, t.takeSlotClosersLocked(i)...)
		}
	}
	t.slots = append([]admissionSlot(nil), next...)
	if nextGen > t.nextGen {
		t.nextGen = nextGen
	}
	t.usersMu.Unlock()
	return closers
}

func (t *ConnTracker) takeSlotClosersLocked(slot int) []func() {
	var out []func()
	for ref := range t.refs {
		if ref.slot != slot {
			continue
		}
		delete(t.refs, ref)
		if ref.close != nil {
			out = append(out, ref.close)
		}
	}
	return out
}

func (t *ConnTracker) trackedRefs() int {
	t.usersMu.RLock()
	defer t.usersMu.RUnlock()
	return len(t.refs)
}

func planSlots(current []admissionSlot, users []model.UserSpec, nextGen uint64) ([]model.UserSpec, []admissionSlot, uint64) {
	live := make(map[int]model.UserSpec, len(users))
	for _, u := range users {
		live[u.ID] = u
	}
	next := append([]admissionSlot(nil), current...)
	for i := range next {
		slot := &next[i]
		if !slot.alive {
			continue
		}
		spec, ok := live[slot.id]
		if ok && spec.UUID == slot.uuid {
			slot.spec = spec
			delete(live, slot.id)
			continue
		}
		slot.alive = false
		slot.uuid = newTombUUID()
		slot.spec = model.UserSpec{ID: -1, UUID: slot.uuid}
	}
	for _, u := range users {
		if _, pending := live[u.ID]; !pending {
			continue
		}
		delete(live, u.ID)
		nextGen++
		next = append(next, admissionSlot{
			id:    u.ID,
			uuid:  u.UUID,
			gen:   nextGen,
			alive: true,
			spec:  u,
		})
	}
	ordered := make([]model.UserSpec, len(next))
	for i, slot := range next {
		ordered[i] = slot.spec
	}
	return ordered, next, nextGen
}

func newTombUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A counter-based fallback still cannot collide with a real user UUID
		// that was issued by the panel; it only has to be unique in-process.
		nextGenFallback.Add(1)
		n := nextGenFallback.Load()
		return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
