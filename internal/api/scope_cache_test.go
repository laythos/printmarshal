package api

import (
	"context"
	"sync/atomic"
	"testing"

	"printmarshal/internal/model"
	"printmarshal/internal/store"
)

// countingStore counts whole-fleet device reads: what resolving a rule group
// in a principal's scope costs.
type countingStore struct {
	store.Store
	fleetLoads atomic.Int64
}

func (c *countingStore) ListDevices(ctx context.Context, f store.DeviceFilter) ([]*model.Device, error) {
	if f.IncludeDecommissioned && f.Q == "" && f.Address == "" && f.State == "" && f.Make == "" && f.Model == "" && f.Severity == "" && len(f.IDs) == 0 && len(f.GroupIDs) == 0 && f.Limit == 0 {
		c.fleetLoads.Add(1)
	}
	return c.Store.ListDevices(ctx, f)
}

// A request by a principal scoped to a rule group resolves the group once,
// however many checks the request goes through, and a later request sees a
// changed group.
func TestScopeIsResolvedOncePerRequest(t *testing.T) {
	ts, s := newTestServer(t)
	ctx := context.Background()
	admin := login(t, ts, "admin", "adminpass123")
	_, in, out := scopedFixture(t, s)
	rule := &model.Group{Name: "one-address", Kind: "rule", Rule: &model.GroupRule{Subnet: in.Address + "/32"}}
	if err := s.Store.CreateGroup(ctx, rule); err != nil {
		t.Fatal(err)
	}
	tok := mkToken(t, ts, admin, `{"name":"bot","role":"operator","scope":["`+rule.ID+`"]}`).Secret
	cs := &countingStore{Store: s.Store}
	s.Store = cs

	// A bulk edit names its devices in the body: the scope check reads them
	// before the handler, and the handler checks them again.
	edit := func(id string) (int, string) {
		return do(t, ts, tok, "POST", "/api/devices/bulk", `{"deviceIds":["`+id+`"],"set":{"location":"Lobby"}}`)
	}
	if code, body := edit(in.ID); code != 200 {
		t.Fatalf("bulk edit: %d %s", code, body)
	}
	if n := cs.fleetLoads.Load(); n != 1 {
		t.Fatalf("the scope was resolved %d times in one request, want 1", n)
	}
	cs.fleetLoads.Store(0)
	if code, body := edit(out.ID); code != 403 {
		t.Fatalf("out-of-scope bulk edit = %d %s, want 403", code, body)
	}
	if n := cs.fleetLoads.Load(); n != 1 {
		t.Fatalf("the scope was resolved %d times on a refused request, want 1", n)
	}

	// The set is per request, not per principal: a group change is seen by
	// the next request.
	rule.Rule = &model.GroupRule{Subnet: out.Address + "/32"}
	if err := s.Store.UpdateGroup(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if code, body := edit(out.ID); code != 200 {
		t.Fatalf("after the group change: %d %s", code, body)
	}
	if code, _ := edit(in.ID); code != 403 {
		t.Fatalf("the former member is still in scope: %d", code)
	}
}
