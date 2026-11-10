package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"printmarshal/internal/model"
	"printmarshal/internal/store"
)

// Reports are readers of the device collection too: a group-scoped principal
// gets its own devices, and cannot widen the report by naming a device or a
// group outside its scope.
func TestReportsAreGroupScoped(t *testing.T) {
	ts, s := newTestServer(t)
	ctx := context.Background()
	admin := login(t, ts, "admin", "adminpass123")
	g, in, out := scopedFixture(t, s)
	other := &model.Group{Name: "site-b", Kind: "static", MemberIDs: []string{out.ID}}
	if err := s.Store.CreateGroup(ctx, other); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*model.Device{in, out} {
		if _, err := s.Store.ApplyPoll(ctx, d.ID, store.PollUpdate{Firmware: "1.0", Reachable: true, At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	tok := mkToken(t, ts, admin, `{"name":"bot","role":"viewer","scope":["`+g.ID+`"]}`).Secret

	var rep struct {
		Range   struct{ Devices int }
		Devices []struct{ DeviceID string }
	}
	code, body := do(t, ts, tok, "GET", "/api/reports/firmware", "")
	if code != 200 {
		t.Fatalf("scoped report: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &rep)
	if rep.Range.Devices != 1 || len(rep.Devices) != 1 || rep.Devices[0].DeviceID != in.ID {
		t.Fatalf("scoped report covers more than the scope: %s", body)
	}
	if strings.Contains(body, out.ID) {
		t.Fatalf("scoped report leaked an out-of-scope device: %s", body)
	}
	if code, body := do(t, ts, tok, "GET", "/api/reports/firmware?group="+g.ID, ""); code != 200 || strings.Contains(body, out.ID) {
		t.Fatalf("own group: %d %s", code, body)
	}
	if code, body := do(t, ts, tok, "GET", "/api/reports/firmware?group="+other.ID, ""); code != 403 {
		t.Fatalf("group outside the scope = %d %s, want 403", code, body)
	}
	if code, body := do(t, ts, tok, "GET", "/api/reports/firmware?device="+out.ID, ""); code != 403 {
		t.Fatalf("device outside the scope = %d %s, want 403", code, body)
	}
	if code, body := do(t, ts, tok, "GET", "/api/reports/firmware?device="+in.ID, ""); code != 200 || !strings.Contains(body, in.ID) {
		t.Fatalf("own device: %d %s", code, body)
	}
	// The aggregate reports take the same scope: the utilisation range counts
	// the scope's devices, not the fleet's.
	code, body = do(t, ts, tok, "GET", "/api/reports/utilisation?days=7", "")
	if code != 200 {
		t.Fatalf("utilisation: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &rep)
	if rep.Range.Devices != 1 {
		t.Fatalf("utilisation range = %+v, want one device: %s", rep.Range, body)
	}
	// Admins are unscoped.
	if code, body := do(t, ts, admin, "GET", "/api/reports/firmware", ""); code != 200 || !strings.Contains(body, out.ID) || !strings.Contains(body, in.ID) {
		t.Fatalf("admin report filtered: %d %s", code, body)
	}
}

// The firmware inventory and the outdated list are fleet readers as well.
func TestFirmwareInventoryIsGroupScoped(t *testing.T) {
	ts, s, _ := newFirmwareServer(t)
	ctx := context.Background()
	admin := login(t, ts, "admin", "adminpass123")
	g, in, out := scopedFixture(t, s)
	other := &model.Group{Name: "site-b", Kind: "static", MemberIDs: []string{out.ID}}
	if err := s.Store.CreateGroup(ctx, other); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*model.Device{in, out} {
		if _, err := s.Store.ApplyPoll(ctx, d.ID, store.PollUpdate{Firmware: "1.0", Reachable: true, At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := upload(t, ts, admin, map[string]string{"vendor": "Acme", "models": "Acme 100", "version": "2.0"}, "acme-2.0.bin", "firmware"); code != 201 {
		t.Fatalf("upload: %d %s", code, body)
	}
	tok := mkToken(t, ts, admin, `{"name":"bot","role":"viewer","scope":["`+g.ID+`"]}`).Secret

	var inv struct {
		Devices int
		Entries []struct{ DeviceIDs []string }
	}
	code, body := do(t, ts, tok, "GET", "/api/firmware/inventory", "")
	if code != 200 {
		t.Fatalf("scoped inventory: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &inv)
	if inv.Devices != 1 || len(inv.Entries) != 1 || len(inv.Entries[0].DeviceIDs) != 1 || inv.Entries[0].DeviceIDs[0] != in.ID {
		t.Fatalf("scoped inventory covers more than the scope: %s", body)
	}
	if code, body := do(t, ts, tok, "GET", "/api/firmware/inventory?group="+other.ID, ""); code != 403 {
		t.Fatalf("group outside the scope = %d %s, want 403", code, body)
	}
	if code, body := do(t, ts, tok, "GET", "/api/firmware/inventory?group="+g.ID, ""); code != 200 || strings.Contains(body, out.ID) {
		t.Fatalf("own group: %d %s", code, body)
	}
	code, body = do(t, ts, tok, "GET", "/api/firmware/outdated", "")
	if code != 200 || !strings.Contains(body, in.ID) || strings.Contains(body, out.ID) {
		t.Fatalf("scoped outdated list: %d %s", code, body)
	}
	if code, body := do(t, ts, admin, "GET", "/api/firmware/outdated", ""); code != 200 || !strings.Contains(body, out.ID) || !strings.Contains(body, in.ID) {
		t.Fatalf("admin outdated list filtered: %d %s", code, body)
	}
	if code, body := do(t, ts, admin, "GET", "/api/firmware/inventory", ""); code != 200 || !strings.Contains(body, `"devices":2`) {
		t.Fatalf("admin inventory filtered: %d %s", code, body)
	}
}
