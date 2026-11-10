package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"printmarshal/internal/model"
)

// An operator settles a pending address change from the device page: confirm
// moves the record, dismiss leaves it; viewers cannot, and there is nothing to
// settle twice.
func TestResolveDeviceAddress(t *testing.T) {
	ts, s := newTestServer(t)
	ctx := context.Background()
	d, _, err := s.Store.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.5", Serial: "SN5", Make: "Acme", Model: "Laser 5", Method: "snmp"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Store.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.6", Serial: "SN5", Method: "snmp"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	admin := login(t, ts, "admin", "adminpass123")
	viewer := login(t, ts, "viewer", "viewerpass1")

	code, body := do(t, ts, viewer, "POST", "/api/devices/"+d.ID+"/address", `{"action":"confirm"}`)
	if code != 403 {
		t.Fatalf("viewer: %d %s", code, body)
	}
	code, body = do(t, ts, admin, "POST", "/api/devices/"+d.ID+"/address", `{"action":"move"}`)
	if code != 400 {
		t.Fatalf("bad action: %d %s", code, body)
	}
	code, body = do(t, ts, admin, "GET", "/api/devices/"+d.ID, "")
	if code != 200 || !strings.Contains(body, `"pendingAddress":"10.0.0.6"`) {
		t.Fatalf("device before: %d %s", code, body)
	}

	code, body = do(t, ts, admin, "POST", "/api/devices/"+d.ID+"/address", `{"action":"dismiss"}`)
	if code != 200 {
		t.Fatalf("dismiss: %d %s", code, body)
	}
	var got model.Device
	if err := json.Unmarshal([]byte(body), &got); err != nil || got.Address != "10.0.0.5" || got.PendingAddress != "" {
		t.Fatalf("after dismiss: %+v %v", got, err)
	}
	code, body = do(t, ts, admin, "POST", "/api/devices/"+d.ID+"/address", `{"action":"confirm"}`)
	if code != 409 {
		t.Fatalf("nothing pending: %d %s", code, body)
	}

	if _, _, err := s.Store.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.7", Serial: "SN5", Method: "snmp"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	code, body = do(t, ts, admin, "POST", "/api/devices/"+d.ID+"/address", `{"action":"confirm"}`)
	if code != 200 {
		t.Fatalf("confirm: %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || got.Address != "10.0.0.7" || got.PendingAddress != "" {
		t.Fatalf("after confirm: %+v %v", got, err)
	}
	code, body = do(t, ts, admin, "POST", "/api/devices/missing/address", `{"action":"confirm"}`)
	if code != 404 {
		t.Fatalf("unknown device: %d %s", code, body)
	}
	audit, _ := s.Store.ListAudit(ctx, 10)
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	if !seen["device.address.confirm"] || !seen["device.address.dismiss"] {
		t.Errorf("audit actions: %v", seen)
	}
}
