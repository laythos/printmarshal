package store

import (
	"context"
	"testing"

	"printmarshal/internal/model"
)

// An identity that matches a record by serial, UUID or MAC but answers from
// another address does not move the record: the address is held as pending,
// nothing else from that identification is merged, and the record follows
// only when the change is confirmed.
func testIdentityAtNewAddressIsPending(t *testing.T, s testStore) {
	ctx := context.Background()
	p, created, err := s.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.5", Serial: "SN-P", UUID: "uuid-p", Firmware: "1.0", Model: "Acme 1", Method: "snmp"},
		map[model.Capability]string{model.CapReadStatus: "snmp"}, []string{"scan"})
	if err != nil || !created {
		t.Fatalf("record: %v created=%v", err, created)
	}
	if err := s.SetDeviceWebURLProbed(ctx, p.ID, "https://10.0.0.5/"); err != nil {
		t.Fatal(err)
	}

	// The same serial answers at another address, with different details.
	seen, created, err := s.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.99", Serial: "SN-P", Firmware: "9.9", Model: "Other", Method: "ipp"},
		map[model.Capability]string{model.CapReadSupplies: "ipp"}, []string{"mdns"})
	if err != nil || created || seen.ID != p.ID {
		t.Fatalf("second identity: %+v created=%v %v", seen, created, err)
	}
	if seen.Address != "10.0.0.5" || seen.PendingAddress != "10.0.0.99" || seen.PendingAddressSeenAt == nil {
		t.Fatalf("the record must keep its address and note the new one: %+v", seen)
	}
	if seen.Firmware != "1.0" || seen.Model != "Acme 1" || seen.Capabilities[model.CapReadSupplies] != "" || len(seen.DiscoveryMethods) != 1 {
		t.Errorf("nothing else from an unconfirmed address is merged: %+v", seen)
	}
	if devs, _ := s.ListDevices(ctx, DeviceFilter{}); len(devs) != 1 {
		t.Errorf("%d records, want 1", len(devs))
	}
	if got, _ := s.GetDevice(ctx, p.ID); got.WebURLProbed != "https://10.0.0.5/" {
		t.Errorf("probed web page changed: %q", got.WebURLProbed)
	}

	// The printer itself, at its recorded address, still updates as before
	// and the pending address stays on show.
	same, _, err := s.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.5", Serial: "SN-P", Firmware: "1.1", Method: "snmp"}, nil, nil)
	if err != nil || same.ID != p.ID || same.Address != "10.0.0.5" || same.Firmware != "1.1" || same.PendingAddress != "10.0.0.99" {
		t.Fatalf("at the recorded address: %+v %v", same, err)
	}

	// Dismissed: the record is unchanged and the pending address is gone.
	gone, err := s.DismissRelocation(ctx, p.ID)
	if err != nil || gone.Address != "10.0.0.5" || gone.PendingAddress != "" || gone.PendingAddressSeenAt != nil {
		t.Fatalf("dismiss: %+v %v", gone, err)
	}
	if _, err := s.DismissRelocation(ctx, p.ID); err != ErrNoPendingRelocation {
		t.Errorf("dismiss with nothing pending: %v", err)
	}
	if _, err := s.ConfirmRelocation(ctx, p.ID); err != ErrNoPendingRelocation {
		t.Errorf("confirm with nothing pending: %v", err)
	}

	// A match by UUID counts the same as one by serial.
	byUUID, _, err := s.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.42", UUID: "uuid-p", Method: "escl"}, nil, nil)
	if err != nil || byUUID.ID != p.ID || byUUID.Address != "10.0.0.5" || byUUID.PendingAddress != "10.0.0.42" {
		t.Fatalf("match by uuid: %+v %v", byUUID, err)
	}

	// The honest case: the printer moved. Confirmed, the record follows and
	// what belonged to the old address is cleared.
	moved, err := s.ConfirmRelocation(ctx, p.ID)
	if err != nil || moved.ID != p.ID || moved.Address != "10.0.0.42" || moved.PendingAddress != "" || moved.PendingAddressSeenAt != nil {
		t.Fatalf("confirm: %+v %v", moved, err)
	}
	if moved.WebURLProbed != "" {
		t.Errorf("the probed web page belonged to the old address: %q", moved.WebURLProbed)
	}
	if moved.Serial != "SN-P" || moved.Firmware != "1.1" || moved.Capabilities[model.CapReadStatus] != "snmp" {
		t.Errorf("confirming changes the address only: %+v", moved)
	}
	// Seen again at the confirmed address, the record updates normally.
	after, _, err := s.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.42", Serial: "SN-P", Firmware: "2.0", Method: "snmp"}, nil, nil)
	if err != nil || after.ID != p.ID || after.Address != "10.0.0.42" || after.Firmware != "2.0" || after.PendingAddress != "" {
		t.Fatalf("after the move: %+v %v", after, err)
	}

	// Another printer at the old address is its own record, as before.
	other, created, err := s.UpsertDevice(ctx, &model.Identity{Address: "10.0.0.5", Serial: "SN-OTHER", Method: "snmp"}, nil, nil)
	if err != nil || !created || other.ID == p.ID {
		t.Fatalf("another printer at the old address: %+v created=%v %v", other, created, err)
	}

	for _, fn := range []func(context.Context, string) (*model.Device, error){s.ConfirmRelocation, s.DismissRelocation} {
		if _, err := fn(ctx, "missing"); err != ErrNotFound {
			t.Errorf("unknown device: %v", err)
		}
	}
}
