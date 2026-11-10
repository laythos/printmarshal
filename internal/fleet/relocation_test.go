package fleet

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"printmarshal/internal/config"
	"printmarshal/internal/engine"
	"printmarshal/internal/jobs"
	"printmarshal/internal/model"
	"printmarshal/internal/secrets"
	"printmarshal/internal/store"
)

// movableDriver is one printer identity (serial MV-1 unless overridden per
// address) that may answer at any number of addresses. It records the
// credentials every identification and status read carried, per address,
// so a test can say where a record's own credential went.
type movableDriver struct {
	mu        sync.Mutex
	answering map[string]bool
	serials   map[string]string   // address -> serial answered there (default MV-1)
	identRecv map[string][]string // address -> communities carried by identifications
	readRecv  map[string][]string // address -> communities carried by status reads
}

func newMovableDriver() *movableDriver {
	return &movableDriver{answering: map[string]bool{}, serials: map[string]string{}, identRecv: map[string][]string{}, readRecv: map[string][]string{}}
}

func (d *movableDriver) answer(addr string, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.answering[addr] = on
}

func (d *movableDriver) serialAt(addr, serial string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.serials[addr] = serial
}

// carried reports whether any call of the given kind to addr carried community.
func (d *movableDriver) carried(kind, addr, community string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.identRecv
	if kind == "read" {
		m = d.readRecv
	}
	for _, c := range m[addr] {
		if strings.Contains(c, community) {
			return true
		}
	}
	return false
}

func (d *movableDriver) Name() string { return "movable" }
func (d *movableDriver) Capabilities() []model.Capability {
	return []model.Capability{model.CapIdentify, model.CapReadStatus}
}
func (d *movableDriver) Supports(dev *model.Device, c model.Capability) bool {
	return engine.ProfileSupports(dev, d.Name(), c)
}
func (d *movableDriver) Priority(model.Capability) int { return 10 }

func (d *movableDriver) Identify(_ context.Context, address string, creds model.Creds) (*model.Identity, error) {
	d.mu.Lock()
	d.identRecv[address] = append(d.identRecv[address], strings.Join(creds.Communities, ","))
	on, serial := d.answering[address], d.serials[address]
	d.mu.Unlock()
	if !on {
		return nil, errors.New("timeout")
	}
	if serial == "" {
		serial = "MV-1"
	}
	return &model.Identity{Address: address, Serial: serial, Make: "Acme", Model: "Acme 100", DeviceType: "printer",
		Capabilities: []model.Capability{model.CapReadStatus}}, nil
}

func (d *movableDriver) ReadStatus(_ context.Context, dev *model.Device, creds model.Creds) (*model.Status, error) {
	d.mu.Lock()
	d.readRecv[dev.Address] = append(d.readRecv[dev.Address], strings.Join(creds.Communities, ","))
	on := d.answering[dev.Address]
	d.mu.Unlock()
	if !on {
		return nil, errors.New("timeout")
	}
	return &model.Status{Online: true, State: "idle", Severity: model.SeverityOK, At: time.Now().UTC()}, nil
}

type eventLog struct {
	mu     sync.Mutex
	events []model.Event
}

func (l *eventLog) add(e model.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) of(typ string) []model.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []model.Event
	for _, e := range l.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// newMovableService builds a service over the movable driver with the
// offline threshold at two failed polls.
func newMovableService(t *testing.T) (*Service, store.Store, *movableDriver, *eventLog) {
	t.Helper()
	box, _ := secrets.New(make([]byte, 32))
	st, err := store.OpenSQLite(t.TempDir()+"/t.db", box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	drv := newMovableDriver()
	reg := engine.NewRegistry()
	reg.Register(drv)
	events := &eventLog{}
	cfg := config.Default()
	cfg.Alerts.OfflineAfterFailures = 2
	runner := jobs.New(st, log, 2, events.add)
	t.Cleanup(runner.Stop)
	svc := New(st, engine.New(reg, log, 4), runner, cfg, log, events.add, func(context.Context, string) bool { return true })
	svc.Resolver = &fakeResolver{}
	svc.WebClient = &http.Client{Transport: noWebProbe{}}
	return svc, st, drv, events
}

// recordPrinter identifies the printer at address and binds a read
// credential to its record alone.
func recordPrinter(t *testing.T, svc *Service, st store.Store, drv *movableDriver, address, community string) *model.Device {
	t.Helper()
	ctx := context.Background()
	drv.answer(address, true)
	p, created, err := svc.IdentifyAndUpsert(ctx, address, []string{"scan"}, discoveryCandidate(address))
	if err != nil || !created || p.Serial != "MV-1" {
		t.Fatalf("record: %+v created=%v %v", p, created, err)
	}
	if err := st.CreateCredential(ctx, &model.Credential{Name: "for " + p.ID, Type: model.CredSNMPCommunity, Scope: "device:" + p.ID, Purpose: model.PurposeRead}, &model.Secret{Community: community}); err != nil {
		t.Fatal(err)
	}
	return p
}

// A host that answers with a recorded printer's identity from another
// address does not take the record over: the address is held as pending,
// polls keep going to the recorded address, and the record's credential is
// never sent to the other host.
func TestIdentitySeenElsewhereIsHeldPending(t *testing.T) {
	svc, st, drv, events := newMovableService(t)
	ctx := context.Background()
	p := recordPrinter(t, svc, st, drv, "10.0.0.5", "only-for-p")

	drv.answer("10.0.0.99", true)
	seen, created, err := svc.IdentifyAndUpsert(ctx, "10.0.0.99", []string{"mdns"}, discoveryCandidate("10.0.0.99"))
	if err != nil || created || seen.ID != p.ID {
		t.Fatalf("second host: %+v created=%v %v", seen, created, err)
	}
	if seen.Address != "10.0.0.5" || seen.PendingAddress != "10.0.0.99" {
		t.Fatalf("the record must keep its address: %+v", seen)
	}
	if devs, _ := st.ListDevices(ctx, store.DeviceFilter{}); len(devs) != 1 {
		t.Fatalf("%d records, want 1", len(devs))
	}

	// The recorded address answers, so every poll goes there, with the
	// record's credential, and the pending address stays pending.
	cur := seen
	for i := 0; i < 3; i++ {
		upd, res, err := svc.PollDevice(ctx, cur)
		if err != nil || !res.Reachable {
			t.Fatalf("poll %d: %+v %v", i, res, err)
		}
		if upd.Address != "10.0.0.5" || upd.PendingAddress != "10.0.0.99" {
			t.Fatalf("poll %d moved the record: %+v", i, upd)
		}
		cur = upd
	}
	if !drv.carried("read", "10.0.0.5", "only-for-p") {
		t.Error("the recorded address should have been read with the record's credential")
	}
	if drv.carried("read", "10.0.0.99", "") || drv.carried("ident", "10.0.0.99", "only-for-p") {
		t.Fatalf("the record's credential or a read reached the unconfirmed address: %v / %v", drv.readRecv["10.0.0.99"], drv.identRecv["10.0.0.99"])
	}
	if got := events.of("device.relocated"); len(got) != 0 {
		t.Errorf("nothing was relocated: %+v", got)
	}

	// A discovery run that reaches the other host reports the pending change
	// and does not poll it.
	j, err := svc.SubmitDiscovery(ctx, DiscoveryParams{Targets: []string{"10.0.0.99"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := svc.Jobs.Wait(wctx, j.ID); err != nil {
		t.Fatal(err)
	}
	results, _ := st.ListJobResults(ctx, j.ID)
	found := false
	for _, r := range results {
		if r.Address == "10.0.0.99" && strings.Contains(r.Message, "pending") {
			found = true
		}
	}
	if !found {
		t.Errorf("discovery results: %+v", results)
	}
	if drv.carried("read", "10.0.0.99", "") {
		t.Fatalf("discovery polled the unconfirmed address: %v", drv.readRecv["10.0.0.99"])
	}
	if got, _ := st.GetDevice(ctx, p.ID); got.Address != "10.0.0.5" || got.PendingAddress != "10.0.0.99" {
		t.Fatalf("after discovery: %+v", got)
	}
}

// The honest case: the printer moved. Once the recorded address has stopped
// answering for the offline threshold and the pending address answers with
// the same identity, the record follows it and polls resume there.
func TestOfflineRecordFollowsItsIdentity(t *testing.T) {
	svc, st, drv, events := newMovableService(t)
	ctx := context.Background()
	p := recordPrinter(t, svc, st, drv, "10.0.0.5", "only-for-p")
	if _, res, err := svc.PollDevice(ctx, p); err != nil || !res.Reachable {
		t.Fatalf("first poll: %+v %v", res, err)
	}

	// The printer comes up at a new address and a discovery finds it there.
	drv.answer("10.0.0.5", false)
	drv.answer("10.0.0.6", true)
	seen, _, err := svc.IdentifyAndUpsert(ctx, "10.0.0.6", []string{"scan"}, discoveryCandidate("10.0.0.6"))
	if err != nil || seen.ID != p.ID || seen.Address != "10.0.0.5" || seen.PendingAddress != "10.0.0.6" {
		t.Fatalf("seen at the new address: %+v %v", seen, err)
	}

	// Two failed polls: the record is offline, still at its address.
	cur := seen
	for i := 1; i <= 2; i++ {
		upd, res, err := svc.PollDevice(ctx, cur)
		if err != nil || res.Reachable {
			t.Fatalf("poll %d: %+v %v", i, res, err)
		}
		if upd.Address != "10.0.0.5" || upd.PendingAddress != "10.0.0.6" {
			t.Fatalf("poll %d moved the record before the threshold: %+v", i, upd)
		}
		cur = upd
	}
	if drv.carried("ident", "10.0.0.6", "only-for-p") || drv.carried("read", "10.0.0.6", "") {
		t.Fatalf("the record's credential reached the new address before the move: %v / %v", drv.identRecv["10.0.0.6"], drv.readRecv["10.0.0.6"])
	}

	// The third poll verifies the pending address and follows it.
	upd, res, err := svc.PollDevice(ctx, cur)
	if err != nil || !res.Reachable {
		t.Fatalf("poll after the threshold: %+v %v", res, err)
	}
	if upd.ID != p.ID || upd.Address != "10.0.0.6" || upd.PendingAddress != "" {
		t.Fatalf("the record should have followed its identity: %+v", upd)
	}
	if drv.carried("ident", "10.0.0.6", "only-for-p") {
		t.Errorf("the verification must use the global credentials only: %v", drv.identRecv["10.0.0.6"])
	}
	if !drv.carried("read", "10.0.0.6", "only-for-p") {
		t.Errorf("after the move the record's credential is used at the new address: %v", drv.readRecv["10.0.0.6"])
	}
	if got := events.of("device.relocated"); len(got) != 1 {
		t.Errorf("relocated events: %d, want 1", len(got))
	} else if d, ok := got[0].Data.(*model.Device); !ok || d.Address != "10.0.0.6" {
		t.Errorf("relocated event data: %+v", got[0].Data)
	}
	if devs, _ := st.ListDevices(ctx, store.DeviceFilter{}); len(devs) != 1 {
		t.Errorf("%d records, want 1", len(devs))
	}
	active, _ := st.ListAlerts(ctx, store.AlertFilter{DeviceID: p.ID, ActiveOnly: true})
	for _, a := range active {
		if a.Key == "offline" {
			t.Errorf("the offline alert should clear once the record is read again: %+v", a)
		}
	}
	// Further polls stay at the new address.
	if again, res, err := svc.PollDevice(ctx, upd); err != nil || !res.Reachable || again.Address != "10.0.0.6" {
		t.Fatalf("later poll: %+v %+v %v", again, res, err)
	}
}

// An offline record does not follow a pending address that no longer answers
// with its identity, nor one that does not answer at all.
func TestOfflineRecordStaysWhenPendingAddressDoesNotMatch(t *testing.T) {
	svc, st, drv, events := newMovableService(t)
	ctx := context.Background()
	p := recordPrinter(t, svc, st, drv, "10.0.0.5", "only-for-p")

	drv.answer("10.0.0.7", true)
	if seen, _, err := svc.IdentifyAndUpsert(ctx, "10.0.0.7", []string{"scan"}, discoveryCandidate("10.0.0.7")); err != nil || seen.PendingAddress != "10.0.0.7" {
		t.Fatalf("seen elsewhere: %+v %v", seen, err)
	}
	drv.answer("10.0.0.5", false)
	cur, _ := st.GetDevice(ctx, p.ID)
	for i := 1; i <= 2; i++ {
		upd, _, err := svc.PollDevice(ctx, cur)
		if err != nil {
			t.Fatal(err)
		}
		cur = upd
	}

	// Offline now. The pending host answers with another serial: no move.
	drv.serialAt("10.0.0.7", "SOMEONE-ELSE")
	upd, res, err := svc.PollDevice(ctx, cur)
	if err != nil || res.Reachable || upd.Address != "10.0.0.5" || upd.PendingAddress != "10.0.0.7" {
		t.Fatalf("another identity at the pending address: %+v %+v %v", upd, res, err)
	}
	// Silent: no move either.
	drv.answer("10.0.0.7", false)
	upd, res, err = svc.PollDevice(ctx, upd)
	if err != nil || res.Reachable || upd.Address != "10.0.0.5" || upd.PendingAddress != "10.0.0.7" {
		t.Fatalf("silent pending address: %+v %+v %v", upd, res, err)
	}
	if drv.carried("read", "10.0.0.7", "") || drv.carried("ident", "10.0.0.7", "only-for-p") {
		t.Fatalf("the record's credential or a read reached the pending address: %v / %v", drv.readRecv["10.0.0.7"], drv.identRecv["10.0.0.7"])
	}
	if got := events.of("device.relocated"); len(got) != 0 {
		t.Errorf("nothing was relocated: %+v", got)
	}

	// An operator dismisses it: the record is left alone and polls continue
	// at its address.
	if d, err := st.DismissRelocation(ctx, p.ID); err != nil || d.PendingAddress != "" || d.Address != "10.0.0.5" {
		t.Fatalf("dismiss: %+v %v", d, err)
	}
	drv.answer("10.0.0.5", true)
	if back, res, err := svc.PollDevice(ctx, upd); err != nil || !res.Reachable || back.Address != "10.0.0.5" {
		t.Fatalf("after dismiss: %+v %+v %v", back, res, err)
	}
}
