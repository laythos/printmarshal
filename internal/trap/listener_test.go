package trap

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"printmarshal/internal/model"
)

type recorder struct {
	mu   sync.Mutex
	got  []string
	sevs []model.Severity
}

func (r *recorder) HandleTrap(_ context.Context, src, desc string, sev model.Severity, _ map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, src+" "+desc)
	r.sevs = append(r.sevs, sev)
}

// newClocked returns a listener with a settable clock and a function that
// advances it.
func newClocked(t *testing.T) (*Listener, func(d time.Duration)) {
	t.Helper()
	l := New("127.0.0.1:0", &recorder{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return at }
	return l, func(d time.Duration) { at = at.Add(d) }
}

func ip4(n int) net.IP { return net.IPv4(10, byte(n>>16), byte(n>>8), byte(n)) }

func TestPerSourceRateLimit(t *testing.T) {
	l, tick := newClocked(t)
	l.RatePerMinute = 3
	for i := 0; i < 3; i++ {
		if !l.accept(ip4(1)) {
			t.Fatalf("trap %d from one source refused", i+1)
		}
	}
	if l.accept(ip4(1)) {
		t.Fatal("fourth trap within a minute accepted")
	}
	if !l.accept(ip4(2)) {
		t.Fatal("another source is throttled by the first")
	}
	tick(61 * time.Second)
	if !l.accept(ip4(1)) {
		t.Fatal("the budget did not recover after a minute")
	}
}

func TestOverallRateLimit(t *testing.T) {
	l, tick := newClocked(t)
	l.TotalPerMinute = 5
	for i := 1; i <= 5; i++ {
		if !l.accept(ip4(i)) {
			t.Fatalf("trap %d refused under the overall cap", i)
		}
	}
	if l.accept(ip4(6)) {
		t.Fatal("a sixth source got through the overall cap")
	}
	if len(l.seen) != 5 {
		t.Fatalf("a refused source is tracked: %d entries", len(l.seen))
	}
	tick(61 * time.Second)
	if !l.accept(ip4(6)) {
		t.Fatal("the overall budget did not recover after a minute")
	}
}

func TestSourceTablesAreBounded(t *testing.T) {
	l, tick := newClocked(t)
	l.MaxSources = 50
	l.TotalPerMinute = 1000
	l.RatePerMinute = 1
	for i := 1; i <= 400; i++ {
		tick(time.Millisecond) // so that eviction has an order to go by
		if !l.accept(ip4(i)) {
			t.Fatalf("source %d refused although the overall cap allows it", i)
		}
		l.accept(ip4(i)) // second packet: refused and logged as such
	}
	if len(l.seen) > 50 {
		t.Fatalf("seen holds %d sources, cap is 50", len(l.seen))
	}
	if len(l.denied) > 50 {
		t.Fatalf("denied holds %d sources, cap is 50", len(l.denied))
	}
	// The most recent sources are the ones kept.
	if _, ok := l.seen[ip4(400).String()]; !ok {
		t.Fatal("the latest source was evicted instead of the oldest")
	}
	if _, ok := l.seen[ip4(1).String()]; ok {
		t.Fatal("the oldest source survived eviction")
	}
	// Sources not in the allow-list are logged into the same bounded table.
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	l.Allowed = []*net.IPNet{n}
	for i := 0; i < 400; i++ {
		if l.accept(net.IPv4(192, 168, byte(i>>8), byte(i))) {
			t.Fatal("a source outside the allow-list was accepted")
		}
	}
	if len(l.denied) > 50 {
		t.Fatalf("denied holds %d sources after an allow-list flood, cap is 50", len(l.denied))
	}
	// A minute later the stale entries are swept and the tables start over.
	tick(2 * time.Minute)
	if !l.accept(ip4(1)) {
		t.Fatal("a source was refused after its entries expired")
	}
	if len(l.seen) != 1 || len(l.denied) != 0 {
		t.Fatalf("tables not swept: seen=%d denied=%d", len(l.seen), len(l.denied))
	}
}

func TestReceivesPrinterAlertTrap(t *testing.T) {
	rec := &recorder{}
	l := New("127.0.0.1:0", rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Pick a free UDP port first since the listener needs a concrete address.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	l.addr = addr
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Run(ctx) }()
	time.Sleep(200 * time.Millisecond)

	host, port, _ := net.SplitHostPort(addr)
	var p uint16
	_, _ = net.LookupPort("udp", port)
	for _, c := range port {
		p = p*10 + uint16(c-'0')
	}
	g := &gosnmp.GoSNMP{Target: host, Port: p, Community: "public", Version: gosnmp.Version2c, Timeout: time.Second, Retries: 0}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	trap := gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1000)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.2.1.43.18.2.0.1"},
		{Name: ".1.3.6.1.2.1.43.18.1.1.2.1.3", Type: gosnmp.Integer, Value: 3},
		{Name: ".1.3.6.1.2.1.43.18.1.1.4.1.3", Type: gosnmp.Integer, Value: 6},
		{Name: ".1.3.6.1.2.1.43.18.1.1.7.1.3", Type: gosnmp.Integer, Value: 3},
		{Name: ".1.3.6.1.2.1.43.18.1.1.8.1.3", Type: gosnmp.OctetString, Value: "Front cover open"},
	}}
	if _, err := g.SendTrap(trap); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := len(rec.got)
		rec.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.got) != 1 || rec.got[0] != "127.0.0.1 Front cover open" || rec.sevs[0] != model.SeverityCritical {
		t.Fatalf("trap not decoded: %v %v", rec.got, rec.sevs)
	}
}
