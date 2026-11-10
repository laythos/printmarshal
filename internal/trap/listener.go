// Package trap receives SNMP traps and informs from devices (spec §8.3
// asynchronous alerts) and hands them to the fleet as events.
package trap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"printmarshal/internal/driver/snmp"
	"printmarshal/internal/model"
)

// Handler consumes decoded traps.
type Handler interface {
	HandleTrap(ctx context.Context, sourceIP string, description string, severity model.Severity, varbinds map[string]string)
}

// Listener wraps gosnmp's trap listener.
type Listener struct {
	addr string
	h    Handler
	log  *slog.Logger
	tl   *gosnmp.TrapListener

	// Allowed restricts accepted sources (CIDRs or addresses); nil = any.
	Allowed []*net.IPNet
	// RatePerMinute caps handled traps per source address (0 = 60).
	RatePerMinute int
	// TotalPerMinute caps handled traps per minute across every source
	// (0 = 600). The per-source cap alone bounds nothing when the sources
	// vary, as they can on UDP.
	TotalPerMinute int
	// MaxSources caps the source addresses tracked at once (0 = 10000);
	// the least recently seen are forgotten first.
	MaxSources int

	now       func() time.Time
	mu        sync.Mutex
	seen      map[string][]time.Time
	total     []time.Time
	denied    map[string]time.Time // last time a drop was logged per source
	lastSweep time.Time
	// deniedFull is the last time a drop went unlogged because the denied
	// table was full; one line a minute says so.
	deniedFull time.Time
}

// Defaults for the limiter fields when they are left at zero.
const (
	DefaultRatePerMinute  = 60
	DefaultTotalPerMinute = 600
	DefaultMaxSources     = 10000
)

// New returns a listener bound to addr (e.g. "0.0.0.0:162"; ports below 1024 need privileges).
func New(addr string, h Handler, log *slog.Logger) *Listener {
	return &Listener{addr: addr, h: h, log: log, now: time.Now, seen: map[string][]time.Time{}, denied: map[string]time.Time{}}
}

// ParseSources turns CIDRs or bare addresses into networks.
func ParseSources(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("trap allowed source %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func (l *Listener) limits() (perSource, total, maxSources int) {
	perSource, total, maxSources = l.RatePerMinute, l.TotalPerMinute, l.MaxSources
	if perSource <= 0 {
		perSource = DefaultRatePerMinute
	}
	if total <= 0 {
		total = DefaultTotalPerMinute
	}
	if maxSources <= 0 {
		maxSources = DefaultMaxSources
	}
	return perSource, total, maxSources
}

// recent keeps the timestamps of the last minute, in place.
func recent(ts []time.Time, now time.Time) []time.Time {
	keep := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	return keep
}

// accept applies the source allow-list, the per-source rate limit (audit
// A13) and the overall rate limit. The tables it keeps are bounded: stale
// entries go once a minute, and the source table forgets the least recently
// seen address when it is full.
func (l *Listener) accept(ip net.IP) bool {
	if len(l.Allowed) > 0 {
		ok := false
		for _, n := range l.Allowed {
			if n.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			l.drop(ip.String(), "source not in trap.allowedSources")
			return false
		}
	}
	perSource, total, maxSources := l.limits()
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= time.Minute {
		l.sweepLocked(now)
	}
	key := ip.String()
	keep := recent(l.seen[key], now)
	if len(keep) >= perSource {
		l.seen[key] = keep
		l.dropLocked(key, "rate limit exceeded", now)
		return false
	}
	l.total = recent(l.total, now)
	if len(l.total) >= total {
		if len(keep) == 0 {
			delete(l.seen, key)
		} else {
			l.seen[key] = keep
		}
		l.dropLocked(key, "overall rate limit exceeded", now)
		return false
	}
	if len(keep) == 0 {
		for len(l.seen) >= maxSources {
			l.evictLocked()
		}
	}
	l.seen[key] = append(keep, now)
	l.total = append(l.total, now)
	return true
}

// sweepLocked drops every entry older than a minute from both tables.
func (l *Listener) sweepLocked(now time.Time) {
	for k, ts := range l.seen {
		if ts = recent(ts, now); len(ts) == 0 {
			delete(l.seen, k)
		} else {
			l.seen[k] = ts
		}
	}
	for k, t := range l.denied {
		if now.Sub(t) >= time.Minute {
			delete(l.denied, k)
		}
	}
	l.lastSweep = now
}

// evictLocked forgets the source whose last trap is the oldest.
func (l *Listener) evictLocked() {
	oldest, found := "", false
	var at time.Time
	for k, ts := range l.seen {
		if last := ts[len(ts)-1]; !found || last.Before(at) {
			oldest, at, found = k, last, true
		}
	}
	if found {
		delete(l.seen, oldest)
	}
}

func (l *Listener) drop(src, why string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= time.Minute {
		l.sweepLocked(now)
	}
	l.dropLocked(src, why, now)
}

// dropLocked logs at most one drop per source per minute so a flood cannot
// flood the log too. The table of logged sources is bounded as well: when
// it is full, drops from further sources are summed up in one line a minute.
func (l *Listener) dropLocked(src, why string, now time.Time) {
	if t, ok := l.denied[src]; ok {
		if now.Sub(t) < time.Minute {
			return
		}
	} else if _, _, maxSources := l.limits(); len(l.denied) >= maxSources {
		if now.Sub(l.deniedFull) >= time.Minute {
			l.deniedFull = now
			l.log.Warn("trap drops from further sources not logged individually", "sources", len(l.denied), "reason", why)
		}
		return
	}
	l.denied[src] = now
	l.log.Warn("trap dropped", "source", src, "reason", why)
}

// Well-known trap OIDs.
const (
	oidSnmpTrapOID  = ".1.3.6.1.6.3.1.1.4.1.0"
	oidColdStart    = ".1.3.6.1.6.3.1.1.5.1"
	oidWarmStart    = ".1.3.6.1.6.3.1.1.5.2"
	oidLinkDown     = ".1.3.6.1.6.3.1.1.5.3"
	oidLinkUp       = ".1.3.6.1.6.3.1.1.5.4"
	oidAuthFailure  = ".1.3.6.1.6.3.1.1.5.5"
	oidPrinterAlert = ".1.3.6.1.2.1.43.18.2.0.1" // printerV2Alert (RFC 3805)
)

// Run listens until ctx ends.
func (l *Listener) Run(ctx context.Context) error {
	l.tl = gosnmp.NewTrapListener()
	l.tl.Params = gosnmp.Default
	l.tl.Params.Community = "" // accept any community on receive; devices are matched by source address
	l.tl.OnNewTrap = l.onTrap
	errCh := make(chan error, 1)
	go func() { errCh <- l.tl.Listen(l.addr) }()
	select {
	case <-l.tl.Listening():
		l.log.Info("trap listener ready", "addr", l.addr)
	case err := <-errCh:
		return err
	}
	select {
	case <-ctx.Done():
		l.tl.Close()
		return nil
	case err := <-errCh:
		return err
	}
}

func (l *Listener) onTrap(p *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	if !l.accept(addr.IP) {
		return
	}
	vars := map[string]string{}
	trapOID := ""
	desc := ""
	sev := model.SeverityWarning
	var alertRows []snmp.PDU
	for _, v := range p.Variables {
		pdu := snmp.PDU{OID: v.Name, Type: v.Type, Value: v.Value}
		vars[v.Name] = snmp.Str(pdu)
		switch {
		case v.Name == oidSnmpTrapOID:
			trapOID = snmp.Str(pdu)
		case strings.HasPrefix(v.Name, snmp.OIDPrtAlertTable+"."):
			alertRows = append(alertRows, pdu)
		}
	}
	if p.Version == gosnmp.Version1 && trapOID == "" {
		trapOID = fmt.Sprintf("%s generic=%d specific=%d", p.Enterprise, p.GenericTrap, p.SpecificTrap)
	}
	if len(alertRows) > 0 {
		if alerts := snmp.ParseDeviceAlerts(alertRows); len(alerts) > 0 {
			a := alerts[0]
			desc = a.Description
			if a.Severity != model.SeverityOK {
				sev = a.Severity
			}
		}
	}
	if desc == "" {
		switch trapOID {
		case oidColdStart:
			desc, sev = "Device cold start", model.SeverityWarning
		case oidWarmStart:
			desc, sev = "Device warm start", model.SeverityWarning
		case oidLinkDown:
			desc, sev = "Link down", model.SeverityCritical
		case oidLinkUp:
			desc, sev = "Link up", model.SeverityOK
		case oidAuthFailure:
			desc, sev = "SNMP authentication failure", model.SeverityWarning
		case oidPrinterAlert:
			desc = "Printer alert"
		default:
			desc = "Trap " + trapOID
		}
	}
	if sev == model.SeverityOK {
		l.log.Info("informational trap", "source", addr.IP.String(), "description", desc)
	}
	l.h.HandleTrap(context.Background(), addr.IP.String(), desc, sev, vars)
}
