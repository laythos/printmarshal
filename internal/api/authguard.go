package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// loginLimiter throttles failed sign-ins per source address (audit A05): after
// `limit` failures within a minute the address must wait before trying again.
type loginLimiter struct {
	mu    sync.Mutex
	limit int
	fails map[string][]time.Time
}

func newLoginLimiter(limit int) *loginLimiter {
	if limit <= 0 {
		limit = 10
	}
	return &loginLimiter{limit: limit, fails: map[string][]time.Time{}}
}

func (l *loginLimiter) prune(ip string, now time.Time) []time.Time {
	ts := l.fails[ip]
	keep := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, ip)
		return nil
	}
	l.fails[ip] = keep
	return keep
}

// Blocked reports whether ip has exceeded the failure budget.
func (l *loginLimiter) Blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(ip, time.Now())) >= l.limit
}

// Fail records a failure.
func (l *loginLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.fails[ip] = append(l.prune(ip, now), now)
}

// Reset clears failures after a successful sign-in.
func (l *loginLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// ParseTrustedProxies turns the trustedProxies setting (CIDRs or bare
// addresses) into networks. An empty list means no proxy is trusted.
func ParseTrustedProxies(list []string) ([]*net.IPNet, error) {
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
			return nil, fmt.Errorf("trustedProxies %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// peerIP returns the TCP peer's address without the port.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func inNets(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedHop parses one X-Forwarded-For entry: an address, with or
// without a port, IPv6 in brackets or bare.
func forwardedHop(s string) net.IP {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.Trim(s, "[]"))
}

// clientIP returns the address that sign-in throttling, the public board's
// budget and the audit log are keyed on. It is the TCP peer, unless the peer
// is one of the configured trusted proxies: then it is the nearest address
// in X-Forwarded-For that is not itself a trusted proxy, read from the right,
// so a client cannot choose its own address by sending the header. With no
// trusted proxies configured, the header is ignored, so every client behind
// an unlisted proxy shares the proxy's address (docs/security.md).
func (s *Server) clientIP(r *http.Request) string {
	peer := peerIP(r)
	if len(s.proxies) == 0 {
		return peer
	}
	ip := net.ParseIP(peer)
	if ip == nil || !inNets(s.proxies, ip) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		h := forwardedHop(hops[i])
		if h == nil {
			break // a malformed hop: nothing to the left of it is trusted
		}
		if !inNets(s.proxies, h) {
			return h.String()
		}
	}
	return peer
}
