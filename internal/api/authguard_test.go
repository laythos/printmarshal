package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIPBehindTrustedProxy(t *testing.T) {
	proxies, err := ParseTrustedProxies([]string{"10.0.0.0/8", " 192.0.2.1 ", "", "fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	trusting := &Server{proxies: proxies}
	plain := &Server{}
	for _, tc := range []struct {
		name string
		s    *Server
		peer string
		xff  []string
		want string
	}{
		{"no proxies: header ignored", plain, "10.0.0.2:4000", []string{"203.0.113.9"}, "10.0.0.2"},
		{"peer not trusted: header ignored", trusting, "198.51.100.4:4000", []string{"203.0.113.9"}, "198.51.100.4"},
		{"trusted peer, one hop", trusting, "10.0.0.2:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"trusted peer, exact address", trusting, "192.0.2.1:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"chain of trusted hops", trusting, "10.0.0.2:4000", []string{"203.0.113.9, 10.0.0.3"}, "203.0.113.9"},
		{"client-sent value behind a trusted chain is not used", trusting, "10.0.0.2:4000", []string{"1.2.3.4, 203.0.113.9, 10.0.0.3"}, "203.0.113.9"},
		{"two header lines", trusting, "10.0.0.2:4000", []string{"203.0.113.9", "10.0.0.3"}, "203.0.113.9"},
		{"hop with a port", trusting, "10.0.0.2:4000", []string{"203.0.113.9:5555"}, "203.0.113.9"},
		{"ipv6 hop in brackets", trusting, "10.0.0.2:4000", []string{"[2001:db8::7]:443"}, "2001:db8::7"},
		{"ipv6 trusted peer", trusting, "[fd00::1]:4000", []string{"2001:db8::7"}, "2001:db8::7"},
		{"no header from a trusted peer", trusting, "10.0.0.2:4000", nil, "10.0.0.2"},
		{"every hop trusted", trusting, "10.0.0.2:4000", []string{"10.0.0.5, 10.0.0.3"}, "10.0.0.2"},
		{"malformed hop stops the walk", trusting, "10.0.0.2:4000", []string{"203.0.113.9, not-an-ip, 10.0.0.3"}, "10.0.0.2"},
		{"empty header", trusting, "10.0.0.2:4000", []string{""}, "10.0.0.2"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		for _, v := range tc.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := tc.s.clientIP(r); got != tc.want {
			t.Errorf("%s: clientIP = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParseTrustedProxiesRejectsBadEntries(t *testing.T) {
	for _, bad := range []string{"proxy", "10.0.0.0/33", "10.0.0"} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if nets, err := ParseTrustedProxies(nil); err != nil || len(nets) != 0 {
		t.Errorf("empty list = %v %v", nets, err)
	}
}

// Behind a listed proxy, sign-in throttling applies to the forwarded client,
// so one client's failures do not block the others.
func TestLoginLimiterKeysOnForwardedClientBehindTrustedProxy(t *testing.T) {
	_, s := newTestServer(t)
	s.Cfg.TrustedProxies = []string{"127.0.0.1", "::1"}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	attempt := func(client string) int {
		req, _ := http.NewRequest("POST", ts.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"wrong-password"}`))
		req.Header.Set("Content-Type", "application/json")
		if client != "" {
			req.Header.Set("X-Forwarded-For", client)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 10; i++ {
		if code := attempt("203.0.113.9"); code != 401 {
			t.Fatalf("attempt %d from the first client = %d", i+1, code)
		}
	}
	if code := attempt("203.0.113.9"); code != 429 {
		t.Fatalf("the first client is not throttled: %d", code)
	}
	if code := attempt("203.0.113.10"); code != 401 {
		t.Fatalf("a second client behind the same proxy is throttled with the first: %d", code)
	}
	if code := attempt(""); code != 401 {
		t.Fatalf("the proxy itself is throttled with the first client: %d", code)
	}
}

// Without trusted proxies the header is ignored, so a client cannot escape
// the throttle by claiming another address.
func TestLoginLimiterIgnoresForwardedHeaderByDefault(t *testing.T) {
	ts, _ := newTestServer(t)
	attempt := func(client string) int {
		req, _ := http.NewRequest("POST", ts.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"wrong-password"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", client)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 10; i++ {
		if code := attempt("203.0.113.9"); code != 401 {
			t.Fatalf("attempt %d = %d", i+1, code)
		}
	}
	if code := attempt("203.0.113.10"); code != 429 {
		t.Fatalf("a forwarded header bought a fresh budget: %d", code)
	}
}
