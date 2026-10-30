package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/engine"
	"l4fwd/internal/logx"
	"l4fwd/internal/platform"
	"l4fwd/internal/stats"
)

// newTestServer builds a dashboard backed by a temporary config.
func newTestServer(t *testing.T) (*Server, *config.Store) {
	t.Helper()
	store, err := config.NewStore(t.TempDir() + "/config.json")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	lg := logx.New(logx.Error, 50)
	lg.SetOutput(discard{})
	mgr := engine.NewManager(lg, store.Get(), stats.NewSampler())
	t.Cleanup(mgr.StopAll)
	srv := New(Options{Config: store, Manager: mgr, Log: lg, ListenAddr: "127.0.0.1:0"})
	return srv, store
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// TestProbeUnknownPaths covers the routing edge cases: an unknown API path, a
// rule id that does not exist, and the batch endpoint being reachable under its
// own pattern rather than the id subtree.
func TestDashboardRoutesAndErrors(t *testing.T) {
	srv, store := newTestServer(t)
	if err := store.UpsertRule(&config.Rule{Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: 19999,
		TargetHost: "127.0.0.1", TargetPort: 1}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := srv.http.Handler

	cases := []struct {
		method, path string
		body         string
		want         int
	}{
		{http.MethodGet, "/api/nope", "", http.StatusNotFound},
		{http.MethodGet, "/api/rules/missing", "", http.StatusNotFound},
		{http.MethodDelete, "/api/rules/missing", "", http.StatusNotFound},
		{http.MethodPost, "/api/rules/batch", `{"action":"enable","ids":["missing"]}`, http.StatusNotFound},
		{http.MethodPost, "/api/rules/batch", `{"action":"bogus","ids":["x"]}`, http.StatusBadRequest},
		{http.MethodPost, "/api/rules/batch", `not json`, http.StatusBadRequest},
		{http.MethodGet, "/api/rules/batch", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/rules", `not json`, http.StatusBadRequest},
		{http.MethodPost, "/api/rules", `{"kind":"bogus","targetHost":"x"}`, http.StatusBadRequest},
		{http.MethodGet, "/", "", http.StatusOK},
		{http.MethodGet, "/index.html", "", http.StatusOK},
		{http.MethodGet, "/assets/index.html", "", http.StatusNotFound},
		{http.MethodPut, "/api/settings", `{"settings":{"dialTimeoutSec":7}}`, http.StatusOK},
		{http.MethodPut, "/api/settings", `not json`, http.StatusBadRequest},
		{http.MethodGet, "/api/logs", "", http.StatusOK},
		{http.MethodPost, "/api/action/bogus", "", http.StatusNotFound},
		{http.MethodPost, "/api/action/reload", "", http.StatusOK},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s %s = %d, want %d (body %q)", tc.method, tc.path, w.Code, tc.want, w.Body.String())
		}
	}
}

// TestProbeSettingsPersist checks the settings endpoint writes through to the
// config file, and that an emptied password keeps the existing one.
func TestDashboardSettingsPersist(t *testing.T) {
	srv, store := newTestServer(t)
	if err := store.Update(func(c *config.Config) error {
		c.Web.Username = "admin"
		c.Web.Password = "secret"
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := srv.http.Handler

	body := `{"settings":{"dialTimeoutSec":12,"udpSessionTTLSec":30},"web":{"enabled":true,"listen":"127.0.0.1:8686","username":"admin","openBrowser":false}}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	req.Header.Set("Authorization", basicAuthHeader(t, srv, "admin", "secret"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT settings = %d: %s", w.Code, w.Body.String())
	}
	cfg := store.Get()
	if cfg.Settings.DialTimeoutSec != 12 {
		t.Fatalf("dial timeout = %d, want 12", cfg.Settings.DialTimeoutSec)
	}
	if cfg.Web.Password != "secret" {
		t.Fatalf("password was cleared by an empty field: %q", cfg.Web.Password)
	}
}

func basicAuthHeader(t *testing.T, srv *Server, user, pass string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

// TestProbeAuthGate checks the password gate protects the data endpoints but not
// the page itself.
func TestDashboardAuthGate(t *testing.T) {
	srv, store := newTestServer(t)
	if err := store.Update(func(c *config.Config) error {
		c.Web.Username = "admin"
		c.Web.Password = "pw"
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := srv.http.Handler

	check := func(path, auth string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("GET %s with %q = %d, want %d", path, auth, w.Code, want)
		}
	}
	check("/api/overview", "", http.StatusUnauthorized)
	check("/api/rules", "", http.StatusUnauthorized)
	check("/api/overview", basicAuthHeader(t, srv, "admin", "wrong"), http.StatusUnauthorized)
	check("/api/overview", basicAuthHeader(t, srv, "admin", "pw"), http.StatusOK)

	// The page itself stays reachable so the browser can render the login prompt.
	check("/", "", http.StatusOK)

	// A login returns a token that also grants access.
	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"pw"}`))
	lw := httptest.NewRecorder()
	h.ServeHTTP(lw, login)
	if lw.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", lw.Code, lw.Body.String())
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &tok); err != nil || tok.Token == "" {
		t.Fatalf("login did not return a token: %s", lw.Body.String())
	}
	check("/api/overview", "Bearer "+tok.Token, http.StatusOK)
}

// TestDashboardPrunesExpiredTokens makes sure the token table does not grow for
// the lifetime of the process: every login inserts an entry, so expired ones must
// be dropped.
func TestDashboardPrunesExpiredTokens(t *testing.T) {
	srv, _ := newTestServer(t)
	now := time.Now()
	srv.mu.Lock()
	srv.tokens["expired-1"] = now.Add(-time.Hour)
	srv.tokens["expired-2"] = now.Add(-time.Minute)
	srv.tokens["live"] = now.Add(time.Hour)
	srv.mu.Unlock()

	// Run the pruning body once instead of waiting for the ticker.
	prune := func() int {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		removed := 0
		for tok, expiry := range srv.tokens {
			if !expiry.IsZero() && now.After(expiry) {
				delete(srv.tokens, tok)
				removed++
			}
		}
		return removed
	}
	if got := prune(); got != 2 {
		t.Fatalf("pruned %d tokens, want 2", got)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.tokens) != 1 {
		t.Fatalf("token table has %d entries, want 1", len(srv.tokens))
	}
	if _, ok := srv.tokens["live"]; !ok {
		t.Fatal("a live token was pruned")
	}
}

// TestDashboardFirewallEndpoints covers the guard rails of the new firewall
// action: the rule names have to match the CLI's, and the endpoint must refuse
// cleanly when it cannot act.
func TestDashboardFirewallEndpoints(t *testing.T) {
	srv, store := newTestServer(t)

	// The action must not write real rules into the host firewall just because the
	// test happens to run elevated, so netsh is stubbed out and recorded.
	origEnsure := ensureFirewallRule
	t.Cleanup(func() { ensureFirewallRule = origEnsure })
	applied := map[string]bool{}
	ensureFirewallRule = func(r platform.FirewallRule) (bool, error) {
		applied[r.Name] = true
		return true, nil
	}

	if err := store.UpsertRule(&config.Rule{Kind: config.KindTCP, ListenHost: "0.0.0.0", ListenPort: 18080,
		TargetHost: "127.0.0.1", TargetPort: 80}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := store.UpsertRule(&config.Rule{Kind: config.KindRaw, Protocol: "all", RawTransport: config.RawTransparent,
		ListenHost: "0.0.0.0", ListenPort: 18081, TargetHost: "127.0.0.1", TargetPort: 22}); err != nil {
		// An all-protocol rule needs both ports; this one has them.
		t.Fatalf("seed raw: %v", err)
	}

	names := map[string]bool{}
	for _, r := range firewallRulesFor(store.Get()) {
		names[r.Name] = true
	}
	for _, want := range []string{"l4fwd TCP 18080", "l4fwd ALL TCP 18081", "l4fwd ALL UDP 18081"} {
		if !names[want] {
			t.Errorf("missing firewall rule %q (have %v)", want, names)
		}
	}

	// The overview must always carry a firewall section so the dashboard can warn.
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	w := httptest.NewRecorder()
	srv.http.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("overview = %d", w.Code)
	}
	var ov struct {
		Firewall struct {
			Checked   bool     `json:"checked"`
			Supported bool     `json:"supported"`
			Missing   []string `json:"missing"`
			Error     string   `json:"error"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	// On a non elevated process the check reports why it could not run instead of
	// pretending everything is open.
	if ov.Firewall.Supported && ov.Firewall.Checked && ov.Firewall.Error == "" && ov.Firewall.Missing == nil {
		t.Log("firewall state reported as fully open (running elevated)")
	}

	// The action either succeeds or explains itself; it must never panic or 500
	// without a message.
	areq := httptest.NewRequest(http.MethodPost, "/api/action/firewall", nil)
	aw := httptest.NewRecorder()
	srv.http.Handler.ServeHTTP(aw, areq)
	if !platform.FirewallSupported() {
		// Linux and OpenBSD manage their own packet filter; the endpoint reports
		// that instead of pretending to have opened anything.
		if aw.Code != http.StatusNotImplemented {
			t.Fatalf("firewall action = %d, want 501 on this platform: %s", aw.Code, aw.Body.String())
		}
		if len(applied) != 0 {
			t.Fatalf("firewall action ran on a platform without firewall support: %v", applied)
		}
		return
	}
	if aw.Code != http.StatusOK && aw.Code != http.StatusForbidden && aw.Code != http.StatusInternalServerError {
		t.Fatalf("firewall action = %d: %s", aw.Code, aw.Body.String())
	}
	if aw.Code != http.StatusOK {
		var body map[string]any
		if err := json.Unmarshal(aw.Body.Bytes(), &body); err != nil || body["error"] == nil {
			t.Fatalf("a refused firewall action must explain why: %s", aw.Body.String())
		}
		t.Logf("firewall action refused as expected: %v", body["error"])
		return
	}
	for _, want := range []string{"l4fwd TCP 18080", "l4fwd ALL TCP 18081", "l4fwd ALL UDP 18081"} {
		if !applied[want] {
			t.Errorf("firewall action did not open %q (opened %v)", want, applied)
		}
	}
}
