// Package webui serves the embedded dashboard and its JSON API.
package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/engine"
	"l4fwd/internal/logx"
	"l4fwd/internal/platform"
	"l4fwd/internal/version"
)

//go:embed assets/*
var assets embed.FS

// Options configures the dashboard server.
type Options struct {
	Config     *config.Store
	Manager    *engine.Manager
	Log        *logx.Logger
	ListenAddr string
	Username   string
	Password   string
	// ReadOnly disables mutating endpoints.
	ReadOnly bool
	// Shutdown is called when the user presses the stop button.
	Shutdown func()
	// Restart is called when the user presses the restart button.
	Restart func()
}

// Server is the dashboard HTTP server.
type Server struct {
	opt    Options
	log    *logx.Logger
	http   *http.Server
	mu     sync.Mutex
	tokens map[string]time.Time

	stopOnce sync.Once
	stop     chan struct{}
	wg       sync.WaitGroup
}

// New builds a server for the given options.
func New(opt Options) *Server {
	s := &Server{opt: opt, log: opt.Log, tokens: map[string]time.Time{}, stop: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("/api/rules", s.auth(s.handleRules))
	// "batch" is registered as its own pattern so it is never mistaken for a rule
	// id by the subtree handler below (the more specific pattern wins).
	mux.HandleFunc("/api/rules/batch", s.auth(s.handleRulesBatch))
	mux.HandleFunc("/api/rules/", s.auth(s.handleRuleByID))
	mux.HandleFunc("/api/logs", s.auth(s.handleLogs))
	mux.HandleFunc("/api/logs/stream", s.auth(s.handleLogStream))
	mux.HandleFunc("/api/stats/stream", s.auth(s.handleStatsStream))
	mux.HandleFunc("/api/settings", s.auth(s.handleSettings))
	mux.HandleFunc("/api/action/", s.auth(s.handleAction))
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.auth(s.handleLogout))

	s.http = &http.Server{
		Addr:              opt.ListenAddr,
		Handler:           s.cors(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Start begins serving; it returns once the listener is bound.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp4", s.http.Addr)
	if err != nil {
		return fmt.Errorf("web listen %s: %w", s.http.Addr, err)
	}
	s.log.Infof("web", "dashboard on http://%s", ln.Addr())
	go func() {
		if err := s.http.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Warnf("web", "server stopped: %v", err)
		}
	}()
	s.wg.Add(1)
	go s.pruneTokens()
	return nil
}

// pruneTokens drops expired login tokens. Without it the map would grow for the
// lifetime of the process: every login adds an entry and nothing ever removes it.
func (s *Server) pruneTokens() {
	defer s.wg.Done()
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			removed := 0
			for tok, expiry := range s.tokens {
				if !expiry.IsZero() && now.After(expiry) {
					delete(s.tokens, tok)
					removed++
				}
			}
			remaining := len(s.tokens)
			s.mu.Unlock()
			if removed > 0 {
				s.log.Debugf("web", "pruned %d expired login token(s), %d left", removed, remaining)
			}
		}
	}
}

// Addr returns the bound address.
func (s *Server) Addr() string { return s.http.Addr }

// ---- middleware ----

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The dashboard is a local tool; only same-origin and explicitly
		// allowed origins may script against it.
		if origin := r.Header.Get("Origin"); origin != "" {
			if s.originAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			} else if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	cfg := s.opt.Config.Get()
	for _, o := range cfg.Web.AllowedOrigins {
		if strings.EqualFold(strings.TrimSpace(o), origin) {
			return true
		}
	}
	// Same host (any port) is always allowed.
	for _, prefix := range []string{"http://127.0.0.1", "http://localhost", "http://[::1]"} {
		if strings.HasPrefix(strings.ToLower(origin), prefix) {
			return true
		}
	}
	return false
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkAuth(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="l4fwd"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		next(w, r)
	}
}

func (s *Server) checkAuth(r *http.Request) bool {
	cfg := s.opt.Config.Get()
	want := cfg.Web
	// A password is what turns authentication on: a local tool with an empty
	// password stays open, which is the default for 127.0.0.1-only setups.
	if want.Password == "" {
		return true
	}
	user, pass, ok := basicAuth(r)
	if ok && subtle.ConstantTimeCompare([]byte(user), []byte(want.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(want.Password)) == 1 {
		return true
	}
	if tok := bearerToken(r); tok != "" {
		s.mu.Lock()
		expiry, valid := s.tokens[tok]
		s.mu.Unlock()
		if valid && (expiry.IsZero() || time.Now().Before(expiry)) {
			return true
		}
	}
	return false
}

func basicAuth(r *http.Request) (string, string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[6:]))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if c, err := r.Cookie("l4fwd_token"); err == nil {
		return c.Value
	}
	return ""
}

// ---- handlers ----

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(assets, "assets/index.html")
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request body"})
		return
	}
	cfg := s.opt.Config.Get()
	if cfg.Web.Password == "" && cfg.Web.Username == "" {
		writeJSON(w, http.StatusOK, map[string]any{"token": "", "message": "authentication disabled"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Username), []byte(cfg.Web.Username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(body.Password), []byte(cfg.Web.Password)) != 1 {
		s.log.Warnf("web", "failed login for user %q from %s", body.Username, r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	tok := randomToken()
	s.mu.Lock()
	s.tokens[tok] = time.Now().Add(12 * time.Hour)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "l4fwd_token", Value: tok, HttpOnly: true, SameSite: http.SameSiteStrictMode, Path: "/"})
	writeJSON(w, http.StatusOK, map[string]any{"token": tok})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tok := bearerToken(r)
	if tok != "" {
		s.mu.Lock()
		delete(s.tokens, tok)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "l4fwd_token", Value: "", MaxAge: -1, Path: "/"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	cfg := s.opt.Config.Get()
	statuses := s.opt.Manager.Statuses()
	byID := map[string]engine.Status{}
	for _, st := range statuses {
		byID[st.RuleID] = st
	}
	type ruleView struct {
		*config.Rule
		Runtime engine.Status `json:"runtime"`
	}
	views := make([]ruleView, 0, len(cfg.Rules))
	for _, rule := range cfg.SortedRules() {
		views = append(views, ruleView{Rule: rule, Runtime: byID[rule.ID]})
	}
	hosts := []net.IP{}
	for _, ip := range localIPv4Strings() {
		hosts = append(hosts, net.ParseIP(ip))
	}
	// The most common "the forwarder does nothing" report is a closed inbound
	// port, so the dashboard reports whether each listening port is actually
	// allowed through the Windows firewall.
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    version.Version,
		"commit":     version.Commit,
		"buildTime":  version.BuildTime,
		"configPath": s.opt.Config.Path(),
		"settings":   cfg.Settings,
		"web":        cfg.Web,
		"totals":     s.opt.Manager.Totals(),
		"hosts":      localIPv4Strings(),
		"rules":      views,
		"firewall":   firewallStatus(cfg, s.log),
		"serverTime": time.Now(),
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.opt.Config.Get()
		writeJSON(w, http.StatusOK, map[string]any{"rules": cfg.SortedRules()})
	case http.MethodPost:
		if s.readOnly(w) {
			return
		}
		var rule config.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
			return
		}
		rule.ID = ""
		if err := s.opt.Config.UpsertRule(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		s.opt.Manager.Apply(s.opt.Config.Get())
		s.log.Infof("web", "rule created: %s", rule.Summary())
		writeJSON(w, http.StatusOK, map[string]any{"rule": rule})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "GET or POST required"})
	}
}

func (s *Server) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "rule id required"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		rule, ok := s.opt.Config.RuleByID(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "rule not found"})
			return
		}
		st, _ := s.opt.Manager.Status(id)
		writeJSON(w, http.StatusOK, map[string]any{"rule": rule, "runtime": st})
	case http.MethodPut:
		if s.readOnly(w) {
			return
		}
		var rule config.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
			return
		}
		rule.ID = id
		if err := s.opt.Config.UpsertRule(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		s.opt.Manager.Apply(s.opt.Config.Get())
		s.log.Infof("web", "rule updated: %s", rule.Summary())
		writeJSON(w, http.StatusOK, map[string]any{"rule": rule})
	case http.MethodDelete:
		if s.readOnly(w) {
			return
		}
		if err := s.opt.Config.DeleteRule(id); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
			return
		}
		s.opt.Manager.Apply(s.opt.Config.Get())
		s.log.Infof("web", "rule deleted: %s", id)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "GET, PUT or DELETE required"})
	}
}

// handleRulesBatch applies one action to several rules at once (enable,
// disable, or delete), so the dashboard's select-all controls do not need N
// round trips.
func (s *Server) handleRulesBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
		return
	}
	if s.readOnly(w) {
		return
	}
	var body struct {
		Action string   `json:"action"`
		IDs    []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
		return
	}
	switch body.Action {
	case "enable", "disable", "delete":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "action must be enable, disable or delete"})
		return
	}
	if len(body.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ids is empty"})
		return
	}

	// A single Update keeps the whole batch atomic: either every requested rule
	// changes, or the file stays as it was.
	wanted := map[string]bool{}
	for _, id := range body.IDs {
		wanted[id] = true
	}
	found := map[string]bool{}
	err := s.opt.Config.Update(func(c *config.Config) error {
		out := c.Rules[:0]
		for _, rule := range c.Rules {
			if !wanted[rule.ID] {
				out = append(out, rule)
				continue
			}
			found[rule.ID] = true
			switch body.Action {
			case "delete":
				continue // drop it
			case "enable":
				rule.Enabled = true
			case "disable":
				rule.Enabled = false
			}
			rule.UpdatedAt = time.Now()
			out = append(out, rule)
		}
		c.Rules = out
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if len(found) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no matching rules"})
		return
	}

	s.opt.Manager.Apply(s.opt.Config.Get())
	missing := make([]string, 0)
	for _, id := range body.IDs {
		if !found[id] {
			missing = append(missing, id)
		}
	}
	s.log.Infof("web", "batch %s applied to %d rule(s)%s", body.Action, len(found), missingNote(missing))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": len(found), "missing": missing})
}

func missingNote(missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d 未找到：%s)", len(missing), strings.Join(missing, ", "))
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
		return
	}
	if s.readOnly(w) {
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/action/")
	switch action {
	case "reload":
		if err := s.opt.Manager.Reload(s.opt.Config); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		s.log.Infof("web", "configuration reloaded from disk")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "shutdown":
		s.log.Warnf("web", "shutdown requested from dashboard")
		if s.opt.Shutdown != nil {
			go s.opt.Shutdown()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "restart":
		s.log.Warnf("web", "restart requested from dashboard")
		if s.opt.Restart != nil {
			go s.opt.Restart()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "firewall":
		if !platform.FirewallSupported() {
			writeJSON(w, http.StatusNotImplemented, map[string]any{
				"error": "自动放行防火墙仅支持 Windows；本系统请手动放行规则端口",
			})
			return
		}
		if !platform.IsElevated() {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "添加防火墙规则需要 " + platform.PrivilegeHint() + "：请用管理员身份重新启动后重试",
			})
			return
		}
		cfg := s.opt.Config.Get()
		created := 0
		var failed []string
		for _, want := range firewallRulesFor(cfg) {
			ok, err := ensureFirewallRule(want)
			if err != nil {
				failed = append(failed, want.Name+"："+err.Error())
				s.log.Warnf("web", "放行 %s 失败：%v", want.Name, err)
				continue
			}
			if ok {
				created++
				s.log.Infof("web", "已放行 %s", want.Name)
			}
		}
		if len(failed) > 0 {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": strings.Join(failed, "；"), "created": created,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "created": created})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown action " + action})
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.opt.Config.Get()
		writeJSON(w, http.StatusOK, map[string]any{"settings": cfg.Settings, "web": cfg.Web})
	case http.MethodPut:
		if s.readOnly(w) {
			return
		}
		var body struct {
			Settings *config.Settings  `json:"settings"`
			Web      *config.WebConfig `json:"web"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
			return
		}
		err := s.opt.Config.Update(func(c *config.Config) error {
			if body.Settings != nil {
				c.Settings = *body.Settings
			}
			if body.Web != nil {
				web := *body.Web
				// Keep the current password when the field is left blank.
				if web.Password == "" {
					web.Password = c.Web.Password
				}
				c.Web = web
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if lvl := body.Settings; lvl != nil {
			s.log.SetLevel(logx.ParseLevel(lvl.LogLevel))
		}
		s.opt.Manager.Apply(s.opt.Config.Get())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "GET or PUT required"})
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	n := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := parseInt(v); err == nil {
			n = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.log.History(n)})
}

func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request) {
	s.stream(w, r, func(send func(any) error) error {
		ch, cancel := s.log.Subscribe(512)
		defer cancel()
		hist := s.log.History(200)
		for _, e := range hist {
			if err := send(e); err != nil {
				return err
			}
		}
		for {
			select {
			case <-r.Context().Done():
				return nil
			case e, ok := <-ch:
				if !ok {
					return nil
				}
				if err := send(e); err != nil {
					return err
				}
			}
		}
	})
}

func (s *Server) handleStatsStream(w http.ResponseWriter, r *http.Request) {
	s.stream(w, r, func(send func(any) error) error {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			cfg := s.opt.Config.Get()
			statuses := s.opt.Manager.Statuses()
			byID := map[string]engine.Status{}
			for _, st := range statuses {
				byID[st.RuleID] = st
			}
			type row struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Summary string `json:"summary"`
				Enabled bool   `json:"enabled"`
				Kind    string `json:"kind"`
				Running bool   `json:"running"`
				Error   string `json:"error,omitempty"`
				Stats   any    `json:"stats"`
			}
			rows := make([]row, 0, len(cfg.Rules))
			for _, rule := range cfg.SortedRules() {
				st := byID[rule.ID]
				rows = append(rows, row{
					ID: rule.ID, Name: rule.Name, Summary: rule.Summary(), Enabled: rule.Enabled,
					Kind: rule.Kind, Running: st.Running, Error: st.Error, Stats: st.Stats,
				})
			}
			if err := send(map[string]any{
				"totals": s.opt.Manager.Totals(),
				"rules":  rows,
				"time":   time.Now(),
			}); err != nil {
				return err
			}
			select {
			case <-r.Context().Done():
				return nil
			case <-t.C:
			}
		}
	})
}

// stream emits server-sent events.
func (s *Server) stream(w http.ResponseWriter, r *http.Request, body func(send func(any) error) error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	enc := json.NewEncoder(w)
	send := func(v any) error {
		if _, err := w.Write([]byte("data: ")); err != nil {
			return err
		}
		if err := enc.Encode(v); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	if err := body(send); err != nil {
		s.log.Debugf("web", "stream ended: %v", err)
	}
}

func (s *Server) readOnly(w http.ResponseWriter) bool {
	if s.opt.ReadOnly {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "server is in read-only mode"})
		return true
	}
	return false
}

// Stop shuts the HTTP server down.
func (s *Server) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	ctx, cancel := contextWithTimeout(3 * time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
	s.wg.Wait()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func randomToken() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}
