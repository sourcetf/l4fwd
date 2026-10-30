// Package cli wires the command line interface to the engine and dashboard.
package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/engine"
	"l4fwd/internal/logx"
	"l4fwd/internal/netutil"
	"l4fwd/internal/platform"
	"l4fwd/internal/stats"
	"l4fwd/internal/version"
	"l4fwd/internal/webui"
)

// Options carries the parsed command line.
type Options struct {
	ConfigPath  string
	ListenSpec  string
	TargetSpec  string
	Kind        string
	Protocol    string
	WebOverride string
	NoBrowser   bool
	LogLevel    string
	LogFile     string
	Firewall    bool
	ReadOnly    bool
	CheckOnly   bool
}

// VersionString returns the banner printed by -version.
func VersionString() string {
	return fmt.Sprintf("l4fwd %s 提交 %s 构建于 %s", version.Version, version.Commit, version.BuildTime)
}

// Run executes the program and blocks until it is asked to stop.
func Run(opt Options) error {
	logger := logx.New(logx.Info, 2000)
	defer logger.Close()

	store, err := config.NewStore(opt.ConfigPath)
	if err != nil {
		return err
	}
	cfg := store.Get()

	level := logger.Level()
	if opt.LogLevel != "" {
		level = logx.ParseLevel(opt.LogLevel)
	} else {
		level = logx.ParseLevel(cfg.Settings.LogLevel)
	}
	logger.SetLevel(level)

	logPath := opt.LogFile
	if logPath == "" && cfg.Settings.LogToFile {
		logPath = cfg.Settings.LogFile
	}
	if logPath != "" {
		if err := logger.SetFile(resolveLogPath(opt.ConfigPath, logPath)); err != nil {
			logger.Warnf("cli", "无法写入日志文件 %s: %v", logPath, err)
		}
	}

	logger.Infof("cli", "l4fwd 启动中，配置文件: %s", opt.ConfigPath)
	if !platform.IsElevated() {
		logger.Warnf("cli", "当前未以 %s 运行：TCP/UDP 转发可用，RAW 原始套接字与混杂捕获会被系统拒绝",
			platform.PrivilegeHint())
	}

	// A one-off rule from the command line is validated before anything starts.
	if opt.ListenSpec != "" || opt.TargetSpec != "" || opt.Kind == "raw" && opt.Protocol != "" {
		rule, err := buildCommandLineRule(opt)
		if err != nil {
			return err
		}
		if err := store.UpsertRule(rule); err != nil {
			return err
		}
		cfg = store.Get()
		logger.Infof("cli", "已添加规则: %s", rule.Summary())
	}

	if opt.CheckOnly {
		for _, r := range store.Get().Rules {
			if err := r.Validate(); err != nil {
				return fmt.Errorf("规则 %s 无效: %w", r.Name, err)
			}
		}
		fmt.Println("配置校验通过：", opt.ConfigPath)
		return nil
	}

	if opt.Firewall {
		return applyFirewall(store.Get(), logger)
	}

	sampler := stats.NewSampler()
	manager := engine.NewManager(logger, store.Get(), sampler)

	// Hot reload: re-read the file whenever it changes on disk.
	stopWatch, err := watchConfig(store, manager, logger)
	if err != nil {
		logger.Warnf("cli", "无法监听配置文件变化: %v", err)
	}
	defer stopWatch()

	manager.Apply(store.Get())
	store.OnChange(func(c *config.Config) { manager.Apply(c) })

	// Sampler loop keeps the dashboard rate numbers fresh.
	stopSampler := make(chan struct{})
	var samplerWG sync.WaitGroup
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		interval := time.Duration(cfg.Settings.SamplerMs) * time.Millisecond
		if interval < 200*time.Millisecond {
			interval = time.Second
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stopSampler:
				return
			case <-t.C:
				manager.RefreshSampler(interval.Seconds())
			}
		}
	}()

	// Dashboard.
	var srv *webui.Server
	webCfg := store.Get().Web
	if opt.WebOverride != "" {
		if strings.EqualFold(opt.WebOverride, "off") || opt.WebOverride == "-" {
			webCfg.Enabled = false
		} else {
			webCfg.Enabled = true
			webCfg.Listen = opt.WebOverride
		}
	}
	shutdownCh := make(chan struct{})
	var shutdownOnce sync.Once
	requestShutdown := func() { shutdownOnce.Do(func() { close(shutdownCh) }) }

	if webCfg.Enabled {
		srv = webui.New(webui.Options{
			Config:     store,
			Manager:    manager,
			Log:        logger,
			ListenAddr: webCfg.Listen,
			Username:   webCfg.Username,
			Password:   webCfg.Password,
			ReadOnly:   opt.ReadOnly,
			Shutdown:   requestShutdown,
			Restart:    restartProcess(logger),
		})
		if err := srv.Start(); err != nil {
			logger.Errorf("web", "%v", err)
			srv = nil
		} else if webCfg.OpenURL && !opt.NoBrowser {
			url := browserURL(webCfg.Listen)
			if err := platform.OpenInBrowser(url); err != nil {
				logger.Debugf("web", "无法自动打开浏览器: %v", err)
			} else {
				logger.Infof("web", "已在浏览器中打开 %s", url)
			}
		}
	} else {
		logger.Infof("web", "网页面板已关闭，使用 -web 127.0.0.1:8686 可重新开启")
	}

	// Signals: Ctrl+C / console close stops cleanly.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Warnf("cli", "收到信号 %v，正在退出", sig)
	case <-shutdownCh:
	}
	close(stopSampler)
	samplerWG.Wait()
	if srv != nil {
		srv.Stop()
	}
	manager.StopAll()
	logger.Infof("cli", "已停止全部转发规则，退出")
	return nil
}

// buildCommandLineRule turns -listen/-target/-type/-proto into a rule.
func buildCommandLineRule(opt Options) (*config.Rule, error) {
	rule := &config.Rule{Kind: strings.ToLower(opt.Kind), Enabled: true, Protocol: opt.Protocol}
	switch rule.Kind {
	case config.KindTCP, config.KindUDP, config.KindRaw:
	default:
		return nil, fmt.Errorf("未知的转发类型 %q（可选 tcp / udp / raw）", opt.Kind)
	}

	if opt.ListenSpec != "" {
		host, port, err := netutil.ParseListen(opt.ListenSpec)
		if err != nil {
			return nil, fmt.Errorf("监听参数 %q 无效: %w", opt.ListenSpec, err)
		}
		rule.ListenHost, rule.ListenPort = host, port
	}
	if opt.Kind != config.KindRaw && rule.ListenPort == 0 {
		return nil, errors.New("请用 -listen 指定本地监听端口，例如 -listen 8080")
	}
	if opt.TargetSpec == "" {
		return nil, errors.New("-target 未指定目标地址")
	}
	host, port, err := netutil.ParseListen(opt.TargetSpec)
	if err != nil {
		return nil, fmt.Errorf("目标参数 %q 无效: %w", opt.TargetSpec, err)
	}
	rule.TargetHost, rule.TargetPort = host, port
	if opt.Kind != config.KindRaw && rule.TargetPort == 0 {
		return nil, errors.New("目标需要包含端口，例如 -target 192.168.1.10:80")
	}
	if rule.Kind == config.KindRaw && rule.Protocol == "" {
		return nil, errors.New("-type raw 时必须用 -proto 指定 IP 协议号或名称")
	}
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	return rule, nil
}

// applyFirewall adds inbound allow rules for every port a rule listens on.
//
// A "raw" rule normally carries protocols the kernel does not terminate (ICMP,
// GRE, a bespoke number), so there is no port to open and the rule is skipped.
// Two raw shapes do own a real TCP/UDP port and must be covered:
//
//	rawTransport "transparent"  – the TCP half of a TCP-shaped rule
//	protocol "all"              – its TCP and UDP halves
func applyFirewall(cfg *config.Config, logger *logx.Logger) error {
	if !platform.FirewallSupported() {
		return errors.New("自动放行防火墙仅支持 Windows；Linux 请用 ufw/nftables，OpenBSD 请编辑 /etc/pf.conf")
	}
	if !platform.IsElevated() {
		return errors.New("添加防火墙规则需要 " + platform.PrivilegeHint())
	}
	type opening struct {
		name  string
		port  int
		proto string
	}
	var wanted []opening
	for _, r := range cfg.Rules {
		if r.ListenPort == 0 {
			continue
		}
		switch {
		case r.Kind == config.KindRaw && r.IsProtocolAll():
			// The all-protocol rule terminates TCP and UDP on the local port, so
			// both need an inbound rule; the remaining protocol numbers travel in
			// IP packets the firewall's port filters cannot express.
			wanted = append(wanted,
				opening{fmt.Sprintf("l4fwd ALL TCP %d", r.ListenPort), r.ListenPort, "TCP"},
				opening{fmt.Sprintf("l4fwd ALL UDP %d", r.ListenPort), r.ListenPort, "UDP"})
		case r.Kind == config.KindRaw && r.Transport() == config.RawTransparent:
			wanted = append(wanted,
				opening{fmt.Sprintf("l4fwd RAW-TCP %d", r.ListenPort), r.ListenPort, "TCP"})
		case r.Kind == config.KindTCP:
			wanted = append(wanted, opening{fmt.Sprintf("l4fwd TCP %d", r.ListenPort), r.ListenPort, "TCP"})
		case r.Kind == config.KindUDP:
			wanted = append(wanted, opening{fmt.Sprintf("l4fwd UDP %d", r.ListenPort), r.ListenPort, "UDP"})
		default:
			// A single-protocol raw rule: nothing port-based to open.
			logger.Infof("firewall", "规则 %q 是原始的单一 IP 协议，无需端口放行（防火墙不按协议号过滤）", r.Name)
		}
	}
	if len(wanted) == 0 {
		fmt.Println("配置里没有需要放行的端口")
		return nil
	}

	added := 0
	for _, o := range wanted {
		if err := platform.AddFirewallRule(platform.FirewallRule{Name: o.name, Port: o.port, Proto: o.proto}); err != nil {
			logger.Warnf("firewall", "%s 添加失败: %v", o.name, err)
			continue
		}
		logger.Infof("firewall", "已放行 %s", o.name)
		added++
	}
	fmt.Printf("已添加 %d 条防火墙入站规则\n", added)
	return nil
}

// FirewallRuleNames returns the rule names applyFirewall would create for the
// config, so the dashboard and the CLI agree on what to add or remove.
func FirewallRuleNames(cfg *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, r := range cfg.Rules {
		if r.ListenPort == 0 {
			continue
		}
		switch {
		case r.Kind == config.KindRaw && r.IsProtocolAll():
			add(fmt.Sprintf("l4fwd ALL TCP %d", r.ListenPort))
			add(fmt.Sprintf("l4fwd ALL UDP %d", r.ListenPort))
		case r.Kind == config.KindRaw && r.Transport() == config.RawTransparent:
			add(fmt.Sprintf("l4fwd RAW-TCP %d", r.ListenPort))
		case r.Kind == config.KindTCP:
			add(fmt.Sprintf("l4fwd TCP %d", r.ListenPort))
		case r.Kind == config.KindUDP:
			add(fmt.Sprintf("l4fwd UDP %d", r.ListenPort))
		}
	}
	return out
}

// watchConfig polls the config file and reloads when it changes on disk.
func watchConfig(store *config.Store, manager *engine.Manager, logger *logx.Logger) (func(), error) {
	path := store.Path()
	var lastMod time.Time
	var lastSize int64
	if fi, err := os.Stat(path); err == nil {
		lastMod, lastSize = fi.ModTime(), fi.Size()
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				fi, err := os.Stat(path)
				if err != nil {
					continue
				}
				if fi.ModTime().Equal(lastMod) && fi.Size() == lastSize {
					continue
				}
				lastMod, lastSize = fi.ModTime(), fi.Size()
				if err := store.Load(); err != nil {
					logger.Errorf("config", "配置文件变更但解析失败: %v", err)
					continue
				}
				cfg := store.Get()
				manager.Apply(cfg)
				logger.SetLevel(logx.ParseLevel(cfg.Settings.LogLevel))
				logger.Infof("config", "检测到配置文件更新，已应用 %d 条规则", len(cfg.Rules))
			}
		}
	}()
	return func() { close(stop); <-done }, nil
}

// restartProcess launches a fresh copy of the executable and exits.
func restartProcess(logger *logx.Logger) func() {
	return func() {
		exe, err := os.Executable()
		if err != nil {
			logger.Errorf("cli", "无法重启: %v", err)
			return
		}
		args := os.Args[1:]
		// Wait for the HTTP response to flush, then hand the console over.
		time.Sleep(300 * time.Millisecond)
		if err := platform.Elevate(append([]string{}, args...)); err != nil {
			logger.Warnf("cli", "提权重启失败，尝试直接启动: %v", err)
			cmd := newCommand(exe, args...)
			if err := cmd.Start(); err != nil {
				logger.Errorf("cli", "重启失败: %v", err)
				return
			}
		}
		logger.Infof("cli", "已启动新实例，退出当前进程")
		os.Exit(0)
	}
}

func resolveLogPath(configPath, logPath string) string {
	if strings.ContainsAny(logPath, `\/:`) {
		return logPath
	}
	return filepathJoin(dirOf(configPath), logPath)
}

func dirOf(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	if i < 0 {
		return "."
	}
	return p[:i]
}

func filepathJoin(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return strings.TrimRight(dir, `\/`) + string(os.PathSeparator) + name
}

// browserURL builds the dashboard URL from the listen address.
func browserURL(listen string) string {
	host, port, err := netutil.ParseListen(listen)
	if err != nil || port == 0 {
		return "http://127.0.0.1:8686/"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s/", netutil.HostPort(host, port))
}
