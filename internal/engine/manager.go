package engine

import (
	"fmt"
	"sort"
	"sync"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/stats"
)

// Status describes the runtime state of one rule.
type Status struct {
	RuleID    string         `json:"ruleId"`
	Running   bool           `json:"running"`
	Error     string         `json:"error,omitempty"`
	Stats     stats.Snapshot `json:"stats"`
	Sessions  int            `json:"sessions"`
	StartedAt string         `json:"startedAt,omitempty"`
}

// runner is the common interface of the TCP, UDP and raw listeners.
type runner interface {
	Start() error
	Stop()
	Active() int64
}

// instance couples a runner with its rule and counters.
type instance struct {
	rule  *config.Rule
	key   string // rule ID
	lnKey string // listener key (kind/host/port), used for conflict detection
	run   runner
	st    *stats.RuleStats
	err   string
}

// Manager owns the running listeners and reconciles them with the config.
type Manager struct {
	log    *logx.Logger
	cfgMux sync.RWMutex
	cfg    *config.Config

	// applyMu serialises Apply. Both the HTTP handler and the config file
	// watcher call it from their own goroutine; without this two reconciliations
	// would race, both try to bind the same port, and the loser would overwrite
	// the winner's instance record — leaving a listener running that the manager
	// can no longer stop.
	applyMu sync.Mutex

	mu   sync.RWMutex
	inss map[string]*instance // by rule ID

	sampler *stats.Sampler
}

// NewManager creates an empty manager.
func NewManager(log *logx.Logger, cfg *config.Config, sampler *stats.Sampler) *Manager {
	m := &Manager{
		log:     log,
		cfg:     cfg.Clone(),
		inss:    map[string]*instance{},
		sampler: sampler,
	}
	if m.sampler == nil {
		m.sampler = stats.NewSampler()
	}
	return m
}

// Settings returns the effective global settings.
func (m *Manager) Settings() config.Settings {
	m.cfgMux.RLock()
	defer m.cfgMux.RUnlock()
	return m.cfg.Settings
}

// Apply reconciles the running listeners with cfg: unchanged rules keep
// running (and keep their counters), changed rules are restarted.
func (m *Manager) Apply(cfg *config.Config) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()

	m.cfgMux.Lock()
	m.cfg = cfg.Clone()
	set := m.cfg.Settings
	m.cfgMux.Unlock()

	want := map[string]*config.Rule{}
	order := make([]string, 0, len(cfg.Rules))
	for _, r := range cfg.SortedRules() {
		want[r.ID] = r
		order = append(order, r.ID)
	}

	// Stop rules that vanished or are disabled.
	m.mu.Lock()
	var stopping []*instance
	for id, ins := range m.inss {
		r, ok := want[id]
		if !ok || !r.Enabled || m.signature(ins.rule) != m.signature(r) {
			stopping = append(stopping, ins)
			delete(m.inss, id)
		}
	}
	m.mu.Unlock()
	for _, ins := range stopping {
		ins.run.Stop()
		m.sampler.Untrack(ins.key)
		m.log.Infof("engine", "stopped %s", ins.rule.Summary())
	}

	// Start anything new or changed.
	for _, id := range order {
		r := want[id]
		if !r.Enabled {
			continue
		}
		m.mu.RLock()
		_, running := m.inss[id]
		m.mu.RUnlock()
		if running {
			continue
		}
		m.startRule(r, set)
	}
}

// signature captures everything that requires a restart when changed.
func (m *Manager) signature(r *config.Rule) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s|%s|%d|%s|%d|%d|%d|%d|%d|%v|%v|%s|%d|%v|%s|%v|%v|%v",
		r.Kind, r.Protocol, r.ListenHost, r.ListenPort, r.TargetHost, r.TargetPort,
		r.DialTimeoutSec, r.IdleTimeoutSec, r.UDPSessionTTLSec, r.MaxConns,
		r.PreserveClientIP, r.Sniff, r.SourceIP, r.TTL, r.Enabled,
		r.RawTransport, r.PayloadPorts, r.Transport(), r.GateOnTarget())
}

func (m *Manager) startRule(r *config.Rule, set config.Settings) {
	st := stats.NewRuleStats()
	var (
		run runner
		err error
	)
	switch r.Kind {
	case config.KindTCP:
		t := NewTCPListener(r, set, st, m.log)
		err = t.Start()
		run = t
	case config.KindUDP:
		u := NewUDPListener(r, set, st, m.log)
		err = u.Start()
		run = u
	case config.KindRaw:
		// An "all protocol" rule fans out into a TCP listener, a UDP listener and
		// one raw socket per remaining protocol number.
		if r.IsProtocolAll() {
			ml, merr := NewMultiListener(r, set, st, m.log)
			if merr != nil {
				err = merr
				break
			}
			err = ml.Start()
			run = ml
			break
		}
		// Raw rules come in two shapes. TCP-shaped traffic goes to the kernel
		// stack (a raw socket cannot carry TCP on Windows); everything else uses
		// the relay's own raw socket on the protocol number.
		if r.Transport() == config.RawTransparent {
			t := NewTransparentTCPListener(r, set, st, m.log)
			err = t.Start()
			run = t
			break
		}
		var rl *RawListener
		rl, err = NewRawListener(r, set, st, m.log)
		if err == nil {
			err = rl.Start()
			run = rl
		}
	default:
		err = fmt.Errorf("unknown rule type %q", r.Kind)
	}

	ins := &instance{rule: r, key: r.ID, lnKey: r.Key(), run: run, st: st}
	if err != nil {
		ins.err = err.Error()
		ins.run = &failedRunner{err: err}
		m.log.Errorf("engine", "cannot start %s: %v", r.Summary(), err)
		st.Error(err.Error())
	} else {
		m.sampler.Track(r.ID, st.Counters)
		m.log.Infof("engine", "started %s", r.Summary())
	}
	m.mu.Lock()
	m.inss[r.ID] = ins
	m.mu.Unlock()
}

// StopAll shuts every listener down. It takes the apply lock so a concurrent
// Apply cannot resurrect a listener while the process is shutting down.
func (m *Manager) StopAll() {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.Lock()
	all := make([]*instance, 0, len(m.inss))
	for _, ins := range m.inss {
		all = append(all, ins)
	}
	m.inss = map[string]*instance{}
	m.mu.Unlock()
	for _, ins := range all {
		ins.run.Stop()
		m.sampler.Untrack(ins.key)
	}
}

// Reload re-reads the config file and applies it (used by SIGHUP style hot reload).
func (m *Manager) Reload(store *config.Store) error {
	if err := store.Load(); err != nil {
		return err
	}
	m.Apply(store.Get())
	return nil
}

// Statuses returns per-rule runtime state, sorted by rule kind and port.
func (m *Manager) Statuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Status, 0, len(m.inss))
	for _, ins := range m.inss {
		s := Status{
			RuleID:  ins.key,
			Running: ins.err == "",
			Error:   ins.err,
		}
		if ins.st != nil {
			s.Stats = ins.st.Snapshot()
			in, outBps := ins.st.Speed()
			s.Stats.SpeedInBps = in
			s.Stats.SpeedOutBps = outBps
			pktIn, pktOut := ins.st.PacketSpeed()
			s.Stats.PktInBps = pktIn
			s.Stats.PktOutBps = pktOut
		}
		if ins.run != nil {
			s.Sessions = int(ins.run.Active())
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// Status returns the state of one rule.
func (m *Manager) Status(ruleID string) (Status, bool) {
	for _, s := range m.Statuses() {
		if s.RuleID == ruleID {
			return s, true
		}
	}
	return Status{}, false
}

// Totals sums the counters of every running rule.
func (m *Manager) Totals() stats.Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var total stats.Snapshot
	for _, ins := range m.inss {
		if ins.st == nil {
			continue
		}
		s := ins.st.Snapshot()
		total.RxBytes += s.RxBytes
		total.TxBytes += s.TxBytes
		total.RxPkts += s.RxPkts
		total.TxPkts += s.TxPkts
		total.Conns += s.Conns
		total.Active += s.Active
		total.Errors += s.Errors
		total.Drops += s.Drops
		in, out := ins.st.Speed()
		total.SpeedInBps += in
		total.SpeedOutBps += out
		pktIn, pktOut := ins.st.PacketSpeed()
		total.PktInBps += pktIn
		total.PktOutBps += pktOut
		if s.UptimeSec > total.UptimeSec {
			total.UptimeSec = s.UptimeSec
		}
	}
	return total
}

// failedRunner stands in for a rule that could not be started.
type failedRunner struct{ err error }

func (f *failedRunner) Start() error  { return f.err }
func (f *failedRunner) Stop()         {}
func (f *failedRunner) Active() int64 { return 0 }

// RefreshSampler recomputes rates; called periodically by the app loop.
func (m *Manager) RefreshSampler(intervalSec float64) { m.sampler.Tick(intervalSec) }
