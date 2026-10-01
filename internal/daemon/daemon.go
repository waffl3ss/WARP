// Package daemon wires the engagement together: the workspace, the radio scheduler, the
// scope gate, the capture pipeline and the RPC surface.
//
// The daemon owns the radios and every running job. It survives client disconnect, because
// the operator will be SSH'd into a NUC in a wiring closet and a dropped session must not end
// the engagement.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/build"
	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/inject"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rogue"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/scope"
	"github.com/waffl3ss/warp/internal/store"
	"github.com/waffl3ss/warp/internal/web"
	"github.com/waffl3ss/warp/internal/workspace"
)

// Daemon is a running engagement.
type Daemon struct {
	ws    *workspace.Workspace
	sched *radio.Scheduler
	store *store.Store
	srv   *rpc.Server
	log   *slog.Logger

	// web is the browser interface, nil unless the operator asked for it.
	web *web.Server

	engine     *Engine
	jobs       *JobManager
	solicitor  *inject.Solicitor
	classifier *rogue.Classifier
	hashes     *handshake.Writer
	acquirer   radio.Acquirer

	// eap holds the running enterprise credential capture, if any.
	eap eapState

	// walkAutoRecon records that a walkthrough started capture because recon was idle, so ending the
	// last walkthrough puts the radios back the way they were - idle if they were idle, still
	// capturing if the operator had recon running. Set/read only in the walkthrough handlers, which
	// are deliberate sequential operator actions.
	walkAutoRecon bool

	// wpsKeys holds the WPS credentials recovered this run (PIN, and the passphrase when the
	// exchange went on to read it from M7), so they surface in the Credentials view alongside the
	// hashes and enterprise credentials. Guarded by wpsMu.
	wpsMu   sync.RWMutex
	wpsKeys []WPSCredential

	// locks holds the operator's manual channel pins, so they outlive the call that made them.
	locks radioLocks

	// hunts holds live direction-finding sessions, keyed by target address.
	huntMu sync.RWMutex
	hunts  map[recon.MAC]*huntSession

	// karmaProbeESSID is the generated name currently being probed for, and karmaResponders
	// records devices that answered it. Both are guarded by karmaMu.
	karmaMu         sync.RWMutex
	karmaProbeESSID string
	karmaResponders map[recon.MAC]string

	// rogueBSSIDs is the set of BSSIDs an operator has manually marked as a potential rogue,
	// hydrated from the store at startup and kept in step with it on every mark/unmark. The AP list
	// reads it to colour a marked device without a database hit on the poll path. Guarded by rogueMu.
	rogueMu     sync.RWMutex
	rogueBSSIDs map[string]bool

	started time.Time
	ctx     context.Context
}

// Deps are the daemon's collaborators.
type Deps struct {
	Workspace *workspace.Workspace
	Scheduler *radio.Scheduler
	Store     *store.Store
	Acquirer  radio.Acquirer
	Hashes    *handshake.Writer
	Log       *slog.Logger

	// Web, when non-nil, starts the browser interface alongside the RPC socket. The
	// dispatcher and logger are filled in from the daemon.
	Web *web.Config
}

// New builds a daemon.
func New(d Deps) (*Daemon, error) {
	if d.Workspace == nil {
		return nil, errors.New("daemon: no workspace")
	}
	if d.Scheduler == nil {
		return nil, errors.New("daemon: no radio scheduler")
	}
	if d.Store == nil {
		return nil, errors.New("daemon: no store")
	}
	if d.Acquirer == nil {
		return nil, errors.New("daemon: no radio acquirer")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}

	dae := &Daemon{
		ws:              d.Workspace,
		sched:           d.Scheduler,
		store:           d.Store,
		acquirer:        d.Acquirer,
		hashes:          d.Hashes,
		srv:             rpc.NewServer(d.Log),
		log:             d.Log,
		solicitor:       inject.NewSolicitor(0),
		hunts:           make(map[recon.MAC]*huntSession),
		karmaResponders: make(map[recon.MAC]string),
		rogueBSSIDs:     make(map[string]bool),
		started:         time.Now(),
	}

	dae.jobs = NewJobManager(dae.onJobUpdate)
	dae.classifier = rogue.NewClassifier(rogue.Config{}, dae.ws.Scope.Match)

	// The store projects a scope-filtered findings file (findings-in-scope.csv); give it the scope
	// membership test. The store is otherwise scope-agnostic.
	dae.store.SetScopeFilter(dae.ws.Scope.Contains)

	// Reload WPS keys recovered in earlier runs so they survive a daemon restart and keep showing
	// in the credentials tab - the recovered passphrase is the deliverable, and the operator
	// restarts warpd routinely between manual tests. The durable file is authoritative.
	dae.loadWPSKeys()

	// Reload manual rogue marks so a marked device stays red across a daemon restart. The findings
	// table is authoritative; this is only the in-memory index the AP poll path reads.
	dae.loadRogueMarks()

	// Write the consolidated credentials summary now, so it reflects WPS keys reloaded from earlier
	// runs and is present (even if empty) from startup - overwriting any stale copy.
	dae.writeCredentialsFile()

	engine, err := NewEngine(EngineOptions{
		Scheduler:    d.Scheduler,
		Acquirer:     d.Acquirer,
		Store:        d.Store,
		Hashes:       d.Hashes,
		Log:          d.Log,
		Broadcast:    dae.Broadcast,
		InScope:      dae.ws.Scope.Contains,
		WorkspaceDir: d.Workspace.Dir,
		CapturesDir:  filepath.Join(d.Workspace.Dir, workspace.CapturesDir),
	})
	if err != nil {
		return nil, err
	}
	dae.engine = engine

	// The karma responder test transmits probes for a name that cannot exist; this is what
	// notices anything that answers. Detection lives on the capture path rather than in the
	// transmitter because a responder may reply on a different radio.
	engine.SetESSIDObserver(func(bssid recon.MAC, essid string) {
		if !dae.NoteKarmaResponse(bssid, essid) {
			return
		}
		dae.Broadcast(rpc.Event{
			Kind: "karma", Level: rpc.LevelWarn,
			Text: fmt.Sprintf("[!] KARMA RESPONDER %s answered a probe for %q, a network that "+
				"does not exist", bssid, essid),
			Fields: map[string]any{"bssid": bssid.String(), "essid": essid},
		})
	})

	if err := dae.register(); err != nil {
		return nil, err
	}

	// The web interface is a client of the RPC server, not a peer of it. It dispatches through
	// exactly the handlers registered above, so anything reachable from the console is
	// reachable from a browser and neither can grow a capability the other lacks.
	if d.Web != nil {
		cfg := *d.Web
		cfg.Dispatcher = dae.srv
		cfg.Log = d.Log
		srv, err := web.New(cfg)
		if err != nil {
			return nil, err
		}
		dae.web = srv
	}
	return dae, nil
}

// Web returns the browser interface, or nil if it was not requested. The caller uses it to
// print the URL and access token at startup.
func (d *Daemon) Web() *web.Server { return d.web }

// Run serves RPC on sockPath until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context, sockPath string) error {
	d.ctx = ctx

	if err := d.srv.Listen(sockPath); err != nil {
		return err
	}
	defer d.srv.Close()

	// Bind the web port before anything else starts. An operator who asked for the browser
	// interface and did not get it would go looking for a dashboard that was never there, so
	// a bind failure ends startup rather than being logged and forgotten.
	if d.web != nil {
		if err := d.web.Listen(); err != nil {
			return err
		}
		go func() {
			if err := d.web.Serve(ctx); err != nil {
				d.log.Error("web interface stopped", "err", err)
			}
		}()
		d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "web interface started", map[string]any{
			"addr": d.web.Addr(),
			"tls":  d.web.TLSEnabled(),
		})
	}

	// No implicit walkthrough. A walkthrough is a deliberate act - someone physically walking the
	// site with an antenna - so observations are tagged to one only when the operator has started
	// it (`warp walkthrough start <name>`). Captures made outside any walkthrough carry none, which
	// is the honest record of a closet deployment where nobody walked.

	d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "daemon started", map[string]any{
		"socket": sockPath,
		"radios": len(d.sched.Devices()),
		"scope":  d.ws.Scope.List(),
	})
	d.log.Info("warpd listening", "socket", sockPath, "radios", len(d.sched.Devices()))

	err := d.srv.Serve(ctx)

	d.shutdown()
	return err
}

// shutdown stops every job and releases every radio.
//
// A panic or an abrupt exit must not leave adapters stranded in monitor mode, so teardown is
// best-effort and every step runs regardless of earlier failures.
func (d *Daemon) shutdown() {
	if n := d.jobs.KillAll(); n > 0 {
		d.log.Info("cancelled running jobs", "count", n)
	}

	// Teardown runs on a fresh context: the daemon's is already cancelled by the time we get
	// here, and radio release must still happen.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d.releaseAllLocks()
	if err := d.engine.Stop(ctx); err != nil {
		d.log.Error("engine shutdown was incomplete", "err", err)
	}
	if d.hashes != nil {
		if err := d.hashes.Close(); err != nil {
			d.log.Error("hash file close failed", "err", err)
		}
	}
	// The capture archive is owned by the engine and closed by engine.Stop above, which also writes
	// its netxml snapshot.
	// Final projection rebuild so the flat files match the database on exit. They have been
	// current to within a few seconds throughout - this is the last one, not the only one.
	if err := d.store.ExportCSV(ctx, d.ws.Dir); err != nil {
		d.log.Error("final CSV export failed", "err", err)
	}
	if err := d.engine.Close(); err != nil {
		d.log.Error("observation log close failed", "err", err)
	}

	d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "daemon stopped", nil)
}

// Broadcast pushes an event to connected clients.
func (d *Daemon) Broadcast(ev rpc.Event) { d.srv.Broadcast(ev) }

func (d *Daemon) onJobUpdate(j Job) {
	level := rpc.LevelInfo
	switch j.State {
	case JobFailed:
		level = rpc.LevelWarn
	case JobDenied:
		level = rpc.LevelWarn
	case JobDone:
		level = rpc.LevelGood
	}
	if j.State == JobRunning {
		d.Broadcast(rpc.Event{
			Kind: "job", Level: level,
			Text:   fmt.Sprintf("[*] job %s started: %s %s", j.ID, j.Kind, j.Target),
			Fields: map[string]any{"id": j.ID, "kind": j.Kind, "state": string(j.State)},
		})
		return
	}
	text := fmt.Sprintf("[*] job %s %s: %s %s", j.ID, j.State, j.Kind, j.Target)
	switch {
	case j.Error != "":
		text += " - " + j.Error
	case j.Detail != "":
		// What the job actually found. Without this a completed Pixie Dust attempt or
		// certificate harvest said only that it had finished, and the operator had to go and
		// read a JSON result to learn whether anything had happened at all.
		text += " - " + j.Detail
	}
	d.Broadcast(rpc.Event{
		Kind: "job", Level: level, Text: text,
		Fields: map[string]any{
			"id": j.ID, "kind": j.Kind, "state": string(j.State),
			"error": j.Error, "detail": j.Detail,
		},
	})
}

func (d *Daemon) logEvent(kind string, outcome audit.Outcome, reason string, detail map[string]any) {
	if err := d.ws.Audit().Log(audit.Event{
		Kind: kind, Outcome: outcome, Module: "daemon", Reason: reason, Detail: detail,
	}); err != nil {
		d.log.Error("audit write failed", "err", err)
	}
}

// register wires the RPC surface.
//
// Both frontends - the one-shot subcommands and the REPL - hit exactly this surface. No
// functionality is REPL-only, so anything reachable interactively is scriptable.
func (d *Daemon) register() error {
	methods := map[string]rpc.Handler{
		// Status and inventory
		"status":               d.handleStatus,
		"radios.list":          d.handleRadiosList,
		"radios.lock":          d.handleRadioLock,
		"radios.unlock":        d.handleRadioUnlock,
		"radios.set-enabled":   d.handleRadioSetEnabled,
		"radios.reset":         d.handleRadioReset,
		"radios.channels":      d.handleRadioChannels,
		"radios.regdomain":     d.handleRegDomainGet,
		"radios.set-regdomain": d.handleRegDomainSet,
		"precheck.list":        d.handlePrecheckList,
		"precheck.fix":         d.handlePrecheckFix,
		"radios.assignments":   d.handleRadioAssignments,

		// Scope
		"scope.list":        d.handleScopeList,
		"scope.confirm":     d.handleScopeConfirm,
		"scope.reject":      d.handleScopeReject,
		"scope.acknowledge": d.handleScopeAcknowledge,
		"scope.add":         d.handleScopeAdd,
		"scope.remove":      d.handleScopeRemove,

		// Recon
		"recon.start":   d.handleReconStart,
		"recon.stop":    d.handleReconStop,
		"recon.status":  d.handleReconStatus,
		"aps.list":      d.handleAPsList,
		"aps.detail":    d.handleAPDetail,
		"stations.list": d.handleStationsList,

		// Survey
		"walkthrough.start":   d.handleWalkthroughStart,
		"walkthrough.end":     d.handleWalkthroughEnd,
		"walkthrough.list":    d.handleWalkthroughList,
		"walkthrough.current": d.handleWalkthroughCurrent,
		"walkthrough.rename":  d.handleWalkthroughRename,
		"walkthrough.split":   d.handleWalkthroughSplit,
		"walkthrough.delete":  d.handleWalkthroughDelete,
		"walkthrough.devices": d.handleWalkthroughDevices,
		"localize":            d.handleLocalize,

		// Rogue detection
		"rogue.classify":   d.handleRogueClassify,
		"rogue.list":       d.handleRogueList,
		"rogue.detail":     d.handleRogueDetail,
		"rogue.karma-test": d.handleKarmaTest,
		"rogue.mark":       d.handleRogueMark,
		"rogue.unmark":     d.handleRogueUnmark,

		// Attacks
		"psk.solicit": d.handleSolicit,
		"psk.deauth":  d.handleDeauth,
		"decloak":     d.handleDecloak,
		"harvest":     d.handleHarvest,
		"wps":         d.handleWPS,

		// Enterprise credential capture: rogue AP + RADIUS + EAP, started as one.
		"eap.start": d.handleEAPStart,
		// The certificate library. The certificate is the pretext, so managing it is not a
		// detail of starting the rogue - it is its own surface.
		"certs.list":     d.handleCertsList,
		"certs.generate": d.handleCertGenerate,
		"certs.import":   d.handleCertImport,
		"certs.select":   d.handleCertSelect,
		"certs.delete":   d.handleCertDelete,
		"eap.stop":       d.handleEAPStop,
		"eap.status":     d.handleEAPStatus,

		// Hunt
		"hunt.start": d.handleHuntStart,
		"hunt.stop":  d.handleHuntStop,
		"hunt.state": d.handleHuntState,

		// Jobs
		"jobs.list": d.handleJobsList,
		"jobs.kill": d.handleJobsKill,

		// Captured hashes - the engagement's actual deliverable.
		"hashes.list": d.handleHashesList,

		// Export and reporting
		"export":        d.handleExport,
		"report":        d.handleReport,
		"report.export": d.handleReportExport,
		"export.bundle": d.handleExportBundle,
	}

	for name, h := range methods {
		if err := d.srv.Register(name, h); err != nil {
			return err
		}
	}
	return nil
}

// StatusResult is the daemon's overall state, and backs the REPL status header.
type StatusResult struct {
	// Version and Author identify the running build. The browser interface serves static
	// assets and cannot link against internal/build, so it reads them from here.
	Version     string    `json:"version"`
	Commit      string    `json:"commit,omitempty"`
	Author      string    `json:"author"`
	Workspace   string    `json:"workspace"`
	StartedAt   time.Time `json:"started_at"`
	Uptime      string    `json:"uptime"`
	ScopeESSIDs int       `json:"scope_essids"`
	PendingAcks []string  `json:"pending_acknowledgments,omitempty"`
	// SiteWide reports an engagement scoped to every named network rather than to a list.
	// Both frontends keep it on screen: a widened scope must never be in force invisibly.
	SiteWide     bool               `json:"site_wide_scope,omitempty"`
	SiteWideNote string             `json:"site_wide_justification,omitempty"`
	Radios       int                `json:"radios"`
	SurveyRadio  string             `json:"survey_radio,omitempty"`
	Assignments  []radio.Assignment `json:"assignments"`
	Capabilities []radio.Capability `json:"capabilities"`

	// Disk is the state of the filesystem the engagement is being written to. It is in the
	// status payload rather than behind its own method because both frontends want it on every
	// refresh, and a capture that quietly stopped for want of space is the failure it exists
	// to prevent.
	Disk workspace.DiskUsage `json:"disk"`

	Recon           EngineStats  `json:"recon"`
	Counts          store.Counts `json:"counts"`
	RunningJobs     int          `json:"running_jobs"`
	Walkthrough     string       `json:"walkthrough,omitempty"`
	PMKIDHashes     int          `json:"pmkid_hashes"`
	HandshakeHashes int          `json:"handshake_hashes"`
}

func (d *Daemon) handleStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	res := StatusResult{
		Version:      build.Version,
		Commit:       build.Commit,
		Author:       build.Author,
		Workspace:    d.ws.Dir,
		StartedAt:    d.started,
		Uptime:       time.Since(d.started).Round(time.Second).String(),
		ScopeESSIDs:  d.ws.Scope.Len(),
		PendingAcks:  d.ws.Gate.PendingAcknowledgments(),
		SiteWide:     d.ws.Scope.IsSiteWide(),
		SiteWideNote: d.ws.Scope.SiteWideNote(),
		Radios:       len(d.sched.Devices()),
		SurveyRadio:  d.engine.SurveyRadioName(),
		Assignments:  d.sched.Assignments(),
		Capabilities: d.sched.Capabilities(),
		Recon:        d.engine.Stats(),
		RunningJobs:  d.jobs.RunningCount(),
	}

	if counts, err := d.store.Counts(ctx); err == nil {
		res.Counts = counts
	}
	if disk, err := d.ws.Disk(); err == nil {
		res.Disk = disk
	} else {
		// Not fatal: a status call must still answer. The frontends render a zero total as
		// "unknown" rather than as a full disk.
		d.log.Debug("disk usage unavailable", "err", err)
	}
	if p, e, err := d.store.HashCounts(ctx); err == nil {
		res.PMKIDHashes, res.HandshakeHashes = p, e
	}
	if w, err := d.store.CurrentWalkthrough(ctx); err == nil && w != nil {
		res.Walkthrough = w.Name
	}
	return res, nil
}

// RadioInfo is one adapter as reported to clients.
type RadioInfo struct {
	ID           string                 `json:"id"`
	Ifname       string                 `json:"ifname"`
	Driver       string                 `json:"driver,omitempty"`
	MAC          string                 `json:"mac,omitempty"`
	Bands        []string               `json:"bands"`
	Injection    string                 `json:"injection"`
	APAndMonitor bool                   `json:"ap_monitor_concurrent"`
	Combinations []string               `json:"interface_combinations"`
	Iftypes      []string               `json:"supported_iftypes"`
	Channels     int                    `json:"usable_channels"`
	Roles        []radio.RoleCapability `json:"roles"`
	// PinnedChannel is the channel an operator pinned this adapter to, 0 when it is following
	// the channel plan. Reported so "why is this card not sweeping" has an answer on screen.
	PinnedChannel int `json:"pinned_channel,omitempty"`
	// Enabled reports whether the operator has this adapter switched on. A switched-off adapter
	// is released and left alone so another tool can use it.
	Enabled bool `json:"enabled"`
	// USB reports whether this adapter is USB-backed and can therefore be USB-reset live from the
	// radios tab. A built-in PCIe/SDIO card reports false and offers no reset button.
	USB bool `json:"usb"`
	// ChannelList are the IEEE channel numbers this adapter can reach, for the channel selector.
	ChannelList []int `json:"channel_list,omitempty"`
	// The operator's current channel-management choice for this adapter.
	SelectedChannels []int `json:"selected_channels,omitempty"`
	ChannelsNo5GHz   bool  `json:"channels_no_5ghz,omitempty"`
	ChannelsRandom   bool  `json:"channels_random,omitempty"`
}

func (d *Daemon) handleRadiosList(context.Context, json.RawMessage) (any, error) {
	devs := d.sched.Devices()
	pinned := d.pinnedChannels()
	out := make([]RadioInfo, 0, len(devs))

	for _, dev := range devs {
		info := RadioInfo{
			PinnedChannel: pinned[dev.ID],
			ID:            dev.ID,
			Ifname:        dev.Ifname,
			Driver:        dev.Driver,
			MAC:           dev.MAC,
			Bands:         dev.Bands(),
			Injection:     dev.Injection.String(),
			Roles:         dev.Capabilities(),
			Enabled:       d.sched.IsEnabled(dev.ID),
			USB:           radio.IsUSBAdapter(dev.Ifname),
		}
		pol := d.engine.ChannelPolicyFor(dev.ID)
		info.SelectedChannels = pol.Channels
		info.ChannelsNo5GHz = pol.Disable5GHz
		info.ChannelsRandom = pol.Random
		if dev.Phy != nil {
			info.APAndMonitor = dev.Phy.SupportsAPMonitorConcurrent()
			usable := dev.Phy.UsableChannels()
			info.Channels = len(usable)
			for _, f := range usable {
				info.ChannelList = append(info.ChannelList, f.Channel)
			}
			for _, t := range dev.Phy.SupportedIftypes {
				info.Iftypes = append(info.Iftypes, t.String())
			}
			for _, c := range dev.Phy.Combinations {
				info.Combinations = append(info.Combinations, c.String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

func (d *Daemon) handleRadioAssignments(context.Context, json.RawMessage) (any, error) {
	return d.sched.Assignments(), nil
}

func (d *Daemon) handleScopeList(context.Context, json.RawMessage) (any, error) {
	return map[string]any{
		"essids":        d.ws.Gate.Snapshot(),
		"confirmations": d.ws.Gate.Confirmations(),
		"rejections":    d.ws.Gate.Rejections(),
	}, nil
}

// bssidParams is the shared shape for the operator's BSSID-level annotations.
//
// Note what this is not: it is not scope input. These are annotations on BSSIDs WARP already
// discovered off the air - a confirmation is advisory, and a rejection only ever narrows
// scope. Authorization still follows from ESSID match.
type bssidParams struct {
	BSSID string `json:"bssid"`
	ESSID string `json:"essid"`
	Note  string `json:"note"`
}

func (d *Daemon) handleScopeConfirm(_ context.Context, params json.RawMessage) (any, error) {
	p, err := decodeBSSIDParams(params)
	if err != nil {
		return nil, err
	}
	if err := d.ws.Gate.Confirm(p.BSSID, p.ESSID, p.Note); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	return map[string]string{
		"bssid": scope.NormalizeBSSID(p.BSSID),
		"note":  "recorded - advisory only; authorization follows from ESSID match either way",
	}, nil
}

func (d *Daemon) handleScopeReject(_ context.Context, params json.RawMessage) (any, error) {
	p, err := decodeBSSIDParams(params)
	if err != nil {
		return nil, err
	}
	if err := d.ws.Gate.Reject(p.BSSID, p.ESSID, p.Note); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	return map[string]string{
		"bssid": scope.NormalizeBSSID(p.BSSID),
		"note":  "excluded from active work",
	}, nil
}

func (d *Daemon) handleScopeAcknowledge(_ context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ESSID    string `json:"essid"`
		Operator string `json:"operator"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if err := d.ws.Gate.AcknowledgeGeneric(p.ESSID, p.Operator); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	return map[string]any{
		"essid":   p.ESSID,
		"pending": d.ws.Gate.PendingAcknowledgments(),
	}, nil
}

func decodeBSSIDParams(params json.RawMessage) (bssidParams, error) {
	var p bssidParams
	if err := json.Unmarshal(params, &p); err != nil {
		return p, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if scope.NormalizeBSSID(p.BSSID) == "" {
		return p, rpc.Errorf(rpc.CodeInvalidParams, "%q is not a MAC address", p.BSSID)
	}
	return p, nil
}

// isScopeDenial reports whether an error is a scope refusal.
//
// Kept distinct from an ordinary failure throughout: a denial means the gate worked, and a
// report must be able to tell "we were refused" from "the tool broke".
func isScopeDenial(err error) bool { return scope.Denied(err) }

// scopeRPCError maps a scope denial onto the RPC error code reserved for it, so clients can
// render a refusal as an authorization decision rather than a malfunction.
func scopeRPCError(err error) error {
	if err == nil {
		return nil
	}
	if isScopeDenial(err) {
		return rpc.Errorf(rpc.CodeScopeDenied, "%v", err)
	}
	return err
}
