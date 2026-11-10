package app

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/discovery"
	"github.com/gr0gu/cerberus/internal/ingest"
	"github.com/gr0gu/cerberus/internal/logstream"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/netdetect"
	"github.com/gr0gu/cerberus/internal/posture"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
	"github.com/gr0gu/cerberus/internal/tracker"
)

// Daemon manages the unified lifecycle of Cerberus Sentinel workers, storage, and the
// loopback agent ingest listener. The UI talks to it through Wails IPC, not HTTP.
type Daemon struct {
	cfg          *config.Config
	store        *storage.Storage
	sched        *scheduler.Scheduler
	scn          *scanner.Scanner
	ingest       *ingest.Server
	posture      *posture.Service
	logs         *logstream.Buffer
	caps         *model.Capabilities
	settings     model.AppSettings
	daemonCtx    context.Context
	cancel       context.CancelFunc
	stopOnce     sync.Once
	errCh        chan error
	eventEmitter func(event string, data any)
	mu           sync.Mutex
	started      bool
	startTime    time.Time
}

// New constructs a new Daemon instance from configuration.
func New(cfg *config.Config) *Daemon {
	return &Daemon{
		cfg:   cfg,
		errCh: make(chan error, 1),
	}
}

// localNetworkWait is how long a discovery sweep waits for the user to allow local network
// access on macOS (the system prompt appears on the first sweep after install).
const localNetworkWait = 60 * time.Second

// interruptedScanMessage is stored on scans that a previous process left as running.
const interruptedScanMessage = "scan interrupted: Cerberus Sentinel stopped before the scan finished"

// SetLogs sets the buffer with the daemon log, served to the UI. Call it before Start.
func (d *Daemon) SetLogs(logs *logstream.Buffer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logs = logs
}

// Logs returns the recent daemon log lines, oldest first.
func (d *Daemon) Logs() []logstream.Entry {
	d.mu.Lock()
	logs := d.logs
	d.mu.Unlock()
	if logs == nil {
		return []logstream.Entry{}
	}
	return logs.Entries()
}

// Start boots preflight, storage, scheduler, and the loopback ingest listener.
func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.started {
		return nil
	}

	// 1. Run Preflight capability inspection
	caps, err := scanner.Preflight(ctx, d.cfg, &scanner.DefaultCommandRunner{}, exec.LookPath)
	if err != nil {
		log.Printf("[Daemon] Preflight inspection warning: %v. Falling back to unprivileged.", err)
		resolvedFallback := scanner.ResolveNmapBinary(d.cfg.NmapPath)
		caps = &model.Capabilities{
			NmapPath:      resolvedFallback,
			EffectiveMode: "unprivileged",
			Warnings:      []string{err.Error()},
		}
	}
	if caps.NmapPath != "" {
		d.cfg.NmapPath = caps.NmapPath
	}
	d.caps = caps

	if n, err := discovery.LoadVendorDatabase(caps.NmapPath); err != nil {
		log.Printf("[Daemon] Warning: MAC vendor database not loaded (%v); using the built-in vendor list", err)
	} else {
		log.Printf("[Daemon] Loaded %d MAC vendor prefixes from the nmap installation", n)
	}

	// 2. Initialize persistent storage
	store, err := storage.New(d.cfg.DBPath)
	if err != nil {
		return fmt.Errorf("initializing storage: %w", err)
	}

	// A scan that a previous process left as "running" can never finish now.
	if n, err := store.FailInterruptedScans(ctx, interruptedScanMessage); err != nil {
		log.Printf("[Daemon] Failed to close interrupted scans: %v", err)
	} else if n > 0 {
		log.Printf("[Daemon] Warning: %d scan(s) of the previous run did not finish; recorded them as interrupted", n)
	}

	// 3. Load or initialize application settings
	defaultSettings := model.AppSettings{
		NetworkMode:          "auto",
		ScanPorts:            d.cfg.ScanPorts,
		DiscoveryIntervalSec: int(d.cfg.DiscoveryInterval.Seconds()),
		VulnIntervalSec:      int(d.cfg.VulnerabilityInterval.Seconds()),
		NmapPath:             caps.NmapPath,
	}
	// An explicit CERBERUS_SUBNET is the starting target; auto-detection would replace it.
	if !d.cfg.AutoDetectNetwork && d.cfg.NetworkCIDR != "" {
		defaultSettings.NetworkMode = "custom"
		defaultSettings.CustomNetworkCIDR = d.cfg.NetworkCIDR
	}
	persistedSettings, _ := store.GetAppSettings(ctx, defaultSettings)
	if persistedSettings.NmapPath == "" || persistedSettings.NmapPath == "nmap" {
		persistedSettings.NmapPath = caps.NmapPath
	}
	if caps.RawSocket {
		caps.EffectiveMode = "privileged"
	} else {
		// Privileged run is mandatory. If not privileged, user must accept / elevate.
		log.Printf("[Daemon] Raw socket access required for mandatory privileged execution. Prompting elevation...")
		if err := scanner.SetupPrivilegesOrInstall(ctx, caps.NmapPath); err != nil {
			log.Printf("[Daemon] Privilege elevation deferred or failed: %v", err)
			caps.EffectiveMode = "unprivileged"
			caps.Warnings = append(caps.Warnings, "Privileged execution is mandatory. User must elevate privileges to perform scans.")
		} else {
			if refreshed, rErr := scanner.Preflight(ctx, d.cfg, &scanner.DefaultCommandRunner{}, exec.LookPath); rErr == nil && refreshed != nil {
				caps = refreshed
				d.caps = caps
			}
		}
	}
	d.settings = persistedSettings

	// Saved intervals win over the environment defaults.
	if d.settings.DiscoveryIntervalSec > 0 {
		d.cfg.DiscoveryInterval = time.Duration(d.settings.DiscoveryIntervalSec) * time.Second
	}
	if d.settings.VulnIntervalSec > 0 {
		d.cfg.VulnerabilityInterval = time.Duration(d.settings.VulnIntervalSec) * time.Second
	}

	// Resolve active network interface and CIDR
	d.applyNetworkSettings(&d.settings)
	if d.settings.EffectiveCIDR != "" {
		d.cfg.NetworkCIDR = d.settings.EffectiveCIDR
	}

	// 4. Initialize scanner, scheduler, posture evaluation, and the ingest listener.
	scn := scanner.New(d.cfg, caps)
	if d.settings.EffectiveExcludeIP != "" {
		scn.SetExcludeIPs(d.settings.EffectiveExcludeIP)
	}
	if d.settings.ScanPorts != "" {
		scn.SetScanPorts(d.settings.ScanPorts)
	}
	d.scn = scn

	sched := scheduler.New(d.cfg, store, scn)
	if d.eventEmitter != nil {
		sched.SetEventEmitter(d.eventEmitter)
	}
	sched.SetLocalNetworkCheck(func(ctx context.Context) error {
		return netdetect.WaitForLocalNetworkAccess(ctx, localNetworkWait)
	})
	postureSvc := posture.NewService(store, posture.DefaultPolicy)
	sched.SetPostureService(postureSvc)

	// 5. Establish independent daemon execution context. The scheduler and the ingest
	// detection pipeline share it, so shutdown stops both.
	d.daemonCtx, d.cancel = context.WithCancel(context.Background())

	ingestSrv := ingest.NewServer(d.daemonCtx, d.cfg, store)

	// 6. Start background workers with the daemon context.
	sched.Start(d.daemonCtx)

	// 7. Serve agent telemetry on loopback. A busy port must not stop the desktop app.
	if d.cfg.IngestDisabled {
		log.Println("[Daemon] Agent ingest listener disabled")
	} else if err := ingestSrv.Start(); err != nil {
		log.Printf("[Daemon] Agent ingest listener unavailable: %v", err)
	}

	d.store = store
	d.sched = sched
	d.ingest = ingestSrv
	d.posture = postureSvc
	d.startTime = time.Now().UTC()
	d.started = true

	return nil
}

// applyNetworkSettings resolves the subnet to scan (EffectiveCIDR) and the own address to
// exclude from scans for the selected network mode.
func (d *Daemon) applyNetworkSettings(s *model.AppSettings) {
	switch s.NetworkMode {
	case "custom":
		if s.CustomNetworkCIDR != "" {
			s.EffectiveCIDR = s.CustomNetworkCIDR
		}
	case "interface":
		ifaces, err := netdetect.ListActiveInterfaces()
		if err == nil {
			for _, iface := range ifaces {
				if iface.Name == s.SelectedInterface {
					s.EffectiveCIDR = iface.CIDR
					s.EffectiveExcludeIP = iface.IPv4
					return
				}
			}
		}
		fallthrough
	default: // "auto"
		def, err := netdetect.DetectDefaultNetwork()
		if err == nil && def != nil {
			s.SelectedInterface = def.Name
			s.EffectiveCIDR = def.CIDR
			s.EffectiveExcludeIP = def.IPv4
			log.Printf("[Daemon] Auto-detected network: %s on %s (self IP %s)", def.CIDR, def.Name, def.IPv4)
		} else if d.cfg.NetworkCIDR != "" {
			s.EffectiveCIDR = d.cfg.NetworkCIDR
		}
	}
}

// Stop gracefully stops all background workers, drains the ingest listener, and closes storage.
func (d *Daemon) Stop(ctx context.Context) error {
	var stopErr error
	d.stopOnce.Do(func() {
		log.Println("[Daemon] Commencing graceful shutdown...")
		if d.cancel != nil {
			d.cancel()
		}

		if d.sched != nil {
			d.sched.Stop()
		}

		if d.ingest != nil {
			if err := d.ingest.Shutdown(ctx); err != nil {
				stopErr = err
			}
		}

		if d.store != nil {
			_ = d.store.Close()
		}

		close(d.errCh)
		d.started = false
		log.Println("[Daemon] Shutdown complete.")
	})
	return stopErr
}

// Errors exposes the channel receiving asynchronous fatal daemon errors.
func (d *Daemon) Errors() <-chan error {
	return d.errCh
}

// Status returns a live snapshot of the sentinel status.
func (d *Daemon) Status() model.SystemStatus {
	d.mu.Lock()
	store := d.store
	sched := d.sched
	caps := d.caps
	postureSvc := d.posture
	ingestSrv := d.ingest
	startTime := d.startTime
	d.mu.Unlock()

	if store == nil {
		return model.SystemStatus{Capabilities: caps}
	}

	totalDevs, activeDevs, totalSvcs, totalVulns, err := store.GetCounts(context.Background())
	if err != nil {
		return model.SystemStatus{Capabilities: caps}
	}

	uptimeDuration := time.Since(startTime)
	var discNext, vulnNext *time.Time
	var discRunning, vulnRunning bool
	if sched != nil {
		discNext, vulnNext, discRunning, vulnRunning = sched.GetNextRuns()
	}

	if caps == nil {
		caps = &model.Capabilities{
			NmapPath:      d.cfg.NmapPath,
			EffectiveMode: "unprivileged",
		}
	}

	status := model.SystemStatus{
		Uptime:               uptimeDuration.Round(time.Second).String(),
		UptimeSeconds:        int64(uptimeDuration.Seconds()),
		TotalDevices:         totalDevs,
		ActiveDevices:        activeDevs,
		TotalServices:        totalSvcs,
		TotalVulnerabilities: totalVulns,
		DiscoveryNextRun:     discNext,
		VulnNextRun:          vulnNext,
		IsDiscoveryRunning:   discRunning,
		IsVulnRunning:        vulnRunning,
		Capabilities:         caps,
	}

	if ingestSrv != nil && ingestSrv.Engine() != nil {
		engine := ingestSrv.Engine()
		status.IngestEventsTotal = engine.IngestEventsTotal()
		status.DetectLagMsP95 = engine.DetectLagMsP95()
		status.IncidentsOpen = engine.OpenIncidentsCount(context.Background())
	}

	if postureSvc != nil {
		if report, repErr := postureSvc.Compute(context.Background()); repErr == nil && report != nil {
			status.FleetScore = report.FleetScore
			status.PostureStatus = report.PostureStatus
		}
	}

	return status
}

// IngestAddr returns the address of the loopback agent ingest listener.
func (d *Daemon) IngestAddr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ingest != nil {
		return d.ingest.Addr()
	}
	return fmt.Sprintf("%s:%d", d.cfg.IngestHost, d.cfg.IngestPort)
}

// --- IPC Business Methods ---

// GetDevices returns all tracked devices with calculated risk scores.
func (d *Daemon) GetDevices(ctx context.Context, statusFilter string) ([]model.Device, error) {
	d.mu.Lock()
	store := d.store
	postureSvc := d.posture
	d.mu.Unlock()

	if store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	devices, err := store.GetDevices(ctx, statusFilter)
	if err != nil {
		return nil, err
	}
	if devices == nil {
		devices = []model.Device{}
	}

	if postureSvc != nil {
		report, err := postureSvc.Compute(ctx)
		if err == nil && report != nil {
			riskMap := make(map[int64]model.DevicePostureSummary, len(report.DeviceScores))
			for _, ds := range report.DeviceScores {
				riskMap[ds.DeviceID] = ds
			}
			for i := range devices {
				if ds, ok := riskMap[devices[i].ID]; ok {
					devices[i].Risk = ds.Risk
					devices[i].Score = ds.Score
				} else {
					devices[i].Risk = 0.0
					devices[i].Score = 100.0
				}
			}
		}
	}

	return devices, nil
}

// GetDeviceByID returns detailed information for a single device.
func (d *Daemon) GetDeviceByID(ctx context.Context, id int64) (*model.Device, error) {
	d.mu.Lock()
	store := d.store
	postureSvc := d.posture
	d.mu.Unlock()

	if store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	dev, err := store.GetDeviceByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, fmt.Errorf("device %d not found", id)
	}

	if postureSvc != nil {
		report, err := postureSvc.Compute(ctx)
		if err == nil && report != nil {
			for _, ds := range report.DeviceScores {
				if ds.DeviceID == dev.ID {
					dev.Risk = ds.Risk
					dev.Score = ds.Score
					break
				}
			}
		}
	}

	return dev, nil
}

// UpdateDevice updates metadata (label, criticality, notes) on a device.
func (d *Daemon) UpdateDevice(ctx context.Context, id int64, req model.UpdateDeviceRequest) (*model.Device, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	return store.UpdateDeviceFields(ctx, id, req.Label, req.Criticality, req.Notes)
}

// DeleteDevice deletes a tracked device.
func (d *Daemon) DeleteDevice(ctx context.Context, id int64) error {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return fmt.Errorf("storage not initialized")
	}

	return store.DeleteDevice(ctx, id)
}

// ClearAllDevices deletes all devices and their dependent items.
func (d *Daemon) ClearAllDevices(ctx context.Context) (int64, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return 0, fmt.Errorf("storage not initialized")
	}

	return store.ClearAllDevices(ctx)
}

// ClearScanHistory deletes all scan execution records.
func (d *Daemon) ClearScanHistory(ctx context.Context) (int64, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return 0, fmt.Errorf("storage not initialized")
	}

	return store.ClearScanHistory(ctx)
}

// DeleteService deletes a single service and its vulnerabilities.
func (d *Daemon) DeleteService(ctx context.Context, id int64) error {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return fmt.Errorf("storage not initialized")
	}

	return store.DeleteService(ctx, id)
}

// DeleteVulnerability deletes a single vulnerability finding.
func (d *Daemon) DeleteVulnerability(ctx context.Context, id int64) error {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return fmt.Errorf("storage not initialized")
	}

	return store.DeleteVulnerability(ctx, id)
}

// GetServices returns all network services detected across devices.
func (d *Daemon) GetServices(ctx context.Context) ([]model.Service, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	svcs, err := store.GetAllServices(ctx)
	if err != nil {
		return nil, err
	}
	if svcs == nil {
		svcs = []model.Service{}
	}
	return svcs, nil
}

// GetVulnerabilities returns all detected vulnerabilities.
func (d *Daemon) GetVulnerabilities(ctx context.Context, severity string) ([]model.Vulnerability, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	vulns, err := store.GetAllVulnerabilities(ctx, severity)
	if err != nil {
		return nil, err
	}
	if vulns == nil {
		vulns = []model.Vulnerability{}
	}
	return vulns, nil
}

// GetScans returns recent scan execution history.
func (d *Daemon) GetScans(ctx context.Context, limit int) ([]model.ScanLog, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}
	if limit <= 0 {
		limit = 50
	}

	scans, err := store.GetRecentScans(ctx, limit)
	if err != nil {
		return nil, err
	}
	if scans == nil {
		scans = []model.ScanLog{}
	}
	return scans, nil
}

// ScanRequestResult is the outcome of a manual scan request. It replaces the old HTTP
// 202/409/503 response: the desktop UI reads the same fields over Wails IPC.
type ScanRequestResult struct {
	Status   string `json:"status"` // "running", "conflict", "forbidden", or "unavailable"
	Message  string `json:"message,omitempty"`
	Error    string `json:"error,omitempty"`
	ScanType string `json:"scan_type"`
}

// RequestScan asks for a manual scan ("discovery" or "vulnerability") without waiting for
// it. The UI follows progress through Status() and GetScans().
func (d *Daemon) RequestScan(scanType string) ScanRequestResult {
	d.mu.Lock()
	caps := d.caps
	sched := d.sched
	d.mu.Unlock()

	if caps == nil || !caps.RawSocket || caps.EffectiveMode != "privileged" {
		// Privileged run is mandatory. Prompt elevation if not yet granted.
		if _, err := d.SetupNmapAndPrivileges(context.Background()); err != nil {
			return ScanRequestResult{
				Status:   "forbidden",
				Error:    "Privileged execution is mandatory. Grant administrator/root access to perform network scans.",
				ScanType: scanType,
			}
		}
		d.mu.Lock()
		caps = d.caps
		sched = d.sched
		d.mu.Unlock()
		if caps == nil || !caps.RawSocket || caps.EffectiveMode != "privileged" {
			return ScanRequestResult{
				Status:   "forbidden",
				Error:    "Privileged execution is mandatory. Grant administrator/root access to perform network scans.",
				ScanType: scanType,
			}
		}
	}

	if sched == nil {
		return ScanRequestResult{
			Status:   "unavailable",
			Error:    "scan scheduler is not available",
			ScanType: scanType,
		}
	}

	request, message := sched.RequestDiscovery, "Discovery scan initiated in background"
	if scanType == "vulnerability" {
		request, message = sched.RequestVulnerabilityScan, "Vulnerability audit initiated in background"
	}
	if err := request(); err != nil {
		return ScanRequestResult{
			Status:   "conflict",
			Error:    fmt.Sprintf("A %s scan is already in progress", scanType),
			ScanType: scanType,
		}
	}
	return ScanRequestResult{
		Status:   "running",
		Message:  message,
		ScanType: scanType,
	}
}

// SetScanEventEmitter registers an event handler for streaming scan lifecycle events to Wails/UI.
func (d *Daemon) SetScanEventEmitter(fn func(event string, data any)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.eventEmitter = fn
	if d.sched != nil {
		d.sched.SetEventEmitter(fn)
	}
}

// CancelScan cancels the active scanning operation.
func (d *Daemon) CancelScan() bool {
	d.mu.Lock()
	sched := d.sched
	d.mu.Unlock()
	if sched != nil {
		return sched.CancelCurrentScan()
	}
	return false
}

// GetPosture returns the live fleet posture report.
func (d *Daemon) GetPosture(ctx context.Context) (*model.PostureReport, error) {
	d.mu.Lock()
	postureSvc := d.posture
	d.mu.Unlock()

	if postureSvc == nil {
		return nil, fmt.Errorf("posture service not available")
	}

	return postureSvc.Compute(ctx)
}

// GetTimeline returns scan ticks and device periods for frontend timeline rendering.
func (d *Daemon) GetTimeline(ctx context.Context, fromStr, toStr, statusFilter string, vulnerableOnly bool) (*model.TimelineResponse, error) {
	d.mu.Lock()
	store := d.store
	d.mu.Unlock()

	if store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	to := now

	if toStr != "" {
		if parsedTo, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = parsedTo.UTC()
		}
	}
	if fromStr != "" {
		if parsedFrom, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = parsedFrom.UTC()
		} else if dur, err := time.ParseDuration(fromStr); err == nil {
			from = to.Add(-dur)
		}
	}

	return store.GetTimeline(ctx, from, to, statusFilter, vulnerableOnly)
}

// GetSettings returns active settings, detected interfaces, and capabilities.
func (d *Daemon) GetSettings(ctx context.Context) (*model.SettingsResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ifaces, _ := netdetect.ListActiveInterfaces()
	return &model.SettingsResponse{
		Settings:     d.settings,
		Interfaces:   ifaces,
		Capabilities: d.caps,
	}, nil
}

// UpdateSettings persists new settings to SQLite and hot-reloads the scanner and target CIDR.
func (d *Daemon) UpdateSettings(ctx context.Context, newSettings model.AppSettings) (*model.SettingsResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	// Apply network mode resolution
	d.applyNetworkSettings(&newSettings)
	if newSettings.EffectiveCIDR == "" {
		return nil, fmt.Errorf("no network to scan: the selected mode did not resolve to a subnet")
	}

	// Ensure privileged execution capability
	if d.caps == nil || !d.caps.RawSocket {
		if err := scanner.SetupPrivilegesOrInstall(ctx, d.cfg.NmapPath); err != nil {
			return nil, fmt.Errorf("privileged execution is mandatory: %w", err)
		}
	}
	if caps, preErr := scanner.Preflight(ctx, d.cfg, &scanner.DefaultCommandRunner{}, exec.LookPath); preErr == nil && caps != nil {
		if d.caps != nil {
			*d.caps = *caps
		} else {
			d.caps = caps
		}
		if caps.NmapPath != "" {
			d.cfg.NmapPath = caps.NmapPath
			newSettings.NmapPath = caps.NmapPath
		}
	}

	// Persist to SQLite
	if err := d.store.SaveAppSettings(ctx, newSettings); err != nil {
		return nil, fmt.Errorf("saving settings: %w", err)
	}
	d.settings = newSettings

	// Hot reload scanner parameters
	if d.scn != nil {
		if newSettings.EffectiveExcludeIP != "" {
			d.scn.SetExcludeIPs(newSettings.EffectiveExcludeIP)
		}
		d.scn.SetScanPorts(newSettings.ScanPorts)
		if d.caps != nil {
			d.scn.SetCapabilities(d.caps)
		}
	}

	if d.sched != nil {
		d.sched.SetDiscoveryTarget(newSettings.EffectiveCIDR)
		d.sched.SetIntervals(
			time.Duration(newSettings.DiscoveryIntervalSec)*time.Second,
			time.Duration(newSettings.VulnIntervalSec)*time.Second,
		)
		// Sweep the (possibly new) network now. A sweep already running is fine too.
		_ = d.sched.RequestDiscovery()
	}

	ifaces, _ := netdetect.ListActiveInterfaces()
	return &model.SettingsResponse{
		Settings:     d.settings,
		Interfaces:   ifaces,
		Capabilities: d.caps,
	}, nil
}

// SetupNmapAndPrivileges prompts the OS dialog to elevate privileges or install Nmap, then re-runs preflight.
func (d *Daemon) SetupNmapAndPrivileges(ctx context.Context) (*model.Capabilities, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nmapTarget := d.settings.NmapPath
	if nmapTarget == "" || nmapTarget == "nmap" {
		nmapTarget = d.cfg.NmapPath
	}

	err := scanner.SetupPrivilegesOrInstall(ctx, nmapTarget)
	if err != nil {
		return d.caps, err
	}

	// Re-run preflight
	caps, preErr := scanner.Preflight(ctx, d.cfg, &scanner.DefaultCommandRunner{}, exec.LookPath)
	if preErr == nil && caps != nil {
		if d.caps != nil {
			*d.caps = *caps
		} else {
			d.caps = caps
		}
		if caps.NmapPath != "" {
			d.cfg.NmapPath = caps.NmapPath
			d.settings.NmapPath = caps.NmapPath
		}
		if caps.RawSocket {
			d.caps.EffectiveMode = "privileged"
		}
		if d.store != nil {
			_ = d.store.SaveAppSettings(ctx, d.settings)
		}
		if d.scn != nil {
			d.scn.SetCapabilities(d.caps)
		}
		if d.sched != nil {
			_ = d.sched.RequestDiscovery()
		}
	}
	return d.caps, preErr
}

// Tracker returns the active users tracker instance managed by the scheduler.
func (d *Daemon) Tracker() *tracker.Tracker {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sched != nil {
		return d.sched.Tracker()
	}
	return nil
}
