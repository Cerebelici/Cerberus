package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/api"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/discovery"
	"github.com/gr0gu/cerberus/internal/logstream"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/netdetect"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
	"github.com/gr0gu/cerberus/internal/tracker"
)

// Daemon manages the unified lifecycle of Cerberus Sentinel workers, storage, and HTTP server.
type Daemon struct {
	cfg       *config.Config
	store     *storage.Storage
	sched     *scheduler.Scheduler
	scn       *scanner.Scanner
	srv       *api.Server
	logs      *logstream.Buffer
	caps      *model.Capabilities
	settings  model.AppSettings
	daemonCtx context.Context
	cancel    context.CancelFunc
	stopOnce  sync.Once
	errCh     chan error
	ln           net.Listener
	eventEmitter func(event string, data any)
	mu           sync.Mutex
	started      bool
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

// Start boots preflight, storage, scheduler, and optionally the HTTP server.
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

	// 4. Initialize scanner, scheduler, and API server
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
	srv := api.NewServer(d.cfg, store, sched, caps)
	sched.SetPostureService(srv.PostureService())
	srv.SetLogs(d.logs)
	srv.SetSettingsProvider(d)

	// 5. Bind the HTTP listener before any worker starts, so a busy port fails fast instead of
	// leaving scans (and their nmap processes) running after Start returned an error.
	var ln net.Listener
	if !d.cfg.DisableHTTPServer {
		addr := fmt.Sprintf("%s:%d", d.cfg.ServerHost, d.cfg.ServerPort)
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			_ = store.Close()
			return fmt.Errorf("binding server address %s: %w", addr, err)
		}
	}

	// 6. Establish independent daemon execution context
	d.daemonCtx, d.cancel = context.WithCancel(context.Background())

	// 7. Start background workers with daemon context
	sched.Start(d.daemonCtx)

	// 8. Serve HTTP requests only if not explicitly disabled (e.g. desktop IPC mode)
	if ln != nil {
		d.ln = ln
		go func() {
			if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
				select {
				case d.errCh <- serveErr:
				default:
				}
			}
		}()
		log.Printf("[Daemon] Started Cerberus Sentinel HTTP listener on %s", ln.Addr().String())
	} else {
		log.Println("[Daemon] HTTP listener disabled (pure IPC desktop mode)")
	}

	d.store = store
	d.sched = sched
	d.srv = srv
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

// Stop gracefully stops all background workers, drains the HTTP server, and closes storage.
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

		if d.srv != nil {
			if err := d.srv.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
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
	srv := d.srv
	d.mu.Unlock()

	if srv != nil {
		st, err := srv.GetStatus(context.Background())
		if err == nil {
			return st
		}
	}
	return model.SystemStatus{
		Capabilities: d.caps,
	}
}

// ServerAddr returns the network address the daemon is listening on.
func (d *Daemon) ServerAddr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln != nil {
		return d.ln.Addr().String()
	}
	return fmt.Sprintf("%s:%d", d.cfg.ServerHost, d.cfg.ServerPort)
}

// Port returns the listening port number, or 0 if not listening.
func (d *Daemon) Port() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln != nil {
		if tcpAddr, ok := d.ln.Addr().(*net.TCPAddr); ok {
			return tcpAddr.Port
		}
	}
	return d.cfg.ServerPort
}

// --- IPC Business Methods ---

// GetDevices returns all tracked devices with calculated risk scores.
func (d *Daemon) GetDevices(ctx context.Context, statusFilter string) ([]model.Device, error) {
	d.mu.Lock()
	store := d.store
	srv := d.srv
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

	if srv != nil && srv.PostureService() != nil {
		report, err := srv.PostureService().Compute(ctx)
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
	srv := d.srv
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

	if srv != nil && srv.PostureService() != nil {
		report, err := srv.PostureService().Compute(ctx)
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

// RequestScan asks for a manual scan ("discovery" or "vulnerability") without waiting for
// it. The result matches POST /api/scans/{type}/trigger: 202 accepted, 409 when a scan of
// that type is already in progress, 503 when the scheduler is not running.
func (d *Daemon) RequestScan(scanType string) api.ManualScanResult {
	d.mu.Lock()
	caps := d.caps
	sched := d.sched
	d.mu.Unlock()

	if caps != nil && !caps.RawSocket && caps.EffectiveMode != "privileged" {
		// Privileged run is mandatory. Prompt elevation if not yet granted.
		if _, err := d.SetupNmapAndPrivileges(context.Background()); err != nil {
			return api.ManualScanResult{
				HTTPStatus: http.StatusForbidden,
				Body: map[string]string{
					"error":     "Privileged execution is mandatory. User must accept administrator privileges to perform network scans.",
					"status":    "forbidden",
					"scan_type": scanType,
				},
			}
		}
		d.mu.Lock()
		sched = d.sched
		d.mu.Unlock()
	}

	return api.RequestManualScan(sched, scanType)
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
	srv := d.srv
	d.mu.Unlock()

	if srv == nil || srv.PostureService() == nil {
		return nil, fmt.Errorf("posture service not available")
	}

	return srv.PostureService().Compute(ctx)
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
