package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/discovery"
	"github.com/gr0gu/cerberus/internal/identity"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/posture"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/storage"
	"github.com/gr0gu/cerberus/internal/tracker"
)

// ErrScanInProgress is returned when a scan of the requested type is already running or queued.
var ErrScanInProgress = errors.New("scan already in progress")

// Scheduler manages independent goroutines for network discovery and vulnerability analysis.
// Discovery and vulnerability work is serialized through scanGate so only one scan pipeline
// (nmap/RustScan/raw sockets) runs at a time.
type Scheduler struct {
	cfg              *config.Config
	storage          *storage.Storage
	scanner          *scanner.Scanner
	discoveryService *discovery.Service
	matcher          *identity.Matcher
	postureService   *posture.Service
	tracker          *tracker.Tracker

	// Concurrency and scheduling
	wg              sync.WaitGroup
	immediateVulnCh chan string
	activeTargets   sync.Map // IP -> bool
	// scanGate is a one-slot semaphore held for the duration of a discovery sweep or a
	// vulnerability audit. Immediate scans wait for it instead of running concurrently.
	scanGate chan struct{}

	discoveryRunning atomic.Bool
	vulnRunning      atomic.Bool
	discoveryQueued  atomic.Bool
	vulnQueued       atomic.Bool
	immediateActive  atomic.Int32

	discoveryNextRun  time.Time
	vulnNextRun       time.Time
	discoveryInterval time.Duration
	vulnInterval      time.Duration
	mu                sync.RWMutex

	manualDiscoveryCh chan chan error
	manualVulnCh      chan chan error
	discoveryResetCh  chan struct{}
	vulnResetCh       chan struct{}

	eventEmitter     func(event string, data any)
	eventMu          sync.RWMutex
	scanCancelMu     sync.Mutex
	activeScanCancel context.CancelFunc
}

// New creates a new Scheduler.
func New(cfg *config.Config, store *storage.Storage, scn *scanner.Scanner) *Scheduler {
	s := &Scheduler{
		cfg:               cfg,
		storage:           store,
		scanner:           scn,
		matcher:           identity.NewMatcher(store, identity.DefaultWeights(), time.Now),
		postureService:    posture.NewService(store, posture.DefaultPolicy),
		tracker:           tracker.New(cfg, store),
		immediateVulnCh:   make(chan string, 100),
		manualDiscoveryCh: make(chan chan error, 5),
		manualVulnCh:      make(chan chan error, 5),
		discoveryResetCh:  make(chan struct{}, 1),
		vulnResetCh:       make(chan struct{}, 1),
		scanGate:          make(chan struct{}, 1),
		discoveryInterval: cfg.DiscoveryInterval,
		vulnInterval:      cfg.VulnerabilityInterval,
	}

	// Wire discovery service to push new devices to immediateVulnCh
	s.discoveryService = discovery.New(cfg, store, scn, s.EnqueueImmediateScan)
	s.storage.SetDiscoveryInterval(cfg.DiscoveryInterval)

	return s
}

// SetLocalNetworkCheck sets the check that runs before every discovery sweep.
func (s *Scheduler) SetLocalNetworkCheck(check discovery.LocalNetworkCheck) {
	s.discoveryService.SetLocalNetworkCheck(check)
}

// SetDiscoveryTarget changes the subnet (CIDR) or address that discovery sweeps scan.
func (s *Scheduler) SetDiscoveryTarget(target string) {
	s.discoveryService.SetTarget(target)
}

// DiscoveryTarget returns the subnet (CIDR) or address that discovery sweeps scan.
func (s *Scheduler) DiscoveryTarget() string {
	return s.discoveryService.Target()
}

// SetIntervals changes how often the periodic scans run. A worker whose interval changed
// restarts its timer at once, so its next run is one new interval from now.
func (s *Scheduler) SetIntervals(discoveryEvery, vulnEvery time.Duration) {
	var changed []chan struct{}
	s.mu.Lock()
	if discoveryEvery > 0 && discoveryEvery != s.discoveryInterval {
		s.discoveryInterval = discoveryEvery
		changed = append(changed, s.discoveryResetCh)
	}
	if vulnEvery > 0 && vulnEvery != s.vulnInterval {
		s.vulnInterval = vulnEvery
		changed = append(changed, s.vulnResetCh)
	}
	disc := s.discoveryInterval
	s.mu.Unlock()

	s.storage.SetDiscoveryInterval(disc)
	for _, ch := range changed {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Intervals returns the current periodic discovery and vulnerability scan intervals.
func (s *Scheduler) Intervals() (discoveryEvery, vulnEvery time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.discoveryInterval, s.vulnInterval
}

// SetPostureService assigns or overrides the posture evaluation service.
func (s *Scheduler) SetPostureService(svc *posture.Service) {
	s.postureService = svc
}

// EnqueueImmediateScan queues a target IP for an immediate on-demand vulnerability scan.
func (s *Scheduler) EnqueueImmediateScan(ip string) {
	select {
	case s.immediateVulnCh <- ip:
		log.Printf("[Scheduler] Enqueued immediate vuln scan for %s", ip)
	default:
		log.Printf("[Scheduler] Immediate scan queue full, dropping %s", ip)
	}
}

// Start boots the background goroutines:
// 1. Discovery Worker: one full sweep at startup, then cheap known-device checks
// (configured interval, default 5 minutes)
// 2. Periodic Vulnerability Worker (configured interval, default 20 minutes)
// 3. Immediate Reactive Vulnerability Worker (event-driven queue)
// 4. Daily Retention Worker (90-day retention)
// 5. Hourly Posture Snapshot Worker
// 6. Daily Active Users Tracking Worker (24 hours)
func (s *Scheduler) Start(ctx context.Context) {
	discEvery, vulnEvery := s.Intervals()
	log.Printf("[Scheduler] Starting background engines (Discovery: %v, Vulnerability: %v)",
		discEvery, vulnEvery)
	if !s.scanner.CanScan() {
		log.Println("[Scheduler] WARNING: privileged execution is not available; scans stay idle until the user grants administrator/root rights")
	}
	s.discoveryService.StartPassive(ctx)

	s.wg.Add(6)
	go s.runDiscoveryWorker(ctx)
	go s.runPeriodicVulnWorker(ctx)
	go s.runImmediateVulnWorker(ctx)
	go s.runRetentionWorker(ctx)
	go s.runPostureWorker(ctx)
	go s.runTrackingWorker(ctx)
}

// Stop waits for all background goroutines to cleanly finish.
func (s *Scheduler) Stop() {
	s.wg.Wait()
	log.Println("[Scheduler] All workers safely stopped.")
}

// -------------------------------------------------------------
// Goroutine 1: Network Discovery (Configured Interval + Manual)
// -------------------------------------------------------------
func (s *Scheduler) runDiscoveryWorker(ctx context.Context) {
	defer s.wg.Done()

	interval, _ := s.Intervals()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// The first run is a full subnet sweep. Later ticks only refresh known devices and
	// listen for passive announcements, so the network is not woken every five minutes.
	s.setNextDiscoveryRun(time.Now().Add(interval))
	s.executeDiscovery(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Discovery Worker] Shutting down.")
			return

		case <-s.discoveryResetCh:
			interval, _ = s.Intervals()
			ticker.Reset(interval)
			s.setNextDiscoveryRun(time.Now().Add(interval))

		case <-ticker.C:
			s.setNextDiscoveryRun(time.Now().Add(interval))
			s.executeKnownDeviceCheck(ctx)

		case respCh := <-s.manualDiscoveryCh:
			err := s.executeDiscovery(ctx)
			s.discoveryQueued.Store(false)
			respCh <- err
		}
	}
}

// SetEventEmitter registers a callback for streaming scan lifecycle events.
func (s *Scheduler) SetEventEmitter(fn func(event string, data any)) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	s.eventEmitter = fn
}

// EmitEvent dispatches a scan event to registered listeners.
func (s *Scheduler) EmitEvent(event string, data any) {
	s.eventMu.RLock()
	fn := s.eventEmitter
	s.eventMu.RUnlock()
	if fn != nil {
		fn(event, data)
	}
}

// CancelCurrentScan aborts any active scan execution context.
func (s *Scheduler) CancelCurrentScan() bool {
	s.scanCancelMu.Lock()
	defer s.scanCancelMu.Unlock()
	if s.activeScanCancel != nil {
		s.activeScanCancel()
		s.activeScanCancel = nil
		return true
	}
	return false
}

func (s *Scheduler) setActiveCancel(cancel context.CancelFunc) {
	s.scanCancelMu.Lock()
	defer s.scanCancelMu.Unlock()
	s.activeScanCancel = cancel
}

// acquireScanGate waits until no other scan pipeline is running. The wait is cancelled
// when ctx ends, so shutdown does not leave a queued worker stuck.
func (s *Scheduler) acquireScanGate(ctx context.Context) error {
	select {
	case s.scanGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Scheduler) releaseScanGate() {
	<-s.scanGate
}

// executeDiscovery runs a full subnet sweep. It is used at startup and for manual
// requests, but not for the recurring five-minute tick.
func (s *Scheduler) executeDiscovery(ctx context.Context) error {
	return s.executeDiscoveryMode(ctx, true)
}

// executeKnownDeviceCheck refreshes known devices and harvests passive announcements.
func (s *Scheduler) executeKnownDeviceCheck(ctx context.Context) error {
	return s.executeDiscoveryMode(ctx, false)
}

func (s *Scheduler) executeDiscoveryMode(ctx context.Context, fullSweep bool) error {
	if !s.scanner.CanScan() {
		log.Println("[Discovery Worker] Skipping scan: privileged execution is required")
		return scanner.ErrPrivilegedRequired
	}
	if !s.discoveryRunning.CompareAndSwap(false, true) {
		log.Println("[Discovery Worker] Scan already in progress, skipping.")
		return fmt.Errorf("discovery scan already in progress")
	}
	defer s.discoveryRunning.Store(false)

	if err := s.acquireScanGate(ctx); err != nil {
		return err
	}
	defer s.releaseScanGate()

	scanCtx, cancel := context.WithCancel(ctx)
	s.setActiveCancel(cancel)
	defer func() {
		s.setActiveCancel(nil)
		cancel()
	}()

	s.EmitEvent("scan:stage_changed", "Stage 1: L2 Mapping")
	var devices []model.Device
	var err error
	if fullSweep {
		devices, err = s.discoveryService.Run(scanCtx)
	} else {
		devices, err = s.discoveryService.RunKnownDeviceCheck(scanCtx)
	}
	if err == nil {
		for _, d := range devices {
			s.EmitEvent("scan:host_discovered", map[string]string{
				"ip":  d.IP,
				"mac": d.MAC,
			})
			if d.Hostname != "" {
				s.EmitEvent("scan:identity_updated", map[string]string{
					"ip":       d.IP,
					"hostname": d.Hostname,
					"vendor":   d.Vendor,
				})
			}
		}
		s.EmitEvent("scan:completed", map[string]any{
			"type":    "discovery",
			"devices": len(devices),
		})
	}
	return err
}

// -------------------------------------------------------------
// Goroutine 2: Periodic Vulnerability Audit (Configured Interval + Manual)
// -------------------------------------------------------------
func (s *Scheduler) runPeriodicVulnWorker(ctx context.Context) {
	defer s.wg.Done()

	_, interval := s.Intervals()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.setNextVulnRun(time.Now().Add(interval))

	for {
		select {
		case <-ctx.Done():
			log.Println("[Vuln Worker] Shutting down periodic scanner.")
			return

		case <-s.vulnResetCh:
			_, interval = s.Intervals()
			ticker.Reset(interval)
			s.setNextVulnRun(time.Now().Add(interval))

		case <-ticker.C:
			s.setNextVulnRun(time.Now().Add(interval))
			s.executePeriodicVulnScan(ctx)

		case respCh := <-s.manualVulnCh:
			err := s.executePeriodicVulnScan(ctx)
			s.vulnQueued.Store(false)
			respCh <- err
		}
	}
}

func (s *Scheduler) executePeriodicVulnScan(ctx context.Context) error {
	if !s.vulnRunning.CompareAndSwap(false, true) {
		log.Println("[Vuln Worker] Periodic vuln scan already running, skipping.")
		return fmt.Errorf("vulnerability scan already running")
	}
	defer s.vulnRunning.Store(false)

	targets, err := s.storage.GetActiveDeviceIPs(ctx)
	if err != nil {
		log.Printf("[Vuln Worker] Failed to get active targets: %v", err)
		return err
	}

	if len(targets) == 0 {
		log.Println("[Vuln Worker] No active devices found in database to audit.")
		return nil
	}

	log.Printf("[Vuln Worker] Starting periodic vulnerability audit on %d active devices: %v",
		len(targets), targets)

	scanCtx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
	defer cancel()

	return s.scanTargets(scanCtx, targets, "vulnerability")
}

// -------------------------------------------------------------
// Goroutine 3: Immediate Reactive Vulnerability Worker
// -------------------------------------------------------------
func (s *Scheduler) runImmediateVulnWorker(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Immediate Vuln Worker] Shutting down.")
			return

		case ip := <-s.immediateVulnCh:
			// Ensure deduplication so we don't scan the target if already active
			if _, loaded := s.activeTargets.LoadOrStore(ip, true); loaded {
				log.Printf("[Immediate Vuln Worker] Target %s already being scanned, skipping duplicate.", ip)
				continue
			}

			log.Printf("[Immediate Vuln Worker] Launching immediate scan on newly discovered host %s", ip)
			func(targetIP string) {
				s.immediateActive.Add(1)
				defer s.immediateActive.Add(-1)
				defer s.activeTargets.Delete(targetIP)
				// Allow newly booted endpoints a short window to finish binding ports
				if s.cfg != nil && s.cfg.ImmediateScanDelay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(s.cfg.ImmediateScanDelay):
					}
				}

				// Create an execution context bounded by ScanTimeout
				scanCtx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
				defer cancel()

				if err := s.scanTargets(scanCtx, []string{targetIP}, "immediate"); err != nil {
					log.Printf("[Immediate Vuln Worker] Scan error on %s: %v", targetIP, err)
				}
			}(ip)
		}
	}
}

// -------------------------------------------------------------
// Target Scanner Execution & DB Persistence
// -------------------------------------------------------------
func (s *Scheduler) scanTargets(ctx context.Context, targets []string, scanType string) error {
	// Deduplicate target IPs so a single scan never probes the same IP multiple times
	seenTargets := make(map[string]bool, len(targets))
	dedupedTargets := make([]string, 0, len(targets))
	for _, t := range targets {
		if t != "" && !seenTargets[t] {
			seenTargets[t] = true
			dedupedTargets = append(dedupedTargets, t)
		}
	}
	targets = dedupedTargets
	if len(targets) == 0 {
		return nil
	}

	if !s.scanner.CanScan() {
		return scanner.ErrPrivilegedRequired
	}

	if err := s.acquireScanGate(ctx); err != nil {
		return err
	}
	defer s.releaseScanGate()

	start := time.Now()
	targetSpec := strings.Join(targets, ", ")
	// Results and the final scan state are saved even when ctx is cancelled during
	// shutdown, so no scan stays "running" forever.
	persistCtx := context.WithoutCancel(ctx)

	scanLog, err := s.storage.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   scanType,
		Status:     "running",
		TargetSpec: targetSpec,
	})
	if err != nil {
		log.Printf("[%s Scan] Failed to create scan log: %v", scanType, err)
	}

	scanCtx, cancel := context.WithCancel(ctx)
	s.setActiveCancel(cancel)
	defer func() {
		s.setActiveCancel(nil)
		cancel()
	}()

	s.EmitEvent("scan:stage_changed", "Stage 2: Port Sweep")
	results, scanErr := s.scanner.RunVulnerabilityScan(scanCtx, targets)
	duration := time.Since(start).Milliseconds()

	if scanErr != nil {
		message := scanner.DescribeScanError(ctx, scanErr)
		log.Printf("[%s Scan] Scan error: %s", scanType, message)
		if scanLog != nil {
			scanLog.Status = "failed"
			scanLog.ErrorMessage = message
			scanLog.DurationMs = duration
			_ = s.storage.UpdateScanLog(persistCtx, scanLog)
		}
		return scanErr
	}
	s.EmitEvent("scan:stage_changed", "Stage 3: Deep Audit")

	discovery.ResolveAll(persistCtx, len(results),
		func(i int) (string, string, string, string) {
			return results[i].IP, results[i].Hostname, results[i].Vendor, results[i].MAC
		},
		func(i int, host, vendor string) {
			if host != "" {
				results[i].Hostname = host
			}
			if vendor != "" {
				results[i].Vendor = vendor
			}
		})

	totalVulnsFound := 0
	for _, res := range results {
		var observedPorts []int
		for _, svc := range res.Services {
			if svc.State == "open" || svc.State == "" {
				observedPorts = append(observedPorts, svc.Port)
			}
		}

		// Skip phantom targets if 0 ports are open and no MAC was observed on the link
		if len(observedPorts) == 0 && res.MAC == "" {
			continue
		}

		portProfile, _ := identity.PortProfile(res.Services)
		obs := identity.Observation{
			IP:           res.IP,
			MAC:          res.MAC,
			Hostname:     res.Hostname,
			Vendor:       res.Vendor,
			Ports:        portProfile,
			Fingerprints: res.Fingerprints,
			ObservedAt:   start,
		}
		dec, err := s.matcher.Resolve(persistCtx, obs)
		if err != nil {
			log.Printf("[%s Scan] Error resolving identity for %s: %v", scanType, res.IP, err)
			continue
		}

		err = s.storage.WithTx(persistCtx, func(tx *storage.Tx) error {
			ctx := persistCtx
			dev, err := tx.ApplyDecision(ctx, dec, obs)
			if err != nil {
				return fmt.Errorf("applying decision for %s: %w", res.IP, err)
			}
			if dev == nil {
				return nil
			}

			// Save Services
			for _, svc := range res.Services {
				svc.DeviceID = dev.ID
				if _, err := tx.UpsertService(ctx, &svc); err != nil {
					log.Printf("[%s Scan] Error saving service %d for %s: %v", scanType, svc.Port, res.IP, err)
				}
			}

			// Save Vulnerabilities
			for _, vuln := range res.Vulnerabilities {
				vuln.DeviceID = dev.ID
				if _, _, err := tx.UpsertVulnerability(ctx, &vuln); err != nil {
					log.Printf("[%s Scan] Error saving vuln %s for %s: %v", scanType, vuln.CVEID, res.IP, err)
				} else {
					totalVulnsFound++
				}
			}

			hostStatus := res.Status
			if hostStatus == "" {
				hostStatus = "up"
			}

			// Reconcile host findings if host is up
			if hostStatus == "up" {
				if err := tx.ReconcileHostFindings(ctx, dev.ID, start.UTC(), observedPorts); err != nil {
					log.Printf("[%s Scan] Error reconciling host findings for %s: %v", scanType, res.IP, err)
				}
			}

			// Record point-in-time observation with newly evaluated vulnerability posture
			if scanLog != nil {
				isVuln, vulnsCount, maxSev, _ := tx.GetDeviceSecurityPosture(ctx, dev.ID)
				_ = tx.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
					DeviceID:     dev.ID,
					ScanID:       scanLog.ID,
					Status:       hostStatus,
					IsVulnerable: isVuln,
					VulnsCount:   vulnsCount,
					MaxSeverity:  maxSev,
					RecordedAt:   time.Now().UTC(),
				})
			}
			return nil
		})
		if err != nil {
			log.Printf("[%s Scan] Error persisting host %s: %v", scanType, res.IP, err)
		}
	}

	log.Printf("[%s Scan] Finished for %d hosts. Found %d vulnerabilities in %dms",
		scanType, len(results), totalVulnsFound, duration)

	if scanLog != nil {
		scanLog.Status = "completed"
		scanLog.HostsFound = len(results)
		scanLog.VulnsFound = totalVulnsFound
		scanLog.DurationMs = duration
		_ = s.storage.UpdateScanLog(persistCtx, scanLog)
	}

	if s.postureService != nil {
		if _, snapErr := s.postureService.Snapshot(persistCtx); snapErr != nil {
			log.Printf("[%s Scan] Error creating posture snapshot: %v", scanType, snapErr)
		}
	}

	s.EmitEvent("scan:completed", map[string]any{
		"type":        scanType,
		"results":     len(results),
		"duration_ms": duration,
	})

	return nil
}

// -------------------------------------------------------------
// Control & Status Methods
// -------------------------------------------------------------

// RequestDiscovery queues an on-demand discovery scan and returns at once. It returns
// ErrScanInProgress when a discovery scan is already running or queued.
func (s *Scheduler) RequestDiscovery() error {
	if s.discoveryRunning.Load() || !s.discoveryQueued.CompareAndSwap(false, true) {
		return ErrScanInProgress
	}
	select {
	case s.manualDiscoveryCh <- make(chan error, 1):
		return nil
	default:
		s.discoveryQueued.Store(false)
		return ErrScanInProgress
	}
}

// RequestVulnerabilityScan queues an on-demand vulnerability scan of all active devices and
// returns at once. It returns ErrScanInProgress when a vulnerability scan is already
// running or queued.
func (s *Scheduler) RequestVulnerabilityScan() error {
	if s.isVulnScanActive() || !s.vulnQueued.CompareAndSwap(false, true) {
		return ErrScanInProgress
	}
	select {
	case s.manualVulnCh <- make(chan error, 1):
		return nil
	default:
		s.vulnQueued.Store(false)
		return ErrScanInProgress
	}
}

func (s *Scheduler) isVulnScanActive() bool {
	return s.vulnRunning.Load() || s.immediateActive.Load() > 0
}

// TriggerDiscovery requests an on-demand discovery scan.
func (s *Scheduler) TriggerDiscovery(ctx context.Context) error {
	respCh := make(chan error, 1)
	select {
	case s.manualDiscoveryCh <- respCh:
		select {
		case err := <-respCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("manual discovery request queue busy")
	}
}

// TriggerVulnerabilityScan requests an on-demand vulnerability scan across all active devices.
func (s *Scheduler) TriggerVulnerabilityScan(ctx context.Context) error {
	respCh := make(chan error, 1)
	select {
	case s.manualVulnCh <- respCh:
		select {
		case err := <-respCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("manual vulnerability request queue busy")
	}
}

func (s *Scheduler) setNextDiscoveryRun(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discoveryNextRun = t
}

func (s *Scheduler) setNextVulnRun(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulnNextRun = t
}

// GetNextRuns returns next scheduled execution times and active flags.
func (s *Scheduler) GetNextRuns() (discTime, vulnTime *time.Time, discRunning, vulnRunning bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var dt, vt *time.Time
	if !s.discoveryNextRun.IsZero() {
		copyDt := s.discoveryNextRun
		dt = &copyDt
	}
	if !s.vulnNextRun.IsZero() {
		copyVt := s.vulnNextRun
		vt = &copyVt
	}

	// Queued manual requests count as running so the UI never shows "idle" between the
	// request and the worker picking it up. Immediate audits of new hosts are vulnerability
	// scans too.
	discRunning = s.discoveryRunning.Load() || s.discoveryQueued.Load()
	vulnRunning = s.isVulnScanActive() || s.vulnQueued.Load()
	return dt, vt, discRunning, vulnRunning
}

// -------------------------------------------------------------
// Goroutine 4: Daily Retention Worker (Purge 90d data)
// -------------------------------------------------------------
func (s *Scheduler) runRetentionWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Initial purge upon startup
	recDeleted, scanDeleted, err := s.storage.PurgeOlderThan(ctx, 90*24*time.Hour, 90*24*time.Hour)
	if err != nil {
		log.Printf("[Retention Worker] Error during startup purge: %v", err)
	} else if recDeleted > 0 || scanDeleted > 0 {
		log.Printf("[Retention Worker] Startup purge removed %d records and %d scans", recDeleted, scanDeleted)
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("[Retention Worker] Shutting down.")
			return
		case <-ticker.C:
			recDeleted, scanDeleted, err := s.storage.PurgeOlderThan(ctx, 90*24*time.Hour, 90*24*time.Hour)
			if err != nil {
				log.Printf("[Retention Worker] Error during purge: %v", err)
			} else if recDeleted > 0 || scanDeleted > 0 {
				log.Printf("[Retention Worker] Purged %d records and %d scans older than 90 days", recDeleted, scanDeleted)
			}
		}
	}
}

// -------------------------------------------------------------
// Goroutine 5: Hourly Posture Snapshot Worker
// -------------------------------------------------------------
func (s *Scheduler) runPostureWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Initial snapshot on startup
	if s.postureService != nil {
		if _, err := s.postureService.Snapshot(ctx); err != nil {
			log.Printf("[Posture Worker] Startup snapshot error: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("[Posture Worker] Shutting down.")
			return
		case <-ticker.C:
			if s.postureService != nil {
				if _, err := s.postureService.Snapshot(ctx); err != nil {
					log.Printf("[Posture Worker] Hourly snapshot error: %v", err)
				}
			}
		}
	}
}

// Tracker returns the active users tracker instance.
func (s *Scheduler) Tracker() *tracker.Tracker {
	return s.tracker
}

// -------------------------------------------------------------
// Goroutine 6: Daily Active Users Tracking Worker (24h)
// -------------------------------------------------------------
func (s *Scheduler) runTrackingWorker(ctx context.Context) {
	if s.tracker != nil {
		s.tracker.Start(ctx, &s.wg)
	} else {
		s.wg.Done()
	}
}
