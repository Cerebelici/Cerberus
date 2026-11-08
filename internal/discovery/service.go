package discovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/identity"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/storage"
)

// OnNewDeviceFunc is a callback invoked whenever a new device is discovered.
type OnNewDeviceFunc func(ip string)

// LocalNetworkCheck returns an error when the OS does not let the app reach the local network.
type LocalNetworkCheck func(ctx context.Context) error

// nameResolveWorkers bounds the parallel hostname and vendor lookups after a sweep.
const nameResolveWorkers = 16

// Service coordinates network host discovery and alerts listeners to new hosts.
type Service struct {
	cfg         *config.Config
	storage     *storage.Storage
	scanner     *scanner.Scanner
	matcher     *identity.Matcher
	onNewDevice OnNewDeviceFunc
	lanCheck    LocalNetworkCheck

	targetMu sync.RWMutex
	target   string
}

// New creates a new Discovery Service.
func New(cfg *config.Config, store *storage.Storage, scn *scanner.Scanner, onNew OnNewDeviceFunc) *Service {
	return &Service{
		cfg:         cfg,
		storage:     store,
		scanner:     scn,
		matcher:     identity.NewMatcher(store, identity.DefaultWeights(), time.Now),
		onNewDevice: onNew,
		target:      cfg.NetworkCIDR,
	}
}

// SetTarget changes the subnet (CIDR) or address that the next sweeps scan.
func (s *Service) SetTarget(target string) {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	s.target = target
}

// Target returns the subnet (CIDR) or address that sweeps scan.
func (s *Service) Target() string {
	s.targetMu.RLock()
	defer s.targetMu.RUnlock()
	return s.target
}

// SetLocalNetworkCheck sets a check that runs before every sweep. When it fails, the scan
// is recorded as failed and known devices keep their state, instead of a sweep that saw
// nothing marking every device as down.
func (s *Service) SetLocalNetworkCheck(check LocalNetworkCheck) {
	s.lanCheck = check
}

// Run executes a network discovery scan, stores live hosts, and immediately
// triggers vulnerability scanning for any newly discovered host.
func (s *Service) Run(ctx context.Context) ([]model.Device, error) {
	start := time.Now().UTC()
	targetSpec := s.Target()
	log.Printf("[Discovery] Starting host discovery on %s", targetSpec)

	// Results and the final scan state are saved even when ctx is cancelled during
	// shutdown, so no scan stays "running" forever.
	persistCtx := context.WithoutCancel(ctx)

	scanLog, err := s.storage.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "discovery",
		Status:     "running",
		TargetSpec: targetSpec,
	})
	if err != nil {
		log.Printf("[Discovery] Failed to create scan log: %v", err)
	}

	fail := func(scanErr error) error {
		message := scanner.DescribeScanError(ctx, scanErr)
		log.Printf("[Discovery] Scan error: %s", message)
		if scanLog != nil {
			scanLog.Status = "failed"
			scanLog.ErrorMessage = message
			scanLog.DurationMs = time.Since(start).Milliseconds()
			_ = s.storage.UpdateScanLog(persistCtx, scanLog)
		}
		return fmt.Errorf("discovery scan failed: %w", scanErr)
	}

	if targetSpec == "" {
		return nil, fail(errors.New("no network to scan: connect to a network, or choose an interface or a custom subnet in Config"))
	}
	if s.lanCheck != nil {
		if err := s.lanCheck(ctx); err != nil {
			return nil, fail(err)
		}
	}

	devices, scanErr := s.scanner.RunDiscoveryScan(ctx, targetSpec)
	duration := time.Since(start).Milliseconds()

	if scanErr != nil {
		return nil, fail(scanErr)
	}

	resolveNames(ctx, devices)

	var newDevicesCount int
	observedIDs := make([]int64, 0, len(devices))

	for i := range devices {
		obs := identity.Observation{
			IP:           devices[i].IP,
			MAC:          devices[i].MAC,
			Hostname:     devices[i].Hostname,
			Vendor:       devices[i].Vendor,
			Fingerprints: devices[i].Fingerprints,
			ObservedAt:   start,
		}
		dec, err := s.matcher.Resolve(persistCtx, obs)
		if err != nil {
			log.Printf("[Discovery] Error resolving identity for %s: %v", devices[i].IP, err)
			continue
		}

		savedDev, err := s.storage.ApplyDecision(persistCtx, dec, obs)
		if err != nil {
			log.Printf("[Discovery] Error applying decision for %s: %v", devices[i].IP, err)
			continue
		}

		observedIDs = append(observedIDs, savedDev.ID)

		// Record point-in-time observation for live device
		if scanLog != nil {
			isVuln, vulnsCount, maxSev, _ := s.storage.GetDeviceSecurityPosture(persistCtx, savedDev.ID)
			_ = s.storage.RecordDeviceScanObservation(persistCtx, &model.DeviceScanRecord{
				DeviceID:     savedDev.ID,
				ScanID:       scanLog.ID,
				Status:       "up",
				IsVulnerable: isVuln,
				VulnsCount:   vulnsCount,
				MaxSeverity:  maxSev,
				RecordedAt:   start,
			})
		}

		if dec.Action == identity.ActionCreateNew {
			newDevicesCount++
			log.Printf("[Discovery] ⚡ NEW DEVICE DETECTED: %s (%s, %s). Triggering immediate vulnerability scan!",
				savedDev.CurrentIP, savedDev.Hostname, savedDev.Vendor)

			if s.onNewDevice != nil {
				// Immediate reactive trigger!
				s.onNewDevice(savedDev.CurrentIP)
			}
		}
	}

	// Mark missing devices as down and record their down observation
	if scanLog != nil {
		if err := s.storage.MarkMissingDevicesDown(persistCtx, scanLog.ID, observedIDs, start); err != nil {
			log.Printf("[Discovery] Error updating missing devices: %v", err)
		}
	}

	log.Printf("[Discovery] Completed. Discovered %d live hosts (%d new) in %dms",
		len(devices), newDevicesCount, duration)

	if scanLog != nil {
		scanLog.Status = "completed"
		scanLog.HostsFound = len(devices)
		scanLog.DurationMs = duration
		_ = s.storage.UpdateScanLog(persistCtx, scanLog)
	}

	return devices, nil
}

// resolveNames fills hostnames, vendors, and classifications of discovered devices.
func resolveNames(ctx context.Context, devices []model.Device) {
	if len(devices) == 0 {
		return
	}

	// 1. Multi-Channel Identity Resolver (Bonjour, NetBIOS, Router PTR, UPnP, Sleeping Mobile Heuristic)
	inputs := make([]identity.HostIdentityInput, len(devices))
	for i, d := range devices {
		inputs[i] = identity.HostIdentityInput{
			IP:             d.IP,
			MAC:            d.MAC,
			RespondedL2ARP: d.MAC != "",
			ExistingHost:   d.Hostname,
			ExistingVendor: d.Vendor,
		}
	}

	resolver := identity.NewMultiChannelResolver()
	classifications := resolver.ResolveBatch(ctx, inputs)

	for i := range devices {
		if cl, ok := classifications[devices[i].IP]; ok {
			if devices[i].Hostname == "" {
				if cl.Hostname != "" {
					devices[i].Hostname = cl.Hostname
				} else if cl.FriendlyName != "" {
					devices[i].Hostname = cl.FriendlyName
				}
			}
			if devices[i].Vendor == "" && cl.Manufacturer != "" {
				devices[i].Vendor = cl.Manufacturer
			}
			if cl.Confidence > 0 {
				devices[i].IdentityConfidence = cl.Confidence
			}
			if cl.DeviceType != "" && devices[i].Notes == "" {
				if cl.OSFamily != "" {
					devices[i].Notes = fmt.Sprintf("%s (%s)", cl.DeviceType, cl.OSFamily)
				} else {
					devices[i].Notes = cl.DeviceType
				}
			}
		}
	}

	// 2. Fallback to standard mDNS, NetBIOS, and vendor prefix database for any unresolved fields
	ResolveAll(ctx, len(devices),
		func(i int) (string, string, string, string) {
			return devices[i].IP, devices[i].Hostname, devices[i].Vendor, devices[i].MAC
		},
		func(i int, host, vendor string) {
			if host != "" && devices[i].Hostname == "" {
				devices[i].Hostname = host
			}
			if vendor != "" && devices[i].Vendor == "" {
				devices[i].Vendor = vendor
			}
		})
}

// ResolveAll runs ResolveHostnameAndVendor for n hosts in parallel. Each lookup waits for
// network answers, so doing them one host at a time would add seconds to large scans.
// get returns the ip, hostname, vendor and MAC of host i; set receives its results.
func ResolveAll(ctx context.Context, n int, get func(i int) (ip, host, vendor, mac string), set func(i int, host, vendor string)) {
	sem := make(chan struct{}, nameResolveWorkers)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		ip, host, vendor, mac := get(i)
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			resolvedHost, resolvedVendor := ResolveHostnameAndVendor(ctx, ip, host, vendor, mac)
			set(i, resolvedHost, resolvedVendor)
		}(i)
	}
	wg.Wait()
}
