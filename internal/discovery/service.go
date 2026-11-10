package discovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
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
//
// The first sweep after startup is a full subnet sweep. Later ticks only check the devices
// that are already known, while new devices are picked up passively from mDNS/SSDP
// announcements and the kernel neighbour table. That keeps the five-minute cadence cheap
// and avoids waking every host on the network every five minutes.
type Service struct {
	cfg         *config.Config
	storage     *storage.Storage
	scanner     *scanner.Scanner
	matcher     *identity.Matcher
	onNewDevice OnNewDeviceFunc
	lanCheck    LocalNetworkCheck
	passive     *identity.MulticastListener
	passiveOnce sync.Once

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
		passive:     identity.NewMulticastListener(),
		target:      cfg.NetworkCIDR,
	}
}

// StartPassive starts the mDNS/SSDP listeners that surface new devices between full sweeps.
// It is safe to call more than once; only the first call starts the listeners.
func (s *Service) StartPassive(ctx context.Context) {
	s.passiveOnce.Do(func() {
		s.passive.Start(ctx)
	})
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

// Run executes a full network discovery sweep, stores live hosts, and immediately
// triggers vulnerability scanning for any newly discovered host.
func (s *Service) Run(ctx context.Context) ([]model.Device, error) {
	return s.run(ctx, true)
}

// RunKnownDeviceCheck refreshes the state of known devices without sweeping the subnet.
// New devices are added only when they announce themselves (mDNS/SSDP) or appear in the
// kernel neighbour table.
func (s *Service) RunKnownDeviceCheck(ctx context.Context) ([]model.Device, error) {
	return s.run(ctx, false)
}

func (s *Service) run(ctx context.Context, fullSweep bool) ([]model.Device, error) {
	start := time.Now().UTC()
	targetSpec := s.Target()
	kind := "known-device check"
	if fullSweep {
		kind = "host discovery"
	}
	log.Printf("[Discovery] Starting %s on %s", kind, targetSpec)

	// Results and the final scan state are saved even when ctx is cancelled during
	// shutdown, so no scan stays "running" forever.
	persistCtx := context.WithoutCancel(ctx)

	// A known-device check runs every few minutes; recording it as a scan would flood the
	// history. Only full sweeps get a scan log. Device last-seen/status updates still apply.
	var scanLog *model.ScanLog
	var err error
	if fullSweep {
		scanLog, err = s.storage.CreateScanLog(ctx, &model.ScanLog{
			ScanType:   "discovery",
			Status:     "running",
			TargetSpec: targetSpec,
		})
		if err != nil {
			log.Printf("[Discovery] Failed to create scan log: %v", err)
		}
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

	var devices []model.Device
	if fullSweep {
		devices, err = s.scanner.RunDiscoveryScan(ctx, targetSpec)
		if err != nil {
			return nil, fail(err)
		}
		// Merge passive announcements before resolving names so new mDNS devices get a
		// hostname in the same pass.
		devices = s.mergePassiveCandidates(ctx, devices, targetSpec)
		resolveNames(ctx, devices)
	} else {
		devices, err = s.monitorKnownDevices(ctx, targetSpec)
		if err != nil {
			return nil, fail(err)
		}
		devices = s.mergePassiveCandidates(ctx, devices, targetSpec)
	}

	duration := time.Since(start).Milliseconds()

	observedIDs, newDevicesCount := s.persist(ctx, scanLog, devices, start)

	// Mark missing devices as down. A full sweep also records timeline rows; a routine
	// known-device check (scanLog == nil) only updates the device state.
	scanID := int64(0)
	if scanLog != nil {
		scanID = scanLog.ID
	}
	if err := s.storage.MarkMissingDevicesDown(persistCtx, scanID, observedIDs, start); err != nil {
		log.Printf("[Discovery] Error updating missing devices: %v", err)
	}

	log.Printf("[Discovery] Completed %s. Observed %d live hosts (%d new) in %dms",
		kind, len(devices), newDevicesCount, duration)

	if scanLog != nil {
		scanLog.Status = "completed"
		scanLog.HostsFound = len(devices)
		scanLog.DurationMs = duration
		_ = s.storage.UpdateScanLog(persistCtx, scanLog)
	}

	return devices, nil
}

// monitorKnownDevices probes only addresses that are already in the database. It returns
// an empty slice when the database has no devices yet; the scheduler treats that as a cold
// start and performs a full sweep instead.
func (s *Service) monitorKnownDevices(ctx context.Context, targetSpec string) ([]model.Device, error) {
	known, err := s.storage.GetDevices(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("loading known devices: %w", err)
	}
	if len(known) == 0 {
		devices, sweepErr := s.scanner.RunDiscoveryScan(ctx, targetSpec)
		if sweepErr != nil {
			return nil, sweepErr
		}
		resolveNames(ctx, devices)
		return devices, nil
	}

	// Check every device that is currently up, plus recently seen devices that may have
	// come back. Very old inventory entries are left alone so the five-minute check stays
	// cheap on installations with a long history.
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	byIP := make(map[string]model.Device, len(known))
	ips := make([]string, 0, len(known))
	for _, dev := range known {
		if dev.CurrentIP == "" {
			continue
		}
		if dev.Status != "up" && dev.LastSeen.Before(cutoff) {
			continue
		}
		byIP[dev.CurrentIP] = dev
		ips = append(ips, dev.CurrentIP)
	}

	observed := s.scanner.ProbeKnownDevices(ctx, ips)
	for i := range observed {
		if dev, ok := byIP[observed[i].IP]; ok {
			if observed[i].MAC == "" {
				observed[i].MAC = dev.MAC
			}
			if observed[i].Hostname == "" {
				observed[i].Hostname = dev.Hostname
			}
			if observed[i].Vendor == "" {
				observed[i].Vendor = dev.Vendor
			}
		}
		observed[i].Status = "up"
	}

	// A known device that renews its DHCP lease may appear at a new address. The
	// neighbour table still carries its MAC, so let the identity matcher merge it.
	neighbors, _ := scanner.ReadNeighborTable(ctx)
	for _, n := range neighbors {
		if _, already := byIP[n.IP]; already {
			continue
		}
		for _, dev := range known {
			if dev.MAC != "" && dev.MAC == n.MAC {
				observed = append(observed, model.Device{
					IP:     n.IP,
					MAC:    n.MAC,
					Status: "up",
				})
				break
			}
		}
	}

	return observed, nil
}

// mergePassiveCandidates adds devices seen in mDNS/SSDP or the neighbour table that were
// not part of the active sweep. It never adds excluded addresses or hosts outside the
// configured target.
func (s *Service) mergePassiveCandidates(ctx context.Context, devices []model.Device, targetSpec string) []model.Device {
	prefix, ok := targetPrefix(targetSpec)
	if !ok {
		return devices
	}

	excluded := make(map[string]bool)
	if s.scanner != nil {
		for _, ip := range s.scanner.ExcludedIPs() {
			excluded[ip] = true
		}
	}
	excluded[prefix.Addr().String()] = true
	if prefix.Bits() <= 30 {
		excluded[lastAddr(prefix).String()] = true
	}

	neighbors, _ := scanner.ReadNeighborTable(ctx)
	var passive map[string]string
	if s.passive != nil {
		passive = s.passive.GetDiscovered()
	}

	return mergePassiveDevices(devices, neighbors, passive, prefix, excluded)
}

// mergePassiveDevices adds neighbour-table and multicast announcements that the active
// sweep did not report. It is kept free of I/O so the filtering rules can be tested.
func mergePassiveDevices(devices []model.Device, neighbors []scanner.Neighbor, passive map[string]string, prefix netip.Prefix, excluded map[string]bool) []model.Device {
	index := make(map[string]bool, len(devices))
	for _, dev := range devices {
		index[dev.IP] = true
	}

	add := func(ip, mac, name string) {
		if ip == "" || excluded[ip] || index[ip] {
			return
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !prefix.Contains(addr) || addr.IsMulticast() || addr.IsLoopback() {
			return
		}
		index[ip] = true
		devices = append(devices, model.Device{
			IP:       ip,
			MAC:      mac,
			Hostname: name,
			Status:   "up",
		})
	}

	for _, n := range neighbors {
		add(n.IP, n.MAC, "")
	}
	for ip, name := range passive {
		add(ip, "", name)
	}

	return devices
}

// persist stores observations and reports how many devices were observed and how many were
// newly created. The caller uses the observed IDs to mark everything else down.
func (s *Service) persist(ctx context.Context, scanLog *model.ScanLog, devices []model.Device, start time.Time) ([]int64, int) {
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
		dec, err := s.matcher.Resolve(ctx, obs)
		if err != nil {
			log.Printf("[Discovery] Error resolving identity for %s: %v", devices[i].IP, err)
			continue
		}

		savedDev, err := s.storage.ApplyDecision(ctx, dec, obs)
		if err != nil {
			log.Printf("[Discovery] Error applying decision for %s: %v", devices[i].IP, err)
			continue
		}

		observedIDs = append(observedIDs, savedDev.ID)

		// Record point-in-time observation for live device
		if scanLog != nil {
			isVuln, vulnsCount, maxSev, _ := s.storage.GetDeviceSecurityPosture(ctx, savedDev.ID)
			_ = s.storage.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
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
				s.onNewDevice(savedDev.CurrentIP)
			}
		}
	}

	return observedIDs, newDevicesCount
}

func targetPrefix(target string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(target); err == nil && p.Addr().Is4() {
		return p.Masked(), true
	}
	if addr, err := netip.ParseAddr(target); err == nil && addr.Is4() {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	a := prefix.Addr().As4()
	hostBits := 32 - prefix.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (uint32(1) << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
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
