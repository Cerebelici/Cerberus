package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/platform"
)

// ScanStage represents the active phase in the hybrid scanning pipeline.
type ScanStage string

const (
	Stage1L2Mapping ScanStage = "Stage 1: L2 Mapping"
	Stage2PortSweep ScanStage = "Stage 2: Port Sweep"
	Stage3DeepAudit ScanStage = "Stage 3: Deep Audit"
	StageCompleted  ScanStage = "Completed"
)

// ScanEventListener receives real-time progress callbacks from the engine.
type ScanEventListener interface {
	OnStageChanged(stage ScanStage)
	OnHostDiscovered(host Stage1Host)
	OnScanCompleted(results []model.ScanHostResult, duration time.Duration)
}

// EngineOptions configures execution parameters of the HybridEngine.
type EngineOptions struct {
	// Target is the CIDR or address used by discovery (e.g. "192.168.1.0/24").
	Target string
	// Subnet is the parsed form of Target, used for the Stage 1 L2 sweep.
	Subnet *net.IPNet
	// Targets overrides discovery for audits: the explicit host IPs to inspect.
	Targets []string
	// ExcludeIPs are never scanned or reported.
	ExcludeIPs []string

	NmapBinary string
	RustBinary string
	VulnScript string
	// Ports is the configured port scope. Empty means the full 1-65535 range.
	Ports      string
	Privileged bool
	Listener   ScanEventListener
}

// HybridEngine coordinates the Tri-Stage Hybrid Scanning Engine.
type HybridEngine struct {
	runner    CommandRunner
	neighbors NeighborSource
	mu        sync.RWMutex
}

// NewHybridEngine creates a new scanning engine instance.
func NewHybridEngine(runner CommandRunner) *HybridEngine {
	if runner == nil {
		runner = &DefaultCommandRunner{}
	}
	return &HybridEngine{
		runner:    runner,
		neighbors: ReadNeighborTable,
	}
}

// SetNeighborSource sets where the engine reads recently resolved link-layer neighbors from.
// A nil source turns the ARP merge off.
func (e *HybridEngine) SetNeighborSource(src NeighborSource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.neighbors = src
}

func (e *HybridEngine) readNeighbors(ctx context.Context) []Neighbor {
	e.mu.RLock()
	src := e.neighbors
	e.mu.RUnlock()
	if src == nil {
		return nil
	}
	neighbors, err := src(ctx)
	if err != nil {
		return nil
	}
	return neighbors
}

// Discover runs host discovery for a subnet. Stage 1 wakes sleeping devices and refreshes the
// kernel ARP cache; nmap supplies hostnames and vendor data; the ARP table fills in devices
// that answer ARP but drop every probed port.
func (e *HybridEngine) Discover(ctx context.Context, opts EngineOptions) ([]model.Device, error) {
	if opts.NmapBinary == "" {
		opts.NmapBinary = platform.ResolveNmap()
	}
	if opts.Target == "" && opts.Subnet != nil {
		opts.Target = opts.Subnet.String()
	}
	if opts.Target == "" {
		return nil, fmt.Errorf("discovery target is required")
	}

	if opts.Listener != nil {
		opts.Listener.OnStageChanged(Stage1L2Mapping)
	}
	if opts.Subnet != nil {
		// The returned hosts are intentionally not used as the discovery result: nmap
		// contributes hostnames/vendor data and can see routed hosts that ARP cannot.
		hosts, err := Stage1ARPSweep(ctx, opts.Subnet, opts.ExcludeIPs)
		if err != nil {
			log.Printf("[Scanner] Stage 1 ARP sweep warning: %v", err)
		}
		if opts.Listener != nil {
			for _, h := range hosts {
				opts.Listener.OnHostDiscovered(h)
			}
		}
	}

	args := []string{
		"-sn",
		"-T4",
		"--max-retries", "1",
		"--max-rtt-timeout", "500ms",
		"--min-parallelism", "64",
		"--host-timeout", "30s",
		"-oX", "-",
	}
	if opts.Privileged {
		args = append(args, "--privileged")
	}
	if len(opts.ExcludeIPs) > 0 {
		args = append(args, "--exclude", strings.Join(opts.ExcludeIPs, ","))
	}
	args = append(args, opts.Target)

	output, err := e.runner.Run(ctx, opts.NmapBinary, args...)
	if err != nil && !isCompleteNmapOutput(output) {
		return nil, fmt.Errorf("discovery scan failed: %w", err)
	}

	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse discovery xml: %w", parseErr)
	}

	devices := ExtractDevices(run)
	if neighbors := e.readNeighbors(ctx); len(neighbors) > 0 {
		devices = mergeNeighbors(devices, neighbors, opts.Target, opts.ExcludeIPs)
	}

	if opts.Listener != nil {
		opts.Listener.OnStageChanged(StageCompleted)
	}
	return devices, nil
}

// Audit runs the complete tri-stage pipeline for explicit target IPs:
// Stage 1 maps L2/MAC data, Stage 2 discovers open ports, and Stage 3 runs targeted
// service/vulnerability scripts against only those ports.
func (e *HybridEngine) Audit(ctx context.Context, targets []string, opts EngineOptions) ([]model.ScanHostResult, error) {
	targets = dedupeTargets(targets)
	if len(targets) == 0 {
		return nil, nil
	}
	if err := validateTargets(targets); err != nil {
		return nil, err
	}

	start := time.Now()
	if opts.NmapBinary == "" {
		opts.NmapBinary = platform.ResolveNmap()
	}
	if opts.VulnScript == "" {
		opts.VulnScript = "vulners"
	}

	if opts.Listener != nil {
		opts.Listener.OnStageChanged(Stage1L2Mapping)
	}

	macs := make(map[string]string)
	if opts.Subnet != nil {
		hosts, err := Stage1ARPSweep(ctx, opts.Subnet, opts.ExcludeIPs)
		if err != nil {
			log.Printf("[Scanner] Stage 1 ARP sweep warning: %v", err)
		}
		for _, h := range hosts {
			if h.MAC != nil {
				macs[h.IP.String()] = h.MAC.String()
			}
			if opts.Listener != nil {
				opts.Listener.OnHostDiscovered(h)
			}
		}
	}
	for _, n := range e.readNeighbors(ctx) {
		if _, ok := macs[n.IP]; !ok {
			macs[n.IP] = n.MAC
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if opts.Listener != nil {
		opts.Listener.OnStageChanged(Stage2PortSweep)
	}
	openPorts, err := e.discoverOpenPorts(ctx, targets, opts)
	if err != nil {
		return nil, fmt.Errorf("stage 2 port discovery failed: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if opts.Listener != nil {
		opts.Listener.OnStageChanged(Stage3DeepAudit)
	}
	stage3Targets := make([]Stage3Target, 0, len(targets))
	for _, ip := range targets {
		stage3Targets = append(stage3Targets, Stage3Target{
			IP:        ip,
			MAC:       macs[ip],
			OpenPorts: openPorts[ip],
		})
	}

	results, auditErr := Stage3NmapAudit(ctx, e.runner, opts.NmapBinary, opts.VulnScript, stage3Targets)
	if auditErr != nil && len(results) == 0 {
		return nil, fmt.Errorf("stage 3 audit failed: %w", auditErr)
	}
	for i := range results {
		if results[i].MAC == "" {
			results[i].MAC = macs[results[i].IP]
		}
	}

	if opts.Listener != nil {
		opts.Listener.OnStageChanged(StageCompleted)
		opts.Listener.OnScanCompleted(results, time.Since(start))
	}
	return results, nil
}

// discoverOpenPorts runs RustScan when it is available and the configured scope is
// expressible as a RustScan range/list. Everything else (missing RustScan, a failed run,
// or nmap-only scopes such as --top-ports N) uses nmap's port discovery.
func (e *HybridEngine) discoverOpenPorts(ctx context.Context, targets []string, opts EngineOptions) (map[string][]int, error) {
	rustBin := opts.RustBinary
	if rustBin == "" {
		rustBin = platform.ResolveRustScan()
	}

	ports := strings.TrimSpace(opts.Ports)
	if rustBin != "" && rustScanSupports(ports) {
		cfg := DefaultRustScanConfig()
		cfg.Binary = rustBin
		cfg.Ports = ports
		openPorts, err := Stage2RustScanWithRunner(ctx, e.runner, targets, &cfg)
		if err == nil {
			return openPorts, nil
		}
		log.Printf("[Scanner] RustScan failed, falling back to nmap: %v", err)
	}

	return e.nmapPortSweep(ctx, targets, opts)
}

// nmapPortSweep is the engine's port-discovery fallback. It is also used when the user
// configures an nmap-only scope such as --top-ports 2000.
func (e *HybridEngine) nmapPortSweep(ctx context.Context, targets []string, opts EngineOptions) (map[string][]int, error) {
	args := []string{
		"-Pn", "-T4", "--max-retries", "1", "--host-timeout", "10m", "--open", "-oX", "-",
	}
	if opts.Privileged {
		args = append(args, "--privileged")
	}
	args = append(args, portSpecArgs(opts.Ports)...)
	args = append(args, targets...)

	output, err := e.runner.Run(ctx, opts.NmapBinary, args...)
	if err != nil && !isCompleteNmapOutput(output) {
		return nil, fmt.Errorf("nmap port sweep failed: %w", err)
	}
	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse port sweep xml: %w", parseErr)
	}

	openPorts := make(map[string][]int)
	for _, host := range run.Hosts {
		var ip string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts[ip] = append(openPorts[ip], port.PortID)
			}
		}
	}
	return openPorts, nil
}

func rustScanSupports(ports string) bool {
	if ports == "" {
		return true // full 1-65535 range
	}
	lower := strings.ToLower(ports)
	if strings.HasPrefix(lower, "--top-ports") || strings.Contains(ports, " ") {
		return false
	}
	// A single range or a comma-separated list of individual ports is supported.
	if _, _, ok := parsePortRange(ports); ok {
		return true
	}
	for _, part := range strings.Split(ports, ",") {
		if !isDecimal(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

func parsePortRange(spec string) (start, end int, ok bool) {
	parts := strings.Split(spec, "-")
	if len(parts) != 2 || !isDecimal(parts[0]) || !isDecimal(parts[1]) {
		return 0, 0, false
	}
	start, end = atoi(parts[0]), atoi(parts[1])
	if start < 1 || end > 65535 || start > end {
		return 0, 0, false
	}
	return start, end, true
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func portSpecArgs(spec string) []string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		// Full range by default. Top-1,000 misses the non-standard high ports used by
		// IoT and embedded devices.
		return []string{"-p", "1-65535"}
	}
	if strings.HasPrefix(spec, "--top-ports ") {
		return []string{"--top-ports", strings.TrimSpace(strings.TrimPrefix(spec, "--top-ports "))}
	}
	if strings.HasPrefix(spec, "--top-ports=") {
		return []string{"--top-ports", strings.TrimSpace(strings.TrimPrefix(spec, "--top-ports="))}
	}
	if strings.HasPrefix(spec, "-p ") {
		return []string{"-p", strings.TrimSpace(strings.TrimPrefix(spec, "-p "))}
	}
	if strings.HasPrefix(spec, "-p") && len(spec) > 2 && spec[2] != ' ' {
		return []string{"-p", strings.TrimSpace(strings.TrimPrefix(spec, "-p"))}
	}
	return []string{"-p", spec}
}

func validateTargets(targets []string) error {
	for _, target := range targets {
		if strings.HasPrefix(target, "-") {
			return fmt.Errorf("invalid scan target %q: target must not begin with '-'", target)
		}
		if _, err := netip.ParseAddr(target); err != nil {
			return fmt.Errorf("invalid scan target %q: must be a valid IP address", target)
		}
	}
	return nil
}

func dedupeTargets(targets []string) []string {
	seen := make(map[string]bool, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}
