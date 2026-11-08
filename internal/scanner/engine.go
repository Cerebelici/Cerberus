package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/platform"
)

// ScanStage represents the active phase in the hybrid scanning pipeline.
type ScanStage string

const (
	Stage1L2Mapping    ScanStage = "Stage 1: L2 Mapping"
	Stage2PortSweep    ScanStage = "Stage 2: Port Sweep"
	Stage3DeepAudit    ScanStage = "Stage 3: Deep Audit"
	StageCompleted     ScanStage = "Completed"
)

// ScanEventListener receives real-time progress callbacks from the engine.
type ScanEventListener interface {
	OnStageChanged(stage ScanStage)
	OnHostDiscovered(host Stage1Host)
	OnScanCompleted(results []model.ScanHostResult, duration time.Duration)
}

// EngineOptions configures execution parameters of the HybridEngine.
type EngineOptions struct {
	Subnet      *net.IPNet
	ExcludeIPs  []string
	NmapBinary  string
	RustBinary  string
	VulnScript  string
	Listener    ScanEventListener
}

// HybridEngine coordinates the Tri-Stage Hybrid Scanning Engine.
type HybridEngine struct {
	runner CommandRunner
	mu     sync.RWMutex
}

// NewHybridEngine creates a new scanning engine instance.
func NewHybridEngine(runner CommandRunner) *HybridEngine {
	if runner == nil {
		runner = &DefaultCommandRunner{}
	}
	return &HybridEngine{
		runner: runner,
	}
}

// RunHybridScan executes the complete tri-stage pipeline:
// Stage 1 (L2 Mapping) -> Stage 2 (RustScan) -> Stage 3 (Targeted Nmap).
func (e *HybridEngine) RunHybridScan(ctx context.Context, opts EngineOptions) ([]model.ScanHostResult, error) {
	start := time.Now()

	if opts.NmapBinary == "" {
		opts.NmapBinary = platform.ResolveNmap()
	}
	if opts.RustBinary == "" {
		opts.RustBinary = platform.ResolveRustScan()
	}

	// -------------------------------------------------------------
	// Stage 1: Fast L2 Broadcast Sweep & Kernel ARP Extraction
	// -------------------------------------------------------------
	if opts.Listener != nil {
		opts.Listener.OnStageChanged(Stage1L2Mapping)
	}

	stage1Hosts, err := Stage1ARPSweep(ctx, opts.Subnet, opts.ExcludeIPs)
	if err != nil {
		return nil, fmt.Errorf("stage 1 ARP sweep failed: %w", err)
	}

	for _, h := range stage1Hosts {
		if opts.Listener != nil {
			opts.Listener.OnHostDiscovered(h)
		}
	}

	if len(stage1Hosts) == 0 {
		if opts.Listener != nil {
			opts.Listener.OnStageChanged(StageCompleted)
			opts.Listener.OnScanCompleted(nil, time.Since(start))
		}
		return nil, nil
	}

	// Extract active IPs
	var targetIPs []string
	hostMACMap := make(map[string]string)
	for _, h := range stage1Hosts {
		ipStr := h.IP.String()
		targetIPs = append(targetIPs, ipStr)
		if h.MAC != nil {
			hostMACMap[ipStr] = h.MAC.String()
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// -------------------------------------------------------------
	// Stage 2: RustScan Async Engine (65,535 TCP ports)
	// -------------------------------------------------------------
	if opts.Listener != nil {
		opts.Listener.OnStageChanged(Stage2PortSweep)
	}

	rustCfg := DefaultRustScanConfig()
	rustCfg.Binary = opts.RustBinary

	openPortsMap, rustErr := Stage2RustScan(ctx, targetIPs, &rustCfg)
	if rustErr != nil {
		// Log warning but proceed with empty ports if rustscan had issues
		openPortsMap = make(map[string][]int)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// -------------------------------------------------------------
	// Stage 3: Targeted Nmap Deep Inspection (Open Ports Only)
	// -------------------------------------------------------------
	if opts.Listener != nil {
		opts.Listener.OnStageChanged(Stage3DeepAudit)
	}

	var stage3Targets []Stage3Target
	for _, ip := range targetIPs {
		stage3Targets = append(stage3Targets, Stage3Target{
			IP:        ip,
			MAC:       hostMACMap[ip],
			OpenPorts: openPortsMap[ip],
		})
	}

	results, auditErr := Stage3NmapAudit(ctx, e.runner, opts.NmapBinary, opts.VulnScript, stage3Targets)
	if auditErr != nil && len(results) == 0 {
		return nil, fmt.Errorf("stage 3 audit failed: %w", auditErr)
	}

	if opts.Listener != nil {
		opts.Listener.OnStageChanged(StageCompleted)
		opts.Listener.OnScanCompleted(results, time.Since(start))
	}

	return results, nil
}
