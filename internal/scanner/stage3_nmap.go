package scanner

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/platform"
)

// Stage3Target pairs an IP with its discovered open ports from Stage 2.
type Stage3Target struct {
	IP        string
	MAC       string
	OpenPorts []int
}

// Stage3NmapAudit executes targeted deep inspection (service detection + vulnerability scripts)
// ONLY against the verified open ports discovered in Stage 2.
// Hosts with 0 open ports are skipped entirely, eliminating the 44s timeout anti-pattern.
func Stage3NmapAudit(ctx context.Context, runner CommandRunner, nmapBinary string, vulnScript string, targets []Stage3Target) ([]model.ScanHostResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	if runner == nil {
		runner = &DefaultCommandRunner{}
	}
	if nmapBinary == "" {
		nmapBinary = platform.ResolveNmap()
	}
	if vulnScript == "" {
		vulnScript = "vulners"
	}
	scriptSpec := vulnScript
	if !strings.Contains(scriptSpec, "ssh-hostkey") {
		scriptSpec += ",ssh-hostkey,ssl-cert"
	}

	var results []model.ScanHostResult

	// Audit each host with open ports individually to avoid port cross-contamination
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if len(target.OpenPorts) == 0 {
			// Zero open ports: record host as up without running expensive scripts
			results = append(results, model.ScanHostResult{
				IP:       target.IP,
				MAC:      target.MAC,
				Status:   "up",
				Services: nil,
			})
			continue
		}

		// Validate target IP
		if strings.HasPrefix(target.IP, "-") {
			continue
		}
		if _, err := netip.ParseAddr(target.IP); err != nil {
			continue
		}

		// Convert open ports to comma-separated argument
		var portStrs []string
		for _, p := range target.OpenPorts {
			if p > 0 && p <= 65535 {
				portStrs = append(portStrs, strconv.Itoa(p))
			}
		}
		if len(portStrs) == 0 {
			continue
		}

		args := []string{
			"-sV",
			"--version-intensity", "5",
			"-Pn",
			"-T4",
			"--max-retries", "2",
			"--host-timeout", "5m",
			"-p", strings.Join(portStrs, ","),
			"--script", scriptSpec,
			"-oX", "-",
			target.IP,
		}
		output, err := runner.Run(ctx, nmapBinary, args...)
		if err != nil && !isCompleteNmapOutput(output) {
			// Partial or failed execution: still try to parse if valid XML
			if !isCompleteNmapOutput(output) {
				continue
			}
		}

		run, parseErr := ParseNmapXML(output)
		if parseErr != nil {
			continue
		}

		hostResults := ExtractHostResults(run)
		for _, hr := range hostResults {
			if hr.MAC == "" && target.MAC != "" {
				hr.MAC = target.MAC
			}
			results = append(results, hr)
		}
	}

	return results, nil
}
