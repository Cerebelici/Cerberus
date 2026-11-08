package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/platform"
)

var (
	// Strict regex matching: Open <IP>:<Port>
	// Examples: "Open 192.168.1.50:80", "Open 10.0.0.1:443"
	rustOpenLineRegex = regexp.MustCompile(`^Open\s+([0-9.]+):(\d+)$`)

	// Strict regex matching: <IP> -> [<port1>,<port2>,...]
	// Example: "192.168.1.50 -> [80,443,8080]"
	rustSummaryRegex = regexp.MustCompile(`^([0-9.]+)\s*->\s*\[([0-9,\s]*)\]$`)
)

// RustScanConfig holds tuning parameters for RustScan execution.
type RustScanConfig struct {
	BatchSize int           // default 4500
	Timeout   time.Duration // default 500ms
	Tries     int           // default 2
	Binary    string
}

// DefaultRustScanConfig returns Profile P-02 (Balanced Sentinel) parameters.
func DefaultRustScanConfig() RustScanConfig {
	return RustScanConfig{
		BatchSize: 4500,
		Timeout:   500 * time.Millisecond,
		Tries:     2,
		Binary:    platform.ResolveRustScan(),
	}
}

// Stage2RustScan executes Profile P-02 async port discovery across all 65,535 TCP ports for target IPs.
// It returns a mapping of IP -> list of verified open ports.
func Stage2RustScan(ctx context.Context, targetIPs []string, cfg *RustScanConfig) (map[string][]int, error) {
	if len(targetIPs) == 0 {
		return make(map[string][]int), nil
	}

	var conf RustScanConfig
	if cfg != nil {
		conf = *cfg
	} else {
		conf = DefaultRustScanConfig()
	}

	if conf.Binary == "" {
		conf.Binary = platform.ResolveRustScan()
	}
	if conf.BatchSize <= 0 {
		conf.BatchSize = 4500
	}
	if conf.Timeout <= 0 {
		conf.Timeout = 500 * time.Millisecond
	}
	if conf.Tries <= 0 {
		conf.Tries = 2
	}

	// Build arguments matching Profile P-02 (Balanced Sentinel)
	args := []string{
		"-a", strings.Join(targetIPs, ","),
		"--batch-size", strconv.Itoa(conf.BatchSize),
		"--timeout", strconv.Itoa(int(conf.Timeout.Milliseconds())),
		"--tries", strconv.Itoa(conf.Tries),
		"--scan-order", "random",
		"--scripts", "none",
		"--no-banner",
	}

	cmd := exec.CommandContext(ctx, conf.Binary, args...)
	configureProcessGroup(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Even if process exited with non-zero, parse whatever stdout was produced
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("rustscan failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
	}

	return ParseRustScanOutput(stdout.Bytes())
}

// ParseRustScanOutput strictly parses stdout from RustScan, preventing the Port 192 artifact.
// It accepts both per-port lines ("Open <IP>:<Port>") and summary blocks ("<IP> -> [<ports>]").
func ParseRustScanOutput(output []byte) (map[string][]int, error) {
	results := make(map[string]map[int]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 1. Check strict "Open IP:Port" pattern
		if matches := rustOpenLineRegex.FindStringSubmatch(line); len(matches) == 3 {
			ipStr := matches[1]
			portStr := matches[2]
			if net.ParseIP(ipStr) != nil {
				port, err := strconv.Atoi(portStr)
				if err == nil && port > 0 && port <= 65535 {
					if results[ipStr] == nil {
						results[ipStr] = make(map[int]bool)
					}
					results[ipStr][port] = true
				}
			}
			continue
		}

		// 2. Check strict "<IP> -> [<ports>]" pattern
		if matches := rustSummaryRegex.FindStringSubmatch(line); len(matches) == 3 {
			ipStr := matches[1]
			portsStr := strings.TrimSpace(matches[2])
			if net.ParseIP(ipStr) != nil {
				if results[ipStr] == nil {
					results[ipStr] = make(map[int]bool)
				}
				if portsStr != "" {
					portTokens := strings.Split(portsStr, ",")
					for _, tok := range portTokens {
						tok = strings.TrimSpace(tok)
						port, err := strconv.Atoi(tok)
						if err == nil && port > 0 && port <= 65535 {
							results[ipStr][port] = true
						}
					}
				}
			}
			continue
		}

		// Any other output line (e.g. banner, warning, ulimit info, IP lines) is discarded
	}

	finalMap := make(map[string][]int, len(results))
	for ip, portSet := range results {
		var ports []int
		for p := range portSet {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		finalMap[ip] = ports
	}

	return finalMap, nil
}
