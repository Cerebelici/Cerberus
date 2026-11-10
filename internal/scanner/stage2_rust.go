package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
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
	// ULimit is passed to RustScan's --ulimit. RustScan cannot exceed the process
	// soft file-descriptor limit, so a low limit (launchd defaults to 256) silently
	// serialises 4,500-port batches and turns a 25-second sweep into many minutes.
	ULimit int // default 65535
	Binary string
	// Ports is empty (full 1-65535 range), a range such as "1-10000", or a
	// comma-separated list such as "22,80,443". Empty must never fall back to
	// RustScan's top-1,000 list: IoT devices commonly listen on non-standard high ports.
	Ports string
}

// DefaultRustScanConfig returns Profile P-02 (Balanced Sentinel) parameters.
func DefaultRustScanConfig() RustScanConfig {
	return RustScanConfig{
		BatchSize: 4500,
		Timeout:   500 * time.Millisecond,
		Tries:     2,
		ULimit:    65535,
		Binary:    platform.ResolveRustScan(),
		Ports:     "1-65535",
	}
}

// Stage2RustScan executes Profile P-02 async port discovery across all 65,535 TCP ports for target IPs.
// It returns a mapping of IP -> list of verified open ports.
func Stage2RustScan(ctx context.Context, targetIPs []string, cfg *RustScanConfig) (map[string][]int, error) {
	return Stage2RustScanWithRunner(ctx, &DefaultCommandRunner{}, targetIPs, cfg)
}

// Stage2RustScanWithRunner is Stage2RustScan using the supplied command runner, so the
// engine's helper/elevation path and unit-test mocks apply to RustScan as well.
func Stage2RustScanWithRunner(ctx context.Context, runner CommandRunner, targetIPs []string, cfg *RustScanConfig) (map[string][]int, error) {
	if len(targetIPs) == 0 {
		return make(map[string][]int), nil
	}
	if runner == nil {
		runner = &DefaultCommandRunner{}
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
	if conf.ULimit <= 0 {
		conf.ULimit = 65535
	}
	// RustScan needs a descriptor per in-flight connection plus headroom for its
	// runtime. Keep the requested limit at least one batch above the batch size.
	if minLimit := conf.BatchSize + 256; conf.ULimit < minLimit {
		conf.ULimit = minLimit
	}

	// Build arguments matching Profile P-02 (Balanced Sentinel)
	args := []string{
		"-a", strings.Join(targetIPs, ","),
		"--batch-size", strconv.Itoa(conf.BatchSize),
		"--timeout", strconv.Itoa(int(conf.Timeout.Milliseconds())),
		"--tries", strconv.Itoa(conf.Tries),
		"--ulimit", strconv.Itoa(conf.ULimit),
		"--scan-order", "random",
		"--scripts", "none",
		"--no-banner",
	}
	ports := strings.TrimSpace(conf.Ports)
	switch {
	case ports == "":
		// A full sweep is the default. Never use "--top" here: it hides services on
		// non-standard high ports, which is exactly where IoT devices tend to listen.
		args = append(args, "--range", "1-65535")
	case strings.Contains(ports, "-") && !strings.Contains(ports, ","):
		args = append(args, "--range", ports)
	default:
		args = append(args, "--ports", ports)
	}

	output, err := runner.Run(ctx, conf.Binary, args...)
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("rustscan failed: %w", err)
	}

	return ParseRustScanOutput(output)
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
