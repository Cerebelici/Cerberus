package scanner

import (
	"context"
	"testing"
	"time"
)

func TestParseRustScanOutput(t *testing.T) {
	// Sample output containing banners, ulimit warnings, per-port Open lines, and summary lines.
	// Specifically testing to prevent the "Port 192 artifact" where 192 in 192.168.1.1 is parsed as a port.
	rawOutput := `
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  ` + "`" + `| |
` + "`" + `-' ` + "`" + `-'` + "`" + `-----'` + "`" + `----'  ` + "`" + `-'  ` + "`" + `----'  ` + "`" + `---' ` + "`" + `-'  ` + "`" + `-'` + "`" + `-' ` + "`" + `-'
The Modern Day Port Scanner.
[~] The config file is expected to be at "/Users/admin/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048475'.
Open 192.168.1.50:80
Open 192.168.1.50:443
Open 192.168.1.1:53
Open 192.168.1.1:80
192.168.1.50 -> [80,443]
192.168.1.1 -> [53,80]
Open 10.0.0.5:8080
10.0.0.5 -> [8080]
`

	parsed, err := ParseRustScanOutput([]byte(rawOutput))
	if err != nil {
		t.Fatalf("ParseRustScanOutput failed: %v", err)
	}

	if len(parsed) != 3 {
		t.Fatalf("Expected 3 hosts, got %d", len(parsed))
	}

	// Verify 192.168.1.50
	ports50, ok := parsed["192.168.1.50"]
	if !ok {
		t.Fatal("Expected 192.168.1.50 in results")
	}
	if len(ports50) != 2 || ports50[0] != 80 || ports50[1] != 443 {
		t.Errorf("Unexpected ports for 192.168.1.50: %v", ports50)
	}

	// Verify no "192" port artifact
	for ip, ports := range parsed {
		for _, p := range ports {
			if p == 192 {
				t.Fatalf("Found Port 192 artifact for host %s!", ip)
			}
		}
	}

	// Verify 192.168.1.1
	ports1, ok := parsed["192.168.1.1"]
	if !ok {
		t.Fatal("Expected 192.168.1.1 in results")
	}
	if len(ports1) != 2 || ports1[0] != 53 || ports1[1] != 80 {
		t.Errorf("Unexpected ports for 192.168.1.1: %v", ports1)
	}

	// Verify 10.0.0.5
	ports10, ok := parsed["10.0.0.5"]
	if !ok {
		t.Fatal("Expected 10.0.0.5 in results")
	}
	if len(ports10) != 1 || ports10[0] != 8080 {
		t.Errorf("Unexpected ports for 10.0.0.5: %v", ports10)
	}
}

func TestStage1ARPSweep(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	hosts, err := Stage1ARPSweep(ctx, nil, nil)
	if err != nil {
		t.Logf("Stage 1 sweep error (expected if isolated): %v", err)
	} else {
		t.Logf("Stage 1 discovered %d active hosts", len(hosts))
		for _, h := range hosts {
			t.Logf("  Host IP: %s, MAC: %s", h.IP, h.MAC)
		}
	}
}

type mockRunner struct {
	lastArgs []string
}

func (m *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.lastArgs = args
	// Return minimal valid Nmap XML
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap" start="1600000000" version="7.94" xmloutputversion="1.05">
<host starttime="1600000000" endtime="1600000001">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache" version="2.4.52"/></port>
</ports>
</host>
<runstats><finished time="1600000001" timestr="Sun Nov  9" elapsed="1" exit="success"/></runstats>
</nmaprun>`
	return []byte(xml), nil
}

func TestStage2RustScanDefaultsToFullRange(t *testing.T) {
	runner := &mockRunner{}
	_, err := Stage2RustScanWithRunner(context.Background(), runner, []string{"192.168.1.50"}, &RustScanConfig{
		Binary: "rustscan",
	})
	if err != nil {
		t.Fatalf("Stage2RustScanWithRunner failed: %v", err)
	}
	found := false
	for i, arg := range runner.lastArgs {
		if arg == "--range" && i+1 < len(runner.lastArgs) && runner.lastArgs[i+1] == "1-65535" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected full port range --range 1-65535, got %v", runner.lastArgs)
	}
	for _, arg := range runner.lastArgs {
		if arg == "--top" {
			t.Fatalf("RustScan must not fall back to top-1,000 ports, got %v", runner.lastArgs)
		}
	}
	ulimitFound := false
	for i, arg := range runner.lastArgs {
		if arg == "--ulimit" && i+1 < len(runner.lastArgs) && runner.lastArgs[i+1] == "65535" {
			ulimitFound = true
			break
		}
	}
	if !ulimitFound {
		t.Fatalf("expected --ulimit 65535 so batch sockets are not serialised, got %v", runner.lastArgs)
	}
}

func TestPortSpecArgsDefaultsToFullRange(t *testing.T) {
	got := portSpecArgs("")
	if len(got) != 2 || got[0] != "-p" || got[1] != "1-65535" {
		t.Fatalf("expected -p 1-65535, got %v", got)
	}
}

func TestStage3NmapAuditNeverUsesConnectScan(t *testing.T) {
	runner := &mockRunner{}
	targets := []Stage3Target{
		{IP: "192.168.1.50", MAC: "AA:BB:CC:DD:EE:FF", OpenPorts: []int{80}},
	}
	if _, err := Stage3NmapAudit(context.Background(), runner, "nmap", "vulners", targets); err != nil {
		t.Fatalf("Stage3NmapAudit failed: %v", err)
	}
	for _, arg := range runner.lastArgs {
		if arg == "-sT" {
			t.Fatalf("scan must not use the -sT fallback, got %v", runner.lastArgs)
		}
	}
}

func TestStage3NmapAuditZeroPorts(t *testing.T) {
	runner := &mockRunner{}
	targets := []Stage3Target{
		{IP: "192.168.1.100", MAC: "00:11:22:33:44:55", OpenPorts: nil},
	}
	results, err := Stage3NmapAudit(context.Background(), runner, "nmap", "vulners", targets)
	if err != nil {
		t.Fatalf("Stage3NmapAudit failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result for zero-port target, got %d", len(results))
	}
	if results[0].IP != "192.168.1.100" || results[0].Status != "up" || len(results[0].Services) != 0 {
		t.Errorf("Unexpected result for zero-port target: %+v", results[0])
	}
	// Verify nmap was NOT executed for zero-port target (eliminates 44s timeout anti-pattern)
	if runner.lastArgs != nil {
		t.Errorf("Expected runner not to be called for zero-port target, but called with %v", runner.lastArgs)
	}
}

func TestStage3NmapAuditWithOpenPorts(t *testing.T) {
	runner := &mockRunner{}
	targets := []Stage3Target{
		{IP: "192.168.1.50", MAC: "AA:BB:CC:DD:EE:FF", OpenPorts: []int{80, 443}},
	}
	results, err := Stage3NmapAudit(context.Background(), runner, "nmap", "vulners", targets)
	if err != nil {
		t.Fatalf("Stage3NmapAudit failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if runner.lastArgs == nil {
		t.Fatal("Expected runner to be called with targeted ports")
	}

	// Verify exact ports argument: "-p", "80,443"
	hasP := false
	for i, arg := range runner.lastArgs {
		if arg == "-p" && i+1 < len(runner.lastArgs) && runner.lastArgs[i+1] == "80,443" {
			hasP = true
			break
		}
	}
	if !hasP {
		t.Errorf("Expected -p 80,443 in nmap args, got %v", runner.lastArgs)
	}
}
