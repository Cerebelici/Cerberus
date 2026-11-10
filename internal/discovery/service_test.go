package discovery

import (
	"net/netip"
	"testing"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
)

func TestTargetPrefix(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
		ok     bool
	}{
		{name: "cidr", target: "192.168.1.42/24", want: "192.168.1.0/24", ok: true},
		{name: "single address", target: "192.168.1.42", want: "192.168.1.42/32", ok: true},
		{name: "host prefix", target: "10.0.0.7/32", want: "10.0.0.7/32", ok: true},
		{name: "ipv6 rejected", target: "fd00::/64"},
		{name: "empty", target: ""},
		{name: "garbage", target: "not-a-network"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := targetPrefix(tt.target)
			if ok != tt.ok {
				t.Fatalf("targetPrefix(%q) ok = %v, want %v", tt.target, ok, tt.ok)
			}
			if ok && got.String() != tt.want {
				t.Fatalf("targetPrefix(%q) = %s, want %s", tt.target, got, tt.want)
			}
		})
	}
}

func TestLastAddr(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
	}{
		{prefix: "192.168.1.0/24", want: "192.168.1.255"},
		{prefix: "10.0.0.0/8", want: "10.255.255.255"},
		{prefix: "172.16.0.0/12", want: "172.31.255.255"},
		{prefix: "192.168.1.42/32", want: "192.168.1.42"},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tt.prefix)
			if got := lastAddr(prefix).String(); got != tt.want {
				t.Fatalf("lastAddr(%s) = %s, want %s", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestMergePassiveDevices(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	excluded := map[string]bool{
		"198.51.100.1":   true, // gateway
		"198.51.100.255": true, // broadcast
	}

	devices := []model.Device{
		{IP: "198.51.100.10", MAC: "AA:BB:CC:DD:EE:01", Hostname: "printer", Status: "up"},
	}
	neighbors := []scanner.Neighbor{
		{IP: "198.51.100.10", MAC: "AA:BB:CC:DD:EE:01"}, // already swept
		{IP: "198.51.100.20", MAC: "AA:BB:CC:DD:EE:02"}, // new passive host
		{IP: "198.51.100.1", MAC: "AA:BB:CC:DD:EE:03"},  // gateway is excluded
		{IP: "8.8.8.8", MAC: "AA:BB:CC:DD:EE:04"},       // outside target
	}
	passive := map[string]string{
		"198.51.100.30":  "living-room-tv", // mDNS only
		"198.51.100.20":  "duplicate",      // neighbour entry wins
		"198.51.100.255": "broadcast",      // excluded
		"224.0.0.251":    "multicast",      // multicast is not a device
		"127.0.0.1":      "loopback",       // loopback is not a device
	}

	got := mergePassiveDevices(devices, neighbors, passive, prefix, excluded)

	want := []struct {
		ip       string
		mac      string
		hostname string
	}{
		{ip: "198.51.100.10", mac: "AA:BB:CC:DD:EE:01", hostname: "printer"},
		{ip: "198.51.100.20", mac: "AA:BB:CC:DD:EE:02", hostname: ""},
		{ip: "198.51.100.30", mac: "", hostname: "living-room-tv"},
	}

	if len(got) != len(want) {
		t.Fatalf("mergePassiveDevices returned %d devices (%v), want %d", len(got), got, len(want))
	}
	for i, w := range want {
		if got[i].IP != w.ip || got[i].MAC != w.mac || got[i].Hostname != w.hostname {
			t.Fatalf("device %d = %+v, want ip=%s mac=%s hostname=%s", i, got[i], w.ip, w.mac, w.hostname)
		}
		if got[i].Status != "up" {
			t.Fatalf("device %d status = %q, want up", i, got[i].Status)
		}
	}
}

func TestMergePassiveDevicesWithoutPassiveListener(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	got := mergePassiveDevices(nil, nil, nil, prefix, nil)
	if len(got) != 0 {
		t.Fatalf("expected no devices, got %v", got)
	}
}
