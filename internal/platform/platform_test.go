package platform

import (
	"testing"
	"time"
)

func TestPlatformProvider(t *testing.T) {
	provider := GetDefaultProvider()
	if provider == nil {
		t.Fatal("Default provider is nil")
	}

	subnet, err := provider.GetLocalSubnet()
	if err != nil {
		t.Logf("GetLocalSubnet returned: %v", err)
	} else {
		t.Logf("Detected local subnet: %s", subnet.String())
	}

	entries, err := provider.GetKernelARPCache()
	if err != nil {
		t.Logf("GetKernelARPCache error: %v", err)
	} else {
		t.Logf("Kernel ARP entries retrieved: %d", len(entries))
		for _, e := range entries {
			t.Logf("  IP: %s, MAC: %s, Adapter: %s, Static: %v", e.IP, e.MAC, e.Adapter, e.IsStatic)
		}
	}

	bonjour, err := provider.ResolveBonjourServices(1 * time.Second)
	if err != nil {
		t.Logf("Bonjour resolution error: %v", err)
	} else {
		t.Logf("Discovered Bonjour services: %d", len(bonjour))
	}
}

func TestBinaryResolver(t *testing.T) {
	nmapPath := ResolveNmap()
	if nmapPath == "" {
		t.Error("ResolveNmap returned empty")
	} else {
		t.Logf("Resolved Nmap: %s", nmapPath)
	}

	rustscanPath := ResolveRustScan()
	if rustscanPath == "" {
		t.Error("ResolveRustScan returned empty")
	} else {
		t.Logf("Resolved RustScan: %s", rustscanPath)
	}
}
