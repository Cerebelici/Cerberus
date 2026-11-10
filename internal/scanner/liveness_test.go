package scanner

import (
	"context"
	"testing"
)

func TestProbeHostsOnlyReportsRequestedAddresses(t *testing.T) {
	neighbors := func(context.Context) ([]Neighbor, error) {
		return []Neighbor{
			{IP: "127.0.0.1", MAC: "AA:BB:CC:DD:EE:01"},
			{IP: "192.0.2.99", MAC: "AA:BB:CC:DD:EE:02"},
		}, nil
	}

	devices := ProbeHosts(context.Background(), []string{"127.0.0.1"}, neighbors)
	if len(devices) != 1 {
		t.Fatalf("ProbeHosts returned %v, want only the requested address", devices)
	}
	if devices[0].IP != "127.0.0.1" {
		t.Fatalf("ProbeHosts returned %s, want 127.0.0.1", devices[0].IP)
	}
	if devices[0].MAC != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("ProbeHosts lost the neighbour MAC: %+v", devices[0])
	}
	if devices[0].Status != "up" {
		t.Fatalf("ProbeHosts status = %q, want up", devices[0].Status)
	}
}

func TestProbeHostsEmptyTargets(t *testing.T) {
	if devices := ProbeHosts(context.Background(), nil, nil); len(devices) != 0 {
		t.Fatalf("ProbeHosts(nil) = %v, want no devices", devices)
	}
}
