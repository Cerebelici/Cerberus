package identity

import (
	"context"
	"testing"
	"time"
)

func TestSleepingMobileHeuristic(t *testing.T) {
	resolver := NewMultiChannelResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Locally administered MAC (byte 0 bit 1 set: e.g. 02:xx:xx:xx:xx:xx, 06:xx:xx:xx:xx:xx)
	// Responded to L2 ARP, but 0 open ports (sleeping phone)
	mobileHost := HostIdentityInput{
		IP:             "192.168.0.189",
		MAC:            "06:3e:43:0f:ea:36", // 0x06 & 0x02 != 0 -> LAA
		RespondedL2ARP: true,
		OpenPorts:      nil,
		AllTcpwrapped:  false,
	}

	cl := resolver.ResolveHost(ctx, mobileHost)
	if cl.DeviceType != "Mobile Smartphone (Sleeping / Power-Saving)" {
		t.Errorf("Expected Sleeping Mobile classification, got: %s", cl.DeviceType)
	}
	if cl.OSFamily != "Android / iOS" {
		t.Errorf("Expected Android / iOS, got: %s", cl.OSFamily)
	}
	if cl.Confidence < 0.8 {
		t.Errorf("Expected confidence >= 0.8, got: %f", cl.Confidence)
	}
}

func TestStandardHostClassification(t *testing.T) {
	resolver := NewMultiChannelResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Non-LAA device (standard vendor OUI) with open ports
	pcHost := HostIdentityInput{
		IP:             "192.168.0.1",
		MAC:            "c0:bc:9a:34:94:c2", // Non-LAA
		RespondedL2ARP: true,
		OpenPorts:      []int{80, 443},
		ExistingHost:   "router.lan",
		ExistingVendor: "TP-Link",
	}

	cl := resolver.ResolveHost(ctx, pcHost)
	if cl.DeviceType == "Mobile Smartphone (Sleeping / Power-Saving)" {
		t.Errorf("Router should not be classified as sleeping smartphone")
	}
	if cl.Hostname != "router.lan" {
		t.Errorf("Expected router.lan, got %s", cl.Hostname)
	}
}

func TestResolveBatch(t *testing.T) {
	resolver := NewMultiChannelResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	hosts := []HostIdentityInput{
		{
			IP:             "192.168.0.189",
			MAC:            "06:3e:43:0f:ea:36",
			RespondedL2ARP: true,
			OpenPorts:      nil,
		},
		{
			IP:             "192.168.0.1",
			MAC:            "c0:bc:9a:34:94:c2",
			RespondedL2ARP: true,
			OpenPorts:      []int{80},
			ExistingHost:   "gateway.home",
		},
	}

	results := resolver.ResolveBatch(ctx, hosts)
	if len(results) != 2 {
		t.Fatalf("Expected 2 results from batch, got %d", len(results))
	}
	if results["192.168.0.189"].DeviceType != "Mobile Smartphone (Sleeping / Power-Saving)" {
		t.Errorf("Expected mobile smartphone for 192.168.0.189, got %s", results["192.168.0.189"].DeviceType)
	}
	if results["192.168.0.1"].Hostname != "gateway.home" {
		t.Errorf("Expected gateway.home for 192.168.0.1, got %s", results["192.168.0.1"].Hostname)
	}
}
