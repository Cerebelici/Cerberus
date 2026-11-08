package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/platform"
)

// Stage1Host represents an active host discovered during L2 ARP sweep.
type Stage1Host struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Adapter  string
	IsStatic bool
}

// Stage1ARPSweep performs a fast Layer-2 sweep and kernel ARP cache extraction.
// It actively prods the local subnet with UDP probes to wake sleeping mobile devices
// (whose Wi-Fi SoC handles ARP offload) and extracts kernel neighbor tables.
// Total execution time is bounded within 3.0 seconds for a /24 subnet.
func Stage1ARPSweep(ctx context.Context, subnet *net.IPNet, excludeIPs []string) ([]Stage1Host, error) {
	if subnet == nil {
		p := platform.GetDefaultProvider()
		if p != nil {
			var err error
			subnet, err = p.GetLocalSubnet()
			if err != nil {
				return nil, fmt.Errorf("unable to determine local subnet: %w", err)
			}
		} else {
			return nil, fmt.Errorf("no subnet specified and no platform provider available")
		}
	}

	excludeMap := make(map[string]bool)
	for _, ex := range excludeIPs {
		excludeMap[ex] = true
	}

	// 1. Initial kernel ARP cache read
	p := platform.GetDefaultProvider()
	var initialEntries []platform.HostARPEntry
	if p != nil {
		initialEntries, _ = p.GetKernelARPCache()
	}

	// 2. Active broadcast & unicast prodding to trigger kernel ARP resolution.
	// Bounded to 1.5s max runtime.
	prodCtx, cancelProd := context.WithTimeout(ctx, 1500*time.Millisecond)
	prodSubnet(prodCtx, subnet)
	cancelProd()

	// 3. Final kernel ARP cache read
	var finalEntries []platform.HostARPEntry
	if p != nil {
		finalEntries, _ = p.GetKernelARPCache()
	}

	// Merge all entries
	merged := make(map[string]Stage1Host)
	addEntry := func(e platform.HostARPEntry) {
		if e.IP == nil || e.MAC == nil || len(e.MAC) != 6 {
			return
		}
		ip4 := e.IP.To4()
		if ip4 == nil {
			return
		}
		// Ignore multicast, loopback, broadcast
		if ip4.IsMulticast() || ip4.IsLoopback() || ip4[3] == 255 || ip4[0] >= 224 {
			return
		}
		if !subnet.Contains(ip4) {
			return
		}
		if excludeMap[ip4.String()] {
			return
		}

		// Don't register all-zero MACs
		allZero := true
		for _, b := range e.MAC {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return
		}

		merged[ip4.String()] = Stage1Host{
			IP:       ip4,
			MAC:      e.MAC,
			Adapter:  e.Adapter,
			IsStatic: e.IsStatic,
		}
	}

	for _, e := range initialEntries {
		addEntry(e)
	}
	for _, e := range finalEntries {
		addEntry(e)
	}

	results := make([]Stage1Host, 0, len(merged))
	for _, host := range merged {
		results = append(results, host)
	}

	return results, nil
}

// prodSubnet sends lightweight UDP probes across the subnet to populate the kernel ARP table.
func prodSubnet(ctx context.Context, subnet *net.IPNet) {
	ip := subnet.IP.To4()
	if ip == nil {
		return
	}

	mask := subnet.Mask
	if len(mask) != 4 {
		return
	}

	// Generate target IPs in subnet
	var ips []net.IP
	base := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	m := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	start := (base & m) + 1
	end := (base | ^m) - 1

	// Limit to max 256 hosts for /24 sweep speed
	count := end - start + 1
	if count > 256 {
		count = 256
		end = start + 255
	}

	for cur := start; cur <= end; cur++ {
		target := net.IPv4(byte(cur>>24), byte(cur>>16), byte(cur>>8), byte(cur))
		ips = append(ips, target)
	}

	// Concurrent dispatch with worker pool
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 64)

	for _, target := range ips {
		select {
		case <-ctx.Done():
			return
		default:
		}

		semaphore <- struct{}{}
		wg.Add(1)

		go func(dst net.IP) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			d := net.Dialer{Timeout: 50 * time.Millisecond}
			conn, err := d.DialContext(ctx, "udp4", fmt.Sprintf("%s:5353", dst.String()))
			if err == nil {
				// Send dummy probe
				_, _ = conn.Write([]byte{0x00})
				_ = conn.Close()
			}
		}(target)
	}

	wg.Wait()
	// Allow small grace period for kernel to process ARP replies
	time.Sleep(100 * time.Millisecond)
}
