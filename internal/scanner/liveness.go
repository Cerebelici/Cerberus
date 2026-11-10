package scanner

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// livenessProbePorts are common service ports used as a last-resort reachability check for
// hosts that the kernel neighbour table cannot confirm (for example routed hosts).
var livenessProbePorts = []string{"80", "443", "22", "445", "548", "8080", "9100", "62078"}

// ProbeHosts performs a lightweight known-device check. It does not sweep a subnet: it
// sends one UDP datagram per known address to make the kernel resolve the link-layer
// address, reads the neighbour table, and only falls back to short TCP handshakes for
// addresses that did not appear. This keeps the 5-minute discovery cadence cheap while
// still marking sleeping or departed devices as down.
func ProbeHosts(ctx context.Context, targets []string, neighbors NeighborSource) []model.Device {
	targets = dedupeTargets(targets)
	if len(targets) == 0 {
		return nil
	}

	prodAddresses(ctx, targets)

	// Give the kernel a moment to process ARP replies before reading its table.
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(150 * time.Millisecond):
	}

	// Only report the addresses that were asked about. Newly seen neighbours are handled
	// separately by passive discovery, which also applies the target/exclusion filters.
	wanted := make(map[string]bool, len(targets))
	for _, ip := range targets {
		wanted[ip] = true
	}
	alive := make(map[string]string)
	for _, n := range readNeighbors(ctx, neighbors) {
		if wanted[n.IP] {
			alive[n.IP] = n.MAC
		}
	}

	// Only hosts that did not answer at layer 2 need a TCP probe. Most LAN devices are
	// resolved by the neighbour cache, so this second phase is usually very small.
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, ip := range targets {
		if _, ok := alive[ip]; ok {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			if tcpReachable(ctx, ip) {
				mu.Lock()
				alive[ip] = ""
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	devices := make([]model.Device, 0, len(alive))
	for ip, mac := range alive {
		devices = append(devices, model.Device{IP: ip, MAC: mac, Status: "up"})
	}
	sort.Slice(devices, func(i, j int) bool {
		a, _ := netip.ParseAddr(devices[i].IP)
		b, _ := netip.ParseAddr(devices[j].IP)
		return a.Less(b)
	})
	return devices
}

func readNeighbors(ctx context.Context, src NeighborSource) []Neighbor {
	if src == nil {
		src = ReadNeighborTable
	}
	neighbors, err := src(ctx)
	if err != nil {
		return nil
	}
	return neighbors
}

// prodAddresses sends a single UDP datagram to each address. No reply is expected; the
// kernel ARP request that precedes transmission is what refreshes the neighbour table.
func prodAddresses(ctx context.Context, targets []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, ip := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			d := net.Dialer{Timeout: 250 * time.Millisecond}
			conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip, "5353"))
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte{0})
			_ = conn.Close()
		}(ip)
	}
	wg.Wait()
}

func tcpReachable(ctx context.Context, ip string) bool {
	for _, port := range livenessProbePorts {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		d := net.Dialer{Timeout: 250 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}
