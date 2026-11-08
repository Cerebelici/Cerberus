package scanner

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/platform"
)

// Neighbor is a host that the OS resolved on the local link (an ARP entry).
type Neighbor struct {
	IP  string
	MAC string
}

// NeighborSource returns the hosts that the OS confirmed on the local link recently.
type NeighborSource func(ctx context.Context) ([]Neighbor, error)

// ReadNeighborTable returns the ARP entries that the OS confirmed recently.
//
// An unprivileged TCP ping sweep cannot see hosts that drop every probed port (phones,
// many IoT devices) and cannot read MAC addresses. The sweep still makes the kernel send
// an ARP request to every address in the subnet, so right after it the ARP table holds
// each host on the link that answered, with its MAC address. Native OS extraction is
// preferred via PlatformProvider (Darwin sysctl, Linux netlink, Windows iphlpapi).
func ReadNeighborTable(ctx context.Context) ([]Neighbor, error) {
	if p := platform.GetDefaultProvider(); p != nil {
		entries, err := p.GetKernelARPCache()
		if err == nil && len(entries) > 0 {
			var neighbors []Neighbor
			for _, e := range entries {
				if e.IP == nil || e.MAC == nil {
					continue
				}
				mac := strings.ToUpper(e.MAC.String())
				if mac == "" || mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF" {
					continue
				}
				neighbors = append(neighbors, Neighbor{
					IP:  e.IP.String(),
					MAC: mac,
				})
			}
			return neighbors, nil
		}
	}

	if runtime.GOOS != "darwin" {
		return nil, nil
	}
	out, err := exec.CommandContext(ctx, "/usr/sbin/arp", "-anx").Output()
	if err != nil {
		return nil, fmt.Errorf("reading ARP table: %w", err)
	}
	return parseDarwinARPTable(string(out)), nil
}

// parseDarwinARPTable parses `arp -anx` output and keeps only entries with a running
// reachability timer. Entries marked "expired" were not confirmed recently and can belong
// to hosts that left the network; "(none)" marks static, broadcast and multicast entries.
func parseDarwinARPTable(out string) []Neighbor {
	var neighbors []Neighbor
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		// Neighbor  Linklayer-Address  Expire(O)  Expire(I)  Netif ...
		if len(fields) < 4 || fields[0] == "Neighbor" {
			continue
		}
		if !isARPTimer(fields[2]) && !isARPTimer(fields[3]) {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil || !addr.Is4() {
			continue
		}
		mac := normalizeARPMAC(fields[1])
		if mac == "" {
			continue
		}
		neighbors = append(neighbors, Neighbor{IP: addr.String(), MAC: mac})
	}
	return neighbors
}

func isARPTimer(field string) bool {
	d, err := time.ParseDuration(field)
	return err == nil && d > 0
}

// normalizeARPMAC turns "80:d:3f:4d:e9:68" into "80:0D:3F:4D:E9:68", the format nmap reports.
func normalizeARPMAC(raw string) string {
	parts := strings.Split(raw, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, part := range parts {
		if len(part) == 0 || len(part) > 2 {
			return ""
		}
		for _, c := range part {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return ""
			}
		}
		if len(part) == 1 {
			part = "0" + part
		}
		parts[i] = strings.ToUpper(part)
	}
	mac := strings.Join(parts, ":")
	if mac == "FF:FF:FF:FF:FF:FF" || mac == "00:00:00:00:00:00" {
		return ""
	}
	return mac
}

// mergeNeighbors adds the MAC address of each neighbor to the matching discovered host, and
// adds neighbors inside target that the sweep did not report as new live hosts.
func mergeNeighbors(devices []model.Device, neighbors []Neighbor, target string, excluded []string) []model.Device {
	prefix, err := netip.ParsePrefix(target)
	if err != nil {
		addr, addrErr := netip.ParseAddr(target)
		if addrErr != nil {
			return devices
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return devices
	}

	skip := make(map[string]bool, len(excluded)+2)
	for _, ip := range excluded {
		skip[ip] = true
	}
	if prefix.Bits() <= 30 {
		skip[prefix.Addr().String()] = true
		skip[lastAddr(prefix).String()] = true
	}

	index := make(map[string]int, len(devices))
	for i, dev := range devices {
		index[dev.IP] = i
	}

	var macsFilled int
	var added []model.Device
	for _, n := range neighbors {
		addr, err := netip.ParseAddr(n.IP)
		if err != nil || !prefix.Contains(addr) || addr.IsMulticast() || skip[n.IP] {
			continue
		}
		if i, ok := index[n.IP]; ok {
			if devices[i].MAC == "" {
				devices[i].MAC = n.MAC
				macsFilled++
			}
			continue
		}
		index[n.IP] = -1
		added = append(added, model.Device{IP: n.IP, MAC: n.MAC, Status: "up"})
	}

	sort.Slice(added, func(i, j int) bool {
		a, _ := netip.ParseAddr(added[i].IP)
		b, _ := netip.ParseAddr(added[j].IP)
		return a.Less(b)
	})
	if macsFilled > 0 || len(added) > 0 {
		log.Printf("[Scanner] ARP table: filled %d MAC addresses, added %d hosts that ignore TCP probes", macsFilled, len(added))
	}
	return append(devices, added...)
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	a := prefix.Addr().As4()
	hostBits := 32 - prefix.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (uint32(1) << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
