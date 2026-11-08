//go:build darwin && !cgo

package platform

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

type DarwinPlatformNoCgo struct{}

func init() {
	SetDefaultProvider(&DarwinPlatformNoCgo{})
}

func (p *DarwinPlatformNoCgo) GetGatewayIP() (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "gateway:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ip := net.ParseIP(fields[1])
					if ip != nil {
						return ip, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("unable to determine default gateway")
}

func (p *DarwinPlatformNoCgo) GetLocalSubnet() (*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					return ipNet, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no active IPv4 subnet found")
}

func (p *DarwinPlatformNoCgo) GetKernelARPCache() ([]HostARPEntry, error) {
	out, err := exec.Command("/usr/sbin/arp", "-an").Output()
	if err != nil {
		return nil, err
	}
	var results []HostARPEntry
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, " at ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			ipStr := strings.Trim(parts[1], "()")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			macStr := parts[3]
			mac, err := net.ParseMAC(macStr)
			if err != nil {
				continue
			}
			adapter := ""
			for i, part := range parts {
				if part == "on" && i+1 < len(parts) {
					adapter = parts[i+1]
					break
				}
			}
			results = append(results, HostARPEntry{
				IP:       ip,
				MAC:      mac,
				Adapter:  adapter,
				IsStatic: strings.Contains(line, "permanent") || strings.Contains(line, "static"),
			})
		}
	}
	return results, nil
}

func (p *DarwinPlatformNoCgo) ResolveBonjourServices(timeout time.Duration) (map[string]string, error) {
	return make(map[string]string), nil
}
