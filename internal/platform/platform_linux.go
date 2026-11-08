//go:build linux

package platform

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

type LinuxPlatform struct{}

func init() {
	SetDefaultProvider(&LinuxPlatform{})
}

// GetGatewayIP retrieves the default gateway using Netlink RTM_GETROUTE or /proc/net/route.
func (p *LinuxPlatform) GetGatewayIP() (net.IP, error) {
	// Try Netlink first
	gw, err := getGatewayViaNetlink()
	if err == nil && gw != nil {
		return gw, nil
	}

	// Fallback to /proc/net/route
	return getGatewayViaProcRoute()
}

func getGatewayViaNetlink() (net.IP, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}
		var hasDst bool
		var gwIP net.IP
		for _, a := range attrs {
			if a.Attr.Type == syscall.RTA_DST {
				hasDst = true
			}
			if a.Attr.Type == syscall.RTA_GATEWAY && len(a.Value) == 4 {
				gwIP = net.IPv4(a.Value[0], a.Value[1], a.Value[2], a.Value[3])
			}
		}
		if !hasDst && gwIP != nil {
			return gwIP, nil
		}
	}
	return nil, fmt.Errorf("gateway not found in routes")
}

func getGatewayViaProcRoute() (net.IP, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			gwHex := fields[2]
			val, err := strconv.ParseUint(gwHex, 16, 32)
			if err != nil {
				continue
			}
			ip := net.IPv4(byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no default gateway found in /proc/net/route")
}

// GetLocalSubnet returns the primary active IPv4 subnet.
func (p *LinuxPlatform) GetLocalSubnet() (*net.IPNet, error) {
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

// GetKernelARPCache retrieves kernel neighbor table via Netlink (RTM_GETNEIGH) with /proc/net/arp fallback.
func (p *LinuxPlatform) GetKernelARPCache() ([]HostARPEntry, error) {
	entries, err := getNeighborsViaNetlink()
	if err == nil && len(entries) > 0 {
		return entries, nil
	}
	return getNeighborsViaProcArp()
}

func getNeighborsViaNetlink() ([]HostARPEntry, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETNEIGH, syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}

	var results []HostARPEntry
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWNEIGH {
			continue
		}
		if len(m.Data) < unix.SizeofNdMsg {
			continue
		}

		state := binary.LittleEndian.Uint16(m.Data[8:10])
		if state&(unix.NUD_FAILED|unix.NUD_NOARP) != 0 {
			continue
		}
		ifIndex := int32(binary.LittleEndian.Uint32(m.Data[4:8]))
		ifaceName := ""
		if ifi, err := net.InterfaceByIndex(int(ifIndex)); err == nil {
			ifaceName = ifi.Name
		}

		b := m.Data[unix.SizeofNdMsg:]
		var ip net.IP
		var mac net.HardwareAddr
		for len(b) >= unix.SizeofRtAttr {
			attrLen := int(binary.LittleEndian.Uint16(b[0:2]))
			attrType := int(binary.LittleEndian.Uint16(b[2:4]))
			if attrLen < unix.SizeofRtAttr || attrLen > len(b) {
				break
			}
			val := b[unix.SizeofRtAttr:attrLen]
			if attrType == unix.NDA_DST && len(val) == 4 {
				ip = net.IPv4(val[0], val[1], val[2], val[3])
			} else if attrType == unix.NDA_LLADDR && len(val) == 6 {
				mac = make(net.HardwareAddr, 6)
				copy(mac, val)
			}
			alen := (attrLen + 4 - 1) & ^(4 - 1)
			if alen > len(b) {
				break
			}
			b = b[alen:]
		}

		if ip != nil && mac != nil {
			isStatic := (state & unix.NUD_PERMANENT) != 0
			results = append(results, HostARPEntry{
				IP:       ip,
				MAC:      mac,
				Adapter:  ifaceName,
				IsStatic: isStatic,
			})
		}
	}

	return results, nil
}

func getNeighborsViaProcArp() ([]HostARPEntry, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []HostARPEntry
	scanner := bufio.NewScanner(file)
	// Skip header line
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 {
			ip := net.ParseIP(fields[0])
			mac, err := net.ParseMAC(fields[3])
			if ip != nil && err == nil && fields[3] != "00:00:00:00:00:00" {
				results = append(results, HostARPEntry{
					IP:       ip,
					MAC:      mac,
					Adapter:  fields[5],
					IsStatic: fields[2] == "0x6",
				})
			}
		}
	}
	return results, nil
}

// ResolveBonjourServices queries Avahi daemon over system D-Bus.
func (p *LinuxPlatform) ResolveBonjourServices(timeout time.Duration) (map[string]string, error) {
	results := make(map[string]string)

	conn, err := dbus.SystemBus()
	if err != nil {
		return results, nil // Avahi/dbus unavailable, fail open
	}

	serverObj := conn.Object("org.freedesktop.Avahi", "/")

	serviceTypes := []string{
		"_companion-link._tcp",
		"_airplay._tcp",
		"_raop._tcp",
		"_googlecast._tcp",
		"_http._tcp",
	}

	for _, st := range serviceTypes {
		var browserPath dbus.ObjectPath
		call := serverObj.Call("org.freedesktop.Avahi.Server.ServiceBrowserNew", 0,
			int32(-1), int32(-1), st, "", uint32(0))
		if call.Err != nil {
			continue
		}
		if err := call.Store(&browserPath); err != nil {
			continue
		}

		browserObj := conn.Object("org.freedesktop.Avahi", browserPath)
		_ = conn.AddMatchSignal(
			dbus.WithMatchInterface("org.freedesktop.Avahi.ServiceBrowser"),
			dbus.WithMatchMember("ItemNew"),
			dbus.WithMatchObjectPath(browserPath),
		)

		sigChan := make(chan *dbus.Signal, 10)
		conn.Signal(sigChan)

		timer := time.NewTimer(timeout / time.Duration(len(serviceTypes)))
	browseLoop:
		for {
			select {
			case sig := <-sigChan:
				if sig == nil {
					break browseLoop
				}
				if len(sig.Body) >= 5 {
					ifaceIndex := sig.Body[0].(int32)
					proto := sig.Body[1].(int32)
					name := sig.Body[2].(string)
					stype := sig.Body[3].(string)
					domain := sig.Body[4].(string)

					// Resolve service
					var resCall *dbus.Call
					resCall = serverObj.Call("org.freedesktop.Avahi.Server.ResolveService", 0,
						ifaceIndex, proto, name, stype, domain, int32(syscall.AF_INET), uint32(0))
					if resCall.Err == nil && len(resCall.Body) >= 8 {
						host := resCall.Body[6].(string)
						addr := resCall.Body[7].(string)
						if addr != "" {
							results[addr] = name
							if host != "" && results[addr] == "" {
								results[addr] = host
							}
						}
					}
				}
			case <-timer.C:
				break browseLoop
			}
		}
		timer.Stop()
		_ = browserObj.Call("org.freedesktop.Avahi.ServiceBrowser.Free", 0)
	}

	return results, nil
}
