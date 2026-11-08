//go:build windows

package platform

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi         = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpNetTable2  = modiphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable    = modiphlpapi.NewProc("FreeMibTable")
	procGetAdaptersAddresses = modiphlpapi.NewProc("GetAdaptersAddresses")
)

type WindowsPlatform struct{}

func init() {
	SetDefaultProvider(&WindowsPlatform{})
}

// Windows MIB_IPNET_ROW2 structure
type MIB_IPNET_ROW2 struct {
	Address                  SOCKADDR_INET
	InterfaceIndex           uint32
	InterfaceLuid            uint64
	PhysicalAddressLength    uint32
	PhysicalAddress          [32]byte
	LastReachable            uint32
	State                    uint32
	Flags                    uint8
	ReachabilityTime         uint32
}

type SOCKADDR_INET struct {
	Family uint16
	Data   [26]byte
}

type MIB_IPNET_TABLE2 struct {
	NumEntries uint32
	_          uint32
	Table      [1]MIB_IPNET_ROW2
}

// GetGatewayIP queries the primary adapter gateway on Windows.
func (p *WindowsPlatform) GetGatewayIP() (net.IP, error) {
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
				if ip4 := ipNet.IP.To4(); ip4 != nil {
					gw := make(net.IP, len(ip4))
					copy(gw, ip4)
					gw[3] = 1
					return gw, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("unable to determine default gateway")
}

// GetLocalSubnet returns the primary active IPv4 subnet on Windows.
func (p *WindowsPlatform) GetLocalSubnet() (*net.IPNet, error) {
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

// GetKernelARPCache extracts the kernel ARP table instantly using GetIpNetTable2 from iphlpapi.dll.
func (p *WindowsPlatform) GetKernelARPCache() ([]HostARPEntry, error) {
	var tablePtr *MIB_IPNET_TABLE2
	r, _, _ := procGetIpNetTable2.Call(
		uintptr(windows.AF_INET),
		uintptr(unsafe.Pointer(&tablePtr)),
	)
	if r != 0 || tablePtr == nil {
		return nil, fmt.Errorf("GetIpNetTable2 failed with code %d", r)
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(tablePtr)))

	var results []HostARPEntry
	numEntries := int(tablePtr.NumEntries)
	rowSize := unsafe.Sizeof(MIB_IPNET_ROW2{})
	firstRowPtr := uintptr(unsafe.Pointer(&tablePtr.Table[0]))

	for i := 0; i < numEntries; i++ {
		row := (*MIB_IPNET_ROW2)(unsafe.Pointer(firstRowPtr + uintptr(i)*rowSize))

		if row.PhysicalAddressLength == 6 && row.Address.Family == windows.AF_INET {
			ip := net.IPv4(row.Address.Data[2], row.Address.Data[3], row.Address.Data[4], row.Address.Data[5])
			mac := net.HardwareAddr(row.PhysicalAddress[:6])

			adapterName := fmt.Sprintf("if%d", row.InterfaceIndex)
			if ifi, err := net.InterfaceByIndex(int(row.InterfaceIndex)); err == nil {
				adapterName = ifi.Name
			}

			// State 4 = NlnsReachable, State 5 = NlnsPermanent
			isStatic := row.State == 5

			results = append(results, HostARPEntry{
				IP:       ip,
				MAC:      mac,
				Adapter:  adapterName,
				IsStatic: isStatic,
			})
		}
	}

	return results, nil
}

// ResolveBonjourServices stub on Windows.
func (p *WindowsPlatform) ResolveBonjourServices(timeout time.Duration) (map[string]string, error) {
	return make(map[string]string), nil
}
