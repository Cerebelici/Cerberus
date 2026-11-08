package platform

import (
	"net"
	"time"
)

// HostARPEntry represents a neighbor/ARP entry in the kernel table.
type HostARPEntry struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Adapter  string
	IsStatic bool
}

// PlatformProvider defines the unified cross-platform interface for low-level OS network operations.
type PlatformProvider interface {
	GetGatewayIP() (net.IP, error)
	GetLocalSubnet() (*net.IPNet, error)
	GetKernelARPCache() ([]HostARPEntry, error)
	ResolveBonjourServices(timeout time.Duration) (map[string]string, error)
}

var currentProvider PlatformProvider

// SetDefaultProvider registers the active platform provider.
func SetDefaultProvider(p PlatformProvider) {
	currentProvider = p
}

// GetDefaultProvider returns the active platform provider.
func GetDefaultProvider() PlatformProvider {
	return currentProvider
}
