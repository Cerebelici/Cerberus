//go:build !darwin && !linux && !windows

package platform

import (
	"fmt"
	"net"
	"time"
)

type GenericPlatform struct{}

func init() {
	SetDefaultProvider(&GenericPlatform{})
}

func (p *GenericPlatform) GetGatewayIP() (net.IP, error) {
	return nil, fmt.Errorf("platform not supported")
}

func (p *GenericPlatform) GetLocalSubnet() (*net.IPNet, error) {
	return nil, fmt.Errorf("platform not supported")
}

func (p *GenericPlatform) GetKernelARPCache() ([]HostARPEntry, error) {
	return nil, fmt.Errorf("platform not supported")
}

func (p *GenericPlatform) ResolveBonjourServices(timeout time.Duration) (map[string]string, error) {
	return make(map[string]string), nil
}
