package identity

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/platform"
)

// RouterIntelligence queries gateway services to uncover hostnames and DHCP leases.
type RouterIntelligence struct {
	GatewayIP net.IP
}

// NewRouterIntelligence initializes gateway intelligence.
func NewRouterIntelligence() *RouterIntelligence {
	p := platform.GetDefaultProvider()
	var gw net.IP
	if p != nil {
		gw, _ = p.GetGatewayIP()
	}
	return &RouterIntelligence{GatewayIP: gw}
}

// QueryGatewayPTR performs a reverse DNS PTR query directly directed at the router DNS server.
func (r *RouterIntelligence) QueryGatewayPTR(ctx context.Context, targetIP string) (string, error) {
	gw := r.GatewayIP
	if gw == nil {
		p := platform.GetDefaultProvider()
		if p != nil {
			gw, _ = p.GetGatewayIP()
		}
	}
	if gw == nil {
		// Fall back to standard reverse lookup
		names, err := net.DefaultResolver.LookupAddr(ctx, targetIP)
		if err == nil && len(names) > 0 {
			return strings.TrimSuffix(names[0], "."), nil
		}
		return "", err
	}

	// Use custom resolver directed at the gateway DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 500 * time.Millisecond}
			return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", gw.String()))
		},
	}

	names, err := resolver.LookupAddr(ctx, targetIP)
	if err != nil || len(names) == 0 {
		return "", err
	}

	cleaned := strings.TrimSuffix(names[0], ".")
	return cleaned, nil
}

// ScrapeRouterLeases attempts to query UPnP IGD / HTTP endpoints on the gateway for DHCP lease tables.
func (r *RouterIntelligence) ScrapeRouterLeases(ctx context.Context) (map[string]string, error) {
	leases := make(map[string]string)
	if r.GatewayIP == nil {
		return leases, nil
	}

	gwStr := r.GatewayIP.String()
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// Probe common UPnP IGD description paths
	paths := []string{
		fmt.Sprintf("http://%s:1900/rootDesc.xml", gwStr),
		fmt.Sprintf("http://%s:49152/wps_device.xml", gwStr),
		fmt.Sprintf("http://%s:5000/rootDesc.xml", gwStr),
		fmt.Sprintf("http://%s/igd.xml", gwStr),
	}

	for _, url := range paths {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		_ = resp.Body.Close()

		if len(body) > 0 && strings.Contains(string(body), "device") {
			// Found UPnP description, extract model/friendly name
			model := extractXMLTag(string(body), "friendlyName")
			if model != "" {
				leases[gwStr] = model
				break
			}
		}
	}

	return leases, nil
}

func extractXMLTag(data, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(data, open)
	if start == -1 {
		return ""
	}
	start += len(open)
	end := strings.Index(data[start:], close)
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(data[start : start+end])
}
