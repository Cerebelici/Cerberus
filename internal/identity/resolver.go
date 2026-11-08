package identity

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Classification contains high-fidelity device identity attributes inferred across multiple channels.
type Classification struct {
	FriendlyName string
	Hostname     string
	DeviceType   string
	OSFamily     string
	Manufacturer string
	Confidence   float64
}

// HostIdentityInput represents device observations collected from scanning stages.
type HostIdentityInput struct {
	IP             string
	MAC            string
	RespondedL2ARP bool
	OpenPorts      []int
	AllTcpwrapped  bool
	ExistingHost   string
	ExistingVendor string
}

// MultiChannelResolver orchestrates parallel resolution across Bonjour, NetBIOS,
// Router DNS/DHCP, UPnP, and Sleeping Mobile Heuristics.
type MultiChannelResolver struct {
	router    *RouterIntelligence
	multicast *MulticastListener
}

// NewMultiChannelResolver creates a new resolver orchestrator.
func NewMultiChannelResolver() *MultiChannelResolver {
	return &MultiChannelResolver{
		router:    NewRouterIntelligence(),
		multicast: NewMulticastListener(),
	}
}

// StartBackgroundListeners starts any long-running multicast listeners.
func (r *MultiChannelResolver) StartBackgroundListeners(ctx context.Context) {
	if r.multicast != nil {
		r.multicast.Start(ctx)
	}
}

// Stop terminates background listeners.
func (r *MultiChannelResolver) Stop() {
	if r.multicast != nil {
		r.multicast.Stop()
	}
}

// ResolveHost executes all identity channels for a specific host and returns enriched classification.
func (r *MultiChannelResolver) ResolveHost(ctx context.Context, input HostIdentityInput) Classification {
	var c Classification

	// -------------------------------------------------------------
	// Channel 4: Sleeping Mobile Heuristic Classifier
	// -------------------------------------------------------------
	// Criteria:
	// 1. Locally administered MAC (bit 1 == 1 in byte 0).
	// 2. Responded to L2 broadcast ARP.
	// 3. All ports closed (len(OpenPorts) == 0) or tcpwrapped.
	isLAA := IsLocallyAdministered(input.MAC)
	hasZeroOrWrappedPorts := len(input.OpenPorts) == 0 || input.AllTcpwrapped

	if isLAA && input.RespondedL2ARP && hasZeroOrWrappedPorts {
		c.DeviceType = "Mobile Smartphone (Sleeping / Power-Saving)"
		c.OSFamily = "Android / iOS"
		c.Confidence = 0.85
	}

	// -------------------------------------------------------------
	// Channels 1, 2, 3: Parallel Resolution (Bonjour, NetBIOS, Router PTR, UPnP)
	// -------------------------------------------------------------
	type channelResult struct {
		bonjourName string
		netbios     *NetBIOSInfo
		routerPTR   string
		upnp        *UPnPIdentity
	}

	var res channelResult
	var wg sync.WaitGroup

	// Channel 2: NetBIOS (UDP 137)
	wg.Add(1)
	go func() {
		defer wg.Done()
		nbCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
		defer cancel()
		nb, err := QueryNetBIOS(nbCtx, input.IP, 500*time.Millisecond)
		if err == nil && nb != nil {
			res.netbios = nb
		}
	}()

	// Channel 3: Router PTR Query
	wg.Add(1)
	go func() {
		defer wg.Done()
		ptrCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
		defer cancel()
		if r.router != nil {
			name, err := r.router.QueryGatewayPTR(ptrCtx, input.IP)
			if err == nil && name != "" {
				res.routerPTR = name
			}
		}
	}()

	// Channel UPnP: If any web/UPnP ports are open
	if len(input.OpenPorts) > 0 {
		var candidatePorts []int
		for _, p := range input.OpenPorts {
			if p == 80 || p == 8080 || p == 5000 || p == 8008 || p == 8009 || p == 49152 || p == 49153 {
				candidatePorts = append(candidatePorts, p)
			}
		}
		if len(candidatePorts) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				upnpCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
				defer cancel()
				u, err := QueryUPnPEndpoint(upnpCtx, input.IP, candidatePorts, 800*time.Millisecond)
				if err == nil && u != nil {
					res.upnp = u
				}
			}()
		}
	}

	wg.Wait()

	// Check multicast sniffer cache
	if r.multicast != nil {
		cached := r.multicast.GetDiscovered()
		if name, ok := cached[input.IP]; ok && name != "" {
			if c.FriendlyName == "" {
				c.FriendlyName = name
			}
		}
	}

	// Synthesize findings
	if res.netbios != nil && res.netbios.ComputerName != "" {
		c.Hostname = res.netbios.ComputerName
		c.FriendlyName = res.netbios.ComputerName
		if c.OSFamily == "" {
			c.OSFamily = "Windows / Samba"
		}
		if c.DeviceType == "" {
			c.DeviceType = "Workstation / PC"
		}
		c.Confidence = 0.95
	}

	if res.upnp != nil {
		if res.upnp.FriendlyName != "" {
			c.FriendlyName = res.upnp.FriendlyName
		}
		if res.upnp.Manufacturer != "" {
			c.Manufacturer = res.upnp.Manufacturer
		}
		if res.upnp.DeviceType != "" && c.DeviceType == "" {
			c.DeviceType = res.upnp.DeviceType
		}
		if res.upnp.HTMLTitle != "" && c.FriendlyName == "" {
			c.FriendlyName = res.upnp.HTMLTitle
		}
	}

	if res.routerPTR != "" {
		if c.Hostname == "" {
			c.Hostname = res.routerPTR
		}
		if c.FriendlyName == "" {
			c.FriendlyName = res.routerPTR
		}
	}

	if c.Hostname == "" && input.ExistingHost != "" {
		c.Hostname = input.ExistingHost
	}
	if c.FriendlyName == "" && c.Hostname != "" {
		c.FriendlyName = c.Hostname
	}
	if c.Manufacturer == "" && input.ExistingVendor != "" {
		c.Manufacturer = input.ExistingVendor
	}

	return c
}

// ResolveBatch executes resolution concurrently across a slice of hosts.
func (r *MultiChannelResolver) ResolveBatch(ctx context.Context, hosts []HostIdentityInput) map[string]Classification {
	results := make(map[string]Classification)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fetch Bonjour mappings once for batch
	bonjourMap, _ := ResolveBonjourChannel(ctx, 1500*time.Millisecond)

	semaphore := make(chan struct{}, 16)

	for _, h := range hosts {
		semaphore <- struct{}{}
		wg.Add(1)

		go func(host HostIdentityInput) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			cl := r.ResolveHost(ctx, host)
			if bName, ok := bonjourMap[host.IP]; ok && bName != "" {
				if cl.FriendlyName == "" || strings.HasSuffix(bName, ".local") {
					cl.FriendlyName = bName
				}
				if cl.OSFamily == "" && (strings.Contains(bName, "Apple") || strings.Contains(bName, "iPhone") || strings.Contains(bName, "Mac")) {
					cl.OSFamily = "Apple macOS / iOS"
				}
			}

			mu.Lock()
			results[host.IP] = cl
			mu.Unlock()
		}(h)
	}

	wg.Wait()
	return results
}
