package identity

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// MulticastListener passively observes mDNS and SSDP broadcast announcements on local subnets.
type MulticastListener struct {
	mu           sync.RWMutex
	discovered   map[string]string // IP -> Identified Name/Server
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewMulticastListener initializes a passive multicast listener.
func NewMulticastListener() *MulticastListener {
	return &MulticastListener{
		discovered: make(map[string]string),
	}
}

// Start spawns background listeners for SSDP (239.255.255.250:1900) and mDNS (224.0.0.251:5353).
func (m *MulticastListener) Start(parentCtx context.Context) {
	m.mu.Lock()
	m.ctx, m.cancel = context.WithCancel(parentCtx)
	m.mu.Unlock()

	go m.listenSSDP()
	go m.listenMDNS()
}

// Stop shuts down the background multicast listeners.
func (m *MulticastListener) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
}

// GetDiscovered returns a copy of captured multicast identity observations.
func (m *MulticastListener) GetDiscovered() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make(map[string]string, len(m.discovered))
	for k, v := range m.discovered {
		res[k] = v
	}
	return res
}

func (m *MulticastListener) listenSSDP() {
	addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		srcIP, _, _ := net.SplitHostPort(src.String())
		content := string(buf[:n])

		// Look for SERVER: or LOCATION: headers in SSDP NOTIFY packets
		lines := strings.Split(content, "\r\n")
		for _, line := range lines {
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "server:") {
				val := strings.TrimSpace(line[len("server:"):])
				if val != "" {
					m.mu.Lock()
					if m.discovered[srcIP] == "" {
						m.discovered[srcIP] = val
					}
					m.mu.Unlock()
				}
			}
		}
	}
}

func (m *MulticastListener) listenMDNS() {
	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		srcIP, _, _ := net.SplitHostPort(src.String())
		// Scan for readable string names in mDNS query/reply packets (e.g. ._tcp.local, .local)
		pkt := string(buf[:n])
		if idx := strings.Index(pkt, ".local"); idx != -1 {
			// Extract printable prefix before .local
			start := idx
			for start > 0 && pkt[start-1] >= 0x20 && pkt[start-1] <= 0x7E {
				start--
			}
			candidate := strings.TrimSpace(pkt[start:idx])
			if len(candidate) > 2 && !strings.HasPrefix(candidate, "_") {
				m.mu.Lock()
				if m.discovered[srcIP] == "" {
					m.discovered[srcIP] = candidate + ".local"
				}
				m.mu.Unlock()
			}
		}
	}
}
