package identity

import (
	"context"
	"time"

	"github.com/gr0gu/cerberus/internal/platform"
)

// ResolveBonjourChannel interrogates the local mDNS daemon (Apple mDNSResponder on Darwin,
// Avahi on Linux) to map discovered service instances directly to local IPv4 endpoints.
func ResolveBonjourChannel(ctx context.Context, timeout time.Duration) (map[string]string, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	p := platform.GetDefaultProvider()
	if p == nil {
		return make(map[string]string), nil
	}

	return p.ResolveBonjourServices(timeout)
}
