//go:build !darwin

package platform

import (
	"context"
	"fmt"
)

type HelperClient struct{}

func NewHelperClient() *HelperClient {
	return &HelperClient{}
}

func (c *HelperClient) IsHelperAvailable() bool {
	return false
}

func (c *HelperClient) ExecutePrivileged(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return nil, fmt.Errorf("privileged helper is only supported on macOS Darwin")
}
