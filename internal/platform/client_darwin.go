//go:build darwin

package platform

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

const HelperSocketPath = "/var/run/com.cerberus.helper.sock"

// HelperClient provides IPC communication to the privileged helper daemon.
type HelperClient struct {
	socketPath string
}

// NewHelperClient creates an IPC client instance.
func NewHelperClient() *HelperClient {
	sock := HelperSocketPath
	if env := os.Getenv("CERBERUS_HELPER_SOCK"); env != "" {
		sock = env
	}
	return &HelperClient{socketPath: sock}
}

// IsHelperAvailable checks if the root helper daemon is running and reachable.
func (c *HelperClient) IsHelperAvailable() bool {
	conn, err := net.DialTimeout("unix", c.socketPath, 300*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send Ping
	req := map[string]any{
		"id":     "ping",
		"method": "Ping",
	}
	data, _ := json.Marshal(req)
	data = append(data, '\n')
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(data); err != nil {
		return false
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return false
	}

	var resp struct {
		Result map[string]string `json:"result"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return false
	}
	return resp.Result["status"] == "ok"
}

// ExecutePrivileged sends command execution request to root helper daemon.
func (c *HelperClient) ExecutePrivileged(ctx context.Context, binary string, args ...string) ([]byte, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to privileged helper: %w", err)
	}
	defer conn.Close()

	req := map[string]any{
		"id":     "exec",
		"method": "Execute",
		"params": map[string]any{
			"binary": binary,
			"args":   args,
		},
	}
	data, _ := json.Marshal(req)
	data = append(data, '\n')

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("sending execution request to helper: %w", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("reading response from helper: %w", err)
	}

	var resp struct {
		Result struct {
			Output string `json:"output"`
		} `json:"result"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("decoding helper response: %w", err)
	}

	if resp.Error != "" {
		return []byte(resp.Result.Output), fmt.Errorf("privileged helper error: %s", resp.Error)
	}

	return []byte(resp.Result.Output), nil
}
