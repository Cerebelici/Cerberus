package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// RootExecutor executes privileged commands directly as root (UID 0).
type RootExecutor struct {
	mu sync.Mutex
}

// NewRootExecutor creates an executor instance.
func NewRootExecutor() *RootExecutor {
	return &RootExecutor{}
}

// Execute runs the specified binary with args and returns stdout/stderr.
func (e *RootExecutor) Execute(ctx context.Context, binary string, args ...string) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("command '%s %s' failed: %w (stderr: %s)",
			binary, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
