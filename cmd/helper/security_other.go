//go:build !darwin

package main

import (
	"net"
)

// VerifyPeerCredentials stub for non-Darwin platforms.
func VerifyPeerCredentials(conn net.Conn) (uint32, error) {
	return 0, nil
}

// RaiseFileLimit is a no-op outside macOS.
func RaiseFileLimit() {}
