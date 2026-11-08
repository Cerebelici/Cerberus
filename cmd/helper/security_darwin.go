//go:build darwin

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// VerifyPeerCredentials inspects the unix domain socket peer credentials.
func VerifyPeerCredentials(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("connection is not a unix domain socket")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("retrieving syscall connection: %w", err)
	}

	var uid uint32
	var credErr error

	err = raw.Control(func(fd uintptr) {
		xucred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = xucred.Uid
	})

	if err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, fmt.Errorf("reading peer credentials: %w", credErr)
	}

	return uid, nil
}
