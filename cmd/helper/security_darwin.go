//go:build darwin

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// desiredFileLimit is high enough for RustScan's 4,500-socket batches plus its
// runtime descriptors. launchd launches daemons with a soft limit of 256, which
// silently serialises scans and makes a full 65,535-port sweep take minutes.
const desiredFileLimit = 65535

// RaiseFileLimit lifts the soft RLIMIT_NOFILE to desiredFileLimit or the hard
// limit, whichever is lower. The helper runs as root, so it may exceed the low
// soft limit launchd assigns.
//
// This must use syscall.Setrlimit rather than unix.Setrlimit: the standard
// library version also clears syscall.origRlimitNofile, which is what os/exec
// otherwise restores in every child. Without that, the helper itself would have
// a high limit but RustScan and nmap would still inherit launchd's 256.
func RaiseFileLimit() {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		log.Printf("[Helper] could not read RLIMIT_NOFILE: %v", err)
		return
	}

	target := uint64(desiredFileLimit)
	if target < lim.Cur {
		target = lim.Cur
	}
	if lim.Max != syscall.RLIM_INFINITY && lim.Max < target {
		// As root the hard limit can be raised; a non-root helper cannot, so
		// clamp to what the process is allowed to request.
		if os.Geteuid() == 0 {
			lim.Max = target
		} else {
			target = lim.Max
		}
	}

	previous := lim.Cur
	lim.Cur = target
	// Always call syscall.Setrlimit, even when Cur is already high enough: the
	// call also clears the pre-runtime limit that os/exec would otherwise
	// restore in every child process.
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		log.Printf("[Helper] could not raise RLIMIT_NOFILE to %d: %v", target, err)
		return
	}
	if previous != target {
		log.Printf("[Helper] RLIMIT_NOFILE raised from %d to %d", previous, target)
	} else {
		log.Printf("[Helper] RLIMIT_NOFILE confirmed at %d", target)
	}
}

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
