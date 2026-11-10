//go:build darwin && cgo

package platform

/*
#cgo darwin LDFLAGS: -framework CoreFoundation
#include "bonjour_darwin.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type DarwinPlatform struct{}

func init() {
	SetDefaultProvider(&DarwinPlatform{})
}

// GetGatewayIP queries the kernel routing table for the default gateway.
func (p *DarwinPlatform) GetGatewayIP() (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "gateway:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ip := net.ParseIP(fields[1])
					if ip != nil {
						return ip, nil
					}
				}
			}
		}
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ip4 := ipNet.IP.To4(); ip4 != nil {
						gw := make(net.IP, len(ip4))
						copy(gw, ip4)
						gw[3] = 1
						return gw, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("unable to determine default gateway")
}

// GetLocalSubnet returns the primary active IPv4 subnet.
func (p *DarwinPlatform) GetLocalSubnet() (*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					return ipNet, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no active IPv4 subnet found")
}

// GetKernelARPCache extracts the kernel ARP cache directly from Darwin BSD memory using sysctl(NET_RT_DUMP).
func (p *DarwinPlatform) GetKernelARPCache() ([]HostARPEntry, error) {
	var entries []HostARPEntry

	mib := [6]C.int{
		C.CTL_NET,
		C.PF_ROUTE,
		0,
		C.AF_INET,
		C.NET_RT_FLAGS,
		C.RTF_LLINFO,
	}

	var needed C.size_t
	if C.sysctl(&mib[0], 6, nil, &needed, nil, 0) < 0 || needed == 0 {
		return p.fallbackKernelARPCache()
	}

	buf := make([]byte, needed)
	if C.sysctl(&mib[0], 6, unsafe.Pointer(&buf[0]), &needed, nil, 0) < 0 {
		return p.fallbackKernelARPCache()
	}

	// Walk the routing messages by offset into buf instead of converting uintptr
	// addresses back to pointers, which would hide the buffer from the garbage
	// collector and trip the unsafe.Pointer checks.
	offset := uintptr(0)
	bufLen := uintptr(len(buf))
	for offset+unsafe.Sizeof(C.struct_rt_msghdr{}) <= bufLen {
		rtm := (*C.struct_rt_msghdr)(unsafe.Pointer(&buf[offset]))
		msgLen := uintptr(rtm.rtm_msglen)
		if msgLen == 0 || offset+msgLen > bufLen {
			break
		}

		sinOff := offset + unsafe.Sizeof(*rtm)
		if sinOff+unsafe.Sizeof(C.struct_sockaddr_in{}) > bufLen {
			break
		}
		sin := (*C.struct_sockaddr_in)(unsafe.Pointer(&buf[sinOff]))
		sinLen := uintptr(sin.sin_len)
		if sinLen == 0 {
			sinLen = unsafe.Sizeof(C.struct_sockaddr_in{})
		}

		sdlOff := sinOff + sinLen
		if sdlOff+unsafe.Sizeof(C.struct_sockaddr_dl{}) > bufLen {
			break
		}
		sdl := (*C.struct_sockaddr_dl)(unsafe.Pointer(&buf[sdlOff]))

		if sdl.sdl_alen == 6 {
			ipBytes := (*[4]byte)(unsafe.Pointer(&sin.sin_addr.s_addr))
			ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

			macPtr := unsafe.Add(unsafe.Pointer(&sdl.sdl_data[0]), uintptr(sdl.sdl_nlen))
			macSlice := C.GoBytes(macPtr, 6)
			mac := net.HardwareAddr(macSlice)

			adapter := C.GoStringN(&sdl.sdl_data[0], C.int(sdl.sdl_nlen))
			isStatic := (rtm.rtm_flags & C.RTF_STATIC) != 0

			entries = append(entries, HostARPEntry{
				IP:       ip,
				MAC:      mac,
				Adapter:  adapter,
				IsStatic: isStatic,
			})
		}

		offset += msgLen
	}

	if len(entries) == 0 {
		return p.fallbackKernelARPCache()
	}

	return entries, nil
}

func (p *DarwinPlatform) fallbackKernelARPCache() ([]HostARPEntry, error) {
	out, err := exec.Command("/usr/sbin/arp", "-an").Output()
	if err != nil {
		return nil, fmt.Errorf("sysctl and arp fallback failed: %w", err)
	}

	var results []HostARPEntry
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, " at ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			ipStr := strings.Trim(parts[1], "()")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			macStr := parts[3]
			mac, err := net.ParseMAC(macStr)
			if err != nil {
				continue
			}
			adapter := ""
			for i, p := range parts {
				if p == "on" && i+1 < len(parts) {
					adapter = parts[i+1]
					break
				}
			}
			results = append(results, HostARPEntry{
				IP:       ip,
				MAC:      mac,
				Adapter:  adapter,
				IsStatic: strings.Contains(line, "permanent") || strings.Contains(line, "static"),
			})
		}
	}
	return results, nil
}

var (
	bonjourMu       sync.Mutex
	activeResolvers = make(map[uintptr]*bonjourContext)
	resolverCounter uintptr
)

type bonjourContext struct {
	results map[string]string
	ctx     context.Context
}

//export browseCallback
func browseCallback(ref unsafe.Pointer, flags uint32, ifIndex uint32, errorCode int32,
	serviceName *C.char, regtype *C.char, domain *C.char, ctx unsafe.Pointer) {
	if errorCode != 0 || (flags&1) == 0 { // 1 = kDNSServiceFlagsAdd
		return
	}
	name := C.GoString(serviceName)
	rt := C.GoString(regtype)
	dom := C.GoString(domain)

	var resolveRef C.DNSServiceRef
	cName := C.CString(name)
	cRt := C.CString(rt)
	cDom := C.CString(dom)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cRt))
	defer C.free(unsafe.Pointer(cDom))

	err := C.cerberus_start_resolve(&resolveRef, C.uint32_t(ifIndex), cName, cRt, cDom, ctx)
	if err == 0 {
		C.cerberus_poll_and_process(resolveRef, 250)
		C.DNSServiceRefDeallocate(resolveRef)
	}
}

//export resolveCallback
func resolveCallback(ref unsafe.Pointer, flags uint32, ifIndex uint32, errorCode int32,
	fullname *C.char, hosttarget *C.char, port uint16, ctx unsafe.Pointer) {
	if errorCode != 0 {
		return
	}
	target := C.GoString(hosttarget)
	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	var addrRef C.DNSServiceRef
	err := C.cerberus_start_addrinfo(&addrRef, C.uint32_t(ifIndex), cTarget, ctx)
	if err == 0 {
		C.cerberus_poll_and_process(addrRef, 250)
		C.DNSServiceRefDeallocate(addrRef)
	}
}

//export addrCallback
func addrCallback(ref unsafe.Pointer, flags uint32, ifIndex uint32, errorCode int32,
	hostname *C.char, address *C.struct_sockaddr, ttl uint32, ctx unsafe.Pointer) {
	if errorCode != 0 || address == nil {
		return
	}
	if address.sa_family == C.AF_INET {
		sin := (*C.struct_sockaddr_in)(unsafe.Pointer(address))
		ipBytes := (*[4]byte)(unsafe.Pointer(&sin.sin_addr.s_addr))
		ipStr := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]).String()

		bonjourMu.Lock()
		bCtx, ok := activeResolvers[*(*uintptr)(ctx)]
		if ok && bCtx != nil {
			name := strings.TrimSuffix(C.GoString(hostname), ".")
			bCtx.results[ipStr] = name
		}
		bonjourMu.Unlock()
	}
}

// ResolveBonjourServices browses and resolves native macOS Bonjour services via <dns_sd.h>.
func (p *DarwinPlatform) ResolveBonjourServices(timeout time.Duration) (map[string]string, error) {
	results := make(map[string]string)
	serviceTypes := []string{
		"_companion-link._tcp",
		"_airplay._tcp",
		"_raop._tcp",
		"_googlecast._tcp",
		"_http._tcp",
	}

	// The DNS-SD callback receives its context as an opaque void* and must not receive a
	// Go pointer, because the pointer outlives the call that passes it. Store the lookup
	// key in C memory and free it once every browse/poll call has finished.
	idMem := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	if idMem == nil {
		return nil, fmt.Errorf("allocating Bonjour resolver context")
	}
	defer C.free(idMem)

	bonjourMu.Lock()
	resolverCounter++
	id := resolverCounter
	bCtx := &bonjourContext{
		results: results,
	}
	activeResolvers[id] = bCtx
	bonjourMu.Unlock()
	*(*uintptr)(idMem) = id

	defer func() {
		bonjourMu.Lock()
		delete(activeResolvers, id)
		bonjourMu.Unlock()
	}()

	deadline := time.Now().Add(timeout)
	for _, st := range serviceTypes {
		if time.Now().After(deadline) {
			break
		}
		var browseRef C.DNSServiceRef
		cType := C.CString(st)
		err := C.cerberus_start_browse(&browseRef, cType, idMem)
		C.free(unsafe.Pointer(cType))

		if err == 0 {
			remaining := time.Until(deadline)
			stepTimeout := int(remaining.Milliseconds()) / len(serviceTypes)
			if stepTimeout < 100 {
				stepTimeout = 100
			}
			C.cerberus_poll_and_process(browseRef, C.int(stepTimeout))
			C.DNSServiceRefDeallocate(browseRef)
		}
	}

	return results, nil
}
