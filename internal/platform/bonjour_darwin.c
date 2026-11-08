//go:build darwin && cgo

#include "bonjour_darwin.h"
#include "_cgo_export.h"
#include <poll.h>
#include <stdlib.h>

static void c_browse_reply(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                           DNSServiceErrorType errorCode, const char *serviceName,
                           const char *regtype, const char *replyDomain, void *context) {
    browseCallback(sdRef, (uint32_t)flags, interfaceIndex, (int32_t)errorCode,
                   (char*)serviceName, (char*)regtype, (char*)replyDomain, context);
}

static void c_resolve_reply(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                            DNSServiceErrorType errorCode, const char *fullname,
                            const char *hosttarget, uint16_t port, uint16_t txtLen,
                            const unsigned char *txtRecord, void *context) {
    resolveCallback(sdRef, (uint32_t)flags, interfaceIndex, (int32_t)errorCode,
                    (char*)fullname, (char*)hosttarget, (uint16_t)port, context);
}

static void c_addr_reply(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                         DNSServiceErrorType errorCode, const char *hostname,
                         const struct sockaddr *address, uint32_t ttl, void *context) {
    addrCallback(sdRef, (uint32_t)flags, interfaceIndex, (int32_t)errorCode,
                 (char*)hostname, (struct sockaddr*)address, ttl, context);
}

DNSServiceErrorType cerberus_start_browse(DNSServiceRef *ref, const char *regtype, void *ctx) {
    return DNSServiceBrowse(ref, 0, 0, regtype, NULL, c_browse_reply, ctx);
}

DNSServiceErrorType cerberus_start_resolve(DNSServiceRef *ref, uint32_t ifIndex, const char *name, const char *regtype, const char *domain, void *ctx) {
    return DNSServiceResolve(ref, 0, ifIndex, name, regtype, domain, c_resolve_reply, ctx);
}

DNSServiceErrorType cerberus_start_addrinfo(DNSServiceRef *ref, uint32_t ifIndex, const char *hostname, void *ctx) {
    return DNSServiceGetAddrInfo(ref, 0, ifIndex, kDNSServiceProtocol_IPv4, hostname, c_addr_reply, ctx);
}

int cerberus_poll_and_process(DNSServiceRef ref, int timeoutMs) {
    int fd = DNSServiceRefSockFD(ref);
    if (fd < 0) return -1;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int res = poll(&pfd, 1, timeoutMs);
    if (res > 0 && (pfd.revents & POLLIN)) {
        if (DNSServiceProcessResult(ref) == kDNSServiceErr_NoError) {
            return 1;
        }
    }
    return res;
}
