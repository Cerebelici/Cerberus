#ifndef BONJOUR_DARWIN_H
#define BONJOUR_DARWIN_H

#include <dns_sd.h>
#include <stdint.h>

DNSServiceErrorType cerberus_start_browse(DNSServiceRef *ref, const char *regtype, void *ctx);
DNSServiceErrorType cerberus_start_resolve(DNSServiceRef *ref, uint32_t ifIndex, const char *name, const char *regtype, const char *domain, void *ctx);
DNSServiceErrorType cerberus_start_addrinfo(DNSServiceRef *ref, uint32_t ifIndex, const char *hostname, void *ctx);
int cerberus_poll_and_process(DNSServiceRef ref, int timeoutMs);

#endif
