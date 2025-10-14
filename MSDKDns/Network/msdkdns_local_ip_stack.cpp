// Tencent is pleased to support the open source community by making Mars available.
// Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.

// Licensed under the MIT License (the "License"); you may not use this file except in
// compliance with the License. You may obtain a copy of the License at
// http://opensource.org/licenses/MIT

// Unless required by applicable law or agreed to in writing, software distributed under the License is
// distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific language governing permissions and
// limitations under the License.


#include "msdkdns_local_ip_stack.h"
#include <strings.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../MSDKDnsLog.h"

/*
 * Connect a UDP socket to a given unicast address. This will cause no network
 * traffic, but will fail fast if the system has no or limited reachability to
 * the destination (e.g., no IPv4 address, no IPv6 default route, ...).
 */
static const unsigned int kMaxLoopCount = 10;

static int msdkdns_test_connect(int pf, struct sockaddr * addr, size_t addrlen) {
    int s = socket(pf, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        return 0;
    }
    int ret;
    unsigned int loop_count = 0;
    do {
        ret = connect(s, addr, addrlen);
    } while (ret < 0 && errno == EINTR && loop_count++ < kMaxLoopCount);
    if (loop_count >= kMaxLoopCount) {
        MSDKDNSLOG(@"connect error. loop_count = %d", loop_count);
    }
    int success = (ret == 0);
    loop_count = 0;
    do {
        ret = close(s);
    } while (ret < 0 && errno == EINTR && loop_count++ < kMaxLoopCount);
    if (loop_count >= kMaxLoopCount) {
        MSDKDNSLOG(@"close error. loop_count = %d", loop_count);
    }
    return success;
}

/*
 * Check if IPv6 address is a DNS64/NAT64 synthesized address
 * DNS64 addresses typically have a 64:ff9b::/96 prefix
 */
static int msdkdns_is_dns64_address(const struct sockaddr_in6* addr6) {
    if (addr6 == NULL) return 0;
    
    const uint8_t* addr_bytes = addr6->sin6_addr.s6_addr;
    
    // Check for standard DNS64 prefix (64:ff9b::/96)
    if (addr_bytes[0] == 0x64 && addr_bytes[1] == 0xff && addr_bytes[2] == 0x9b && addr_bytes[3] == 0x00) {
        return 1;
    }
    
    // Check for other common DNS64 prefixes
    // 64:ff9b:1::/48
    if (addr_bytes[0] == 0x64 && addr_bytes[1] == 0xff && addr_bytes[2] == 0x9b && addr_bytes[3] == 0x01) {
        return 1;
    }
    
    // Check for well-known prefix patterns used by some operators
    // Look for patterns that suggest DNS64 translation
    if (addr_bytes[0] == 0x20 && addr_bytes[1] == 0x01 && addr_bytes[2] == 0x00 && 
        (addr_bytes[3] & 0xFC) == 0x00) {
        // This might be a 2001:0::/32 prefix used by some DNS64 implementations
        return 1;
    }
    
    return 0;
}

/*
 * Check if interface is a tunnel/virtual interface that might provide false IPv6 connectivity
 */
static int msdkdns_is_tunnel_interface(const char* ifname) {
    if (ifname == NULL) return 0;
    
    // Common tunnel interface prefixes
    if (strncmp(ifname, "tun", 3) == 0) return 1;
    if (strncmp(ifname, "utun", 4) == 0) return 1;
    if (strncmp(ifname, "ipsec", 5) == 0) return 1;
    if (strncmp(ifname, "ppp", 3) == 0) return 1;
    
    return 0;
}

/*
 * Check local network interfaces for actual IP stack configuration
 * This provides more accurate detection than UDP connectivity tests
 */
static int msdkdns_check_local_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    int has_ipv4 = 0;
    int has_ipv6 = 0;
    int has_native_ipv6 = 0;
    
    if (getifaddrs(&ifaddr) == -1) {
        MSDKDNSLOG(@"getifaddrs failed");
        return 0;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        int family = ifa->ifa_addr->sa_family;
        
        // Skip loopback, non-active interfaces, and tunnel interfaces
        if ((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_LOOPBACK) || 
            msdkdns_is_tunnel_interface(ifa->ifa_name)) {
            continue;
        }
        
        if (family == AF_INET) {
            has_ipv4 = 1;
        } else if (family == AF_INET6) {
            has_ipv6 = 1;
            
            // Check if this is a native IPv6 address (not DNS64)
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)ifa->ifa_addr;
            if (!msdkdns_is_dns64_address(addr6)) {
                has_native_ipv6 = 1;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    
    // Return bitmask: IPv4(1) | IPv6(2) | NativeIPv6(4)
    int result = 0;
    if (has_ipv4) result |= 1;
    if (has_ipv6) result |= 2;
    if (has_native_ipv6) result |= 4;
    
    return result;
}

/*
 * Improved IPv6 detection that distinguishes between native IPv6 and DNS64/NAT64
 */
static int msdkdns_have_ipv6_improved() {
    // First check local interfaces for actual IPv6 configuration
    int interface_flags = msdkdns_check_local_interfaces();
    int has_ipv6_interfaces = (interface_flags & 2) != 0;
    int has_native_ipv6 = (interface_flags & 4) != 0;
    
    MSDKDNSLOG(@"Interface check: IPv6=%d, NativeIPv6=%d", has_ipv6_interfaces, has_native_ipv6);
    
    // If we have native IPv6 interfaces, do a connectivity test
    if (has_native_ipv6) {
        static struct sockaddr_in6 sin6_test = {0};
        sin6_test.sin6_family = AF_INET6;
        sin6_test.sin6_port = 80;
        sin6_test.sin6_flowinfo = 0;
        sin6_test.sin6_scope_id = 0;
        bzero(sin6_test.sin6_addr.s6_addr, sizeof(sin6_test.sin6_addr.s6_addr));
        
        // Use complete Google IPv6 DNS address (2001:4860:4860::8888)
        sin6_test.sin6_addr.s6_addr[0] = 0x20;
        sin6_test.sin6_addr.s6_addr[1] = 0x01;
        sin6_test.sin6_addr.s6_addr[2] = 0x48;
        sin6_test.sin6_addr.s6_addr[3] = 0x60;
        sin6_test.sin6_addr.s6_addr[4] = 0x48;
        sin6_test.sin6_addr.s6_addr[5] = 0x60;
        sin6_test.sin6_addr.s6_addr[15] = 0x88;  // ::8888
        
        msdkdns::msdkdns_sockaddr_union addr = {.msdkdns_in6 = sin6_test};
        return msdkdns_test_connect(PF_INET6, &addr.msdkdns_generic, sizeof(addr.msdkdns_in6));
    }
    
    // If we only have DNS64/NAT64 interfaces, be more conservative
    if (has_ipv6_interfaces && !has_native_ipv6) {
        MSDKDNSLOG(@"DNS64/NAT64 environment detected, IPv6 support limited");
        return 0; // Treat DNS64/NAT64 as limited IPv6 support
    }
    
    return 0;
}

static int msdkdns_have_ipv4() {
    static struct sockaddr_in sin_test = {0};
    sin_test.sin_family = AF_INET;
    sin_test.sin_port = 80;
    sin_test.sin_addr.s_addr = htonl(0x08080808L);  // 8.8.8.8
    // union
    msdkdns::msdkdns_sockaddr_union addr = {.msdkdns_in = sin_test};
    return msdkdns_test_connect(PF_INET, &addr.msdkdns_generic, sizeof(addr.msdkdns_in));
}

msdkdns::MSDKDNS_TLocalIPStack msdkdns::msdkdns_detect_local_ip_stack() {
    MSDKDNSLOG(@"detect local ip stack");
    
    // Use improved detection that considers DNS64/NAT64 environments
    int have_ipv4 = msdkdns_have_ipv4();
    int have_ipv6 = msdkdns_have_ipv6_improved();
    
    int local_stack = 0;
    if (have_ipv4) {
        local_stack |= msdkdns::MSDKDNS_ELocalIPStack_IPv4;
    }
    if (have_ipv6) {
        local_stack |= msdkdns::MSDKDNS_ELocalIPStack_IPv6;
    }
    
    MSDKDNSLOG(@"improved detection: have_ipv4=%d have_ipv6=%d", have_ipv4, have_ipv6);
    return (msdkdns::MSDKDNS_TLocalIPStack) local_stack;
}
