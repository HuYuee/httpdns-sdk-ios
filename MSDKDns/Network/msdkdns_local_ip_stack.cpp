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

/*
 * Check if we are in a DNS64/NAT64 environment.
 * Returns true if NAT64 prefix is detected.
 */
static bool msdkdns_is_nat64_environment(const struct in6_addr *addr) {
    // RFC 6052: Well-Known Prefix 64:ff9b::/96
    if (addr->s6_addr[0] == 0x00 && 
        addr->s6_addr[1] == 0x64 &&
        addr->s6_addr[2] == 0xff &&
        addr->s6_addr[3] == 0x9b &&
        addr->s6_addr[4] == 0x00 &&
        addr->s6_addr[5] == 0x00 &&
        addr->s6_addr[6] == 0x00 &&
        addr->s6_addr[7] == 0x00 &&
        addr->s6_addr[8] == 0x00 &&
        addr->s6_addr[9] == 0x00 &&
        addr->s6_addr[10] == 0x00 &&
        addr->s6_addr[11] == 0x00) {
        return true;
    }
    
    // Additional common NAT64 prefixes
    // 64:ff9b:1::/48 (RFC 8215)
    if (addr->s6_addr[0] == 0x00 && 
        addr->s6_addr[1] == 0x64 &&
        addr->s6_addr[2] == 0xff &&
        addr->s6_addr[3] == 0x9b &&
        addr->s6_addr[4] == 0x00 &&
        addr->s6_addr[5] == 0x01) {
        return true;
    }
    
    // Some carriers use custom NAT64 prefixes like 2001:db8::/32
    // However, we only check well-known prefixes to avoid false positives
    
    return false;
}

/*
 * Check interface status for both IPv4 and IPv6 in a single pass.
 * This is more efficient than calling getifaddrs() twice.
 * 
 * @param ipv4_result Output: IPv4 interface status (1 if found, 0 otherwise)
 * @param ipv6_result Output: IPv6 interface status (2=global, 1=limited, 0=none/NAT64-only)
 */
static void msdkdns_check_interfaces(int *ipv4_result, int *ipv6_result) {
    struct ifaddrs *ifaddr, *ifa;
    *ipv4_result = 0;
    *ipv6_result = 0;
    bool has_nat64 = false;
    
    if (getifaddrs(&ifaddr) == -1) {
        MSDKDNSLOG(@"getifaddrs failed, errno=%d", errno);
        return;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        
        // Skip loopback and down interfaces
        if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }
        
        // Check IPv4
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)ifa->ifa_addr;
            uint32_t ip = ntohl(addr4->sin_addr.s_addr);
            
            // Skip special-use addresses
            if ((ip >> 24) == 0 ||      // 0.0.0.0/8
                (ip >> 24) == 127 ||     // 127.0.0.0/8
                (ip >> 16) == 0xA9FE) {  // 169.254.0.0/16
                continue;
            }
            
            if (*ipv4_result == 0) {  // Only log first one
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr4->sin_addr, addr_str, sizeof(addr_str));
                MSDKDNSLOG(@"Found IPv4 address on %s: %s", 
                          ifa->ifa_name ? ifa->ifa_name : "unknown", addr_str);
                *ipv4_result = 1;
                
                // If we already found best IPv6, we can exit early
                if (*ipv6_result == 2) {
                    break;
                }
            }
        }
        // Check IPv6
        else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            
            // Skip loopback and link-local
            if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) || 
                IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
                continue;
            }
            
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr6->sin6_addr, addr_str, sizeof(addr_str));
            
            // Check for NAT64 prefix
            if (msdkdns_is_nat64_environment(&addr6->sin6_addr)) {
                MSDKDNSLOG(@"Found NAT64 prefix address on %s: %s", 
                          ifa->ifa_name ? ifa->ifa_name : "unknown", addr_str);
                has_nat64 = true;
                continue;  // Don't count as native IPv6
            }
            
            // Check for Global Unicast Address (2000::/3)
            if ((addr6->sin6_addr.s6_addr[0] & 0xE0) == 0x20) {
                MSDKDNSLOG(@"Found native global IPv6 address on %s: %s", 
                          ifa->ifa_name ? ifa->ifa_name : "unknown", addr_str);
                *ipv6_result = 2;  // Best result
                // If we already found IPv4, we can exit early
                if (*ipv4_result == 1) {
                    break;
                }
            }
            // Check for Unique Local Address (fc00::/7)
            else if ((addr6->sin6_addr.s6_addr[0] & 0xFE) == 0xFC) {
                if (*ipv6_result < 1) {
                    MSDKDNSLOG(@"Found ULA IPv6 address on %s: %s", 
                              ifa->ifa_name ? ifa->ifa_name : "unknown", addr_str);
                    *ipv6_result = 1;
                }
            }
            // Any other IPv6 address
            else if (*ipv6_result < 1) {
                MSDKDNSLOG(@"Found other IPv6 address on %s: %s", 
                          ifa->ifa_name ? ifa->ifa_name : "unknown", addr_str);
                *ipv6_result = 1;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    
    // Note: has_nat64 flag typically won't be set because NAT64 prefixes 
    // appear in DNS responses, not local interface addresses.
    // This is kept for edge cases where a device might have such an address configured.
    if (*ipv6_result == 0 && has_nat64) {
        MSDKDNSLOG(@"NAT64 prefix detected on local interface (rare case)");
    }
}



static int msdkdns_test_connect(int pf, struct sockaddr * addr, size_t addrlen) {
    int s = socket(pf, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        MSDKDNSLOG(@"socket creation failed, pf=%d, errno=%d", pf, errno);
        return 0;
    }
    
    // For UDP sockets, connect() is synchronous and just sets the default destination
    // It will succeed immediately if routing is available, or fail with specific errors
    int ret;
    unsigned int loop_count = 0;
    do {
        ret = connect(s, addr, addrlen);
    } while (ret < 0 && errno == EINTR && loop_count++ < kMaxLoopCount);
    
    int success = (ret == 0);
    
    if (loop_count >= kMaxLoopCount) {
        MSDKDNSLOG(@"connect error. loop_count = %d, pf=%d, errno=%d", loop_count, pf, errno);
    } else if (ret < 0) {
        // Common errno values for UDP connect failure:
        // ENETUNREACH: Network is unreachable
        // EHOSTUNREACH: No route to host  
        // EADDRNOTAVAIL: Address not available (no suitable source address)
        MSDKDNSLOG(@"connect failed, pf=%d, errno=%d (%s)", pf, errno, 
                  errno == ENETUNREACH ? "network unreachable" :
                  errno == EHOSTUNREACH ? "host unreachable" :
                  errno == EADDRNOTAVAIL ? "address not available" : "other error");
    }
    
    loop_count = 0;
    do {
        ret = close(s);
    } while (ret < 0 && errno == EINTR && loop_count++ < kMaxLoopCount);
    if (loop_count >= kMaxLoopCount) {
        MSDKDNSLOG(@"close error. loop_count = %d, errno=%d", loop_count, errno);
    }
    return success;
}

/*
 * Test IPv6 connectivity with fallback to backup addresses.
 */
static int msdkdns_test_ipv6_connectivity() {
    struct sockaddr_in6 sin6_test;
    
    // Primary test: Google Public DNS IPv6: 2001:4860:4860::8888
    memset(&sin6_test, 0, sizeof(sin6_test));
    sin6_test.sin6_family = AF_INET6;
    sin6_test.sin6_port = htons(53);
    sin6_test.sin6_flowinfo = 0;
    sin6_test.sin6_scope_id = 0;
    
    // 2001:4860:4860::8888 in hex bytes
    sin6_test.sin6_addr.s6_addr[0] = 0x20;
    sin6_test.sin6_addr.s6_addr[1] = 0x01;
    sin6_test.sin6_addr.s6_addr[2] = 0x48;
    sin6_test.sin6_addr.s6_addr[3] = 0x60;
    sin6_test.sin6_addr.s6_addr[4] = 0x48;
    sin6_test.sin6_addr.s6_addr[5] = 0x60;
    sin6_test.sin6_addr.s6_addr[6] = 0x00;  // Explicitly set for clarity
    sin6_test.sin6_addr.s6_addr[7] = 0x00;
    sin6_test.sin6_addr.s6_addr[8] = 0x00;
    sin6_test.sin6_addr.s6_addr[9] = 0x00;
    sin6_test.sin6_addr.s6_addr[10] = 0x00;
    sin6_test.sin6_addr.s6_addr[11] = 0x00;
    sin6_test.sin6_addr.s6_addr[12] = 0x00;
    sin6_test.sin6_addr.s6_addr[13] = 0x00;
    sin6_test.sin6_addr.s6_addr[14] = 0x88;
    sin6_test.sin6_addr.s6_addr[15] = 0x88;
    
    msdkdns::msdkdns_sockaddr_union addr = {.msdkdns_in6 = sin6_test};
    int result = msdkdns_test_connect(PF_INET6, &addr.msdkdns_generic, sizeof(addr.msdkdns_in6));
    
    if (result) {
        MSDKDNSLOG(@"IPv6 connectivity test succeeded (Google DNS)");
        return 1;
    }
    
    MSDKDNSLOG(@"Primary IPv6 test failed, trying backup address");
    
    // Backup test: Cloudflare DNS IPv6: 2606:4700:4700::1111
    memset(&sin6_test.sin6_addr, 0, sizeof(sin6_test.sin6_addr));
    sin6_test.sin6_addr.s6_addr[0] = 0x26;
    sin6_test.sin6_addr.s6_addr[1] = 0x06;
    sin6_test.sin6_addr.s6_addr[2] = 0x47;
    sin6_test.sin6_addr.s6_addr[3] = 0x00;
    sin6_test.sin6_addr.s6_addr[4] = 0x47;
    sin6_test.sin6_addr.s6_addr[5] = 0x00;
    sin6_test.sin6_addr.s6_addr[6] = 0x00;
    sin6_test.sin6_addr.s6_addr[7] = 0x00;
    sin6_test.sin6_addr.s6_addr[8] = 0x00;
    sin6_test.sin6_addr.s6_addr[9] = 0x00;
    sin6_test.sin6_addr.s6_addr[10] = 0x00;
    sin6_test.sin6_addr.s6_addr[11] = 0x00;
    sin6_test.sin6_addr.s6_addr[12] = 0x00;
    sin6_test.sin6_addr.s6_addr[13] = 0x00;
    sin6_test.sin6_addr.s6_addr[14] = 0x11;
    sin6_test.sin6_addr.s6_addr[15] = 0x11;
    
    addr.msdkdns_in6 = sin6_test;
    result = msdkdns_test_connect(PF_INET6, &addr.msdkdns_generic, sizeof(addr.msdkdns_in6));
    
    if (result) {
        MSDKDNSLOG(@"IPv6 connectivity test succeeded (Cloudflare DNS)");
        return 1;
    }
    
    MSDKDNSLOG(@"Both IPv6 connectivity tests failed");
    return 0;
}

/*
 * Test IPv6 connectivity using pre-checked interface status.
 * @param interface_check Result from msdkdns_check_interfaces (2=global, 1=limited, 0=none)
 * 
 * Note on App Store IPv6-only review environment:
 * - In NAT64/DNS64 networks, devices have normal IPv6 addresses (2001::/3, etc.)
 * - interface_check will be 2 (global), not a special NAT64 flag
 * - This function will detect IPv6 support and return 1
 * - SDK will request AAAA records, DNS64 synthesizes them automatically
 * - No special NAT64 detection needed at interface level
 */
static int msdkdns_have_ipv6(int interface_check) {
    if (interface_check == 0) {
        MSDKDNSLOG(@"No usable IPv6 interface found");
        return 0;
    }
    
    MSDKDNSLOG(@"IPv6 interface check result: %d (2=global, 1=limited)", interface_check);
    
    // Test actual connectivity with multiple addresses
    int connectivity_result = msdkdns_test_ipv6_connectivity();
    
    if (!connectivity_result) {
        MSDKDNSLOG(@"IPv6 connectivity test failed (but interface exists)");
        // If we have global IPv6 interface but connectivity test fails,
        // it might be temporary network issue, still return success
        // to allow IPv6 resolution attempts
        if (interface_check == 2) {
            MSDKDNSLOG(@"Global IPv6 interface exists, returning success despite connectivity test failure");
            return 1;
        }
        return 0;
    }
    
    MSDKDNSLOG(@"IPv6 connectivity test succeeded");
    return 1;
}

/*
 * Test IPv4 connectivity with fallback to backup addresses.
 */
static int msdkdns_test_ipv4_connectivity() {
    struct sockaddr_in sin_test;
    
    // Primary test: Google Public DNS: 8.8.8.8
    memset(&sin_test, 0, sizeof(sin_test));
    sin_test.sin_family = AF_INET;
    sin_test.sin_port = htons(53);
    sin_test.sin_addr.s_addr = htonl(0x08080808L);  // 8.8.8.8
    
    msdkdns::msdkdns_sockaddr_union addr = {.msdkdns_in = sin_test};
    int result = msdkdns_test_connect(PF_INET, &addr.msdkdns_generic, sizeof(addr.msdkdns_in));
    
    if (result) {
        MSDKDNSLOG(@"IPv4 connectivity test succeeded (Google DNS 8.8.8.8)");
        return 1;
    }
    
    MSDKDNSLOG(@"Primary IPv4 test failed, trying backup address");
    
    // Backup test: Cloudflare DNS: 1.1.1.1
    sin_test.sin_addr.s_addr = htonl(0x01010101L);  // 1.1.1.1
    addr.msdkdns_in = sin_test;
    result = msdkdns_test_connect(PF_INET, &addr.msdkdns_generic, sizeof(addr.msdkdns_in));
    
    if (result) {
        MSDKDNSLOG(@"IPv4 connectivity test succeeded (Cloudflare DNS 1.1.1.1)");
        return 1;
    }
    
    MSDKDNSLOG(@"Both IPv4 connectivity tests failed");
    return 0;
}

/*
 * Test IPv4 connectivity using pre-checked interface status.
 * @param interface_check Result from msdkdns_check_interfaces (1=found, 0=none)
 */
static int msdkdns_have_ipv4(int interface_check) {
    if (interface_check == 0) {
        MSDKDNSLOG(@"No usable IPv4 interface found");
        return 0;
    }
    
    MSDKDNSLOG(@"IPv4 interface found");
    
    // Test actual connectivity with multiple addresses
    int connectivity_result = msdkdns_test_ipv4_connectivity();
    
    if (!connectivity_result) {
        MSDKDNSLOG(@"IPv4 connectivity test failed (but interface exists)");
        // Similar to IPv6, if interface exists, be optimistic
        return 1;
    }
    
    MSDKDNSLOG(@"IPv4 connectivity test succeeded");
    return 1;
}

msdkdns::MSDKDNS_TLocalIPStack msdkdns::msdkdns_detect_local_ip_stack() {
    MSDKDNSLOG(@"detect local ip stack");
    
    // Check both interfaces in one pass to avoid duplicate getifaddrs() calls
    int ipv4_interface_check, ipv6_interface_check;
    msdkdns_check_interfaces(&ipv4_interface_check, &ipv6_interface_check);
    
    MSDKDNSLOG(@"Interface check - IPv4:%d IPv6:%d", ipv4_interface_check, ipv6_interface_check);
    
    // Use the pre-checked results to avoid redundant interface scanning
    int have_ipv4 = msdkdns_have_ipv4(ipv4_interface_check);
    int have_ipv6 = msdkdns_have_ipv6(ipv6_interface_check);
    
    int local_stack = 0;
    if (have_ipv4) {
        local_stack |= msdkdns::MSDKDNS_ELocalIPStack_IPv4;
    }
    if (have_ipv6) {
        local_stack |= msdkdns::MSDKDNS_ELocalIPStack_IPv6;
    }
    
    MSDKDNSLOG(@"Final result - have_ipv4:%d have_ipv6:%d stack:%d", have_ipv4, have_ipv6, local_stack);
    return (msdkdns::MSDKDNS_TLocalIPStack) local_stack;
}
