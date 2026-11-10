/*
 * build_ns_packet(mac, src_ipv6, target): Neighbor Solicitation sent to the
 * solicited-node multicast address of 'target', with a valid ICMPv6 checksum, using the mac and
 * src_ipv6 provided.
 */
#include "wk_test.h"
#include "golden_nd.h"
#include <arpa/inet.h>

#include "test_pkt.h"
#include "wakupator/net/net.h"

static struct in6_addr ip6(const char *s)
{
    struct in6_addr a;
    WK_CHECK(inet_pton(AF_INET6, s, &a) == 1);
    return a;
}

static void test_ns_golden(void)
{
    struct in6_addr link = ip6(ND_LINK_1), target = ip6(ND_TARGET_1);
    ns_packet pkt = build_ns_packet(ND_MAC_1, &link, &target);
    WK_CHECK(sizeof pkt == sizeof GOLDEN_NS);
    check_bytes("build_ns_packet", &pkt, GOLDEN_NS, sizeof GOLDEN_NS);
}

int main(void)
{
    WK_RUN(test_ns_golden);
    return 0;
}