/*
 * build_na_packet(mac, received_ns, spoofed_ip): answers a received NS as
 * 'spoofed_ip' owned by 'mac'. The reply goes to the source MAC
 * and source IP of the NS.
 */
#include "wk_test.h"
#include "golden_nd.h"
#include <arpa/inet.h>
#include <string.h>

#include "test_pkt.h"
#include "wakupator/net/net.h"

static struct in6_addr ip6(const char *s)
{
    struct in6_addr a;
    WK_CHECK(inet_pton(AF_INET6, s, &a) == 1);
    return a;
}

/* Copy raw bytes into a properly aligned ns_packet (never cast the byte array:
 * it may not be aligned, which matters on MIPS) */
static ns_packet as_ns(const uint8_t *bytes, size_t len)
{
    ns_packet ns;
    WK_CHECK(sizeof ns == len);
    memcpy(&ns, bytes, len);
    return ns;
}

static void test_na_golden(void)
{
    ns_packet rx = as_ns(GOLDEN_NS, sizeof GOLDEN_NS);
    struct in6_addr spoofed = ip6(ND_TARGET_1);

    na_packet pkt = build_na_packet(ND_MAC_2, &rx, &spoofed);

    WK_CHECK(sizeof pkt == sizeof GOLDEN_NA);
    check_bytes("build_na_packet", &pkt, GOLDEN_NA, sizeof GOLDEN_NA);
}

int main(void)
{
    WK_RUN(test_na_golden);
    return 0;
}