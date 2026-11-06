/*
 * Test the raw socket filtered to catch NS request for a specific IPv6 and filter a src mac address.
 *
 * create_raw_socket_ns_request(if_index, target, ignored_mac)
 *
 * - The socket must capture Neighbor Solicitations whose TARGET address is exactly 'target' (all 128 bits)
 * - Drop packet if the source MAC is 'ignored_mac'.
 * - Everything else must be dropped.
 */
#include "wk_test.h"
#include "test_env.h"
#include "test_pkt.h"
#include "test_expect.h"
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "wakupator/net/socket.h"

/* Offsets in an Ethernet + IPv6 + ICMPv6 packet, used to corrupt one field */
#define OFF_ETHERTYPE   12
#define OFF_NEXT_HDR    20   /* 14 + 6  */
#define OFF_ICMP_TYPE   54   /* 14 + 40 */

static const uint8_t MAC_SAME_HI[6]  = {WK_MAC_0, WK_MAC_1, WK_MAC_2, WK_MAC_3, 0x00, 0x01};
static const uint8_t MAC_SAME_LO[6]  = {0x02, 0x11, 0x22, 0x99, WK_MAC_4, WK_MAC_5};

static int tx, ifidx;

static ssize_t ns(uint8_t *b, size_t cap, const uint8_t mac[6], const char *target)
{
    const ssize_t n = wk_pkt_ns(b, cap, mac, WK_IP6_ADDR_B, target);
    WK_CHECK(n > 0);
    return n;
}

static void test_ns_filter(void)
{
    struct in6_addr target;
    WK_CHECK(inet_pton(AF_INET6, WK_IP6_ADDR_A, &target) == 1);

    int rx = create_raw_socket_ns_request(ifidx, target, WK_MAC_A);
    WK_CHECK(rx >= 0);

    uint8_t good[256], bad[256];
    ssize_t ngood = ns(good, sizeof good, WK_MAC_B, WK_IP6_ADDR_A);
    ssize_t nbad;

    /* --- must be captured --- */
    wk_expect_captured(tx, rx, "NS for the monitored target", good, ngood);

    nbad = ns(bad, sizeof bad, MAC_SAME_HI, WK_IP6_ADDR_A);
    wk_expect_captured(tx, rx, "MAC sharing the first 4 bytes with the ignored one", bad, nbad);
    nbad = ns(bad, sizeof bad, MAC_SAME_LO, WK_IP6_ADDR_A);
    wk_expect_captured(tx, rx, "MAC sharing the last 2 bytes with the ignored one", bad, nbad);

    /* --- source MAC --- */
    nbad = ns(bad, sizeof bad, WK_MAC_A, WK_IP6_ADDR_A);
    wk_expect_dropped(tx, rx, "source MAC == ignored MAC", bad, nbad, good, ngood);

    /* --- target address: one case per 32-bit word compared by the BPF --- */
    static const struct { const char *what, *target; } wrong_target[] = {
        { "target differs in word 0", WK_IP6_ADDR_A_ALT1 },
        { "target differs in word 1", WK_IP6_ADDR_A_ALT2 },
        { "target differs in word 2", WK_IP6_ADDR_A_ALT3 },
        { "target differs in word 3", WK_IP6_ADDR_A_ALT4 },
        // Same solicited-node multicast address (same last 24 bits)
        { "same multicast group, other target", "2001:db8::ff34:5678" },
    };
    for (size_t i = 0; i < sizeof wrong_target / sizeof *wrong_target; i++) {
        nbad = ns(bad, sizeof bad, WK_MAC_B, wrong_target[i].target);
        wk_expect_dropped(tx, rx, wrong_target[i].what, bad, nbad, good, ngood);
    }

    /* --- right target, but one protocol field corrupted --- */
    nbad = ns(bad, sizeof bad, WK_MAC_B, WK_IP6_ADDR_A);
    bad[OFF_ETHERTYPE] = 0x88; bad[OFF_ETHERTYPE + 1] = 0xb5;   /* local experimental */
    wk_expect_dropped(tx, rx, "wrong ethertype", bad, nbad, good, ngood);

    nbad = ns(bad, sizeof bad, WK_MAC_B, WK_IP6_ADDR_A);
    bad[OFF_NEXT_HDR] = IPPROTO_UDP;
    wk_expect_dropped(tx, rx, "next header is not ICMPv6", bad, nbad, good, ngood);

    nbad = ns(bad, sizeof bad, WK_MAC_B, WK_IP6_ADDR_A);
    bad[OFF_ICMP_TYPE] = 136; // NA
    wk_expect_dropped(tx, rx, "ICMPv6 type is NA, not NS", bad, nbad, good, ngood);

    /* --- random other valid traffic (ARP here) --- */
    nbad = wk_pkt_arp(bad, sizeof bad, 1, WK_MAC_B, "10.0.0.2", "10.0.0.1");
    wk_expect_dropped(tx, rx, "ARP request (not IPv6)", bad, nbad, good, ngood);

    close(rx);
}

int main(void)
{
    if (wk_env_init() < 0) {
        fprintf(stderr, "SKIP: cannot create the network namespace\n");
        return WK_SKIP_CODE;
    }
    ifidx = (int) if_nametoindex(WK_VETH_A);
    tx = wk_open_tx(WK_VETH_B);
    WK_CHECK(ifidx > 0 && tx >= 0);

    WK_RUN(test_ns_filter);

    close(tx);
    return 0;
}