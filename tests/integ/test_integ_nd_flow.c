/*
 * End-to-end Neighbor Discovery behavior on two veth (filter semantics are
 * covered by test_integ_ns_socket.c, packet contents by the unit tests).
 *
 * GOLDEN_NS (real capture, sent by ND_MAC_1) is injected on veth1. It must be
 * captured by the filtered socket on veth0, and send_ndp_na() must answer with
 * GOLDEN_NA as reference on the wire.
 */
#include "wk_test.h"
#include "test_env.h"
#include "test_pkt.h"
#include "golden_nd.h"
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "wakupator/net/net.h"
#include "wakupator/net/socket.h"

#define OFF_ETHERTYPE 12
#define OFF_NEXT_HDR  20
#define OFF_ICMP_TYPE 54

static int ifidx;
static int tx;
static int cap; // capture on veth1, IPv6 only

// Return true if the packet is a na (as kernel can send MDL, NS etc. automatically)
static int is_na(const uint8_t *p, size_t n, void *ctx)
{
    (void)ctx;
    return n > OFF_ICMP_TYPE
        && p[OFF_ETHERTYPE] == 0x86 && p[OFF_ETHERTYPE + 1] == 0xdd
        && p[OFF_NEXT_HDR] == 58            /* ICMPv6 */
        && p[OFF_ICMP_TYPE] == 136;         /* NA     */
}

static void test_ns_is_answered(void)
{
    struct in6_addr target;
    WK_CHECK(inet_pton(AF_INET6, ND_TARGET_1, &target) == 1);

    int rx   = create_raw_socket_ns_request(ifidx, target, ND_MAC_2);
    int sock = wk_open_tx(WK_VETH_A);
    WK_CHECK(rx >= 0 && sock >= 0);

    wk_drain(cap); wk_drain(rx);
    WK_CHECK(wk_send(tx, WK_VETH_B, GOLDEN_NS, sizeof GOLDEN_NS) == 0);

    /* Capture the NS */
    uint8_t packet[256];
    ssize_t size = wk_recv(rx, packet, sizeof packet, 300);
    if (size < (ssize_t)sizeof(ns_packet))
        WK_FAIL("the NS was not captured by the filtered socket (got %zd)", size);
    check_bytes("NS captured", packet, GOLDEN_NS, sizeof GOLDEN_NS);

    ns_packet ns_pkt;
    WK_CHECK(sizeof ns_pkt == sizeof GOLDEN_NS);
    memcpy(&ns_pkt, packet, sizeof ns_pkt);

    /* Build and send the NA based on the received golden NS */
    WK_CHECK(send_ndp_na(sock, ND_MAC_2, &ns_pkt, &target) == 0);

    uint8_t got[256];
    ssize_t n = wk_recv_match(cap, got, sizeof got, 300, is_na, NULL);
    if (n != (ssize_t)sizeof GOLDEN_NA)
        WK_FAIL("expected a %zu bytes NA, got %zd", sizeof GOLDEN_NA, n);
    check_bytes("NA on the wire", got, GOLDEN_NA, sizeof GOLDEN_NA);

    WK_CHECK(wk_recv_match(cap, got, sizeof got, 50, is_na, NULL) == 0);
    WK_LOG("exactly one NA was sent");
    close(rx); close(sock);
}

int main(void)
{
    wk_env_init_or_exit();

    ifidx = (int)if_nametoindex(WK_VETH_A);
    tx  = wk_open_tx(WK_VETH_B);
    cap = wk_open_rx(WK_VETH_B, ETH_P_IPV6);
    WK_CHECK(ifidx > 0 && tx >= 0 && cap >= 0);

    WK_RUN(test_ns_is_answered);

    close(tx); close(cap);
    return 0;
}