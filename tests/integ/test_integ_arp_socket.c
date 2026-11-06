/*
 * Test the raw socket filtered to catch all ARP request (and probe) for a specific IP.
 * create_raw_socket_arp_request(ifidx, ip, MAC_IGNORED);
 *
 * - The socket must capture ARP Request (type=1) whose TARGET address is exactly 'target' (all 32 bits)
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

static const uint8_t MAC_SAME_HI[6]  = {WK_MAC_0, WK_MAC_1, WK_MAC_2, WK_MAC_3, 0x00, 0x01};
static const uint8_t MAC_SAME_LO[6]  = {0x02, 0x11, 0x22, 0x99, WK_MAC_4, WK_MAC_5};

static int tx;
static int ifidx;
static uint8_t buf[2048];

static void test_arp_filter(void)
{
    struct in_addr ip;
    WK_CHECK(inet_pton(AF_INET, "10.0.0.1", &ip) == 1);

    int rx = create_raw_socket_arp_request(ifidx, ip, WK_MAC_A);
    WK_CHECK(rx >= 0);

    /* Reference "good" packet: ARP request asking who has 10.0.0.1 with a MAC different from rx */
    uint8_t good[128];
    ssize_t ngood = wk_pkt_arp(good, sizeof good, 1, WK_MAC_B, "10.0.0.2", "10.0.0.1");

    /* 1. Nominal case */
    wk_expect_captured(tx, rx, "ARP request for the monitored IP", good, ngood);

    /* 2. Source MAC == ignored MAC -> dropped */
    ssize_t n = wk_pkt_arp(buf, sizeof buf, 1, WK_MAC_A, "10.0.0.2", "10.0.0.1");
    wk_expect_dropped(tx, rx, "source MAC == ignored MAC", buf, n, good, ngood);

    /* 3. Partial src MAC matches must still be captured */
    n = wk_pkt_arp(buf, sizeof buf, 1, MAC_SAME_HI, "10.0.0.2", "10.0.0.1");
    wk_expect_captured(tx, rx, "Partial MAC matches (High)", buf, n);
    n = wk_pkt_arp(buf, sizeof buf, 1, MAC_SAME_LO, "10.0.0.2", "10.0.0.1");
    wk_expect_captured(tx, rx, "Partial MAC matches (Low)", buf, n);

    /* 4. ARP reply (op 2) for the right IP -> dropped */
    n = wk_pkt_arp(buf, sizeof buf, 2, WK_MAC_B, "10.0.0.2", "10.0.0.1");
    wk_expect_dropped(tx, rx, "ARP Reply", buf, n, good, ngood);

    /* 5. ARP request for another IP -> dropped */
    n = wk_pkt_arp(buf, sizeof buf, 1, WK_MAC_B, "10.0.0.2", "10.0.0.7");
    wk_expect_dropped(tx, rx, "ARP Request for another IP", buf, n, good, ngood);

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

    WK_RUN(test_arp_filter);

    close(tx);
    return 0;
}