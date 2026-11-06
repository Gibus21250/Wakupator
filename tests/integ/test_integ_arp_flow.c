/*
 * End-to-end ARP behavior on two veth (filter semantics are covered by
 * test_integ_arp_socket.c, packet contents by the unit tests).
 *
 *  1. send_arp_probe() really puts the golden probe on the wire.
 *  2. Our own probe is NOT captured by the filtered socket, even though it is
 *     an ARP request for the monitored IP (only the source MAC check stops it).
 *  3. An ARP request for the monitored IP, injected on veth1, is captured by the
 *     filtered socket on veth0 and answered with the golden reply.
 *
 * Roles: we play host 10.0.0.2 (GOLDEN_ARP_MAC_2) which is monitored.
 */

#include "wk_test.h"
#include "test_env.h"
#include "test_pkt.h"
#include "golden_arp.h"
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "wakupator/net/net.h"
#include "wakupator/net/socket.h"
#include <sys/random.h>

static int ifidx;   /* veth0 */
static int tx;      /* veth1 */
static int cap;     /* capture on veth1, ARP only */

//random MAC

#define OFF_ETH_DST 0
#define OFF_ETH_SRC 6
#define OFF_ARP_SHA 22
#define OFF_ARP_SPA 28
#define OFF_ARP_THA 32
#define OFF_ARP_TPA 38

static void random_mac(uint8_t mac[6])
{
    WK_CHECK(getrandom(mac, 6, 0) == 6);
    mac[0] = (uint8_t)((mac[0] & 0xfe) | 0x02); //Avoid MC mac address (mac[0] = odd)
}

static struct in_addr ip(const char *s)
{
    struct in_addr a;
    WK_CHECK(inet_pton(AF_INET, s, &a) == 1);
    return a;
}

/* ---- 1. the probe reaches the wire ---- */
static void test_probe_on_wire(void)
{
    int sock = wk_open_tx(WK_VETH_A);
    WK_CHECK(sock >= 0);

    uint8_t got[256];
    wk_drain(cap);
    WK_CHECK(send_arp_probe(sock, WK_MAC_A, WK_IP4_ADDR_B) == 0);

    ssize_t n = wk_recv(cap, got, sizeof got, 300);
    if (n != GOLDEN_ARP_LEN)
        WK_FAIL("expected a %d bytes frame, got %zd", GOLDEN_ARP_LEN, n);
    check_bytes("probe on the wire", got, GOLDEN_ARP_PROBE, GOLDEN_ARP_LEN);

    WK_CHECK(wk_recv(cap, got, sizeof got, 50) == 0);
    WK_LOG("exactly one packet was sent");
    close(sock);
}

/* ---- 2. our own probe must not wake our own filter ---- */
static void test_own_probe_not_captured(void)
{
    // Capture anything on ETH_A (especially outgoing packet)
    int ctl  = wk_open_rx(WK_VETH_A, ETH_P_ARP);
    //
    int filt = create_raw_socket_arp_request(ifidx, WK_IP4_ADDR_B, WK_MAC_A);
    //
    int sock = wk_open_tx(WK_VETH_B);
    WK_CHECK(ctl >= 0 && filt >= 0 && sock >= 0);

    uint8_t got[256];
    wk_drain(ctl); wk_drain(filt);
    WK_CHECK(send_arp_probe(sock, WK_MAC_A, WK_IP4_ADDR_B) == 0);

    WK_CHECK(wk_recv_ex(ctl, got, sizeof got, 300, 1) == GOLDEN_ARP_LEN);
    WK_LOG("control socket sees the outgoing probe");

    if (wk_recv_ex(filt, got, sizeof got, 200, 1) != 0)
        WK_FAIL("the filtered socket captured our own probe");
    WK_LOG("filtered socket ignores our own probe");

    close(ctl); close(filt); close(sock);
}

/* ---- 3. request in, reply out ----
 * Host A (random MAC, 10.0.0.1) asks who have 10.0.0.2. We are host B (random MAC, 10.0.0.2).
 * The request goes through veth1 -> veth0, is captured by the filtered socket, then send_arp_reply() answers.
 * We expect the golden reply patched with the MAC / IP fields replaced by this test's values. */
static void test_request_is_answered(void)
{
    uint8_t mac_a[6], mac_b[6];
    do { random_mac(mac_a); random_mac(mac_b); } while (memcmp(mac_a, mac_b, 6) == 0);
    WK_LOG("requester MAC %02x:%02x:%02x:%02x:%02x:%02x, our MAC %02x:%02x:%02x:%02x:%02x:%02x",
           mac_a[0], mac_a[1], mac_a[2], mac_a[3], mac_a[4], mac_a[5],
           mac_b[0], mac_b[1], mac_b[2], mac_b[3], mac_b[4], mac_b[5]);

    const struct in_addr ip_a = WK_IP4_ADDR_A, ip_b = WK_IP4_ADDR_B;

    int rx   = create_raw_socket_arp_request(ifidx, ip_b, mac_b);           /* MAC to ignore = ours */
    int sock = wk_open_tx(WK_VETH_A);                                 /* stands for main_raw_socket */
    WK_CHECK(rx >= 0 && sock >= 0);

    /* 1. Inject the request from A */
    uint8_t req[128];
    ssize_t nreq = wk_pkt_arp(req, sizeof req, 1, mac_a, WK_IP4_STR_A, WK_IP4_STR_B);
    WK_CHECK(nreq == (ssize_t)sizeof(arp_packet));
    wk_drain(cap); wk_drain(rx);
    WK_CHECK(wk_send(tx, WK_VETH_B, req, (size_t)nreq) == 0);

    /* 2. The filtered socket captures it (same steps as reply_to_probe) */
    uint8_t packet[256];
    ssize_t size = wk_recv(rx, packet, sizeof packet, 300);
    if (size < (ssize_t)sizeof(arp_packet))
        WK_FAIL("the request was not captured by the filtered socket (got %zd)", size);
    arp_packet arp_pkt;
    memcpy(&arp_pkt, packet, sizeof arp_pkt);

    /* 3. Function under test */
    WK_CHECK(send_arp_reply(sock, mac_b, &arp_pkt, ip_b) == 0);

    /* 4. Expected frame: golden reply with this test's MACs and IPs */
    uint8_t expected[GOLDEN_ARP_LEN];
    memcpy(expected, GOLDEN_ARP_REPLY, sizeof expected);
    memcpy(expected + OFF_ETH_DST, mac_a, 6);              /* back to the requester */
    memcpy(expected + OFF_ETH_SRC, mac_b, 6);
    memcpy(expected + OFF_ARP_SHA, mac_b, 6);
    memcpy(expected + OFF_ARP_SPA, &ip_b.s_addr, 4);       /* we own 10.0.0.2       */
    memcpy(expected + OFF_ARP_THA, mac_a, 6);
    memcpy(expected + OFF_ARP_TPA, &ip_a.s_addr, 4);       /* requester's sender IP */

    uint8_t got[256];
    ssize_t n = wk_recv(cap, got, sizeof got, 300);
    if (n != GOLDEN_ARP_LEN)
        WK_FAIL("expected a %d bytes reply, got %zd", GOLDEN_ARP_LEN, n);
    check_bytes("reply on the wire", got, expected, GOLDEN_ARP_LEN);

    WK_CHECK(wk_recv(cap, got, sizeof got, 50) == 0);
    WK_LOG("exactly one reply was sent");
    close(rx); close(sock);
}

int main(void)
{
    if (wk_env_init() < 0) {
        fprintf(stderr, "SKIP: cannot create the network namespace\n");
        return WK_SKIP_CODE;
    }
    ifidx = (int)if_nametoindex(WK_VETH_A);
    tx  = wk_open_tx(WK_VETH_B);
    cap = wk_open_rx(WK_VETH_B, ETH_P_ARP);
    WK_CHECK(ifidx > 0 && tx >= 0 && cap >= 0);

    WK_RUN(test_probe_on_wire);
    WK_RUN(test_own_probe_not_captured);
    WK_RUN(test_request_is_answered);

    close(tx); close(cap);
    return 0;
}