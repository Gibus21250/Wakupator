/*
 * build_reply_arp_packet(mac_raw[6], request_arp, spoofed_ip) must produce a Reply ARP with the good target IP.
 */
#include "wk_test.h"
#include "golden_arp.h"
#include <string.h>

#include "test_env.h"
#include "wakupator/net/net.h"

// Test a reply to the golden probe (RFC 5227).
static void test_reply_to_arp_probe(void)
{
    arp_packet *probe = (arp_packet*) GOLDEN_ARP_PROBE;

    const arp_packet reply = build_reply_arp_packet(WK_MAC_B, probe, WK_IP4_ADDR_B);
    WK_CHECK(sizeof reply == GOLDEN_ARP_LEN);
    if (memcmp(&reply, GOLDEN_ARP_REPLY, GOLDEN_ARP_LEN) != 0)
        WK_FAIL("built packet differs from the golden reference");
    WK_LOG("built packet matches the golden reference byte for byte");
}

// Modify the golden request and add a sender IP (IP_1). And expect an ARP reply to IP_1
static void test_reply_to_arp_request(void)
{
    uint8_t req[GOLDEN_ARP_LEN], expected[GOLDEN_ARP_LEN];
    memcpy(req, GOLDEN_ARP_PROBE, sizeof req);
    memcpy(expected, GOLDEN_ARP_REPLY, sizeof expected);

    memcpy(req + 28, &WK_IP4_ADDR_A, 4);        /* request: sender IP */
    memcpy(expected + 38, &WK_IP4_ADDR_A, 4);   /* reply: target IP   */

    const arp_packet reply = build_reply_arp_packet(WK_MAC_B, (arp_packet*) req, WK_IP4_ADDR_B);

    if (memcmp(&reply, expected, sizeof expected) != 0)
        WK_FAIL("reply to a regular request is wrong");
    WK_LOG("target IP of the reply follows the sender IP of the request");
}

int main(void)
{
    WK_RUN(test_reply_to_arp_probe);
    WK_RUN(test_reply_to_arp_request);
    return 0;
}