/*
 * build_probe_arp_packet(mac, target_ip) must produce the exact 42 bytes of
 * an ARP probe (RFC 5227). probe_arp() must send exactly these bytes with
 * one send() call, and return -1 if send() fails.
 */
#include "wk_test.h"
#include "test_env.h"
#include "golden_arp.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "wakupator/net/net.h"

static void test_reply_to_arp_probe(void)
{
    const arp_packet reply = build_probe_arp_packet(WK_MAC_A, WK_IP4_ADDR_B);
    WK_CHECK(sizeof reply == GOLDEN_ARP_LEN);
    if (memcmp(&reply, GOLDEN_ARP_PROBE, GOLDEN_ARP_LEN) != 0)
        WK_FAIL("built packet differs from the golden reference");
    WK_LOG("built packet matches the golden reference byte for byte");
}

// Other values: catches hardcoded fields and byte swaps (host endianness mismatches)
static void test_build_other_values(void)
{
    uint8_t expected[GOLDEN_ARP_LEN];
    memcpy(expected, GOLDEN_ARP_PROBE, sizeof expected);
    memcpy(expected + 6,  WK_MAC_B, 6);    /* ethernet source */
    memcpy(expected + 22, WK_MAC_B, 6);    /* ARP sender MAC  */
    expected[38] = 192; expected[39] = 168; expected[40] = 0; expected[41] = 125;

    struct in_addr addr_test;
    WK_CHECK(inet_pton(AF_INET, "192.168.0.125", &addr_test) == 1);

    const arp_packet pkt = build_probe_arp_packet(WK_MAC_B, addr_test);
    if (memcmp(&pkt, expected, sizeof expected) != 0)
        WK_FAIL("packet with other MAC/IP is wrong");
    WK_LOG("packet with other MAC and IP is correct");
}

/* probe_arp() sends the packet through a socketpair: no network involved */
static void test_probe_sends_packet(void)
{
    int sv[2];
    WK_CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);

    WK_CHECK(send_arp_probe(sv[0], WK_MAC_A, WK_IP4_ADDR_B) == 0);

    uint8_t got[256];
    ssize_t n = recv(sv[1], got, sizeof got, MSG_DONTWAIT);
    if (n != GOLDEN_ARP_LEN || memcmp(got, GOLDEN_ARP_PROBE, GOLDEN_ARP_LEN) != 0)
        WK_FAIL("probe_arp did not send the golden packet (got %zd bytes)", n);
    WK_LOG("probe_arp sent the golden packet in a single send()");

    close(sv[0]); close(sv[1]);
}

static void test_probe_send_error(void)
{
    WK_CHECK(send_arp_probe(-1, WK_MAC_A, WK_IP4_ADDR_A) == -1);
    WK_LOG("returns -1 when send() fails with an invalid socket");
}

int main(void)
{
    WK_RUN(test_reply_to_arp_probe);
    WK_RUN(test_build_other_values);
    WK_RUN(test_probe_sends_packet);
    WK_RUN(test_probe_send_error);
    return 0;
}