#pragma once
#include <stdint.h>
#include <sys/types.h>

#include "wk_test.h"


/* Build an Ethernet + ARP packet (broadcast destination).
 * op: 1 = request, 2 = reply. src_mac is used for both the Ethernet source
 * and the ARP sender hardware address.
 * Returns the packet size, or -1 if cap is too small. */
ssize_t wk_pkt_arp(uint8_t *buf, size_t cap, uint16_t op, const uint8_t src_mac[6],
                   const char *sender_ip, const char *target_ip);

/* Build a Neighbor Solicitation (Ethernet + IPv6 + ICMPv6 + SLLA option) with a
 * valid checksum. Destination = solicited-node multicast address of the target,
 * as a real host would send it. */
ssize_t wk_pkt_ns(uint8_t *buf, size_t cap, const uint8_t src_mac[6],
                  const char *src_ip6, const char *target_ip6);

// Open a raw socket which receive nothing. Used to send packets.
int wk_open_tx(const char *ifname);

// Open a socket only to receive a type of packet
int wk_open_rx(const char *ifname, uint16_t ethertype);

int wk_send(int tx_fd, const char *ifname, const void *buf, size_t len);

// Wait for one incoming packet. Returns its size, 0 on timeout, -1 on error.
ssize_t wk_recv(int fd, void *buf, size_t cap, int timeout_ms);

// keep_outgoing = 1: also return packets emitted by this host (PACKET_OUTGOING)
ssize_t wk_recv_ex(int fd, void *buf, size_t cap, int timeout_ms, int keep_outgoing);

typedef int (*wk_pred_fn)(const uint8_t *pkt, size_t len, void *ctx);

/* First non-outgoing packet matching pred; 0 on timeout, -1 on error.
 * Non-matching packets (kernel MLD, etc.) are skipped. */
ssize_t wk_recv_match(int fd, void *buf, size_t cap, int timeout_ms,
                      wk_pred_fn pred, void *ctx);

void wk_drain(int fd);

static void check_bytes(const char *what, const void *got, const uint8_t *want, size_t n)
{
    const uint8_t *g = got;
    int error = 0;
    for (size_t i = 0; i < n; i++)
        if (g[i] != want[i]) {
            WK_LOG("[%s] difference at offset %zu: got 0x%02x, expected 0x%02x",
                    what, i, g[i], want[i]);
            error = 1;
        }
    if (error == 0)
        WK_LOG("%s matches the golden reference", what);
    else
        WK_FAIL("%s doesnt matches the golden reference", what);
}