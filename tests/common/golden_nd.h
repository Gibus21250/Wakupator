#pragma once
#include <stdint.h>

/* Real captures (Wireshark). ND_MAC_1 sends the NS, ND_MAC_2 (the router) answers with the NA. */
static const uint8_t ND_MAC_1[6] = {0xa8, 0xa1, 0x59, 0xf0, 0xd2, 0xe3};
static const uint8_t ND_MAC_2[6] = {0xe4, 0xfa, 0xc4, 0x55, 0xf5, 0x7d};

#define ND_LINK_1   "fd15:802a:d674:0:857:8db4:8586:d3c6"  // Source IP of the NS
#define ND_TARGET_1 "fd15:802a:d674::1"                    // Address being resolved

/* Neighbor Solicitation, ICMPv6 checksum 0x0d64 as captured.
 * Regular address resolution only: unicast source address, SLLA option
 * present (86 bytes).
 */
static const uint8_t GOLDEN_NS[86] = {
    /* Ethernet */
    0x33, 0x33, 0xff, 0x00, 0x00, 0x01,   /* dst: 33:33 + last 32 bits of the multicast IP  */
    0xa8, 0xa1, 0x59, 0xf0, 0xd2, 0xe3,   /* src: ND_MAC_1                                   */
    0x86, 0xdd,                           /* ethertype: IPv6                                 */
    /* IPv6 */
    0x60, 0x00, 0x00, 0x00,               /* version 6, class 0, flow 0                      */
    0x00, 0x20,                           /* payload length: 32                              */
    0x3a,                                 /* next header: ICMPv6 (58)                        */
    0xff,                                 /* hop limit: 255                                  */
    0xfd, 0x15, 0x80, 0x2a, 0xd6, 0x74, 0x00, 0x00,
    0x08, 0x57, 0x8d, 0xb4, 0x85, 0x86, 0xd3, 0xc6,   /* src: ND_LINK_1                      */
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x01,   /* dst: ff02::1:ff00:1                 */
    /* ICMPv6 Neighbor Solicitation */
    0x87,                                 /* type: 135                                       */
    0x00,                                 /* code                                            */
    0x0d, 0x64,                           /* checksum (from the capture)                     */
    0x00, 0x00, 0x00, 0x00,               /* reserved                                        */
    0xfd, 0x15, 0x80, 0x2a, 0xd6, 0x74, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,   /* target: ND_TARGET_1                 */
    0x01, 0x01,                           /* option: source link-layer addr, length 1 (x8)   */
    0xa8, 0xa1, 0x59, 0xf0, 0xd2, 0xe3,   /* ND_MAC_1                                        */
};

// Neighbor Advertisement answering GOLDEN_NS.
static const uint8_t GOLDEN_NA[86] = {
    /* Ethernet */
    0xa8, 0xa1, 0x59, 0xf0, 0xd2, 0xe3,   /* dst: ND_MAC_1 (source of the NS)                */
    0xe4, 0xfa, 0xc4, 0x55, 0xf5, 0x7d,   /* src: ND_MAC_2                                   */
    0x86, 0xdd,
    /* IPv6 */
    0x60, 0x00, 0x00, 0x00,
    0x00, 0x20,
    0x3a,
    0xff,
    0xfd, 0x15, 0x80, 0x2a, 0xd6, 0x74, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,   /* src: ND_TARGET_1 (spoofed)                      */
    0xfd, 0x15, 0x80, 0x2a, 0xd6, 0x74, 0x00, 0x00,
    0x08, 0x57, 0x8d, 0xb4, 0x85, 0x86, 0xd3, 0xc6,   /* dst: ND_LINK_1 (source of the NS)               */
    /* ICMPv6 Neighbor Advertisement */
    0x88,                                             /* type: 136                                       */
    0x00,
    0x8c, 0x5a,                                       /* checksum                                        */
    0x60, 0x00, 0x00, 0x00,                           /* flags: R=0 S=1 O=1                              */
    0xfd, 0x15, 0x80, 0x2a, 0xd6, 0x74, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,   /* target: ND_TARGET_1                             */
    0x02, 0x01,                                       /* option: target link-layer addr, length 1 (x8)   */
    0xe4, 0xfa, 0xc4, 0x55, 0xf5, 0x7d,               /* ND_MAC_2                                        */
};