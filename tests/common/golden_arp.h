#pragma once
#include <stdint.h>

#define GOLDEN_ARP_LEN 42

/* Reference ARP probe (RFC 5227) MAC WK_MAC_A, target WK_IP4_ADDR_A. */
static const uint8_t GOLDEN_ARP_PROBE[GOLDEN_ARP_LEN] = {
    /* Ethernet */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   /* dst mac                    */
    0x02, 0x11, 0x22, 0x33, 0xc4, 0xd4,   /* src mac: WK_MAC_A          */
    0x08, 0x06,                           /* ethertype : ARP            */
    /* ARP */
    0x00, 0x01,                           /* htype: Ethernet            */
    0x08, 0x00,                           /* protocol type: IPv4        */
    0x06, 0x04,                           /* hw / proto address lengths */
    0x00, 0x01,                           /* operation: request         */
    0x02, 0x11, 0x22, 0x33, 0xc4, 0xd4,   /* sender MAC                 */
    0x00, 0x00, 0x00, 0x00,               /* sender IP: 0.0.0.0         */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* target MAC: zero (RFC 5227)*/
    0x0a, 0x00, 0x00, 0x02,               /* target IP: WK_IP4_ADDR_B   */
};

/* reference ARP Reply. Reply to RFC5227 ARP Request: to WK_MAC_A (WK_IP4_ADDR_A) from WK_MAC_B (0.0.0.0)  */
static const uint8_t GOLDEN_ARP_REPLY[GOLDEN_ARP_LEN] = {
    /* Ethernet */
    0x02, 0x11, 0x22, 0x33, 0xc4, 0xd4,    /* dst Mac: WK_MAC_A          */
    0xd4, 0xc4, 0x33, 0x22, 0x11, 0x02,    /* src mac: WK_MAC_B          */
    0x08, 0x06,                            /* ethertype : ARP            */
    /* ARP */
    0x00, 0x01,                            /* htype: Ethernet            */
    0x08, 0x00,                            /* protocol type: IPv4        */
    0x06, 0x04,                            /* hw / proto address lengths */
    0x00, 0x02,                            /* operation: reply           */
    0xd4, 0xc4, 0x33, 0x22, 0x11, 0x02,    /* sender WK_MAC_B            */
    0x0a, 0x00, 0x00, 0x02,                /* sender IP: WK_IP4_ADDR_B   */
    0x02, 0x11, 0x22, 0x33, 0xc4, 0xd4,    /* targ MAC: WK_MAC_A         */
    0x00, 0x00, 0x00, 0x00                 /* target IP: 0.0.0.0         */
};
