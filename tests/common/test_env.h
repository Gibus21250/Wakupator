#pragma once

#define WK_VETH_A "veth0"
#define WK_VETH_B "veth1"

#define WK_MAC_0 0x02
#define WK_MAC_1 0x11
#define WK_MAC_2 0x22
#define WK_MAC_3 0x33
#define WK_MAC_4 0xc4
#define WK_MAC_5 0xd4

#define WK_MAC_A ((const uint8_t[6]){WK_MAC_0, WK_MAC_1, WK_MAC_2, WK_MAC_3, WK_MAC_4, WK_MAC_5})
#define WK_MAC_B ((const uint8_t[6]){WK_MAC_5, WK_MAC_4, WK_MAC_3, WK_MAC_2, WK_MAC_1, WK_MAC_0})

// ----- IPv4 -----

#define WK_IP4_STR_A "10.0.0.1"
#define WK_IP4_STR_B "10.0.0.2"

#define WK_IP4_ADDR_A ((const struct in_addr){ .s_addr = htonl(0x0a000001)})
#define WK_IP4_ADDR_B ((const struct in_addr){ .s_addr = htonl(0x0a000002) })

// ----- IPv6 -----

#define WK_IP6_ADDR_A         "2001:db8::1234:5678"
#define WK_IP6_ADDR_A_ALT1    "2001:db9::1234:5678"
#define WK_IP6_ADDR_A_ALT2    "2001:db8:0:1::1234:5678"
#define WK_IP6_ADDR_A_ALT3    "2001:db8::1:0:1234:5678"
#define WK_IP6_ADDR_A_ALT4    "2001:db8::1234:5679"

#define WK_IP6_ADDR_B         "2001:db8::8765:4321"

// unshare netns (+ userns if non-root). Create veth0<->veth1
// Return 0, or -1. (-1 mean SKIP test).
int wk_env_init(void);