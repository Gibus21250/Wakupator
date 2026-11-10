#include <stddef.h>
#include "wakupator/net/net.h"

_Static_assert(sizeof(arp_packet) == 14 + 28, "ARP packet size");
_Static_assert(offsetof(arp_packet, arp) == 14, "ARP header offset");

_Static_assert(sizeof(na_packet) == 14 + 40 + 24 + 2 + 6, "NA packet size");
_Static_assert(offsetof(na_packet, ipv6) == 14, "IPv6 offset");
_Static_assert(offsetof(na_packet, na)   == 54, "ICMPv6 offset");
_Static_assert(offsetof(na_packet, opt)  == 78, "option offset");

_Static_assert(sizeof(ns_packet) == 14 + 40 + 24 + 2 + 6, "NS packet size");
_Static_assert(offsetof(ns_packet, ipv6) == 14, "IPv6 offset");
_Static_assert(offsetof(ns_packet, ns)   == 54, "ICMPv6 offset");
_Static_assert(offsetof(ns_packet, opt)  == 78, "option offset");

int main() {
    return 0;
}
