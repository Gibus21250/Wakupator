#ifndef NET_H
#define NET_H
#include <net/if.h>
#include <net/ethernet.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "wakupator/core/manager.h"

// ------ General net ------

int parse_mac(const char *macStr, unsigned char *macRaw);

int get_ipv6_link_local(const char *ifName, struct in6_addr *addr);

int send_wake_on_lan(int rawSocket, int ifIndex, const unsigned char *macSrc, const unsigned char *macTarget);

// ------ Netlink manipulations ------

int add_ip(const char* ifName, const char* ip_str);
int remove_ip(const char* ifName, const char* ip_str);

typedef struct {
    int found;
    char ifname[IFNAMSIZ];
    uint32_t ifindex;
} ip_search_result_t;

int check_ip_exists(const char *ip_str, ip_search_result_t *result);

// ------ ARP and NS IPv6 ------

typedef struct {
    struct ether_header eth;
    struct {
        uint16_t htype;
        uint16_t ptype;
        uint8_t hlen;
        uint8_t plen;
        uint16_t oper;
        uint8_t sha[6];
        uint8_t spa[4];
        uint8_t tha[6];
        uint8_t tpa[4];
    } __attribute__((packed)) arp; //28 Bytes for ARP payload
} __attribute__((packed)) arp_packet;

typedef struct {
    struct ether_header eth;
    struct ip6_hdr ipv6;
    struct nd_neighbor_solicit ns;
    struct nd_opt_hdr opt;
    uint8_t src_mac[6];     //Data for nd opt
} __attribute__((packed)) ns_packet;

int send_arp(const manager *mng, const char* target_ip);

int send_ns(const manager *mng, const char* target_ip);

#endif //NET_H
