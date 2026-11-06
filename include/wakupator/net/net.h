#ifndef NET_H
#define NET_H
#include <net/if.h>
#include <net/ethernet.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>

#include "wakupator/core/manager.h"

// ------ General net ------

int str_to_raw_mac(const char *mac_str, unsigned char *mac_raw);

int clear_socket(int socket);

int get_ipv6_link_local(const char *if_name, struct in6_addr *addr);

int send_wake_on_lan(int raw_socket, const unsigned char *mac_src, const unsigned char *mac_target);

// ------ Netlink manipulations ------

typedef enum {
    IP_OP_ADD,
    IP_OP_REMOVE
} ip_operation_t;

/**
 * Add or remove a static route into the main table for the IP on the host.
*/
int modify_route(int if_index, const char *ip_str, ip_operation_t op) ;
int modify_neighbor(int if_index, const char *ip_str, const uint8_t mac_raw[6], ip_operation_t op);

// ----------------------------------------- RAW packet manipulation ---------------------------------------------------

        // ---------------------- IPv4 ARP
typedef struct __attribute__((packed)) {
    struct ether_header eth;
    struct ether_arp arp;
} arp_packet;

/**
 * Send an ARP Request of type Probe
 * (src APR IP = 0.0.0.0)
 * @param target_ip Big Endian IPv4
 * @return 0 if OK, -1 if error
 */
int send_arp_probe(int raw_socket, const uint8_t mac_raw[6], struct in_addr target_ip);

arp_packet build_probe_arp_packet(const uint8_t mac_raw[6], struct in_addr target_ip);

/**
 * Reply to an ARP Request for a specific IP
 * Warning: assume request_arp is filled with big endian data.
 * @param request_arp ARP Request to reply to
 * @param spoofed_ip Big endian IPv4
 * @return
 */
int send_arp_reply(int raw_socket, const uint8_t mac_raw[6], const arp_packet *request_arp, struct in_addr spoofed_ip);

arp_packet build_reply_arp_packet(const uint8_t mac_raw[6], const arp_packet *request_arp, struct in_addr spoofed_ip);

        // ---------------------- IPv6 NS and NA ICMPv6

typedef struct {
    struct ether_header eth;
    struct ip6_hdr ipv6;
    struct nd_neighbor_solicit ns;
    struct nd_opt_hdr opt;
    uint8_t src_mac[6];     //Data for nd opt
} __attribute__((packed)) ns_packet;

typedef struct {
    struct ether_header eth;
    struct ip6_hdr ipv6;
    struct nd_neighbor_advert na;
    struct nd_opt_hdr opt;
    uint8_t target_mac[6];
} __attribute__((packed)) na_packet;

/**
 * Compute ICMP6 checksum independently of host endianness
 * @param src Standard network-byte representation of source IPv6
 * @param dst Standard network-byte representation of destination IPv6
 * @param icmp_data must contain the ICMPv6 message bytes exactly as they should appear on the wire. Its checksum field must be zeroed before calculation.
 * @param icmp6_len host-order integer of the icmp length
 * @return Host endian icmp6 checksum
 */
uint16_t icmp6_checksum(const struct in6_addr *src, const struct in6_addr *dst, const void *icmp_data, uint32_t icmp6_len);

/**
 * Build and send an NS for the target IP using the linkipv6 ip as source.
 * @param raw_socket raw socket
 * @param target_ip Big endian target IPv6
 * @return -1 if error, 0 if OK
 */
int send_ndp_ns(int raw_socket, const uint8_t mac_raw[6], const struct in6_addr *link_ipv6, const struct in6_addr *target_ip);

/**
 * Build a ICMPv6 Network Solicitation packet in network endianness
 * @param mac_raw Source MAC to use
 * @param src_ipv6 Source IPv6
 * @param target_ip Target IPv6
 * @return ns_packet
 */
ns_packet build_ns_packet(const uint8_t mac_raw[6], const struct in6_addr *src_ipv6, const struct in6_addr *target_ip);

/**
 * Take an NS packet and reply with an NA to the raw_socket, using the mac_raw of the interface and the spoofed IP
 * Reply to an NS for a specific IP.
 * Warning: assume request_arp is filled with big endian data.
 * @param received ns_packet in Big Endian
 * @param spoofed_ip Big endian IPv6
 * @return -1 if error, 0 if OK
 */
int send_ndp_na(int raw_socket, const uint8_t mac_raw[6], const ns_packet *received, const struct in6_addr *spoofed_ip);

/**
 * Build a ICMPv6 Network Advertisements packet in network endianness from a NS.
 * @param mac_raw Source MAC to use
 * @param received Network Solicitation packet to reply to
 * @param spoofed_ip IPv6 to reply with
 * @return na_packet
 */
na_packet build_na_packet(const uint8_t mac_raw[6], const ns_packet *received, const struct in6_addr *spoofed_ip);

#endif //NET_H
