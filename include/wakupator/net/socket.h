//
// Created by Nathan on 27/10/2026.
//

#ifndef WAKUPATOR_SOCKET_H
#define WAKUPATOR_SOCKET_H

#include "wakupator/core/client.h"

/**
 * Create a raw socket bound to the 'if_index', with a dynamic BPF filter.
 * This socket capture all traffic for a specific IP and a list of port and protocol
 * @param if_index Index of the interface to bind the socket to
 * @param ip_port_info pointer to ip_port_info struct
 * @return fd of the socket, -1 if error
 */
int create_raw_socket_filtered_ip_port(int if_index, const ip_port_info *ip_port_info);

/**
 * Create a raw socket with a BPF filter to capture all packets with src MAC == mac_raw
 * @param mac_raw Mac raw to filter
 * @return fd of the socket, -1 if error
 */
int create_raw_socket_any_traffic_from_mac(const uint8_t mac_raw[6]);

/**
 * Create a raw socket bound to the 'if_index', with a BPF filter to capture all ARP request packets destined to IP and where Mac SRC != mac_raw
 * @param if_index Index of the interface to bind the socket to
 * @param ip_raw network oriented ip6 addr to filter
 * @param mac_raw Mac raw to filter
 * @return fd of the socket, -1 if error
 */
int create_raw_socket_arp_request(int if_index, struct in_addr ip_raw, const uint8_t mac_raw[6]);

/**
 * Create a raw socket bound to the 'if_index', with a BPF filter to capture all NS packets destined to IP and where Mac SRC != mac_raw
 * @param if_index Index of the interface to bind the socket to
 * @param ip_raw network oriented addr to filter
 * @param mac_raw Mac raw to filter
 * @return fd of the socket, -1 if error
 */
int create_raw_socket_ns_request(int if_index, struct in6_addr ip_raw, const uint8_t mac_raw[6]);

struct sock_fprog create_bpf_filter_for_ip_ports(const ip_port_info *ip_port_info);

#endif //WAKUPATOR_SOCKET_H