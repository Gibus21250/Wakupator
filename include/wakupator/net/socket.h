//
// Created by Nathan on 27/10/2026.
//

#ifndef WAKUPATOR_SOCKET_H
#define WAKUPATOR_SOCKET_H

#include "wakupator/core/client.h"

int create_raw_socket_filtered_ip_port(int if_index, const ip_port_info *ip_port_info);
int create_raw_socket_any_traffic_from_mac(const uint8_t mac_raw[6]);
int create_raw_socket_arp_request(int if_index, struct in_addr ip_raw, const uint8_t mac_raw[6]);
int create_raw_socket_ns_request(int if_index, struct in6_addr ip_raw, const uint8_t mac_raw[6]);

struct sock_fprog create_bpf_filter_for_ip_ports(const ip_port_info *ip_port_info);

#endif //WAKUPATOR_SOCKET_H