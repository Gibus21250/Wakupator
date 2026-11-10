//
// Created by Nathan on 07/09/2024.
//

#ifndef WAKUPATOR_BPF_UTILS_H
#define WAKUPATOR_BPF_UTILS_H

#include <stdint.h>
#include <linux/filter.h>

uint32_t filter_ether(struct sock_filter *buffer, uint32_t code_index, unsigned short ether_type);

uint32_t filter_mac(struct sock_filter *buffer, uint32_t code_index, const uint8_t mac_raw[6]);

uint32_t filter_ipv4(struct sock_filter *buffer, uint32_t code_index, struct in_addr raw_ipv4, int l3_start);

uint32_t filter_ipv6(struct sock_filter *buffer, uint32_t code_index, struct in6_addr raw_ipv6, int l3_start);

uint32_t filter_protocol(struct sock_filter *buffer, uint32_t code_index, uint16_t proto, uint32_t ip_family, int l3_start);

uint32_t filter_ports(struct sock_filter *buffer, uint32_t code_index, const uint16_t *ports, uint32_t nb_port,  int l4_start);

#endif