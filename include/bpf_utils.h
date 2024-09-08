//
// Created by Nathan on 07/09/2024.
//

#ifndef WAKUPATOR_BPF_UTILS_H
#define WAKUPATOR_BPF_UTILS_H

#include <stdint.h>
#include <linux/filter.h>

uint32_t filter_ether(struct sock_filter *buffer, uint32_t codeIndex, unsigned short etherType);

uint32_t filter_ipv4(struct sock_filter *buffer, uint32_t codeIndex, uint32_t raw_ipv4, int l3Start);

uint32_t filter_ipv6(struct sock_filter *buffer, uint32_t codeIndex, const uint32_t raw_ipv6[4], int l3Start);

uint32_t filter_protocol(struct sock_filter *buffer, uint32_t codeIndex, uint16_t proto, uint32_t ipFamily, int l3Start);

uint32_t filter_ports(struct sock_filter *buffer, uint32_t codeIndex, const uint16_t *ports, uint32_t nbPort,  int l4Start);

#endif