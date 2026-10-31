//
// Created by Nathan on 07/09/2024.
//
#include <byteswap.h>
#include <arpa/inet.h>

#include "../../include/wakupator/net/bpf.h"

uint32_t filter_ether(struct sock_filter *buffer, uint32_t code_index, const uint16_t ether_type)
{
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xc); // Load EtherType
    buffer[code_index++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ether_type, 1, 0); // etherType
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0); //Skip current packet

    return code_index;
}

/**
 *  Capture packets with SRC MAC == mac_raw
 */
uint32_t filter_mac(struct sock_filter *buffer, uint32_t code_index, const uint8_t mac_raw[6])
{

    const uint32_t mac_hi32 = ((uint32_t)mac_raw[0] << 24) |
                              ((uint32_t)mac_raw[1] << 16) |
                              ((uint32_t)mac_raw[2] << 8)  |
                               (uint32_t)mac_raw[3];

    const uint32_t mac_lo16 = ((uint32_t)mac_raw[4] << 8) | mac_raw[5];

    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x6);
    buffer[code_index++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_hi32, 0, 2);

    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xa);
    buffer[code_index++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_lo16, 1, 0);

    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0);

    return code_index;
}

/**
 * Fill the sock_filter buffer with BPF instruction to filter IPv4 in DST
 */
uint32_t filter_ipv4(struct sock_filter *buffer, uint32_t code_index, const struct in_addr raw_ipv4, const int l3_start)
{
    //Convert big endian to host. BPF auto convert big endian (network endian) to host endian
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, l3_start + 16); //Load dst IPV4
    buffer[code_index++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohl(raw_ipv4.s_addr), 1, 0); // == raw_IPv4 ?
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_RET+BPF_K, 0); //Skip current packet

    return code_index;
}

uint32_t filter_ipv6(struct sock_filter *buffer, uint32_t code_index, const struct in6_addr raw_ipv6, const int l3_start)
{
    int offset = l3_start + 24;

    for (int i = 0; i < 4; ++i) {
        //Load 32bits of IPv6
        buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offset);

        const uint8_t jt = (i == 3) ? 1 : 0;
        const uint8_t jf = (i == 3) ? 0 : (uint8_t)((3 - i) * 2); // Remaining jump to RET 0

        buffer[code_index++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohl(raw_ipv6.s6_addr32[i]), jt, jf);

        offset += 4;
    }

    //Skip current packet
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0);

    return code_index;
}

uint32_t filter_protocol(struct sock_filter *buffer, uint32_t code_index, const uint16_t proto, const uint32_t ip_family, const int l3_start)
{
    const uint32_t padding_proto = ip_family == AF_INET?9:6;
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_B + BPF_ABS, l3_start + padding_proto); //Load proto in layer IP
    buffer[code_index++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, proto, 1, 0);
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0); //Skip current packet
    return code_index;
}

uint32_t filter_ports(struct sock_filter *buffer, uint32_t code_index, const uint16_t *ports, const uint32_t nb_port, const int l4_start)
{

    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_H + BPF_ABS, l4_start + 0x2); //Load dport in layer4

    for (uint32_t i = 0; i < nb_port; ++i) {
        buffer[code_index++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ports[i], nb_port - i, 0);
    }
    buffer[code_index++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0); //Skip current packet
    return code_index;
}
