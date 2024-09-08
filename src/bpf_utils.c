//
// Created by Nathan on 07/09/2024.
//
#include <byteswap.h>
#include <arpa/inet.h>

#include "bpf_utils.h"

uint32_t filter_ether(struct sock_filter *buffer, uint32_t codeIndex, const unsigned short etherType)
{
    //int vlanPadding = vlan == ETHERTYPE_VLAN ? 4:0;
    //MAC src + MAC dst = 12 or 16 if VLAN
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xc); // Load EtherType
    buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, etherType, 1, 0); // IPvx header ?
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_RET+BPF_K, 0); //Skip current packet

    return codeIndex;
}

uint32_t filter_ipv4(struct sock_filter *buffer, uint32_t codeIndex, const uint32_t raw_ipv4, const int l3Start)
{
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, l3Start + 12); //Load dst IPV4
    buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, raw_ipv4, 1, 0); // == raw_IPv4 ?
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_RET+BPF_K, 0); //Skip current packet

    return codeIndex;
}

uint32_t filter_ipv6(struct sock_filter *buffer, uint32_t codeIndex, const uint32_t raw_ipv6[4], const int l3Start)
{
    //Todo improve if IPv6 multiple next header compute padding
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, l3Start + 24); //Load first chunk IPV6
    buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, bswap_32(raw_ipv6[0]), 0, 6); // == raw_IPv6[0] ?
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, l3Start + 28); //Load second chunk IPV6 TODO rechanger + value
    buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, bswap_32(raw_ipv6[1]), 0, 4); // == raw_IPv6[1] ?
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, l3Start + 32); //etc
    buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, bswap_32(raw_ipv6[2]), 0, 2); // etc
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_W + BPF_ABS, l3Start + 36);
    buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, bswap_32(raw_ipv6[3]), 1, 0);
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0); //Skip current packet

    return codeIndex;
}

uint32_t filter_protocol(struct sock_filter *buffer, uint32_t codeIndex, const uint16_t proto, const uint32_t ipFamily, const int l3Start)
{
    uint32_t paddingProto = ipFamily == AF_INET?9:6;
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_B + BPF_ABS, l3Start + paddingProto); //Load proto in layer IP
    buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, proto, 1, 0);
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0); //Skip current packet
    return codeIndex;
}

//Set a register to contain padding for port ?
uint32_t filter_ports(struct sock_filter *buffer, uint32_t codeIndex, const uint16_t *ports, const uint32_t nbPort, const int l4Start)
{

    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_LD + BPF_H + BPF_ABS, l4Start + 0x2); //Load port in layer4

    for (uint32_t i = 0; i < nbPort; ++i) {
        buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ports[i], nbPort - i, 0);
    }
    //buffer[codeIndex++] = (struct sock_filter) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ports[0], 1, 0);
    buffer[codeIndex++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, 0); //Skip current packet
    return codeIndex;
}
