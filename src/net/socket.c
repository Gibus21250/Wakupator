#include "wakupator/net/socket.h"

#include <stdlib.h>
#include <unistd.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>

#include "wakupator/log/log.h"
#include "wakupator/net/bpf.h"
#include "wakupator/net/net.h"
#include "wakupator/utils/utils.h"

int create_raw_socket_any_traffic_from_mac(const uint8_t mac_raw[6])
{
    const int raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(raw_socket == -1)
        return -1;

    const uint32_t mac_hi32 = ((uint32_t)mac_raw[0] << 24) |
                              ((uint32_t)mac_raw[1] << 16) |
                              ((uint32_t)mac_raw[2] << 8)  |
                               (uint32_t)mac_raw[3];

    const uint32_t mac_lo16 = ((uint32_t)mac_raw[4] << 8) | mac_raw[5];

    struct sock_filter bpf_code[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x6),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_hi32, 0, 3),
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xa),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_lo16, 0, 1),

        BPF_STMT(BPF_RET + BPF_K, -1),
        BPF_STMT(BPF_RET + BPF_K, 0)
    };

    const struct sock_fprog bpf = {
        sizeof(bpf_code) / sizeof(struct sock_filter),
        bpf_code,
    };

    // Apply BPF filter to the socket
    if (setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_error("Error while setting the BPF prog to the raw socket");
        close(raw_socket);
        return -1;
    }

    const int res = clear_socket(raw_socket);

    if (res != 0) {
        log_error("Error while clearing the raw socket");
        close(raw_socket);
        return -1;
    }

    return raw_socket;
}

int create_raw_socket_filtered_ip_port(const int if_index, const ip_port_info *ip_port_info)
{

    //Generate and prepare BPF asm for the kernel
    const int raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(raw_socket == -1)
        return -1;

    struct sockaddr_ll addr = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = if_index,
    };

    if(bind(raw_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_error("Error while binding the raw socket to the network interface");
        close(raw_socket);
        return -1;
    }

    const struct sock_fprog bpf = create_bpf_filter_for_ip_ports(ip_port_info);

    if(bpf.len == (unsigned short) -1)
    {
        log_error("Error while creating the BPF prog");
        close(raw_socket);
        return -1;
    }

    // Apply BPF filter to the socket
    if (setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_error("Error while setting the BPF prog to the raw socket");
        close(raw_socket);
        free(bpf.filter);
        return -1;
    }

    free(bpf.filter);

    const int res = clear_socket(raw_socket);

    if (res != 0) {
        log_error("Error while clearing the raw socket");
        close(raw_socket);
        return -1;
    }

    return raw_socket;
}

int create_raw_socket_arp_request(const int if_index, const struct in_addr ip_raw, const uint8_t mac_raw[6])
{
    const int raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(raw_socket == -1)
    {
        log_error("Error while creating the ARP raw socket\n");
        return -1;
    }

    struct sockaddr_ll addr = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = if_index,
    };

    if(bind(raw_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_error("Error while binding the raw socket to the network interface\n");
        close(raw_socket);
        return -1;
    }

    const uint32_t mac_hi32 = ((uint32_t)mac_raw[0] << 24) |
                              ((uint32_t)mac_raw[1] << 16) |
                              ((uint32_t)mac_raw[2] << 8)  |
                               (uint32_t)mac_raw[3];

    const uint32_t mac_lo16 = ((uint32_t)mac_raw[4] << 8) | mac_raw[5];

    struct sock_filter bpf_code[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x6),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_hi32, 0, 2),
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xa),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_lo16, 7, 0),

        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xc),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 5),
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0x14),                           // Load ARP type
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 1, 0, 3),                       //ARP type == 1 (request) ?
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x26),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohl(ip_raw.s_addr), 0, 1),
        BPF_STMT(BPF_RET + BPF_K, -1),
        BPF_STMT(BPF_RET + BPF_K, 0)
    };

    const struct sock_fprog bpf = {
        sizeof(bpf_code) / sizeof(struct sock_filter),
        bpf_code,
    };

    // Apply BPF filter to the socket
    if (setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_error("Error while setting the BPF prog to the raw socket\n");
        close(raw_socket);
        return -1;
    }

    //Sometimes, the time between socket creation and applying the filter, can catch some packets
    const int res = clear_socket(raw_socket);

    if (res != 0) {
        log_error("Error while clearing the raw socket");
        close(raw_socket);
        return -1;
    }

    return raw_socket;
}

int create_raw_socket_ns_request(int if_index, struct in6_addr ip_raw, const uint8_t mac_raw[6])
{

    //doc:
    //https://support.huawei.com/enterprise/en/doc/EDOC1100174721/ce2e60ac/icmpv6-neighbor-solicitation-ns-message
    //NS are multicast to resolve an address, and unicast when verifying the reachability of a neighbor

    const int raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (raw_socket == -1)
    {
        log_error("Error while creating the NS raw socket\n");
        return -1;
    }

    struct sockaddr_ll addr = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = if_index,
    };

    if (bind(raw_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_error("Error while binding the raw socket to the network interface\n");
        close(raw_socket);
        return -1;
    }

    const uint32_t mac_hi32 = ((uint32_t)mac_raw[0] << 24) |
                              ((uint32_t)mac_raw[1] << 16) |
                              ((uint32_t)mac_raw[2] << 8)  |
                               (uint32_t)mac_raw[3];

    const uint32_t mac_lo16 = ((uint32_t)mac_raw[4] << 8) | mac_raw[5];

    struct sock_filter bpf_code[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x6),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_hi32, 0, 2),

        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xa),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_lo16, 15, 0),

        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0xc),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0, 13),

        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 0x14),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 11),

        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 0x36),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 0, 9),

        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x3e),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohl(ip_raw.s6_addr32[0]), 0, 7),

        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x42),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohl(ip_raw.s6_addr32[1]), 0, 5),

        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x46),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohl(ip_raw.s6_addr32[2]), 0, 3),

        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0x4a),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohl(ip_raw.s6_addr32[3]), 0, 1),

        BPF_STMT(BPF_RET + BPF_K, -1),
        BPF_STMT(BPF_RET + BPF_K, 0)
    };

    const struct sock_fprog bpf = {
        sizeof(bpf_code) / sizeof(struct sock_filter),
        bpf_code,
    };

    if (setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_error("Error while setting the BPF prog to the raw socket\n");
        close(raw_socket);
        return -1;
    }

    const int res = clear_socket(raw_socket);

    if (res != 0) {
        log_error("Error while clearing the raw socket");
        close(raw_socket);
        return -1;
    }

    return raw_socket;
}

struct sock_fprog create_bpf_filter_for_ip_ports(const ip_port_info *ip_port_info)
{

    //TODO control allocation size VS needed (tips: jt et jf sont des uint8, donc on pourra jamais sauter + de 255)
    //Apres calculs, ça donne 119 ports en ipv4 et 113 en ipv6. Sinon, il faudra le faire en deux parties etc (hell)
    struct sock_fprog res = {
            .filter = NULL,
            .len = -1
    };

    struct sock_filter *bpf_code = calloc(128, sizeof(struct sock_filter));

    if(bpf_code == NULL)
    {
        log_error("Error while allocating memory for the BPF filter for ip ports struct\n");
        return res;
    }

    uint32_t code_size = 0;


    if(ip_port_info->ip_format == AF_INET)
    {
        code_size = filter_ether(bpf_code, code_size, ETH_P_IP);
        code_size = filter_ipv4(bpf_code, code_size, ip_port_info->ipv4, 14);
    }
    else
    {
        code_size = filter_ether(bpf_code, code_size, ETH_P_IPV6);
        code_size = filter_ipv6(bpf_code, code_size, ip_port_info->ipv6, 14);
    }

    //TODO weak design if extension header in IPv6 (which push TCP/UDP indices in the packet)

    code_size = filter_protocol(bpf_code, code_size, IPPROTO_TCP, ip_port_info->ip_format, 14);
    code_size = filter_ports(bpf_code, code_size, ip_port_info->ports, ip_port_info->port_count, 14 + (ip_port_info->ip_format==AF_INET?20:40));

    bpf_code[code_size++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, -1); // Accept

    res.filter = bpf_code;
    res.len = code_size;

    return res;
}