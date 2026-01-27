#include "wakupator/utils/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <netpacket/packet.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "wakupator/log/log.h"


#define BUFFER_SIZE 8192

// ------ General net ------

int parse_mac(const char *macStr, unsigned char *macRaw)
{

    if (sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macRaw[0], &macRaw[1], &macRaw[2],
                                                                &macRaw[3], &macRaw[4], &macRaw[5]) != 6)
        return -1;

    return 0;
}

int get_ipv6_link_local(const char *ifName, struct in6_addr *addr)
{
    struct ifaddrs *ifaddr;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        log_error("Error while retrieving IPv6 on the host.\n");
        return -1;
    }

    //For each IPv6
    for (const struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET6 && strcmp(ifa->ifa_name, ifName) == 0) {

            const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;

            if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
                memcpy(addr, &addr6->sin6_addr, sizeof(struct in6_addr));
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

int send_wake_on_lan(const int rawSocket, const int ifIndex, const unsigned char *macSrc, const unsigned char *macTarget)
{
    char frame[ETHER_HDR_LEN + 102];

    struct ether_header *eth = (struct ether_header *) frame;

    memset(eth->ether_dhost, 0xFF, ETH_ALEN);
    memcpy(&eth->ether_shost, macSrc, ETH_ALEN);
    eth->ether_type = htons(0x0842); //WoL proto 0x0842 (historical)

    unsigned char *payload = (unsigned char *)(frame + ETHER_HDR_LEN);
    //Sync stream
    memset(payload, 0xFF, 6);

    //Write magic pattern
    for (int i = 0; i < 16; i++) {
        memcpy(payload + 6 + i * ETH_ALEN, macTarget, ETH_ALEN);
    }

    struct sockaddr_ll socket_address = {0};
    socket_address.sll_ifindex = ifIndex;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, eth->ether_shost, ETH_ALEN);

    //Now send the packet through the lan
    if (sendto(rawSocket, frame, sizeof(frame), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        return -1;
    }
    return 0;
}

// ------ Netlink manipulations ------

typedef enum {
    IP_OP_ADD,
    IP_OP_REMOVE
} ip_operation_t;

int modify_ip_on_interface(const char* ifName, const char* ip_str, const ip_operation_t operation) {

    const int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Error while creating raw socket for Netlink.");
        return -1;
    }

    //Bind to NetLink
    struct sockaddr_nl local = {
        .nl_family = AF_NETLINK
    };

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        perror("Error while binding raw socket for Netlink.");
        close(sock);
        return -1;
    }

    char buf[BUFFER_SIZE] = {0};

    //NetLink header
    struct nlmsghdr *nlh = (struct nlmsghdr*) buf;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)(buf + sizeof(struct nlmsghdr));

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    if (operation == IP_OP_ADD) {
        nlh->nlmsg_type = RTM_NEWADDR;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    } else {  // IP_OP_REMOVE
        nlh->nlmsg_type = RTM_DELADDR;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    }

    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    ifa->ifa_family = strchr(ip_str, ':') ? AF_INET6 : AF_INET;
    ifa->ifa_prefixlen = (ifa->ifa_family == AF_INET) ? 32 : 128;
    ifa->ifa_scope = 0;
    ifa->ifa_index = if_nametoindex(ifName);

    if (ifa->ifa_index == 0) {
        fprintf(stderr, "Invalid interface name: %s.\n", ifName);
        close(sock);
        return -1;
    }

    // IP struct
    void* addr_buf = NULL;
    int addr_len = 0;

    if (ifa->ifa_family == AF_INET) {
        struct in_addr* ip = malloc(sizeof(struct in_addr));
        if (inet_pton(AF_INET, ip_str, ip) != 1) {
            fprintf(stderr, "Invalid IPv4 address: %s.\n", ip_str);
            free(ip);
            close(sock);
            return -1;
        }
        addr_buf = ip;
        addr_len = sizeof(struct in_addr);
    } else {
        struct in6_addr* ip6 = malloc(sizeof(struct in6_addr));
        if (inet_pton(AF_INET6, ip_str, ip6) != 1) {
            fprintf(stderr, "Invalid IPv6 address: %s.\n", ip_str);
            free(ip6);
            close(sock);
            return -1;
        }
        addr_buf = ip6;
        addr_len = sizeof(struct in6_addr);
    }

    //Prepare RTA struct and copy IP binary
    struct rtattr *rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(addr_len);
    memcpy(RTA_DATA(rta), addr_buf, addr_len);
    free(addr_buf);

    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_LENGTH(addr_len);

    //If IPv6 and adding, disable DAD for this IP and adjust header len
    if (ifa->ifa_family == AF_INET6 && operation == IP_OP_ADD) {
        struct rtattr* rta_flags = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
        const uint32_t flags = IFA_F_NODAD;

        rta_flags->rta_type = IFA_FLAGS;
        rta_flags->rta_len = RTA_LENGTH(sizeof(uint32_t));
        memcpy(RTA_DATA(rta_flags), &flags, sizeof(uint32_t));

        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_LENGTH(sizeof(uint32_t));
    }

    // Prepare to send
    struct sockaddr_nl kernel = {
        .nl_family = AF_NETLINK
    };

    struct iovec iov = {
        .iov_base = nlh,
        .iov_len = nlh->nlmsg_len
    };

    const struct msghdr msg = {
        .msg_name = &kernel,
        .msg_namelen = sizeof(kernel),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    // Send message
    if (sendmsg(sock, &msg, 0) < 0) {
        perror("Error while sending the message to Netlink");
        close(sock);
        return -1;
    }

    // "Control" ACK
    const ssize_t len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) {
        perror("Error while receiving the message to Netlink");
        close(sock);
        return -1;
    }

    struct nlmsghdr *h = (struct nlmsghdr*) buf;
    //Should be all the time true (because of ACK asked)
    if (h->nlmsg_type == NLMSG_ERROR) {
        const struct nlmsgerr *err = NLMSG_DATA(h);
        //True error ?
        if (err->error) {
            const char* op_name = (operation == IP_OP_ADD) ? "adding" : "removing";
            fprintf(stderr, "Error while %s IP: %s\n", op_name, strerror(-err->error));
            close(sock);
            return -1;
        }
    }

    close(sock);
    return 0;
}

int add_ip(const char* ifName, const char* ip_str) {
    return modify_ip_on_interface(ifName, ip_str, IP_OP_ADD);
}

int remove_ip(const char* ifName, const char* ip_str){
    return modify_ip_on_interface(ifName, ip_str, IP_OP_REMOVE);
}

int check_ipv4_exists(const char *ip_str, ip_search_result_t *result) {
    int sock;
    struct sockaddr_nl sa;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;
    char buffer[BUFFER_SIZE];
    ssize_t len;
    struct nlmsghdr *nlh;
    struct in_addr target_addr;

    if (result) {
        result->found = 0;
        result->ifindex = -1;
        memset(result->ifname, 0, sizeof(result->ifname));
    }else
        return -1;

    if (inet_pton(AF_INET, ip_str, &target_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ip_str);
        return -1;
    }

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Error while creating raw socket for Netlink.");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Error while binding raw socket for Netlink.");
        close(sock);
        return -1;
    }

    // Prepare request RTM_GETADDR
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.ifa.ifa_family = AF_INET;

    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("Error while sending request to Netlink.");
        close(sock);
        return -1;
    }

    // Loop through all response
    while (1) {
        len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("Error while receiving request response from Netlink");
            close(sock);
            return -1;
        }

        if (len == 0) {
            break;
        }

        // Parsing
        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {

            //End
            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return result->found;
            }

            //Error
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Error Netlink\n");
                close(sock);
                return -1;
            }

            if (nlh->nlmsg_type != RTM_NEWADDR) {
                continue;
            }

            struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
            struct rtattr *rta = IFA_RTA(ifa);
            int rtl = IFA_PAYLOAD(nlh);

            // Parsing attributes
            while (RTA_OK(rta, rtl)) {
                if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
                    struct in_addr *addr = (struct in_addr *)RTA_DATA(rta);

                    // Compare with target IP
                    if (memcmp(addr, &target_addr, sizeof(struct in_addr)) == 0) {
                        result->found = 1;
                        result->ifindex = ifa->ifa_index;
                        if_indextoname(ifa->ifa_index, result->ifname);
                        close(sock);
                        return 1; //Founded
                    }
                }
                rta = RTA_NEXT(rta, rtl);
            }
        }
    }

    close(sock);
    return 0;
}

int check_ipv6_exists(const char *ip_str, ip_search_result_t *result) {
    int sock;
    struct sockaddr_nl sa;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;
    char buffer[BUFFER_SIZE];
    ssize_t len;
    struct nlmsghdr *nlh;
    struct in6_addr target_addr;

    if (inet_pton(AF_INET6, ip_str, &target_addr) != 1) {
        fprintf(stderr, "Invalid IPv6 address: %s\n", ip_str);
        return -1;
    }

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Error while creating raw socket for Netlink.");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Error while binding raw socket for Netlink.");
        close(sock);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.ifa.ifa_family = AF_INET6;

    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("Error while sending request to Netlink.");
        close(sock);
        return -1;
    }

    if (result) {
        result->found = 0;
        result->ifindex = -1;
        memset(result->ifname, 0, sizeof(result->ifname));
    }

    while (1) {
        len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("Error while receiving request to Netlink.");
            close(sock);
            return -1;
        }

        if (len == 0) {
            break;
        }

        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return result ? result->found : 0;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Error Netlink\n");
                close(sock);
                return -1;
            }

            if (nlh->nlmsg_type != RTM_NEWADDR) {
                continue;
            }

            struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
            struct rtattr *rta = IFA_RTA(ifa);
            int rtl = IFA_PAYLOAD(nlh);

            while (RTA_OK(rta, rtl)) {
                if (rta->rta_type == IFA_ADDRESS) {
                    struct in6_addr *addr = (struct in6_addr *)RTA_DATA(rta);

                    if (memcmp(addr, &target_addr, sizeof(struct in6_addr)) == 0) {
                        if (result) {
                            result->found = 1;
                            result->ifindex = ifa->ifa_index;
                            if_indextoname(ifa->ifa_index, result->ifname);
                        }
                        close(sock);
                        return 1;
                    }
                }
                rta = RTA_NEXT(rta, rtl);
            }
        }
    }

    close(sock);
    return 0;
}

/**
 *
 * @param ip_str Char format of the target IP
 * @param result Struct filled to store the result
 * @return -1 if error, 0 if not found and 1 if found
 */
int check_ip_exists(const char *ip_str, ip_search_result_t *result) {
    if (strchr(ip_str, ':') != NULL) {
        return check_ipv6_exists(ip_str, result);
    } else {
        return check_ipv4_exists(ip_str, result);
    }
}

// ------ ARP and NS IPv6 ------
int send_arp(const manager *mng, const char* target_ip)
{

    arp_packet pkt = {0};
    struct sockaddr_ll addr;

    struct in_addr target_addr;

    if (inet_pton(AF_INET, target_ip, &target_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", target_ip);
    }

    // ------ Ethernet Header ------
    memset(pkt.eth.ether_dhost, 0xFF, 6);           // Broadcast
    memcpy(pkt.eth.ether_shost, mng->ifMacRaw, 6);  // src mac
    pkt.eth.ether_type = htons(ETH_P_ARP);

    // ------ ARP Packet ------
    pkt.arp.htype = htons(1);            // Ethernet
    pkt.arp.ptype = htons(ETH_P_IP);     // IPv4
    pkt.arp.hlen = 6;                            // MAC Length
    pkt.arp.plen = 4;                            // IPv4 Length
    pkt.arp.oper = htons(1);             // ARP Request

    // Sender
    memcpy(pkt.arp.sha, mng->ifMacRaw, 6);
    memset(pkt.arp.spa, 0, 4);                   // 0.0.0.0 (gratuitous ARP)

    // Target
    memset(pkt.arp.tha, 0, 6);
    memcpy(pkt.arp.tpa, &target_addr.s_addr, 4);

    // ------ Destination Address (layer 2) ------
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = mng->ifIndex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xFF, 6);              // Broadcast Ethernet

    // Send packet
    if (sendto(mng->mainRawSocket, &pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    return 0;

}

uint16_t icmpv6_checksum(const struct in6_addr *src, const struct in6_addr *dst, void *icmp_data, const size_t icmp_len)
{
    //https://www.rfc-editor.org/rfc/rfc2463#section-2.3

    //Pseudo header "IPv6 header"
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t length;
        uint8_t zeros[3];
        uint8_t next_header;
    } __attribute__((packed)) pseudo_header;

    memcpy(&pseudo_header.src, src, sizeof(struct in6_addr));
    memcpy(&pseudo_header.dst, dst, sizeof(struct in6_addr));
    pseudo_header.length = htonl(icmp_len);
    pseudo_header.zeros[0] = 0;
    pseudo_header.zeros[1] = 0;
    pseudo_header.zeros[2] = 0;
    pseudo_header.next_header = IPPROTO_ICMPV6;

    uint32_t sum = 0;

    // Checksum pseudo header
    const uint16_t *ptr = (uint16_t *)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Checksum ICMPv6 data
    ptr = (uint16_t *)icmp_data;
    for (size_t i = 0; i < icmp_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Circular padding if odd
    if (icmp_len % 2) {
        sum += ((uint8_t *)icmp_data)[icmp_len - 1] << 8;
    }

    // Carry
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ntohs(~sum);
}

int send_ns(const manager *mng, const char* target_ip)
{

    ns_packet pkt;

    const size_t icmp_len = sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr) + 6;

    struct sockaddr_ll addr;
    struct in6_addr target_addr;
    struct in6_addr solicited_node_addr;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;

    if (inet_pton(AF_INET6, target_ip, &target_addr) != 1) {
        log_error("Invalid IPv6 address: %s\n", target_ip);
        return -1;
    }

    // ff02::1:ffXX:XXXX
    memset(&solicited_node_addr, 0, sizeof(solicited_node_addr));
    solicited_node_addr.s6_addr[0] = 0xff;
    solicited_node_addr.s6_addr[1] = 0x02;
    solicited_node_addr.s6_addr[11] = 0x01;
    solicited_node_addr.s6_addr[12] = 0xff;
    solicited_node_addr.s6_addr[13] = target_addr.s6_addr[13];
    solicited_node_addr.s6_addr[14] = target_addr.s6_addr[14];
    solicited_node_addr.s6_addr[15] = target_addr.s6_addr[15];

    // ------ Ethernet Header ------
    // MAC multicast IPv6: 33:33:XX:XX:XX:XX (last 32 bits of the IPv6 multicast)
    pkt.eth.ether_dhost[0] = 0x33;
    pkt.eth.ether_dhost[1] = 0x33;
    memcpy(&pkt.eth.ether_dhost[2], &solicited_node_addr.s6_addr[12], 4);
    //Src
    memcpy(pkt.eth.ether_shost, mng->ifMacRaw, 6);
    pkt.eth.ether_type = htons(ETH_P_IPV6);

    // ------ IPv6 Header ------
    pkt.ipv6.ip6_vfc = 0x60;
    pkt.ipv6.ip6_plen = htons(sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr) + 6);
    pkt.ipv6.ip6_nxt = IPPROTO_ICMPV6;
    pkt.ipv6.ip6_hlim = 255;

    // Src = manager IPv6 Link Local address
    memcpy(pkt.ipv6.ip6_src.s6_addr, &mng->ifIPv6LinkLocal, sizeof(struct in6_addr));

    // Dest = solicited-node multicast
    memcpy(&pkt.ipv6.ip6_dst, &solicited_node_addr, sizeof(struct in6_addr));

    memcpy(&dst_addr, &solicited_node_addr, sizeof(struct in6_addr));
    memcpy(&src_addr, &mng->ifIPv6LinkLocal, sizeof(struct in6_addr));

    // ------ Neighbor Solicitation ------
    pkt.ns.nd_ns_type = ND_NEIGHBOR_SOLICIT;
    pkt.ns.nd_ns_code = 0;
    pkt.ns.nd_ns_reserved = 0;
    memcpy(&pkt.ns.nd_ns_target, &target_addr, sizeof(struct in6_addr));

    // ------ Option: Source Link-Layer Address ------
    pkt.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    pkt.opt.nd_opt_len = 1;
    memcpy(pkt.src_mac, mng->ifMacRaw, 6);

    //Checksum
    pkt.ns.nd_ns_cksum = icmpv6_checksum(&src_addr, &dst_addr, &pkt.ns, icmp_len);

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = mng->ifIndex;
    addr.sll_halen = 6;
    memcpy(addr.sll_addr, pkt.eth.ether_dhost, 6);

    //Send
    if (sendto(mng->mainRawSocket, &pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    return 0;
}