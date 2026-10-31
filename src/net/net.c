#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <asm-generic/errno-base.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "wakupator/log/log.h"
#include "wakupator/net/net.h"

#include <errno.h>
#include <asm-generic/errno.h>

#define BUFFER_SIZE 512

// ------ General net ------

int str_to_raw_mac(const char *mac_str, unsigned char *mac_raw)
{

    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_raw[0], &mac_raw[1], &mac_raw[2],
                                                                &mac_raw[3], &mac_raw[4], &mac_raw[5]) != 6)
        return -1;

    return 0;
}

int clear_socket(const int socket)
{
    char buffer[128];
    ssize_t len;

    //Clear if necessary
    while ((len = recv(socket, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0) {}

    if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return -1;
    }

    return 0;
}

int get_ipv6_link_local(const char *if_name, struct in6_addr *addr)
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

        if (ifa->ifa_addr->sa_family == AF_INET6 && strcmp(ifa->ifa_name, if_name) == 0) {

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

int send_wake_on_lan(const int raw_socket, const unsigned char *mac_src, const unsigned char *mac_target)
{
    char frame[ETHER_HDR_LEN + 102];

    struct ether_header *eth = (struct ether_header *) frame;

    memset(eth->ether_dhost, 0xFF, ETH_ALEN);
    memcpy(&eth->ether_shost, mac_src, ETH_ALEN);
    eth->ether_type = htons(0x0842); //WoL proto 0x0842 (historical)

    unsigned char *payload = (unsigned char *)(frame + ETHER_HDR_LEN);
    //Sync stream
    memset(payload, 0xFF, 6);

    //Write magic pattern
    for (int i = 0; i < 16; i++) {
        memcpy(payload + 6 + i * ETH_ALEN, mac_target, ETH_ALEN);
    }

    if (send(raw_socket, frame, sizeof(frame), 0) < 0) {
        return -1;
    }
    return 0;
}

// ------ Netlink manipulations ------

/**
 * Wrapper to create and send a NetLink message
 */
static int nl_talk(struct nlmsghdr *nlh) {
    const int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Error creating Netlink socket");
        return -1;
    }

    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        perror("Error binding Netlink socket");
        close(sock);
        return -1;
    }

    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
    const struct msghdr msg = {
        .msg_name = &kernel,
        .msg_namelen = sizeof(kernel),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    if (sendmsg(sock, &msg, 0) < 0) {
        perror("Error sending Netlink message");
        close(sock);
        return -1;
    }

    char buf[BUFFER_SIZE] = {0};
    const ssize_t len = recv(sock, buf, sizeof(buf), 0);
    close(sock);

    if (len < 0) {
        perror("Error receiving Netlink ACK");
        return -1;
    }

    struct nlmsghdr *h = (struct nlmsghdr*) buf;
    if (h->nlmsg_type == NLMSG_ERROR) {
        const struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
        if (err->error != 0) {
            // Ignore ENOENT / EEXIST
            if (err->error == -EEXIST || err->error == -ENOENT) return 0;
            fprintf(stderr, "Netlink error: %s\n", strerror(-err->error));
            return -1;
        }
    }
    return 0;
}

int modify_route(const int if_index, const char *ip_str, const ip_operation_t op) {

    LOG_DEBUG("%s a static route on Interface %d to IP %s\n",
        op == IP_OP_ADD ? "Adding" : "Removing",
        if_index, ip_str);

    char buf[BUFFER_SIZE] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr*)buf;
    struct rtmsg *rtm = (struct rtmsg*)(buf + sizeof(struct nlmsghdr));

    const int is_v6 = (strchr(ip_str, ':') != NULL);
    const int family = is_v6 ? AF_INET6 : AF_INET;

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = (op == IP_OP_ADD) ? RTM_NEWROUTE : RTM_DELROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (op == IP_OP_ADD) nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

    rtm->rtm_family = family;
    rtm->rtm_dst_len = is_v6 ? 128 : 32;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_BOOT;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = RTN_UNICAST;

    // RTA_DST Target IP
    struct rtattr *rta = (struct rtattr*)(((char*)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = RTA_DST;

    if (is_v6) {
        rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
        inet_pton(AF_INET6, ip_str, RTA_DATA(rta));
    } else {
        rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
        inet_pton(AF_INET, ip_str, RTA_DATA(rta));
    }
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + rta->rta_len;

    // RTA_OIF = device
    rta = (struct rtattr*)(((char*)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = RTA_OIF;
    rta->rta_len = RTA_LENGTH(sizeof(unsigned int));
    memcpy(RTA_DATA(rta), &if_index, sizeof(unsigned int));
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + rta->rta_len;

    return nl_talk(nlh);
}

static int nl_add_attr(struct nlmsghdr *nlh, size_t max_len, const unsigned short type, const void *data, const size_t data_len) {
    const size_t rta_len = RTA_LENGTH(data_len);
    if (NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta_len) > max_len) {
        perror("Netlink message too large\n");
        return -1;
    }

    struct rtattr *rta = (struct rtattr*)(((char*)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = rta_len;
    memcpy(RTA_DATA(rta), data, data_len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + rta_len;
    return 0;
}

int modify_neighbor(const int if_index, const char *ip_str, const uint8_t mac_raw[6], const ip_operation_t op) {

    LOG_DEBUG("%s a static neigh on Interface %d for IP %s and MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
          op == IP_OP_ADD ? "Adding" : "Removing",
          if_index, ip_str,
          mac_raw[0], mac_raw[1], mac_raw[2],
          mac_raw[3], mac_raw[4], mac_raw[5]);

    char buf[BUFFER_SIZE] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr*)buf;
    struct ndmsg *ndm = (struct ndmsg*)NLMSG_DATA(nlh);

    const int is_v6 = (strchr(ip_str, ':') != NULL);
    const int family = is_v6 ? AF_INET6 : AF_INET;

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    nlh->nlmsg_type = (op == IP_OP_ADD) ? RTM_NEWNEIGH : RTM_DELNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (op == IP_OP_ADD) nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

    ndm->ndm_family = family;
    ndm->ndm_ifindex = if_index;
    ndm->ndm_state = (op == IP_OP_ADD) ? NUD_PERMANENT : 0;

    // NDA_DST
    unsigned char ip_bin[sizeof(struct in6_addr)];

    if (inet_pton(family, ip_str, ip_bin) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }
    if (nl_add_attr(nlh, sizeof(buf), NDA_DST, ip_bin,
                    is_v6 ? sizeof(struct in6_addr) : sizeof(struct in_addr)) < 0)
        return -1;

    // NDA_LLADDR only when adding a neigh
    if (op == IP_OP_ADD) {
        if (nl_add_attr(nlh, sizeof(buf), NDA_LLADDR, mac_raw, ETH_ALEN) < 0)
            return -1;
    }

    return nl_talk(nlh);
}

// ------ ARP ------

int probe_arp(const int raw_socket, const uint8_t mac_raw[6], const struct in_addr target_ip)
{

    const arp_packet arp_pkt = build_probe_arp_packet(mac_raw, target_ip);

    if (send(raw_socket, &arp_pkt, sizeof(arp_pkt), 0) < 0)
        return -1;

    return 0;

}

arp_packet build_probe_arp_packet(const uint8_t mac_raw[6], const struct in_addr target_ip)
{
    arp_packet arp_pkt = {0};

    // ------ Ethernet Header ------
    memset(arp_pkt.eth.ether_dhost, 0xFF, 6);                     // Broadcast
    memcpy(arp_pkt.eth.ether_shost, mac_raw, 6);                    // src mac
    arp_pkt.eth.ether_type = htons(ETH_P_ARP);

    // ------ ARP Packet ------
    arp_pkt.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);                  // Ethernet
    arp_pkt.arp.ea_hdr.ar_pro = htons(ETH_P_IP);                      // IPv4
    arp_pkt.arp.ea_hdr.ar_hln = ETHER_ADDR_LEN;                               // MAC Length
    arp_pkt.arp.ea_hdr.ar_pln = sizeof(struct in_addr);                       // IPv4 Length
    arp_pkt.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);                  // ARP Request

    // Sender
    memcpy(arp_pkt.arp.arp_sha, mac_raw, ETHER_ADDR_LEN);
    memset(arp_pkt.arp.arp_spa, 0, sizeof(struct in_addr));          // 0.0.0.0

    // Target
    memset(arp_pkt.arp.arp_tha, 0, ETHER_ADDR_LEN);
    memcpy(arp_pkt.arp.arp_tpa, &target_ip.s_addr, sizeof(uint32_t));

    return arp_pkt;
}

int reply_arp(const int raw_socket, const uint8_t mac_raw[6], const arp_packet *request_arp, const struct in_addr spoofed_ip)
{

    const arp_packet reply_arp = build_reply_arp_packet(mac_raw, request_arp, spoofed_ip);

    if (send(raw_socket, &reply_arp, sizeof(arp_packet), 0) < 0)
        return -1;

    return 0;

}

arp_packet build_reply_arp_packet(const uint8_t mac_raw[6], const arp_packet *request_arp, struct in_addr spoofed_ip)
{
    arp_packet reply_arp = {0};

    //Note:
    //ETH header MAC src can be different from ARP src sender

    // ------ Ethernet Header ------
    memcpy(reply_arp.eth.ether_dhost, request_arp->eth.ether_shost, ETHER_ADDR_LEN);         // Mac from the request
    memcpy(reply_arp.eth.ether_shost, mac_raw, ETHER_ADDR_LEN);                              // Mac from the bounded interface
    reply_arp.eth.ether_type = htons(ETH_P_ARP);

    // ------ ARP Packet ------
    reply_arp.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);                                  // Ethernet
    reply_arp.arp.ea_hdr.ar_pro = htons(ETH_P_IP);                                      // IPv4
    reply_arp.arp.ea_hdr.ar_hln = ETHER_ADDR_LEN;                                               // MAC Length
    reply_arp.arp.ea_hdr.ar_pln = sizeof(struct in_addr);                                       // IPv4 Length
    reply_arp.arp.ea_hdr.ar_op = htons(ARPOP_REPLY);                                    // ARP Reply

    // Sender
    memcpy(reply_arp.arp.arp_sha, mac_raw, ETHER_ADDR_LEN);
    memcpy(reply_arp.arp.arp_spa, &spoofed_ip.s_addr, sizeof(struct in_addr));                // Spoofed IP

    // Target
    memcpy(reply_arp.arp.arp_tha, &request_arp->arp.arp_sha, ETHER_ADDR_LEN);                 // Use ARP src MAC
    memcpy(reply_arp.arp.arp_tpa, &request_arp->arp.arp_spa, sizeof(struct in_addr));         // Use ARP src IP

    return reply_arp;
}

// ------ ND IPv6 ------

static uint32_t sum16(uint32_t sum, const uint8_t *p, size_t len)
{
    for (; len > 1; p += 2, len -= 2)
        sum += (uint32_t)(p[0] << 8 | p[1]);
    if (len)
        sum += (uint32_t)p[0] << 8;   // odd ?
    return sum;
}

uint16_t icmp6_checksum(const struct in6_addr *src, const struct in6_addr *dst, const void *icmp_data, const uint32_t icmp6_len)
{

    //https://www.rfc-editor.org/info/rfc4443/#section-2.3
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t length;
        uint8_t zeros[3];
        uint8_t next_header;
    } __attribute__((packed)) pseudo_header_icmp6;

    memcpy(&pseudo_header_icmp6.src, src, sizeof pseudo_header_icmp6.src);
    memcpy(&pseudo_header_icmp6.dst, dst, sizeof pseudo_header_icmp6.dst);
    pseudo_header_icmp6.length = htonl(icmp6_len);
    memset(pseudo_header_icmp6.zeros, 0, sizeof pseudo_header_icmp6.zeros);
    pseudo_header_icmp6.next_header = IPPROTO_ICMPV6;   //58

    // Checksum pseudo header
    uint32_t sum = sum16(0, (const uint8_t *)&pseudo_header_icmp6, sizeof pseudo_header_icmp6);

    //Checksum icmp data
    sum = sum16(sum, icmp_data, icmp6_len);

    // Carry
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t) ~sum;
}

int probe_ns(const int raw_socket, const uint8_t mac_raw[6], const struct in6_addr* link_ipv6,
    const struct in6_addr* target_ip)
{

    ns_packet pkt;

    const size_t icmp_len = sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr) + 6;

    struct in6_addr solicited_node_addr = {0};

    // ff02::1:ffXX:XXXX
    solicited_node_addr.s6_addr[0] = 0xff;
    solicited_node_addr.s6_addr[1] = 0x02;
    solicited_node_addr.s6_addr[11] = 0x01;
    solicited_node_addr.s6_addr[12] = 0xff;
    solicited_node_addr.s6_addr[13] = target_ip->s6_addr[13];
    solicited_node_addr.s6_addr[14] = target_ip->s6_addr[14];
    solicited_node_addr.s6_addr[15] = target_ip->s6_addr[15];

    // ------ Ethernet Header ------
    // MAC multicast IPv6: 33:33:XX:XX:XX:XX (last 32 bits of the IPv6 multicast)
    pkt.eth.ether_dhost[0] = 0x33;
    pkt.eth.ether_dhost[1] = 0x33;
    memcpy(&pkt.eth.ether_dhost[2], &solicited_node_addr.s6_addr[12], 4);
    //Src
    memcpy(pkt.eth.ether_shost, mac_raw, 6);
    pkt.eth.ether_type = htons(ETH_P_IPV6);

    // ------ IPv6 Header ------
    pkt.ipv6.ip6_vfc = 0x60;
    pkt.ipv6.ip6_plen = htons(sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr) + 6);
    pkt.ipv6.ip6_nxt = IPPROTO_ICMPV6;
    pkt.ipv6.ip6_hlim = 255;

    // Src = manager IPv6 Link Local address
    memcpy(pkt.ipv6.ip6_src.s6_addr, link_ipv6, sizeof(struct in6_addr));

    // Dest = solicited-node multicast
    memcpy(&pkt.ipv6.ip6_dst, &solicited_node_addr, sizeof(struct in6_addr));

    // ------ Neighbor Solicitation ------
    pkt.ns.nd_ns_type = ND_NEIGHBOR_SOLICIT;
    pkt.ns.nd_ns_code = 0;
    pkt.ns.nd_ns_reserved = 0;
    pkt.ns.nd_ns_cksum = 0;
    memcpy(&pkt.ns.nd_ns_target, target_ip, sizeof(struct in6_addr));

    // ------ Option: Source Link-Layer Address ------
    pkt.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    pkt.opt.nd_opt_len = 1;
    memcpy(pkt.src_mac, mac_raw, 6);



    //Checksum (converted to network endianness)
    pkt.ns.nd_ns_cksum = htons(icmp6_checksum(link_ipv6, &solicited_node_addr, &pkt.ns, icmp_len));

    //Send
    if (send(raw_socket, &pkt, sizeof(pkt), 0) < 0)
        return -1;

    return 0;
}


int reply_ns(int raw_socket, const uint8_t mac_raw[6], const ns_packet *received,
    const struct in6_addr *spoofed_ip)
{
    na_packet pkt;
    const size_t icmp_len = sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + 6;

    struct sockaddr_ll addr;
    struct in6_addr dst_addr;

    memcpy(&dst_addr, &received->ipv6.ip6_src, sizeof(struct in6_addr));

    // No DAD (::) reply
    if (IN6_IS_ADDR_UNSPECIFIED(&dst_addr)) {
        return -1;
    }

    // ------ Ethernet Header ------
    memcpy(pkt.eth.ether_dhost, received->eth.ether_shost, 6);
    memcpy(pkt.eth.ether_shost, mac_raw, 6);
    pkt.eth.ether_type = htons(ETH_P_IPV6);

    // ------ IPv6 Header ------
    pkt.ipv6.ip6_vfc = 0x60;
    pkt.ipv6.ip6_plen = htons(icmp_len);
    pkt.ipv6.ip6_nxt = IPPROTO_ICMPV6;
    pkt.ipv6.ip6_hlim = 255;
    memcpy(&pkt.ipv6.ip6_src, spoofed_ip, sizeof(struct in6_addr));
    memcpy(&pkt.ipv6.ip6_dst, &dst_addr, sizeof(struct in6_addr));

    // ------ Neighbor Advertisement ------
    pkt.na.nd_na_type = ND_NEIGHBOR_ADVERT;
    pkt.na.nd_na_code = 0;
    pkt.na.nd_na_cksum = 0;
    pkt.na.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
    memcpy(&pkt.na.nd_na_target, spoofed_ip, sizeof(struct in6_addr));

    // ------ Option: Target LLAddr ------
    pkt.opt.nd_opt_type = ND_OPT_TARGET_LINKADDR;
    pkt.opt.nd_opt_len = 1;
    memcpy(pkt.target_mac, mac_raw, 6);

    // Checksum (converted to network endianness)
    pkt.na.nd_na_cksum = htons(icmp6_checksum(spoofed_ip, &dst_addr, &pkt.na, icmp_len));

    if (send(raw_socket, &pkt, sizeof(pkt), 0) < 0)
        return -1;

    return 0;
}