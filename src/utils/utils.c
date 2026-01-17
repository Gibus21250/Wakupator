#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include "wakupator/utils/utils.h"

#include <stdlib.h>

int init_ip_socket(const char *ip, const int port, const int sockType, const int protocol, struct sockaddr_storage* storeAddrInfo, int* sockaddr_size)
{
    const int opt = 1;
    const int AF = (strchr(ip, ':') != NULL) ? AF_INET6 : AF_INET;

    //Clear storeAddrInfo struct
    memset(storeAddrInfo, 0, sizeof(struct sockaddr_storage));

    // Create the socket
    const int sock = socket(AF, sockType, protocol);

    if (sock == -1) {
        return -1;
    }

    // To avoid bind: Address already in use (when restarted too fast)
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (AF == AF_INET6) {
        // Disable Dual stack listening (for [::] binding)
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    }

    if (AF == AF_INET) {
        // IPv4
        struct sockaddr_in* saddr = (struct sockaddr_in*) storeAddrInfo;
        saddr->sin_family = AF_INET;
        saddr->sin_port = htons(port);
        memset(&saddr->sin_zero, 0, sizeof(saddr->sin_zero));
        if (inet_pton(AF_INET, ip, &(saddr->sin_addr)) != 1) {
            close(sock);
            return -1;
        }
        *sockaddr_size = sizeof(struct sockaddr_in);

    } else {
        // IPv6
        struct sockaddr_in6 *saddr = (struct sockaddr_in6*) storeAddrInfo;
        saddr->sin6_family = AF_INET6;
        saddr->sin6_port = htons(port);
        saddr->sin6_flowinfo = 0;
        saddr->sin6_scope_id = 0;
        if(inet_pton(AF_INET6, ip, &(saddr->sin6_addr)) != 1) {
            close(sock);
            return -1;
        }
        *sockaddr_size = sizeof(struct sockaddr_in6);
    }

    return sock;
}

const char* print_ip_packet_info(const unsigned char *buffer, ssize_t packet_size)
{

    const size_t MSG_SIZE = 512;
    char* message = (char*) malloc(MSG_SIZE * sizeof (const char));

    if (!message)
        return NULL;

    if (packet_size < sizeof(struct ethhdr)) {
        sprintf(message, "Packet is too small. (%ld bytes)", packet_size);
        return message;
    }

    char src_ip_str[INET6_ADDRSTRLEN+2];
    char dst_ip_str[INET6_ADDRSTRLEN+2];
    uint16_t dst_port = 0;
    uint16_t src_port = 0;

    struct ethhdr *eth = (struct ethhdr *)buffer;
    uint16_t ether_type = ntohs(eth->h_proto);

    if (ether_type == ETH_P_IP)
    {
        struct iphdr *ip4 = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        if (ip4->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip4->ihl * 4));
            dst_port = ntohs(tcp->dest);
            src_port = ntohs(tcp->source);

            inet_ntop(AF_INET, &ip4->saddr, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip4->daddr, dst_ip_str, INET_ADDRSTRLEN);

        }
    }
    else if (ether_type == ETH_P_IPV6)
    {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));

        if (ip6->ip6_nxt == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
            dst_port = ntohs(tcp->dest);
            src_port = ntohs(tcp->source);

            char tmp_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, tmp_ip, INET6_ADDRSTRLEN);
            snprintf(src_ip_str, INET6_ADDRSTRLEN, "[%s]", tmp_ip);

            inet_ntop(AF_INET6, &ip6->ip6_dst, tmp_ip, INET6_ADDRSTRLEN);
            snprintf(dst_ip_str, INET6_ADDRSTRLEN, "[%s]", tmp_ip);

        }
    }

    snprintf(message, MSG_SIZE, "From %s:%u to %s:%u", src_ip_str, src_port, dst_ip_str, dst_port);

    return message;

}

void print_packet_details_ipv6(const struct ethhdr *eth, const struct ip6_hdr *ip6, const struct tcphdr *tcp)
{
    char src_ip_str[INET6_ADDRSTRLEN];
    char dest_ip_str[INET6_ADDRSTRLEN];
    char src_mac[18], dest_mac[18];

    inet_ntop(AF_INET6, &ip6->ip6_src, src_ip_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6->ip6_dst, dest_ip_str, INET6_ADDRSTRLEN);

    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    snprintf(dest_mac, sizeof(dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
             eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // Layer 2
    printf("Ethernet Frame Details:\n");
    printf("Source MAC: %s\n", src_mac);
    printf("Destination MAC: %s\n", dest_mac);
    printf("EtherType: 0x%04x\n", ntohs(eth->h_proto));

    // Layer 3
    printf("IPv6 Packet Details:\n");
    printf("Source IP: %s\n", src_ip_str);
    printf("Destination IP: %s\n", dest_ip_str);
    printf("Traffic Class: 0x%02x\n", (ip6->ip6_flow >> 20) & 0xFF);
    printf("Flow Label: 0x%05x\n", ntohl(ip6->ip6_flow) & 0xFFFFF);
    printf("Payload Length: %d\n", ntohs(ip6->ip6_plen));
    printf("Next Header: 0x%02x (TCP)\n", ip6->ip6_nxt);
    printf("Hop Limit: %d\n", ip6->ip6_hlim);

    // Layer 4
    printf("TCP Segment Details:\n");
    printf("Source Port: %d\n", ntohs(tcp->source));
    printf("Destination Port: %d\n", ntohs(tcp->dest));
    printf("Sequence Number: %u\n", ntohl(tcp->seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp->ack_seq));
    printf("Data Offset: %d (bytes: %d)\n", tcp->doff, tcp->doff * 4);
    printf("Flags:\n");
    printf("  SYN: %s\n", tcp->syn ? "Set" : "Not Set");
    printf("  ACK: %s\n", tcp->ack ? "Set" : "Not Set");
    printf("  FIN: %s\n", tcp->fin ? "Set" : "Not Set");
    printf("  RST: %s\n", tcp->rst ? "Set" : "Not Set");
    printf("  PSH: %s\n", tcp->psh ? "Set" : "Not Set");
    printf("  URG: %s\n", tcp->urg ? "Set" : "Not Set");
    printf("  NS: %s\n", (tcp->res1 & 0x1) ? "Set" : "Not Set");
    printf("Window Size: %d\n", ntohs(tcp->window));
    printf("Checksum: 0x%04x\n", ntohs(tcp->check));
    printf("Urgent Pointer: %d\n", ntohs(tcp->urg_ptr));
}