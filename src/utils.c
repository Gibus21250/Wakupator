#include "utils.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

int init_socket(const char *ip, int port, int sockType, int protocol, struct sockaddr_storage* storeAddrInfo)
{
    int AF = (strchr(ip, ':') != NULL) ? AF_INET6 : AF_INET;

    // Create the socket
    int sock = socket(AF, sockType, protocol);

    if (sock == -1) {
        perror("Error while creating the server socket!\n");
        return -1;
    }

    if (AF == AF_INET) {
        // IPv4
        struct sockaddr_in* saddr = (struct sockaddr_in*) storeAddrInfo;
        saddr->sin_family = AF_INET;
        saddr->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &(saddr->sin_addr)) != 1) {
            perror("Error while writing IPv4 address in sockaddr\n");
            close(sock);
            return -1;
        }

    } else {
        // IPv6
        struct sockaddr_in6 *saddr = (struct sockaddr_in6*) storeAddrInfo;
        saddr->sin6_family = AF_INET6;
        saddr->sin6_port = htons(port);
        if(inet_pton(AF_INET6, ip, &(saddr->sin6_addr)) != 1) {
            perror("Error while writing IPv6 address in sockaddr\n");
            close(sock);
            return -1;
        }
    }

    return sock;
}

void print_packet_details_ipv6(struct ethhdr *eth, struct ip6_hdr *ip6, struct tcphdr *tcp)
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