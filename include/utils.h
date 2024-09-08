//
// Created by Nathan on 01/09/2024.
//
#ifndef WAKUPATOR_UTILS_H
#define WAKUPATOR_UTILS_H

#include <sys/socket.h>
#include <netinet/ip6.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <netinet/tcp.h>

/**
 * Init a socket, based on a char* ip (IPv4/IPv6), a port, and a type (STREAM or DTG), and fill the sockaddr_storage struct provided
 * @param ip
 * @param port
 * @param sockType
 * @param protocol
 * @param storeAddrInfo
 * @return The file descriptor of the socket
 */
int init_socket(const char *ip, int port, int sockType, int protocol, struct sockaddr_storage* storeAddrInfo);
void print_packet_details_ipv6(struct ethhdr *eth, struct ip6_hdr *ip6, struct tcphdr *tcp);

void wake_up_on_lan(const char* mac, int proto);
#endif //WAKUPATOR_UTILS_H