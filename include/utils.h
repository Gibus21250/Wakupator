//
// Created by Nathan on 01/09/2024.
//
#ifndef WAKUPATOR_UTILS_H
#define WAKUPATOR_UTILS_H

#include <sys/socket.h>
#include <netinet/ip6.h>
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
void print_packet_details_ipv6(const struct ethhdr *eth, const struct ip6_hdr *ip6, const struct tcphdr *tcp);
#endif //WAKUPATOR_UTILS_H