//
// Created by Nathan on 01/09/2024.
//
#ifndef WAKUPATOR_UTILS_H
#define WAKUPATOR_UTILS_H

#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>

/**
 * Init a socket, based on a char* ip (IPv4/IPv6), a port, and a type (STREAM or DTG), and fill the sockaddr_storage struct provided
 * @return The file descriptor of the socket, -1 if error
 */
int init_ip_socket(const char *ip, int port, int sock_type, int protocol, struct sockaddr_storage* store_addr_info, int* sockaddr_size);
const char* print_ip_packet_info(const unsigned char *packet_buffer, ssize_t packet_size);
void format_duration_hms(uint64_t seconds, char *buf, size_t buf_size);
void print_arp_info(const unsigned char *buf, size_t buf_size);
int64_t now_ms(void);

#endif //WAKUPATOR_UTILS_H