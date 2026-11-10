//
// Created by Nathan on 09/09/2024.
//

#ifndef WAKUPATOR_CLIENT_H
#define WAKUPATOR_CLIENT_H

#include <netinet/in.h>

typedef struct ip_port_info {
    //Note: ipv4 and ipv6 are in big endian (filled from inet_pton in parser.c)
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    };
    char ip_str[48]; //ASCII IP format (45 is the maximum size of ASCII IP for IPv6 + mapped IPv4)
    uint32_t ip_format; //AF_INET or AF_INET6
    uint32_t port_count;
    uint16_t *ports;
} ip_port_info;

typedef struct client {
    char mac_str[18]; //ASCII string format MAC address
    uint8_t mac_raw[6]; //Raw format MAC
    char name[64];
    ip_port_info *ip_port_info;
    uint64_t time_started;           //Track time since spoofing have been started
    uint32_t count_ip;
} client;

void destroy_client(client *cl);

char *get_client_str_info(const client *cl);

#endif //WAKUPATOR_CLIENT_H
