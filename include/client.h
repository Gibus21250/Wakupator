//
// Created by Nathan on 09/09/2024.
//

#ifndef WAKUPATOR_CLIENT_H
#define WAKUPATOR_CLIENT_H

#include <stdint.h>

typedef struct ip_port_info {
    char *ipStr;
    uint32_t ipFormat; //AF_INET or AF_INET6
    uint32_t portCount;
    uint16_t *ports;
} ip_port_info;

typedef struct client {
    char mac[18]; //ASCII string format MAC address
    uint32_t countIp;
    ip_port_info *ipPortInfo;
} client;

void destroy_client(client *cl);

#endif //WAKUPATOR_CLIENT_H
