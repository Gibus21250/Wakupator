//
// Created by Nathan on 01/09/2024.
//

#ifndef WAKUPATOR_CORE_H
#define WAKUPATOR_CORE_H

#include <stdint.h>
#include <sys/socket.h>
#include <semaphore.h>
#include <sys/poll.h>

typedef enum CLIENT_MONITORING_CODE {
    MONITORING_OK = 0,
    MONITORING_MAC_ADDRESS_ALREADY_MONITORED,
    MONITORING_THREAD_CREATION_ERROR,
    MONITORING_THREAD_INIT_ERROR
} CLIENT_MONITORING_CODE;

typedef struct ip_port_info {
    char *ipStr;
    uint32_t ipFormat; //AF_INET or AF_INET6
    uint32_t portCount;
    uint16_t *ports;
} ip_port_info;

typedef struct client {
    char mac[18]; //char format MAC address
    uint32_t countIp;
    struct ip_port_info *ipPortInfo;
} client;

typedef struct pool_raw_client {
    struct pollfd *fds;
    uint32_t count;
} pool_raw_client;

typedef struct managed_client {
    client *clients;
    pthread_t *clients_thread;
    pool_raw_client *clients_raw_pools;
    uint32_t count;
    pthread_mutex_t lock;
} managed_client;

void init_managed_client(struct managed_client *mng_client);
void destroy_managed_client(struct managed_client *mng_client);

CLIENT_MONITORING_CODE register_client(struct managed_client *mng_client, client *newClient);
void unregister_client(struct managed_client *mng_client, char* strMac);

void destroy_client(client *cl);
#endif //WAKUPATOR_CORE_H
