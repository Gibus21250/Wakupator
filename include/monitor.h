//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_MONITOR_H
#define WAKUPATOR_MONITOR_H

#include <pthread.h>
#include <netinet/tcp.h>

#include "core.h"

typedef struct main_client_args {
    manager *managerMain;
    client *client;
    pthread_mutex_t *notify;
    pthread_cond_t *cond;
    char error;
    pthread_mutex_t *selfNotify;
    pthread_cond_t *selfCond;
} main_client_args;

void *main_client_monitoring(void* args);

int create_raw_filter_socket(const ip_port_info *ipPortInfo);

void wake_up(int rawSocket, int ifIndex, const char *macStr);

#endif //WAKUPATOR_MONITOR_H
