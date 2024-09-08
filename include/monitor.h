//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_MONITOR_H
#define WAKUPATOR_MONITOR_H

#include <pthread.h>

#include "core.h"

typedef struct main_client_args {
    managed_client *managedClient;
    client *client;
    pthread_mutex_t *notify;
    pthread_cond_t *cond;
    pool_raw_client *pollHandler;
    char error;
} main_client_args;

void *main_client_monitoring(void* args);

int create_raw_filter_socket(const ip_port_info *ipPortInfo);

void wake_up(const char *macStr);

void redirect_packet(void* packet, const char *macStr);

const char* get_monitor_error(CLIENT_MONITORING_CODE code);

#endif //WAKUPATOR_MONITOR_H
