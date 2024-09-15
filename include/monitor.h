//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_MONITOR_H
#define WAKUPATOR_MONITOR_H

#include <pthread.h>

#include "core.h"

//TODO add error message
typedef enum MONITOR_ERROR {
    MONITOR_OK = 0,
    MONITOR_OUT_OF_MEMORY
} MONITOR_ERROR;

typedef struct main_client_args {
    manager *managerMain;
    client *client;
    pthread_mutex_t *notify;
    pthread_cond_t *cond;
    char error;
} main_client_args;

void *main_client_monitoring(void* args);

int create_raw_filter_socket(const ip_port_info *ipPortInfo);

void wake_up(const char *macStr);

void redirect_packet(void* packet, const char *macStr);

#endif //WAKUPATOR_MONITOR_H
