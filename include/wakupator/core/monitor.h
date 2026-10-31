//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_MONITOR_H
#define WAKUPATOR_MONITOR_H

#include "wakupator/core/manager.h"

typedef struct main_monitor_args {
    manager *manager;                   //Pointer to the manager struct
    client *client;                     //Pointer to the client
    wakupator_code *wakupator_code;     //Pointer to return code (! invalid just before the main while)
} main_monitor_args;

void *main_client_monitoring(void* args);


#endif //WAKUPATOR_MONITOR_H
