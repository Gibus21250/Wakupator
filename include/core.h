//
// Created by Nathan on 01/09/2024.
//

#ifndef WAKUPATOR_CORE_H
#define WAKUPATOR_CORE_H

#include <stdint.h>
#include <sys/socket.h>
#include <semaphore.h>
#include <sys/poll.h>

#include "client.h"

typedef enum MANAGER_CODE {
    MANAGER_OK = 0,
    MANAGER_MAC_ADDRESS_ALREADY_MONITORED,
    MANAGER_HOST_OUT_OF_MEMORY,
    MANAGER_THREAD_CREATION_ERROR,
    MANAGER_THREAD_INIT_ERROR
} MANAGER_CODE;

typedef struct thread_monitor_info {
    char mac[18];
    pthread_t thread;
} thread_monitor_info;

typedef struct manager {
    uint32_t bufferSize;        //size of the buffer
    uint32_t count;             //number of client monitored identified by mac address
    thread_monitor_info *clientThreadInfos;
    pthread_mutex_t lock;       //lock used when adding or removing client
    int mainRawSocket;          //Raw socket used by thread to send packets
    int ifIndex;
    int notify[2];              //Pipe used to unlock all thread
} manager;

void init_manager(struct manager *mng_client);
void destroy_manager(struct manager *mng_client);

MANAGER_CODE register_client(struct manager *mng_client, client *newClient);
void unregister_client(struct manager *mng_client, char* strMac);

const char* get_monitor_error(MANAGER_CODE code);

#endif //WAKUPATOR_CORE_H
