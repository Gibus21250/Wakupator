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

typedef enum REGISTER_CODE {
    OK = 0,
    OUT_OF_MEMORY,

    //Parsing error code
    PARSING_CJSON_ERROR,
    PARSING_INVALID_MAC_ADDRESS,
    PARSING_INVALID_IP_ADDRESS,
    PARSING_INVALID_PORT,

    //Manager error
    MANAGER_MAC_ADDRESS_ALREADY_MONITORED,
    MANAGER_THREAD_CREATION_ERROR,
    MANAGER_THREAD_INIT_TIMEOUT,
    MANAGER_THREAD_INIT_ERROR,

    //Thread monitor error
    MONITOR_DAD_ERROR, //Duplicate Addr Detection
    MONITOR_RAW_SOCKET_CREATION_ERROR,
    MONITOR_IP_ALREADY_USED

} REGISTER_CODE;

typedef struct thread_monitor_info {
    char mac[18];
    pthread_t thread;
} thread_monitor_info;

typedef struct manager {
    uint32_t bufferSize;        //size of the buffer
    uint32_t count;             //number of client monitored identified by mac address
    thread_monitor_info *clientThreadInfos;
    pthread_mutex_t lock;       //lock used when adding or removing client
    int mainRawSocket;          //Raw socket used by threads to send packets
    int ifIndex;                //Index of the interface
    char *itName;               //Char name of the interface
    int notify[2];              //Pipe used to unlock all thread
} manager;

void init_manager(struct manager *mng_client);
void destroy_manager(struct manager *mng_client);

REGISTER_CODE register_client(struct manager *mng_client, client *newClient);
void unregister_client(struct manager *mng_client, char* strMac);

const char* get_register_error(REGISTER_CODE code);

#endif //WAKUPATOR_CORE_H
