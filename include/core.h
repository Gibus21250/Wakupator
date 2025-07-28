//
// Created by Nathan on 01/09/2024.
//
#ifndef WAKUPATOR_CORE_H
#define WAKUPATOR_CORE_H

#include <stdint.h>

#include "client.h"

typedef enum WAKUPATOR_CODE {
    OK = 0,
    OUT_OF_MEMORY,

    //System error (Initialisation of Wakupator)
    INIT_MUTEX_CREATION_ERROR,
    INIT_PIPE_CREATION_ERROR,
    INIT_RAW_SOCKET_CREATION_ERROR,
    INIT_INTERFACE_GATHER_ERROR,

    //Parsing error
    PARSING_CJSON_ERROR,
    PARSING_INVALID_MAC_ADDRESS,
    PARSING_INVALID_IP_ADDRESS,
    PARSING_DUPLICATED_IP_ADDRESS,
    PARSING_INVALID_PORT,

    //Manager error
    MANAGER_MAC_ADDRESS_ALREADY_MONITORED,
    MANAGER_THREAD_CREATION_ERROR,
    MANAGER_THREAD_INIT_TIMEOUT,
    MANAGER_THREAD_INIT_ERROR,

    //Thread monitor error
    MONITOR_DAD_ERROR, //Duplicate Addr Detection
    MONITOR_CHECK_IP_ERROR,
    MONITOR_RAW_SOCKET_CREATION_ERROR,
    MONITOR_IP_ALREADY_USED

} WAKUPATOR_CODE;

typedef struct thread_monitor_info {
    client cl;
    pthread_t thread;
} thread_monitor_info;

typedef struct manager {
    //All clients infos
    uint32_t bufferSize;                        //Size of the buffer
    uint32_t count;                             //Number of client monitored identified by mac address
    thread_monitor_info *clientThreadInfos;     //Array of all client thread info
    pthread_mutex_t mainLock;                   //Lock used when manipulating the struct (add/remove client)
    pthread_mutex_t registeringMutex;           //Mutex used by master and child thread when init the monitoring thread
    pthread_cond_t registeringCond;             //Cond used by master and child thread when init the monitoring thread
    int notify[2];                              //Pipe used to unlock all client's thread

    //Manager options
    int mainRawSocket;                          //Raw socket used by threads to send packets
    int ifIndex;                                //Index of the interface
    const char *ifName;                         //Char* name of the interface
    uint32_t nbAttempt;                         //Number of WoL attempt to wake up the machine
    uint32_t timeBtwAttempt;                    //Time in seconds between each WoL attempt
    uint32_t keepClient;                        //What to do when the machine didn't seems to start after nbAttempt;
} manager;

WAKUPATOR_CODE init_manager(manager *mng_client, const char* ifName);
void destroy_manager(manager *mng_client);

WAKUPATOR_CODE register_client(manager *mng_client, client *newClient);

void unregister_client(manager *mng_client, const char* strMac);
void start_monitoring(manager *mng_client, const char* macClient);

char *get_client_str_info(const client *cl);

const char* get_wakupator_message_code(WAKUPATOR_CODE code);

#endif //WAKUPATOR_CORE_H
