#ifndef WAKUPATOR_MANAGER_H
#define WAKUPATOR_MANAGER_H
#include <stdint.h>
#include <bits/pthreadtypes.h>
#include <netinet/in.h>

#include "client.h"
#include "core.h"

typedef struct client_thread_monitor_info {
    client cl;
    pthread_t thread;
} thread_monitor_info;

typedef struct manager {

    // ------ Self filled Data ------

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
        uint16_t ifIndex;                                //Index of the interface
        const char *ifName;                         //Char* name of the interface
        const unsigned char ifMacRaw[6];            //Raw mac address of the manager interface

        //IPv6
        struct in6_addr ifIPv6LinkLocal;            //IPv6 LL Address
        uint8_t hasIPv6;                            //Has IPv6

    // ------ Manually filled Data ------

    uint8_t keepClient;                         //What to do when the machine didn't seems to start after nbAttempt
    uint16_t nbAttempt;                         //Number of WoL attempt to wake up the machine
    uint32_t timeBtwAttempt;                    //Time in seconds between each WoL attempt

    uint32_t shutdownTimeout;                   //Timeout in seconds waiting the machine to shut down
    uint32_t probeInterval;                     //Interval between each ARP/NS probe

} manager;

WAKUPATOR_CODE init_manager(manager *manager, const char* ifName);
void destroy_manager(manager *mng_client);

WAKUPATOR_CODE register_client(manager *mng_client, client *newClient);
int unregister_client(manager *mng_client, const char* strMac);

void start_monitoring(manager *mng_client, const char* macClient);

#endif //WAKUPATOR_MANAGER_H