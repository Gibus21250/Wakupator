//
// Created by Nathan on 01/09/2024.
//
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_GROW_STEP 4

#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "wakupator/core/core.h"
#include "wakupator/core/monitor.h"
#include "wakupator/log/log.h"

WAKUPATOR_CODE init_manager(manager *mng_client, const char* ifName)
{

    //Create main raw socket (for sending WoL packets)
    mng_client->mainRawSocket = socket(PF_PACKET, SOCK_RAW, 0);

    if(mng_client->mainRawSocket == -1)
    {
        return INIT_RAW_SOCKET_CREATION_ERROR;
    }

    struct ifreq ifr = {0};

    strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(mng_client->mainRawSocket, SIOCGIFINDEX, &ifr) < 0)
    {
        close(mng_client->mainRawSocket);
        return INIT_INTERFACE_GATHER_ERROR;
    }

    mng_client->ifIndex = ifr.ifr_ifindex;
    mng_client->ifName = ifName;

    //Buffer data
    mng_client->count = 0;
    mng_client->bufferSize = BUFFER_GROW_STEP;

    mng_client->clientThreadInfos = (thread_monitor_info*) malloc(BUFFER_GROW_STEP * sizeof(thread_monitor_info));
    if(mng_client->clientThreadInfos == NULL)
    {
        close(mng_client->mainRawSocket);
        return OUT_OF_MEMORY;
    }

    //Create struct mutex
    if(pthread_mutex_init(&mng_client->mainLock, NULL) != 0)
    {
        free(mng_client->clientThreadInfos);
        close(mng_client->mainRawSocket);
        return INIT_MUTEX_CREATION_ERROR;
    }

    if(pthread_mutex_init(&mng_client->registeringMutex, NULL) != 0)
    {
        free(mng_client->clientThreadInfos);
        close(mng_client->mainRawSocket);
        pthread_mutex_destroy(&mng_client->mainLock);
        return INIT_MUTEX_CREATION_ERROR;
    }

    if(pthread_cond_init(&mng_client->registeringCond, NULL) != 0)
    {
        free(mng_client->clientThreadInfos);
        close(mng_client->mainRawSocket);
        pthread_mutex_destroy(&mng_client->mainLock);
        pthread_mutex_destroy(&mng_client->registeringMutex);
        return INIT_MUTEX_CREATION_ERROR;
    }

    //Create pipe for notification
    if(pipe(mng_client->notify) != 0)
    {
        free(mng_client->clientThreadInfos);
        close(mng_client->mainRawSocket);
        pthread_mutex_destroy(&mng_client->mainLock);
        pthread_mutex_destroy(&mng_client->registeringMutex);
        pthread_cond_destroy(&mng_client->registeringCond);
        return INIT_PIPE_CREATION_ERROR;
    }

    return OK;
}

void destroy_manager(manager *mng_client)
{

    pthread_mutex_lock(&mng_client->mainLock);
    if(mng_client->count != 0)
    {
        log_info("At least one client is still registered and will be woken up.\n");
        const char placebo = '1';
        write(mng_client->notify[1], &placebo, 1);

        pthread_mutex_unlock(&mng_client->mainLock);
        //monitor thread need the mutex to remove client

        log_debug("Waiting for all thread to stop\n");
        //Waiting all child thread to clean shutdown before cleanup the struct
        for (int i = 0; i < mng_client->count; ++i)
            pthread_join(mng_client->clientThreadInfos[i].thread, NULL);

        log_debug("All thread execute a clean shutdown\n");
        log_info("All the client have been woken up.");
    } else
        pthread_mutex_unlock(&mng_client->mainLock);

    free(mng_client->clientThreadInfos);
    pthread_mutex_destroy(&mng_client->mainLock);
    pthread_mutex_destroy(&mng_client->registeringMutex);

    pthread_cond_destroy(&mng_client->registeringCond);

    close(mng_client->notify[0]);
    close(mng_client->notify[1]);
    close(mng_client->mainRawSocket);

}

/**
 * Register the client into the manager, and prepare the client's monitoring thread.
 * @return OK if done, otherwise the client hasn't been registered
 */
WAKUPATOR_CODE register_client(manager *mng_client, client *newClient)
{
    //Lock the manager struct
    pthread_mutex_lock(&mng_client->mainLock);

    //Verify that the client's mac address isn't already monitored
    for (int i = 0; i < mng_client->count; ++i) {
        if(strcasecmp(newClient->mac, mng_client->clientThreadInfos[i].cl.mac) == 0)
        {
            pthread_mutex_unlock(&mng_client->mainLock);
            return MANAGER_MAC_ADDRESS_ALREADY_MONITORED;
        }
    }

    //If the buffer isn't big enough
    if(mng_client->count == mng_client->bufferSize)
    {
        thread_monitor_info *tmp = realloc(mng_client->clientThreadInfos, (mng_client->bufferSize + BUFFER_GROW_STEP) * sizeof(thread_monitor_info));
        if(tmp != NULL)
        {
            mng_client->clientThreadInfos = tmp;
            mng_client->bufferSize += BUFFER_GROW_STEP;
        } else {
            pthread_mutex_unlock(&mng_client->mainLock);
            return OUT_OF_MEMORY;
        }
    }

    const uint32_t index = mng_client->count;

    pthread_mutex_t *childMutex = &mng_client->registeringMutex;
    pthread_cond_t *childCond = &mng_client->registeringCond;

    WAKUPATOR_CODE code = 0;

    main_monitor_args args = {
            mng_client,
            newClient,
            &code
    };

    //Lock the child mutex first
    pthread_mutex_lock(childMutex);
    pthread_t childThread;

    //Now we can start the child thread that going to monitor the client
    if(pthread_create(&childThread, NULL, main_client_monitoring, &args))
    {
        //If error while creating the thread
        pthread_mutex_unlock(childMutex);
        pthread_mutex_unlock(&mng_client->mainLock);
        return MANAGER_THREAD_CREATION_ERROR;
    }

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 5; //more than 5 seconds to launch the chill thread is like an error

    //Wait a notification from the child thread, and this can time out
    //This call implicit atomically unlock the mutex, and main Lock it again after cond notified
    if(pthread_cond_timedwait(childCond, childMutex, &timeout))
    {
        pthread_mutex_unlock(childMutex);
        pthread_cancel(childThread); //Tell the child thread to cleanly abort
        pthread_mutex_unlock(&mng_client->mainLock);
        return MANAGER_THREAD_INIT_TIMEOUT;
    }

    //Check if no execution error during init phase of the child thread
    if(code != OK)
    {
        pthread_mutex_unlock(childMutex);
        pthread_join(childThread, NULL);
        pthread_mutex_unlock(&mng_client->mainLock);
        return code;
    }

    //Finally, everything is ok
    //Shallow copy of the client, the child thread is responsible for the struct
    mng_client->clientThreadInfos[index].cl = *newClient;
    mng_client->clientThreadInfos[index].thread = childThread;
    mng_client->count++;

    pthread_mutex_unlock(childMutex);
    pthread_mutex_unlock(&mng_client->mainLock);

    return OK;
}

void unregister_client(manager *mng_client, const char* strMac)
{
    pthread_mutex_lock(&mng_client->mainLock);

    for (int i = 0; i < mng_client->count; ++i) {
        //if we found the client
        if(strcasecmp(strMac, mng_client->clientThreadInfos[i].cl.mac) == 0)
        {

            destroy_client(&mng_client->clientThreadInfos[i].cl);

            //shift all thread_client_info to the left starting this index
            for (int j = i; j < mng_client->count-1; ++j)
                mng_client->clientThreadInfos[j] = mng_client->clientThreadInfos[(j+1)];

            mng_client->count--;
            log_info("Client [%s] has been retired from monitoring.\n", strMac);
            break;
        }
    }
    pthread_mutex_unlock(&mng_client->mainLock);
}

void start_monitoring(manager *mng_client, const char* macClient)
{
    pthread_mutex_lock(&mng_client->mainLock);

    for (int i = 0; i < mng_client->count; ++i) {

        if(strcasecmp(macClient, mng_client->clientThreadInfos[i].cl.mac) == 0)
        {
            //Notify the thread to start!
            pthread_mutex_lock(&mng_client->registeringMutex);
            pthread_cond_signal(&mng_client->registeringCond);
            pthread_mutex_unlock(&mng_client->registeringMutex);
            break;
        }
    }
    pthread_mutex_unlock(&mng_client->mainLock);
}

const char* get_wakupator_message_code(const WAKUPATOR_CODE code)
{
    switch (code)
    {
        case OK: return "OK.";
        case OUT_OF_MEMORY: return "Out of memory on the host.";

        case INIT_MUTEX_CREATION_ERROR: return "Error while creating a mutex.";
        case INIT_PIPE_CREATION_ERROR: return "Error while creating main pipe.";
        case INIT_RAW_SOCKET_CREATION_ERROR: return "Error while creating a raw socket, did you have the permissions ?.";
        case INIT_INTERFACE_GATHER_ERROR: return "Error while gathering interface information, please verify the interface name.";

        case PARSING_CJSON_ERROR: return "An error has been found in the JSON. Please check the types, key names and structure.";
        case PARSING_INVALID_MAC_ADDRESS: return "Invalid MAC address format.";
        case PARSING_INVALID_SHUTDOWN_TIME_FORMAT: return "Invalid Shutdown value format.";
        case PARSING_INVALID_NAME_FORMAT: return "Invalid Name format.";
        case PARSING_INVALID_NAME_TOO_LONG: return "Name value is too long (max 45 char).";
        case PARSING_INVALID_IP_ADDRESS: return "Invalid IP address format.";
        case PARSING_DUPLICATED_IP_ADDRESS: return "A duplicate IP has been found in the JSON, please merge all ports in an array for this IP.";
        case PARSING_INVALID_PORT: return "Invalid port value.";

        case MANAGER_MAC_ADDRESS_ALREADY_MONITORED: return "A client with this MAC address is already being monitored.";
        case MANAGER_THREAD_CREATION_ERROR: return "Internal error when creating the monitor thread.";
        case MANAGER_THREAD_INIT_ERROR: return "Error during initialisation of information for the monitor thread.";
        case MANAGER_THREAD_INIT_TIMEOUT: return "The initialization state of the monitor thread has taken too long.";

        case MONITOR_DAD_ERROR: return "Unable to temporarily disable the IPv6 duplicate address detector.";
        case MONITOR_CHECK_IP_ERROR: return "Error when executing the IP duplication verification command.";
        case MONITOR_RAW_SOCKET_CREATION_ERROR: return "Error when creating a raw socket for the client.";
        case MONITOR_IP_ALREADY_USED: return "A client has already registered one of the requested IP addresses.";
    }
    return "";
}

char *get_client_str_info(const client *cl)
{

    //Count allocation size needed
    size_t size = 0;

    size += snprintf(NULL, 0, "%s (%s)\n", cl->name, cl->mac);
    size += snprintf(NULL, 0, "\tMonitored IP/port(s):\n");

    for (int i = 0; i < cl->countIp; ++i) {
        size += snprintf(NULL, 0, "\t\t- %s on port: [", cl->ipPortInfo[i].ipStr);

        for (int j = 0; j < cl->ipPortInfo[i].portCount; ++j)
        {
            if (j != cl->ipPortInfo[i].portCount - 1)
                size += snprintf(NULL, 0, "%d, ", cl->ipPortInfo[i].ports[j]);
            else //last one
                size += snprintf(NULL, 0, "%d", cl->ipPortInfo[i].ports[j]);
        }
        size += snprintf(NULL, 0, "]\n");
    }

    char *buffer = malloc(size + 1);

    if (!buffer) {
        log_error("Out of memory\n");
        return NULL;
    }

    size_t offset = snprintf(buffer, size + 1, "%s (%s)\n", cl->name, cl->mac);
    offset += snprintf(buffer + offset, size + 1, "\tMonitored IP/port(s):\n");

    for (int i = 0; i < cl->countIp; ++i) {
        offset += snprintf(buffer + offset, size + 1 - offset, "\t\t- %s on port: [", cl->ipPortInfo[i].ipStr);

        for (int j = 0; j < cl->ipPortInfo[i].portCount; ++j)
        {
            if (j != cl->ipPortInfo[i].portCount - 1)
                offset += snprintf(buffer + offset, size + 1 - offset, "%d, ", cl->ipPortInfo[i].ports[j]);
            else //last one
                offset += snprintf(buffer + offset, size + 1 - offset, "%d", cl->ipPortInfo[i].ports[j]);
        }
        offset += snprintf(buffer + offset, size + 1 - offset, "]\n");
    }

    return buffer;
}