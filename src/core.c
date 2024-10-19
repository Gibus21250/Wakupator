//
// Created by Nathan on 01/09/2024.
//
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_GROW_STEP 4

#include <sys/eventfd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "core.h"
#include "monitor.h"
#include "logger.h"

void init_manager(struct manager *mng_client)
{
    mng_client->clientThreadInfos = (thread_monitor_info*) malloc(BUFFER_GROW_STEP * sizeof(thread_monitor_info));
    mng_client->count = 0;
    mng_client->bufferSize = BUFFER_GROW_STEP;
    pthread_mutex_init(&mng_client->lock, NULL);
    pipe(mng_client->notify);
}

void destroy_manager(struct manager *mng_client)
{

    pthread_mutex_lock(&mng_client->lock);
    if(mng_client->count != 0)
    {
        log_info("At least one client is registered, they will be awakened.\n");
        const char placebo = '1';
        write(mng_client->notify[1], &placebo, 1);

        pthread_mutex_unlock(&mng_client->lock);

        log_debug("Waiting for all thread to stop\n");
        //Waiting all child thread to clean shutdown before cleanup the struct
        for (int i = 0; i < mng_client->count; ++i)
            pthread_join(mng_client->clientThreadInfos[i].thread, NULL);

        log_debug("All thread execute a clean shutdown\n");
        log_info("All clients have been awakened.");
    } else
        pthread_mutex_unlock(&mng_client->lock);

    pthread_mutex_destroy(&mng_client->lock);
    free(mng_client->clientThreadInfos);
    mng_client->count = 0;
    close(mng_client->notify[0]);
    close(mng_client->notify[1]);

}

REGISTER_CODE register_client(manager *mng_client, client *newClient)
{
    //Lock the struct
    pthread_mutex_lock(&mng_client->lock);

    //Verify that the client's mac address isn't already monitored
    for (int i = 0; i < mng_client->count; ++i) {
        if(strcasecmp(newClient->mac, mng_client->clientThreadInfos[i].mac) == 0)
        {
            pthread_mutex_unlock(&mng_client->lock);
            return MANAGER_MAC_ADDRESS_ALREADY_MONITORED;
        }
    }

    //If the buffer isn't big enough
    if(mng_client->count == mng_client->bufferSize)
    {
        thread_monitor_info *tmp = (thread_monitor_info*) realloc(mng_client->clientThreadInfos, (mng_client->bufferSize + BUFFER_GROW_STEP) * sizeof(thread_monitor_info));
        if(tmp != NULL)
        {
            mng_client->clientThreadInfos = tmp;
            mng_client->bufferSize += BUFFER_GROW_STEP;
        } else {
            pthread_mutex_unlock(&mng_client->lock);
            return OUT_OF_MEMORY;
        }
    }

    uint32_t index = mng_client->count;

    //Init thread's notify stuff
    pthread_mutex_init(&mng_client->clientThreadInfos[index].mutex, NULL);
    pthread_cond_init(&mng_client->clientThreadInfos[index].cond, NULL);

    //Setup notify stuff for this thread
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    //Create sync stuff for the child thread
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    main_client_args args = {
            mng_client,
            newClient,
            &mutex,
            &cond,
            0,
            &mng_client->clientThreadInfos[index].mutex,
            &mng_client->clientThreadInfos[index].cond
    };

    //Lock this thread's mutex
    pthread_mutex_lock(&mutex);
    pthread_t child;

    //Now we can start the thread who going to monitor the client
    if(pthread_create(&child, NULL, main_client_monitoring, (void*) &args))
    {
        pthread_mutex_unlock(&mutex);

        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);

        pthread_mutex_destroy(&mng_client->clientThreadInfos[index].mutex);
        pthread_cond_destroy(&mng_client->clientThreadInfos[index].cond);

        pthread_mutex_unlock(&mng_client->lock);
        return MANAGER_THREAD_CREATION_ERROR;
    }

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 5; //more than 5 seconds to launch the thread is like an error

    //Wait a notification from the child thread, and this can time out
    //This call implicit atomically unlock the mutex, and lock it again after execution
    if(pthread_cond_timedwait(&cond, &mutex, &timeout))
    {
        pthread_mutex_unlock(&mutex);
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_mutex_destroy(&mng_client->clientThreadInfos[index].mutex);
        pthread_cond_destroy(&mng_client->clientThreadInfos[index].cond);
        pthread_cancel(child); //Tell the child to cleanly abort
        pthread_mutex_unlock(&mng_client->lock);
        return MANAGER_THREAD_INIT_TIMEOUT;
    }

    //Check if no execution error during execution of the child thread
    if(args.error != OK)
    {
        pthread_mutex_unlock(&mutex);
        pthread_join(child, NULL);
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_mutex_destroy(&mng_client->clientThreadInfos[index].mutex);
        pthread_cond_destroy(&mng_client->clientThreadInfos[index].cond);
        pthread_mutex_unlock(&mng_client->lock);
        return args.error;
    }

    //Finally, everything is ok
    memcpy(&mng_client->clientThreadInfos[index].mac, &newClient->mac, 18);
    mng_client->clientThreadInfos[index].thread = child;
    mng_client->count++;

    pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);

    pthread_mutex_unlock(&mng_client->lock);

    return OK;
}

void unregister_client(struct manager *mng, char* strMac)
{
    pthread_mutex_lock(&mng->lock);

    for (int i = 0; i < mng->count; ++i) {
        //if we found the client
        if(strcasecmp(strMac, mng->clientThreadInfos[i].mac) == 0)
        {
            //Clean monitor's notify stuff
            pthread_mutex_destroy(&mng->clientThreadInfos[i].mutex);
            pthread_cond_destroy(&mng->clientThreadInfos[i].cond);
            //shift all thread_client_info to the left starting this index
            for (int j = i; j < mng->count-1; ++j)
                mng->clientThreadInfos[j] = mng->clientThreadInfos[(j+1)];

            mng->count--;
            log_info("Client [%s] has been retired from monitoring.\n", strMac);
            break;
        }
    }
    pthread_mutex_unlock(&mng->lock);
}

void start_monitoring(struct manager *mng, const char* macClient)
{
    pthread_mutex_lock(&mng->lock);

    for (int i = 0; i < mng->count; ++i) {

        if(strcasecmp(macClient, mng->clientThreadInfos[i].mac) == 0)
        {
            //Notify the thread to start!
            pthread_mutex_lock(&mng->clientThreadInfos[i].mutex);
            pthread_cond_signal(&mng->clientThreadInfos[i].cond);
            pthread_mutex_unlock(&mng->clientThreadInfos[i].mutex);
            break;
        }
    }
    pthread_mutex_unlock(&mng->lock);
}

const char* get_register_message(REGISTER_CODE code)
{
    switch (code)
    {
        case OK: return "OK.";
        case OUT_OF_MEMORY: return "Out of memory on the host.";

        case PARSING_CJSON_ERROR: return "An error has been found in the JSON. Please check the types, key names and structure.";
        case PARSING_INVALID_MAC_ADDRESS: return "Invalid MAC address format.";
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
    size_t size = 0;

    size += snprintf(NULL, 0, "[%s]\n", cl->mac);

    for (int i = 0; i < cl->countIp; ++i) {
        size += snprintf(NULL, 0, "\tIP: %s, port: [", cl->ipPortInfo[i].ipStr);
        for (int j = 0; j < cl->ipPortInfo[i].portCount; ++j)
        {
            if (j != cl->ipPortInfo[i].portCount - 1)
                size += snprintf(NULL, 0, "%d, ", cl->ipPortInfo[i].ports[j]);
            else
                size += snprintf(NULL, 0, "%d]\n", cl->ipPortInfo[i].ports[j]);
        }
    }

    char *buffer = (char*)malloc(size + 1);

    if (!buffer) {
        log_error("Out of memory\n");
        return NULL;
    }

    int offset = snprintf(buffer, size + 1, "[%s]\n", cl->mac);

    for (int i = 0; i < cl->countIp; ++i)
    {
        offset += snprintf(buffer + offset, size + 1 - offset, "\tIP: %s, port: [", cl->ipPortInfo[i].ipStr);
        for (int j = 0; j < cl->ipPortInfo[i].portCount; ++j)
        {
            if (j != cl->ipPortInfo[i].portCount - 1)
                offset += snprintf(buffer + offset, size + 1 - offset, "%d, ", cl->ipPortInfo[i].ports[j]);
            else
                offset += snprintf(buffer + offset, size + 1 - offset, "%d]\n", cl->ipPortInfo[i].ports[j]);
        }
    }

    return buffer;
}