//
// Created by Nathan on 01/09/2024.
//
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_GROW_STEP 1

#include <sys/eventfd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "core.h"
#include "monitor.h"

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
        printf("At least one client are registered, wake them up!\n");
        const char placebo = '1';
        write(mng_client->notify[1], &placebo, 1);

        pthread_mutex_unlock(&mng_client->lock);

        printf("Waiting for all thread to stop\n");
        //Waiting all child thread to clean shutdown before cleanup the struct
        for (int i = 0; i < mng_client->count; ++i)
            pthread_join(mng_client->clientThreadInfos[i].thread, NULL);

        printf("All thread execute a clean shutdown\n");
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
    timeout.tv_sec += 99999; //more than 1 second to launch the thread is like an error

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

const char* get_register_error(REGISTER_CODE code)
{
    switch (code)
    {
        case OK: return "OK.";
        case OUT_OF_MEMORY: return "Out of memory on the host.";

        case PARSING_CJSON_ERROR: return "An error was find in the JSON. Please verify types, keynames and structure.";
        case PARSING_INVALID_MAC_ADDRESS: return "Invalid MAC address format.";
        case PARSING_DUPLICATED_IP_ADDRESS: return "Duplicated IP asked.";
        case PARSING_INVALID_IP_ADDRESS: return "Invalid IP address format.";
        case PARSING_INVALID_PORT: return "Invalid port value.";

        case MANAGER_MAC_ADDRESS_ALREADY_MONITORED: return "A client with this MAC address is already monitored.";
        case MANAGER_THREAD_CREATION_ERROR: return "Intern error while creating thread monitor.";
        case MANAGER_THREAD_INIT_ERROR: return "Error while init information for the thread monitor.";
        case MANAGER_THREAD_INIT_TIMEOUT: return "Thread's initializing state took too much time.";

        case MONITOR_DAD_ERROR: return "Impossible to temporally disable IPv6 Duplicate Address Detector.";
        case MONITOR_CHECK_IP_ERROR: return "Error while executing command to check IP duplication.";
        case MONITOR_RAW_SOCKET_CREATION_ERROR: return "Error while creating raw socket for the client.";
        case MONITOR_IP_ALREADY_USED: return "A client have already register one of IPs asked.";
    }
    return "";
}