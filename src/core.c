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

MANAGER_CODE register_client(manager *mng_client, client *newClient)
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
            return MANAGER_HOST_OUT_OF_MEMORY;
        }
    }

    uint32_t index = mng_client->count;

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
            0
    };

    pthread_mutex_lock(&mutex);
    pthread_t child;
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 999999; //more than 1 second to launch the thread is like an error

    //Now we can register this client
    if(pthread_create(&child, NULL, main_client_monitoring, (void*) &args))
    {
        pthread_mutex_unlock(&mutex);
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_mutex_unlock(&mng_client->lock);
        return MANAGER_THREAD_CREATION_ERROR;
    }

    //Wait a notification from the child thread, and this can time out
    //This call implicit atomically unlock the mutex, and lock it again after execution
    if(pthread_cond_timedwait(&cond, &mutex, &timeout))
    {
        pthread_mutex_unlock(&mutex);
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_cancel(child); //Tell the child to cleanly abort
        pthread_mutex_unlock(&mng_client->lock);
        return MANAGER_THREAD_CREATION_ERROR;
    }

    //Check if no execution error during execution of the child thread
    if(args.error != 0)
    {
        pthread_mutex_unlock(&mutex);
        pthread_join(child, NULL);
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_mutex_unlock(&mng_client->lock);
        return MANAGER_THREAD_INIT_ERROR;
    }

    //Finally, everything is ok
    memcpy(&mng_client->clientThreadInfos[index].mac, &newClient->mac, 18);
    mng_client->clientThreadInfos[index].thread = child;
    mng_client->count++;

    pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);

    pthread_mutex_unlock(&mng_client->lock);

    return MANAGER_OK;
}

void unregister_client(struct manager *mng_client, char* strMac)
{
    pthread_mutex_lock(&mng_client->lock);

    for (int i = 0; i < mng_client->count; ++i) {
        //if we found the client
        if(strcasecmp(strMac, mng_client->clientThreadInfos[i].mac) == 0)
        {
            //shift all thread_client_info to the left starting this index
            for (int j = i; j < mng_client->count-1; ++j)
                mng_client->clientThreadInfos[j] = mng_client->clientThreadInfos[(j+1)];

            mng_client->count--;
            break;
        }
    }
    pthread_mutex_unlock(&mng_client->lock);
}

const char* get_monitor_error(MANAGER_CODE code)
{
    switch (code)
    {
        case MANAGER_OK: return "OK.";
        case MANAGER_MAC_ADDRESS_ALREADY_MONITORED: return "A client with this MAC address is already monitored.";
        case MANAGER_THREAD_CREATION_ERROR: return "Intern error while creating thread monitor.";
        case MANAGER_THREAD_INIT_ERROR: return "Error while init information for the thread monitor.";
    }
}