//
// Created by Nathan on 01/09/2024.
//
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_GROW_STEP 8

#include "core.h"
#include "monitor.h"


void init_managed_client(managed_client *mng_client)
{
    mng_client->clients = (client*) malloc(BUFFER_GROW_STEP * sizeof(client));
    mng_client->clients_thread = (pthread_t*) malloc(BUFFER_GROW_STEP * sizeof(pthread_t));
    mng_client->clients_raw_pools = (pool_raw_client*) malloc(BUFFER_GROW_STEP * sizeof(pool_raw_client));
    mng_client->count = 0;
    pthread_mutex_init(&mng_client->lock, NULL);
}

void destroy_managed_client(managed_client *mng_client)
{
    printf("Destroy managed client\n");
    if(mng_client->count != 0)
    {
        pthread_mutex_lock(&mng_client->lock);

        for (int i = 0; i < mng_client->count; ++i) {
            for (int j = 0; j < mng_client->clients_raw_pools[i].count; ++j) {
                close(mng_client->clients_raw_pools[i].fds[j].fd); //This "unlock" waiting threads
            }
        }

        //Wait all child thread to clean shutdown before cleanup the struct
        for (int i = 0; i < mng_client->count; ++i)
            pthread_join(mng_client->clients_thread[i], NULL);

        pthread_mutex_unlock(&mng_client->lock);
        pthread_mutex_destroy(&mng_client->lock);

        for (int i = 0; i < mng_client->count; ++i)
            destroy_client(&mng_client->clients[i]);

    }
    free(mng_client->clients);
    free(mng_client->clients_thread);
    mng_client->count = 0;
}

CLIENT_MONITORING_CODE register_client(managed_client *mng_client, client *newClient)
{
    pthread_mutex_lock(&mng_client->lock);
    //Verify that the client's mac address isn't already monitored
    for (int i = 0; i < mng_client->count; ++i) {
        if(strcasecmp(newClient->mac, mng_client->clients[i].mac) != 0)
        {
            pthread_mutex_unlock(&mng_client->lock);
            return MONITORING_MAC_ADDRESS_ALREADY_MONITORED;
        }
    }

    uint32_t index = 0;
    //Get the first index in the buffer where no client is registered TODO improve memory handle
    for (int i = 0; i < mng_client->count; ++i) {
        if(mng_client->clients[i].mac[0] == 0)
        {
            index = i;
            break;
        }
    }

    //Shallow copy of the client
    mng_client->clients[index] = *newClient;

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    main_client_args args = {
            mng_client,
            &mng_client->clients[index],
            &mutex,
            &cond,
            0
    };

    pthread_mutex_lock(&mutex);
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 999999; //more than 1 second to launch the thread is like an error

    //Now we can register this client
    if(pthread_create(&mng_client->clients_thread[index], NULL, main_client_monitoring, (void*) &args))
    {
        pthread_mutex_unlock(&mutex);
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_mutex_unlock(&mng_client->lock);
        memset(&mng_client->clients[index], 0, sizeof(client));
        return MONITORING_THREAD_CREATION_ERROR;
    }

    //Wait a notification from the child thread, and this can time out
    //This call implicit atomically unlock the mutex, and lock it again after execution
    if(pthread_cond_timedwait(&cond, &mutex, &timeout))
    {
        pthread_mutex_unlock(&mutex);
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_cancel(mng_client->clients_thread[index]); //Tell the child to cleanly abort
        memset(&mng_client->clients[index], 0, sizeof(client));
        pthread_mutex_unlock(&mng_client->lock);
        return MONITORING_THREAD_CREATION_ERROR;
    }

    //Check if no execution error during execution of the child thread
    if(args.error != 0)
    {
        pthread_mutex_unlock(&mutex);
        pthread_join(mng_client->clients_thread[index], NULL);
        memset(&mng_client->clients[index], 0, sizeof(client));
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        pthread_mutex_unlock(&mng_client->lock);
        return MONITORING_THREAD_INIT_ERROR;
    }

    //Finally, everything is ok
    mng_client->count++;

    pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    pthread_mutex_unlock(&mng_client->lock);

    return MONITORING_OK;
}

void unregister_client(struct managed_client *mng_client, char* strMac)
{
    pthread_mutex_lock(&mng_client->lock);

    for (int i = 0; i < mng_client->count; ++i) {
        if(strcasecmp(strMac, mng_client->clients[i].mac) == 0)
        {
            destroy_client(&mng_client->clients[i]);
            break;
        }
    }
    mng_client->count--; //TODO redesign managed memory
    pthread_mutex_unlock(&mng_client->lock);
}

void destroy_client(client *cl)
{
    for (int i = 0; i < cl->countIp; ++i)
    {
        free(cl->ipPortInfo[i].ipStr);
        free(cl->ipPortInfo[i].ports);
    }
    free(cl->ipPortInfo);

    memset(cl, 0, sizeof(client));
}
