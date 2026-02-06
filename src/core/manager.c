#include "wakupator/core/manager.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "wakupator/core/monitor.h"
#include "wakupator/log/log.h"
#include "wakupator/utils/net.h"

#define BUFFER_GROW_STEP 4

WAKUPATOR_CODE init_manager(manager *manager, const char* ifName)
{

    log_debug("Initializing manager.\n");

    //Create main raw socket (for sending WoL packets)
    manager->mainRawSocket = socket(PF_PACKET, SOCK_RAW, 0);

    if(manager->mainRawSocket == -1)
    {
        return INIT_RAW_SOCKET_CREATION_ERROR;
    }

    struct ifreq ifr = {0};

    //Gather if index from the interface name
    strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(manager->mainRawSocket, SIOCGIFINDEX, &ifr) < 0)
    {
        close(manager->mainRawSocket);
        return INIT_INTERFACE_GATHER_IF_INDEX_ERROR;
    }

    manager->ifIndex = ifr.ifr_ifindex;
    manager->ifName = ifName;

    //Gather if mac address from the interface name
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(manager->mainRawSocket, SIOCGIFHWADDR, &ifr) < 0)
    {
        close(manager->mainRawSocket);
        return INIT_INTERFACE_GATHER_IF_MAC_ERROR;
    }

    memcpy((void*) manager->ifMacRaw, ifr.ifr_hwaddr.sa_data, 6);

    //Gather IPv6 Link Local IP if available
    if (get_ipv6_link_local(ifName, &manager->ifIPv6LinkLocal) != 0)
    {
        log_info("No IPv6 link-local address on %s, IPv6 fonctionalities disabled\n", ifName);
        manager->hasIPv6 = 0;
    }
    else
    {
        manager->hasIPv6 = 1;
        char ipv6_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &manager->ifIPv6LinkLocal, ipv6_str, sizeof(ipv6_str));
        log_debug("IPv6 link-local found on %s: %s\n", ifName, ipv6_str);
    }

    //Buffer data
    manager->count = 0;
    manager->bufferSize = BUFFER_GROW_STEP;

    manager->clientThreadInfos = (thread_monitor_info*) malloc(BUFFER_GROW_STEP * sizeof(thread_monitor_info));
    if(manager->clientThreadInfos == NULL)
    {
        close(manager->mainRawSocket);
        return OUT_OF_MEMORY;
    }

    //Init mutex
    if(pthread_mutex_init(&manager->mainLock, NULL) != 0)
    {
        free(manager->clientThreadInfos);
        close(manager->mainRawSocket);
        return INIT_MUTEX_CREATION_ERROR;
    }

    if(pthread_mutex_init(&manager->registeringMutex, NULL) != 0)
    {
        free(manager->clientThreadInfos);
        close(manager->mainRawSocket);
        pthread_mutex_destroy(&manager->mainLock);
        return INIT_MUTEX_CREATION_ERROR;
    }

    if(pthread_cond_init(&manager->registeringCond, NULL) != 0)
    {
        free(manager->clientThreadInfos);
        close(manager->mainRawSocket);
        pthread_mutex_destroy(&manager->mainLock);
        pthread_mutex_destroy(&manager->registeringMutex);
        return INIT_MUTEX_CREATION_ERROR;
    }

    //Create pipe for notification
    if(pipe(manager->notify) != 0)
    {
        free(manager->clientThreadInfos);
        close(manager->mainRawSocket);
        pthread_mutex_destroy(&manager->mainLock);
        pthread_mutex_destroy(&manager->registeringMutex);
        pthread_cond_destroy(&manager->registeringCond);
        return INIT_PIPE_CREATION_ERROR;
    }

    log_debug("Manager successfully initialized.\n");

    return OK;
}

void destroy_manager(manager *mng_client)
{

    log_debug("Destroying manager\n");

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
        log_info("All the client have been woken up.\n");
    } else
        pthread_mutex_unlock(&mng_client->mainLock);

    free(mng_client->clientThreadInfos);
    pthread_mutex_destroy(&mng_client->mainLock);
    pthread_mutex_destroy(&mng_client->registeringMutex);

    pthread_cond_destroy(&mng_client->registeringCond);

    close(mng_client->notify[0]);
    close(mng_client->notify[1]);
    close(mng_client->mainRawSocket);

    log_debug("Manager successfully destroyed\n");

}

/**
 * Register the client into the manager, and prepare the client's monitoring thread.
 * @return OK if done, otherwise the client hasn't been registered
 */
WAKUPATOR_CODE register_client(manager *mng_client, client *newClient)
{
    //Lock the manager struct
    pthread_mutex_lock(&mng_client->mainLock);

    if (mng_client->hasIPv6 == 0)
    {
        //Verify that all requested IP addresses do not contain any IPv6 addresses
        for(int i = 0; i < newClient->countIp; ++i)
        {
            if (newClient->ipPortInfo[i].ipFormat == AF_INET6)
            {
                pthread_mutex_unlock(&mng_client->mainLock);
                return MANAGER_IP6_NOT_AVAILABLE;
            }
        }
    }


    //Verify that the client's mac address isn't already monitored
    for (int i = 0; i < mng_client->count; ++i) {
        if(strcasecmp(newClient->macStr, mng_client->clientThreadInfos[i].cl.macStr) == 0)
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

int unregister_client(manager *mng_client, const char* strMac)
{
    int found = 0;
    pthread_mutex_lock(&mng_client->mainLock);

    for (int i = 0; i < mng_client->count; ++i) {
        //if we found the client
        if(strcasecmp(strMac, mng_client->clientThreadInfos[i].cl.macStr) == 0)
        {

            destroy_client(&mng_client->clientThreadInfos[i].cl);

            //shift all thread_client_info to the left starting this index
            for (int j = i; j < mng_client->count-1; ++j)
                mng_client->clientThreadInfos[j] = mng_client->clientThreadInfos[(j+1)];

            mng_client->count--;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&mng_client->mainLock);
    return found;
}

void start_monitoring(manager *mng_client, const char* macClient)
{
    pthread_mutex_lock(&mng_client->mainLock);

    for (int i = 0; i < mng_client->count; ++i) {

        if(strcasecmp(macClient, mng_client->clientThreadInfos[i].cl.macStr) == 0)
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