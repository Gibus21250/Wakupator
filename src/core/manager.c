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

wakupator_code init_manager(manager *manager, const char* if_name)
{

    //Create main raw socket (for sending WoL packets)
    manager->mainRawSocket = socket(PF_PACKET, SOCK_RAW, 0);

    //Create main raw socket (for sending WoL, ARP, NS/NA packets)
    manager->main_raw_socket = socket(PF_PACKET, SOCK_RAW, 0);

    if(manager->main_raw_socket == -1)
    {
        return WK_RAW_SOCKET_CREATION_ERROR;
    }

    struct ifreq ifr = {0};

    //Gather if index from the interface name
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
    if (ioctl(manager->main_raw_socket, SIOCGIFINDEX, &ifr) < 0)
    {
        return WK_GATHER_INTERFACE_INDEX_ERROR;
    }

    manager->if_index = ifr.ifr_ifindex;
    manager->if_name = if_name;


    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);

    //Gather if mac address from the interface name
    if (ioctl(manager->main_raw_socket, SIOCGIFHWADDR, &ifr) < 0)
    {
        return WK_GATHER_INTERFACE_MAC_ERROR;
    }

    memcpy((void*) manager->if_mac_raw, ifr.ifr_hwaddr.sa_data, 6);

    //Gather IPv6 Link Local IP if available
    if (get_ipv6_link_local(if_name, &manager->if_ipv6_link_local) != 0)
    {
        log_info("No IPv6 link-local address on %s, IPv6 functionalities disabled.\n", if_name);
        manager->has_ipv6 = 0;
    }
    else
    {
        manager->has_ipv6 = 1;
        char ipv6_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &manager->if_ipv6_link_local, ipv6_str, sizeof(ipv6_str));
        log_info("IPv6 link-local found on %s: %s.\n", if_name, ipv6_str);
    }

    // ------ Buffers ------
    //thread_monitor_info
    manager->client_thread_infos = (thread_monitor_info*) malloc(BUFFER_GROW_STEP * sizeof(thread_monitor_info));
    if(manager->client_thread_infos == NULL)
    {
        close(manager->main_raw_socket);
        return WK_OUT_OF_MEMORY;
    }
    manager->client_capacity = BUFFER_GROW_STEP;
    manager->client_count = 0;

    //Buffer data
    manager->count = 0;
    manager->bufferSize = BUFFER_GROW_STEP;

    manager->clientThreadInfos = (thread_monitor_info*) malloc(BUFFER_GROW_STEP * sizeof(thread_monitor_info));
    if(manager->clientThreadInfos == NULL)
    {
        close(manager->mainRawSocket);
        return OUT_OF_MEMORY;
    }

    // ------ Init mutex ------
    if(pthread_mutex_init(&manager->lock, NULL) != 0)
    {
        free(manager->client_thread_infos);
        close(manager->main_raw_socket);
        return WK_MUTEX_CREATION_ERROR;
    }

    if(pthread_mutex_init(&manager->registering_mutex, NULL) != 0)
    {
        free(manager->client_thread_infos);
        close(manager->main_raw_socket);
        pthread_mutex_destroy(&manager->lock);
        return WK_MUTEX_CREATION_ERROR;
    }

    if(pthread_cond_init(&manager->registering_cond, NULL) != 0)
    {
        free(manager->client_thread_infos);
        close(manager->main_raw_socket);
        pthread_mutex_destroy(&manager->lock);
        pthread_mutex_destroy(&manager->registering_mutex);
        return WK_MUTEX_CREATION_ERROR;
    }

    //Create pipe for notification
    if(pipe(manager->notify) != 0)
    {
        free(manager->client_thread_infos);
        close(manager->main_raw_socket);
        pthread_mutex_destroy(&manager->lock);
        pthread_mutex_destroy(&manager->registering_mutex);
        pthread_cond_destroy(&manager->registering_cond);
        return WK_PIPE_CREATION_ERROR;
    }

    log_debug("Manager successfully initialized.\n");

    return WK_OK;
}

void destroy_manager(manager *manager)
{

    log_debug("Destroying manager\n");

    //Notify all thread to wake up
    const char placebo = '1';
    write(manager->notify[1], &placebo, 1);

    pthread_mutex_lock(&manager->lock);
    if(manager->client_count != 0)
    {
        log_info("At least one client is still registered and will be woken up.\n");

        do {
            //monitor thread need the mutex to remove client
            pthread_mutex_unlock(&manager->lock);
            sleep(1);
            pthread_mutex_lock(&manager->lock);
        }while (manager->client_count != 0);

        log_info("All the client have been woken up.\n");
    }
    free(manager->client_thread_infos);

    pthread_mutex_destroy(&manager->lock);
    pthread_mutex_destroy(&manager->registering_mutex);

    pthread_cond_destroy(&manager->registering_cond);

    close(manager->notify[0]);
    close(manager->notify[1]);
    close(manager->main_raw_socket);

    log_debug("Manager successfully destroyed\n");

}

/**
 * Register the client into the manager, and prepare the client's monitoring thread.
 * @return WK_OK if done, otherwise the client hasn't been registered
 */
wakupator_code register_client(manager *manager, client *new_client)
{
    //Lock the manager struct
    pthread_mutex_lock(&manager->lock);

    log_debug("Manager locked.\n");

    if (manager->has_ipv6 == 0)
    {
        //Verify that all requested IP addresses do not contain any IPv6 addresses
        for(int i = 0; i < new_client->count_ip; ++i)
        {
            if (new_client->ip_port_info[i].ip_format == AF_INET6)
            {
                pthread_mutex_unlock(&manager->lock);
                return WK_MANAGER_IP6_NOT_AVAILABLE;
            }
        }
    }

    //Verify that the client's mac address isn't already monitored
    for (int i = 0; i < manager->client_count; ++i) {
        if(strcasecmp(new_client->mac_str, manager->client_thread_infos[i].cl.mac_str) == 0)
        {
            pthread_mutex_unlock(&manager->lock);
            return WK_MANAGER_MAC_ADDRESS_ALREADY_MONITORED;
        }
    }

    //If the buffer isn't big enough
    if(manager->client_count == manager->client_capacity)
    {
        log_debug("Increasing manager's clients buffer size.");
        thread_monitor_info *tmp = realloc(manager->client_thread_infos, (manager->client_capacity + BUFFER_GROW_STEP) * sizeof(thread_monitor_info));
        if(tmp != NULL)
        {
            log_debug("Increase buffer size OK.");
            manager->client_thread_infos = tmp;
            manager->client_capacity += BUFFER_GROW_STEP;
        } else {
            pthread_mutex_unlock(&manager->lock);
            return WK_OUT_OF_MEMORY;
        }
    }

    const uint32_t index = manager->client_count;

    pthread_mutex_t *register_mutex = &manager->registering_mutex;
    pthread_cond_t *register_cond = &manager->registering_cond;

    wakupator_code code = -1;

    main_monitor_args args = {
            manager,
            new_client,
            &code
    };


    //Lock the child mutex first
    log_debug("Register mutex locked\n");
    pthread_mutex_lock(register_mutex);
    pthread_t child_thread;

    //Now we can start the child thread that going to monitor the client
    if(pthread_create(&child_thread, NULL, main_client_monitoring, &args))
    {
        //If error while creating the thread
        pthread_mutex_unlock(register_mutex);
        pthread_mutex_unlock(&manager->lock);
        return WK_MANAGER_MONITOR_THREAD_CREATION_ERROR;
    }

    log_debug("Client thread started mutex locked\n");

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 5; //more than 5 seconds to launch the chill thread is like an error

    //Wait a notification from the child thread, and this can time out
    //This call implicit atomically unlock the mutex, and main Lock it again after cond notified
    if(pthread_cond_timedwait(register_cond, register_mutex, &timeout))
    {
        log_debug("Client thread timeout. Abort registering\n");
        pthread_mutex_unlock(register_mutex);
        pthread_cancel(child_thread); //Tell the child thread to cleanly abort
        pthread_mutex_unlock(&manager->lock);
        return WK_MANAGER_MONITOR_THREAD_INIT_TIMEOUT;
    }

    log_debug("Client notify received.\n");

    //Check if no execution error during init phase of the child thread
    if(code != WK_OK)
    {
        log_debug("Error while initializing Client thread.\n");
        pthread_mutex_unlock(register_mutex);
        pthread_join(child_thread, NULL);
        pthread_mutex_unlock(&manager->lock);
        return code;
    }

    log_debug("Client Thread is OK.\n");

    //Finally, everything is ok
    //Shallow copy of the client, the child thread is responsible for the struct
    manager->client_thread_infos[index].cl = *new_client;
    manager->client_thread_infos[index].thread = child_thread;
    manager->client_count++;

    pthread_detach(child_thread);

    pthread_mutex_unlock(register_mutex);
    pthread_mutex_unlock(&manager->lock);

    return WK_OK;
}

wakupator_code unregister_client(manager *manager, const char* str_mac)
{
    pthread_mutex_lock(&manager->lock);

    for (int i = 0; i < manager->client_count; ++i) {
        if (strcasecmp(str_mac, manager->client_thread_infos[i].cl.mac_str) == 0)
        {
            destroy_client(&manager->client_thread_infos[i].cl);

            const uint32_t last = manager->client_count - 1;
            if (i != last) {
                manager->client_thread_infos[i] = manager->client_thread_infos[last];
            }
            manager->client_count--;

            pthread_mutex_unlock(&manager->lock);
            return WK_OK;
        }
    }
    pthread_mutex_unlock(&manager->lock);
    return WK_MANAGER_CLIENT_NOT_FOUND;
}

            mng_client->count--;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&mng_client->mainLock);
    return found;
}