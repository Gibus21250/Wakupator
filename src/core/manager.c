#include "wakupator/core/manager.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

#include "wakupator/core/monitor.h"
#include "wakupator/log/log.h"
#include "../../include/wakupator/net/net.h"
#include "wakupator/utils/utils.h"

#define BUFFER_GROW_STEP 4

void notify_master_thread(manager *manager, wakupator_code *master_dst, const wakupator_code code)
{
    pthread_mutex_t *register_mutex = &manager->registering_mutex;
    pthread_cond_t *register_cond = &manager->registering_cond;

    pthread_mutex_lock(register_mutex);
    *master_dst = code;
    pthread_cond_signal(register_cond);
    pthread_mutex_unlock(register_mutex);
}

wakupator_code init_manager(manager *manager, const char* if_name)
{

    LOG_DEBUG("Initializing manager.\n");

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

    struct sockaddr_ll addr = {0};
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = manager->if_index;

    if (bind(manager->main_raw_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(manager->main_raw_socket);
        return WK_RAW_SOCKET_BIND_ERROR;
    }

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

    if (manager->has_ipv6)
    {
        manager->mld_socket = socket(AF_INET6, SOCK_DGRAM, 0);

        if (manager->mld_socket == -1) {
            close(manager->main_raw_socket);
            return WK_MLD_SOCKET_CREATION_ERROR;
        }

        manager->mld_members = (mld_member_info*) malloc(BUFFER_GROW_STEP * sizeof(mld_member_info));
        if(manager->mld_members == NULL)
        {
            close(manager->main_raw_socket);
            close(manager->mld_socket);
            free(manager->client_thread_infos);
            return WK_OUT_OF_MEMORY;
        }
        manager->mld_count = 0;
        manager->mld_capacity = BUFFER_GROW_STEP;
    }
    else {
        manager->mld_socket = -1;
        manager->mld_members = NULL;
        manager->mld_count = 0;
        manager->mld_capacity = 0;
    }

    // ------ Init mutex ------
    if(pthread_mutex_init(&manager->lock, NULL) != 0)
    {
        free(manager->client_thread_infos);
        free(manager->mld_members);
        close(manager->main_raw_socket);
        if (manager->mld_socket != -1)
            close(manager->mld_socket);
        return WK_MUTEX_CREATION_ERROR;
    }

    if(pthread_mutex_init(&manager->registering_mutex, NULL) != 0)
    {
        free(manager->client_thread_infos);
        free(manager->mld_members);
        close(manager->main_raw_socket);
        if (manager->mld_socket != -1)
            close(manager->mld_socket);
        pthread_mutex_destroy(&manager->lock);
        return WK_MUTEX_CREATION_ERROR;
    }

    if(pthread_cond_init(&manager->registering_cond, NULL) != 0)
    {
        free(manager->client_thread_infos);
        free(manager->mld_members);
        close(manager->main_raw_socket);
        if (manager->mld_socket != -1)
            close(manager->mld_socket);
        pthread_mutex_destroy(&manager->lock);
        pthread_mutex_destroy(&manager->registering_mutex);
        return WK_MUTEX_CREATION_ERROR;
    }

    //Create pipe for notification
    if(pipe(manager->notify) != 0)
    {
        free(manager->client_thread_infos);
        free(manager->mld_members);
        close(manager->main_raw_socket);
        if (manager->mld_socket != -1)
            close(manager->mld_socket);
        pthread_mutex_destroy(&manager->lock);
        pthread_mutex_destroy(&manager->registering_mutex);
        pthread_cond_destroy(&manager->registering_cond);
        return WK_PIPE_CREATION_ERROR;
    }
    LOG_DEBUG("Manager successfully initialized.\n");

    return WK_OK;
}

void destroy_manager(manager *manager)
{

    LOG_DEBUG("Destroying manager\n");

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
    if (manager->has_ipv6)
    {
        free(manager->mld_members);
        close(manager->mld_socket);
    }

    pthread_mutex_destroy(&manager->lock);
    pthread_mutex_destroy(&manager->registering_mutex);

    pthread_cond_destroy(&manager->registering_cond);

    close(manager->notify[0]);
    close(manager->notify[1]);
    close(manager->main_raw_socket);

    LOG_DEBUG("Manager successfully destroyed\n");

}

/**
 * Register the client into the manager, and prepare the client's monitoring thread.
 * @return WK_OK if done, otherwise the client hasn't been registered
 */
wakupator_code register_client(manager *manager, client *new_client)
{
    //Lock the manager struct
    pthread_mutex_lock(&manager->lock);

    LOG_DEBUG("Manager locked.\n");

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
        LOG_DEBUG("Increasing manager's clients buffer size.\n");
        thread_monitor_info *tmp = realloc(manager->client_thread_infos, (manager->client_capacity + BUFFER_GROW_STEP) * sizeof(thread_monitor_info));
        if(tmp != NULL)
        {
            manager->client_thread_infos = tmp;
            manager->client_capacity += BUFFER_GROW_STEP;
            LOG_DEBUG("Increase client buffer size OK.\n");
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
    pthread_mutex_lock(register_mutex);
    LOG_DEBUG("Register mutex locked\n");
    pthread_t child_thread;

    //Now we can start the child thread that going to monitor the client
    if(pthread_create(&child_thread, NULL, main_client_monitoring, &args))
    {
        //If error while creating the thread
        pthread_mutex_unlock(register_mutex);
        pthread_mutex_unlock(&manager->lock);
        return WK_MANAGER_MONITOR_THREAD_CREATION_ERROR;
    }

    LOG_DEBUG("Client thread started mutex locked\n");

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 5; //more than 5 seconds to launch the chill thread is like an error

    //Wait a notification from the child thread, and this can time out
    //This call implicit atomically unlock the mutex, and main Lock it again after cond notified
    if(pthread_cond_timedwait(register_cond, register_mutex, &timeout))
    {
        LOG_DEBUG("Client thread timeout. Abort registering\n");
        pthread_mutex_unlock(register_mutex);
        pthread_cancel(child_thread); //Tell the child thread to cleanly abort
        pthread_mutex_unlock(&manager->lock);
        return WK_MANAGER_MONITOR_THREAD_INIT_TIMEOUT;
    }

    LOG_DEBUG("Client notify received.\n");

    //Check if no execution error during init phase of the child thread
    if(code != WK_OK)
    {
        LOG_DEBUG("Error while initializing Client thread.\n");
        pthread_mutex_unlock(register_mutex);
        pthread_join(child_thread, NULL);
        pthread_mutex_unlock(&manager->lock);
        return code;
    }

    LOG_DEBUG("Client Thread is OK.\n");

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

wakupator_code add_mld_member(manager *manager, const struct in6_addr addr)
{
    if (!manager->has_ipv6)
        return WK_MANAGER_IP6_NOT_AVAILABLE;

    //ff02::1:ffXX:XXXX
    struct in6_addr ns_mc_addr = {0};

    ns_mc_addr.s6_addr[0] = 0xff;
    ns_mc_addr.s6_addr[1] = 0x02;
    ns_mc_addr.s6_addr[11] = 0x01;
    ns_mc_addr.s6_addr[12] = 0xff;

    ns_mc_addr.s6_addr[13] = addr.s6_addr[13];
    ns_mc_addr.s6_addr[14] = addr.s6_addr[14];
    ns_mc_addr.s6_addr[15] = addr.s6_addr[15];

    pthread_mutex_lock(&manager->lock);

    mld_member_info *mld_info = NULL;

    //Check if we are already subscribed to this sn-multicast
    for (uint32_t i = 0; i < manager->mld_count; ++i)
    {
        if (memcmp(&manager->mld_members[i].addr, &ns_mc_addr, sizeof(struct in6_addr)) == 0) {
            mld_info = &manager->mld_members[i];
            break;
        }
    }

    //Already subscribed, just increment the counter
    if (mld_info != NULL) {
        mld_info->count++;
        LOG_DEBUG("Found a record for the IP\n");
        pthread_mutex_unlock(&manager->lock);
        return WK_OK;
    }

    //New subscription
    if(manager->mld_count == manager->mld_capacity)
    {
        LOG_DEBUG("Increasing manager's MLD buffer size.\n");
        mld_member_info *tmp = realloc(manager->mld_members, (manager->mld_capacity + BUFFER_GROW_STEP) * sizeof(mld_member_info));
        if(tmp != NULL)
        {
            manager->mld_members = tmp;
            manager->mld_capacity += BUFFER_GROW_STEP;
            LOG_DEBUG("Increase MLD buffer size OK.\n");
        } else {
            pthread_mutex_unlock(&manager->lock);
            return WK_OUT_OF_MEMORY;
        }
    }
    struct ipv6_mreq mreq = {0};

    memcpy(&mreq.ipv6mr_multiaddr, &ns_mc_addr, sizeof(struct in6_addr));
    mreq.ipv6mr_interface = manager->if_index;

    if (setsockopt(manager->mld_socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,sizeof(mreq)) < 0)
    {
        pthread_mutex_unlock(&manager->lock);
        log_error("Failed to join IPv6 multicast group.\n");
        return WK_MLD_ADDING_MEMBER_ERROR;
    }

    LOG_DEBUG("MLD record added.\n");
    manager->mld_members[manager->mld_count].addr = ns_mc_addr;
    manager->mld_members[manager->mld_count].count = 1;
    manager->mld_count++;
    pthread_mutex_unlock(&manager->lock);

    return WK_OK;
}

wakupator_code remove_mld_member(manager *manager, const struct in6_addr addr)
{
    if (!manager->has_ipv6)
        return WK_MANAGER_IP6_NOT_AVAILABLE;

    struct in6_addr ns_mc_addr = {0};

    ns_mc_addr.s6_addr[0] = 0xff;
    ns_mc_addr.s6_addr[1] = 0x02;
    ns_mc_addr.s6_addr[11] = 0x01;
    ns_mc_addr.s6_addr[12] = 0xff;

    ns_mc_addr.s6_addr[13] = addr.s6_addr[13];
    ns_mc_addr.s6_addr[14] = addr.s6_addr[14];
    ns_mc_addr.s6_addr[15] = addr.s6_addr[15];

    pthread_mutex_lock(&manager->lock);

    mld_member_info *mld_info = NULL;
    uint32_t index = 0;

    //Check if we are already subscribed to this sn-multicast
    for (uint32_t i = 0; i < manager->mld_count; ++i)
    {
        if (memcmp(&manager->mld_members[i].addr, &ns_mc_addr, sizeof(struct in6_addr)) == 0) {
            mld_info = &manager->mld_members[i];
            index = i;
            break;
        }
    }

    if (mld_info != NULL) {

        if (mld_info->count > 1) {
            mld_info->count--;
            LOG_DEBUG("MLD record more than one time, decreasing the counter.\n");
        }
        else //Remove the entry and mld data
        {
            struct ipv6_mreq mreq = {0};

            memcpy(&mreq.ipv6mr_multiaddr, &ns_mc_addr, sizeof(struct in6_addr));
            mreq.ipv6mr_interface = manager->if_index;

            if (setsockopt(manager->mld_socket, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq,sizeof(mreq)) < 0)
            {
                pthread_mutex_unlock(&manager->lock);
                log_error("Failed to drop IPv6 multicast group.\n");
                return WK_MLD_REMOVE_MEMBER_ERROR;
            }

            LOG_DEBUG("MLD record removed.\n");
            //remove-swap
            const uint32_t last = manager->mld_count - 1;
            if (index != last) {
                manager->mld_members[index] = manager->mld_members[last];
            }
            manager->mld_count--;
        }
    }

    pthread_mutex_unlock(&manager->lock);
    return WK_OK;

}