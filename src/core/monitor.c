//
// Created by Nathan on 02/09/2024.
//

#include <malloc.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <memory.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <errno.h>

#include <pthread.h>

#include "wakupator/core/monitor.h"

#include "wakupator/utils/bpf.h"
#include "wakupator/utils/utils.h"

#include "wakupator/log/log.h"

void *main_client_monitoring(void* args)
{

    //Shallow copy
    const main_monitor_args mainClientArgs = *(main_monitor_args*) args;
    manager *manager = mainClientArgs.managerMain;

    pthread_mutex_t *selfMutex = &manager->registeringMutex;
    pthread_cond_t *selfCond = &manager->registeringCond;

    //Shallow copy of the client
    client cl = *mainClientArgs.client;

    log_debug("Client [%s]: init monitor thread.\n", cl.mac);

    //Verify that all IP asked are not already assigned on the host
    const int code = verify_ips(&cl);

    if(code != OK)
    {
        pthread_mutex_lock(selfMutex);
        *mainClientArgs.wakupator_code = code;
        pthread_cond_signal(selfCond);
        pthread_mutex_unlock(selfMutex);
        return NULL;
    }
    log_debug("Client [%s]: IP(s) provided can be spoofed.\n", cl.mac);

    //Array: count(IP with port(s) provided) + 2 (ARP/NS & Master Notify)
    //[fdIP1, fdIP2, ..., fdARP/NS, fdNotify]
    struct pollfd *fds = calloc(cl.countIp + 2, sizeof(struct pollfd));

    if(fds == NULL)
    {
        pthread_mutex_lock(selfMutex);
        *mainClientArgs.wakupator_code = OUT_OF_MEMORY;
        pthread_cond_signal(selfCond);
        pthread_mutex_unlock(selfMutex);
        return NULL;
    }

    uint32_t nbSockCreated = 0;

    //Create all socket needed: on per group IP/ports (continue if no ports was provided)
    for (uint32_t i = 0; i < cl.countIp; ++i) {
        const ip_port_info *info = &cl.ipPortInfo[i];

        if (info->portCount == 0)
            continue;

        const int sock = create_raw_filtered_socket(info);

        if(sock == -1) //Error
        {
            for (uint32_t k = 0; k < nbSockCreated; ++k)
                close(fds[k].fd);

            pthread_mutex_lock(selfMutex);
            *mainClientArgs.wakupator_code = MONITOR_RAW_SOCKET_CREATION_ERROR;
            pthread_cond_signal(selfCond);
            pthread_mutex_unlock(selfMutex);
            free(fds);
            return NULL;
        }

        fds[nbSockCreated].fd = sock;
        fds[nbSockCreated].events = POLLIN;

        nbSockCreated++;

    }

    log_debug("Client [%s]: %d raw sockets created. (%d IP without ports provided)\n", cl.mac, nbSockCreated, cl.countIp - nbSockCreated);

    //Create a raw socket to detect if the client has been started manually
    fds[nbSockCreated].fd = create_raw_socket_arp_ns(cl.mac);
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    //Adding at the last the pipe for handling master's notification (close socket from a poll fd seems to not unlock the thread)
    fds[nbSockCreated].fd = manager->notify[0];
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    log_debug("Client [%s]: ARP/NS and Master Notify created.\n", cl.mac);

    //------------ Notify the master that everything is OK ------------
    pthread_mutex_lock(selfMutex);
    *mainClientArgs.wakupator_code = OK;
    pthread_cond_signal(selfCond);
    pthread_mutex_unlock(selfMutex);

    //------------ Waiting notify from master to start spoofing and monitoring ------------

    pthread_mutex_lock(selfMutex);

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 10;

    //Wait a notification from the main thread to start monitoring
    if(pthread_cond_timedwait(selfCond, selfMutex, &timeout))
    {
        free(fds);
        return NULL;
    }
    pthread_mutex_unlock(selfMutex);

    char cmd[256];

    //Spoofs IPs
    spoof_ips(manager, &cl);

    //----------- Clear the raw socket for ARP and NS detection -----------
    while (recv(fds[nbSockCreated-2].fd, cmd, sizeof(cmd), MSG_DONTWAIT) > 0) {}

    //------------ Waiting for activities ------------
    log_info("Client [%s]: Monitoring started.\n", cl.mac);
    char monitoring = 1;

    while (monitoring)
    {
        poll(fds, nbSockCreated, -1); //Waiting traffic

        //----------- traffic has been caught ------------

        //remove all IP spoofed
        remove_ips(manager, &cl);

        //If the "traffic" is the master's notification, send only one WoL, and stop the thread.
        //We can't do a clean wake-up, because the system waits for the thread to stop quickly.
        if(fds[nbSockCreated-1].revents == POLLIN)
        {
            log_info("Client [%s]: Wake-On-Lan sent.\n", cl.mac);
            wake_up(manager->mainRawSocket, manager->ifIndex,cl.mac);
            monitoring = 0;
        }
        //If the traffic is an ARP/NS
        else if(fds[nbSockCreated-2].revents == POLLIN)
        {
            log_info("Client [%s]: the machine has been started manually.\n", cl.mac);
            monitoring = 0;
        }
        //Other "real" traffic monitored
        else
        {
            log_info("Client [%s]: traffic detected.\n", cl.mac);
            int nbAttempt = 1;
            int res = 0;

            struct timespec start_time, end_time;
            clock_gettime(CLOCK_MONOTONIC, &start_time);

            do //Attempt a Wake On LAN, and wait the machine to start
            {
                //If we receive anything from the machine (arp, ns etc.), that means that the machine is up!
                if(fds[nbSockCreated-2].revents == POLLIN)
                    break;
                log_info("Client [%s]: Wake-On-Lan sent. (attempt %d)\n", cl.mac, nbAttempt);
                //Attempt a WoL
                wake_up(manager->mainRawSocket, manager->ifIndex,cl.mac);
                nbAttempt++;

                //Waiting only for arp/ns socket activity
                res = poll(&fds[nbSockCreated-2], 1, (int) manager->timeBtwAttempt * 1000);

                //== 0 means no activity detected (= timeout), and no error
            }while(res == 0 && nbAttempt <= manager->nbAttempt);

            clock_gettime(CLOCK_MONOTONIC, &end_time);
            const double time_spent = (double) (end_time.tv_sec - start_time.tv_sec) + (double) (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

            //The machine has been started successfully (res record one activity)
            if(res != 0)
            {
                log_info("Client [%s]: the machine has been started successfully. (%.2fs)\n", cl.mac, time_spent);
                monitoring = 0;
            }
            else
            {
                if(manager->keepClient == 1)
                {
                    spoof_ips(manager, &cl);
                    log_info("Client [%s]: the machine does not appear to have started after %d attempts, monitoring resumes. (%.2fs)\n", cl.mac, manager->nbAttempt, time_spent);
                }else
                {
                    log_info("Client [%s]: the machine does not appear to have started after %d attempts. (%.2fs)\n", cl.mac, manager->nbAttempt, time_spent);
                    monitoring = 0;
                }
            }

        }

    }//Monitoring loop

    //Close all sockets created (but not the Master Notify)
    for (int i = 0; i < nbSockCreated - 1; ++i) {
        close(fds[i].fd);
    }

    unregister_client(manager, cl.mac);

    free(fds);
    return NULL;
}

void spoof_ips(const manager *mng, const client *cl)
{
    char cmd[128];

    //Get the original value of accept_dad
    snprintf(cmd, sizeof(cmd), "sysctl net.ipv6.conf.%s.accept_dad", mng->ifName);
    FILE *fp = popen(cmd, "r");

    char originalDadValue = '1';

    if(fp == NULL)
    {
        return;
    }

    if (fgets(cmd, sizeof(cmd), fp) != NULL) {
        const size_t len = strlen(cmd);
        if (len > 0) {
            originalDadValue = cmd[len - 2];
        }
    }
    fclose(fp);

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv6.conf.%s.accept_dad=0 > /dev/null 2>&1", mng->ifName);
    system(cmd);

    //Assign IP of the client on the host
    for (int j = 0; j < cl->countIp; ++j) {
        snprintf(cmd, sizeof(cmd), "ip a add %s dev %s", cl->ipPortInfo[j].ipStr, mng->ifName);
        system(cmd);
    }

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv6.conf.%s.accept_dad=%c > /dev/null 2>&1", mng->ifName, originalDadValue);
    system(cmd);
}

void remove_ips(const manager *mng, const client *cl)
{
    char cmd[128];
    for (int i = 0; i < cl->countIp; ++i) {
        if(cl->ipPortInfo[i].ipFormat == AF_INET6)
            snprintf(cmd, sizeof(cmd), "ip a del %s/128 dev %s", cl->ipPortInfo[i].ipStr, mng->ifName);
        else
            snprintf(cmd, sizeof(cmd), "ip a del %s/32 dev %s", cl->ipPortInfo[i].ipStr, mng->ifName);

        system(cmd);
    }
}

int verify_ips(const client *cl)
{
    char buffer[128];

    for (int i = 0; i < cl->countIp; ++i) {

        snprintf(buffer, sizeof(buffer), "ip a | grep -w %s", cl->ipPortInfo[i].ipStr);

        FILE *fp = popen(buffer, "r");
        if (fp == NULL) {
            return MONITOR_CHECK_IP_ERROR;
        }

        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            pclose(fp);
            return MONITOR_IP_ALREADY_USED;
        }
        pclose(fp);

    }
    return OK;
}

int create_raw_socket_arp_ns(const char macStr[18])
{
    const int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(rawSocket == -1)
        return -1;

    uint8_t macRaw[6];

    if (sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &macRaw[0], &macRaw[1], &macRaw[2],
               &macRaw[3], &macRaw[4], &macRaw[5]) != 6) {
        log_error("Error while parsing the MAC address\n");
        close(rawSocket);
        return -1;
    }

    struct sock_filter *bpf_code = calloc(10, sizeof(struct sock_filter));

    if(bpf_code == NULL)
    {
        close(rawSocket);
        log_error("Error while creating the BPF prog");
        return -1;
    }


    uint32_t codeSize = 0;
    codeSize = filter_mac(bpf_code, codeSize, macRaw);
    bpf_code[codeSize++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, -1); // Accept

    const struct sock_fprog bpf = {
            .filter = bpf_code,
            .len = codeSize
    };

    // Apply BPF filter to the socket
    if (setsockopt(rawSocket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_error("Error while setting the BPF prog to the raw socket");
        close(rawSocket);
        free(bpf.filter);
        return -1;
    }

    free(bpf.filter);

    return rawSocket;
}

int create_raw_filtered_socket(const ip_port_info *ipPortInfo)
{

    //Generate and prepare BPF asm for the kernel
    const uint16_t etherType = ipPortInfo->ipFormat == AF_INET ? ETH_P_IP : ETH_P_IPV6;

    const int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(etherType));

    if(rawSocket == -1)
        return -1;

    const struct sock_fprog bpf = create_bpf_filter(ipPortInfo);

    if(bpf.len == (unsigned short) -1)
    {
        log_error("Error while creating the BPF prog");
        close(rawSocket);
        return -1;
    }

    // Apply BPF filter to the socket
    if (setsockopt(rawSocket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        log_error("Error while setting the BPF prog to the raw socket");
        close(rawSocket);
        free(bpf.filter);
        return -1;
    }

    free(bpf.filter);

    //Sometimes, the time between socket creation and applying the filter, can catch some packets
    char buffer[128];
    ssize_t len;

    //Clear if necessary
    while ((len = recv(rawSocket, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0) {}

    //Check if different error code returned
    if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        log_error("Error while clearing the raw socket");
        close(rawSocket);
        return -1;
    }

    return rawSocket;
}

struct sock_fprog create_bpf_filter(const ip_port_info *ipPortInfo)
{

    struct sock_fprog res = {
            .filter = NULL,
            .len = -1
    };


    uint32_t ipRaw[4];
    if(inet_pton((int) ipPortInfo->ipFormat, ipPortInfo->ipStr, ipRaw) != 1)
    {
        log_error("Error while parsing IP when creating the BPF filter\n", strerror(errno));
        return res;
    }

    struct sock_filter *bpf_code = calloc(100, sizeof(struct sock_filter));

    if(bpf_code == NULL)
    {
        return res;
    }

    const uint16_t etherType = ipPortInfo->ipFormat == AF_INET ? ETH_P_IP : ETH_P_IPV6;

    uint32_t codeSize = 0;
    //codeSize = filter_ether(bpf_code, codeSize, etherType);

    if(etherType == ETH_P_IP)
        codeSize = filter_ipv4(bpf_code, codeSize, ipRaw[0], 14);
    else
        codeSize = filter_ipv6(bpf_code, codeSize, ipRaw, 14);

    codeSize = filter_protocol(bpf_code, codeSize, IPPROTO_TCP, ipPortInfo->ipFormat, 14);
    codeSize = filter_ports(bpf_code, codeSize, ipPortInfo->ports, ipPortInfo->portCount, 14 + (ipPortInfo->ipFormat==AF_INET?20:40));

    bpf_code[codeSize++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, -1); // Accept


    res.filter = bpf_code;
    res.len = codeSize;

    return res;
}

void wake_up(const int rawSocket, const int ifIndex, const char *macStr)
{
    char frame[ETH_HLEN + 102] = {0};

    unsigned char mac_bytes[6];
    sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);

    struct ethhdr *eth = (struct ethhdr *) frame;

    memcpy(&eth->h_dest, mac_bytes, 6);
    eth->h_proto = htons(0x0842); //WoL proto

    memset(frame + ETH_HLEN, 0xFF, 6);

    //Write magic pattern
    for (int i = 1; i <= 16; i++) {
        memcpy(frame + ETH_HLEN + i * 6, mac_bytes, 6);
    }

    struct sockaddr_ll socket_address = {0};
    socket_address.sll_ifindex = ifIndex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, eth->h_dest, 6);

    //Now send the packet through the lan
    if (sendto(rawSocket, frame, sizeof(frame), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("Error while sending the WoL packet.");
    }
}