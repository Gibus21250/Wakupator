//
// Created by Nathan on 02/09/2024.
//

#include <malloc.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <errno.h>

#include <pthread.h>

#include "wakupator/core/monitor.h"

#include <stdlib.h>
#include <threads.h>

#include "wakupator/core/manager.h"

#include "wakupator/utils/bpf.h"
#include "wakupator/utils/utils.h"

#include "wakupator/log/log.h"
#include "wakupator/utils/net.h"

void *main_client_monitoring(void* args)
{

    //Shallow copy
    const main_monitor_args mainClientArgs = *(main_monitor_args*) args;
    manager *manager = mainClientArgs.manager;

    pthread_mutex_t *selfMutex = &manager->registeringMutex;
    pthread_cond_t *selfCond = &manager->registeringCond;

    //Shallow copy of the client
    client cl = *mainClientArgs.client;

    char clientHeader[sizeof(cl.macStr) + sizeof(cl.name) + 16];
    snprintf(clientHeader, sizeof(clientHeader),"Client %s (%s)", cl.name, cl.macStr);

    log_debug("%s: init monitor thread.\n", clientHeader);

    //Verify that all IP asked are not already assigned on the host
    const int code = validate_client_ips(&cl);

    if(code != OK)
    {
        pthread_mutex_lock(selfMutex);
        *mainClientArgs.wakupator_code = code;
        pthread_cond_signal(selfCond);
        pthread_mutex_unlock(selfMutex);
        return NULL;
    }

    log_debug("%s: IP(s) provided can be spoofed.\n", clientHeader);

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

    //Create all socket needed: on per group IP/ports
    //(continue if no ports was provided)
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

    log_debug("%s: %d raw sockets created. (%d IP without ports provided)\n", clientHeader, nbSockCreated, cl.countIp - nbSockCreated);

    //Create a raw socket to detect activity from the target interface.
    //(ARP/NS and all others)
    fds[nbSockCreated].fd = create_raw_socket_arp_ns(cl.macStr);
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    //Adding at the last the pipe for handling master's notification
    //(close socket from a poll fd seems to not unlock the thread)
    fds[nbSockCreated].fd = manager->notify[0];
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    log_debug("%s: ARP/NS and Master Notify created.\n", clientHeader);

    // --------------------------------- Notify the master that everything is OK -------------------------------------
    pthread_mutex_lock(selfMutex);
    *mainClientArgs.wakupator_code = OK;
    pthread_cond_signal(selfCond);
    pthread_mutex_unlock(selfMutex);

    // ---------------------------------- Waiting notify from master to continue -------------------------------------

    pthread_mutex_lock(selfMutex);
    pthread_cond_wait(selfCond, selfMutex);
    pthread_mutex_unlock(selfMutex);


    log_info("%s: Waiting for the machine to stop completely before proceeding with the monitoring...\n",
                    clientHeader);

    const ip_port_info clientTargetIP = cl.ipPortInfo[0];

    log_info("%s: Using the IP %s as representative to check if the machine is off.\n",
                    clientHeader, clientTargetIP.ipStr);

    char buffer[1024];

    const uint16_t nbMaxProbe = manager->shutdownTimeout / manager->probeInterval;

    struct timespec start, end;
    char timeBuf[64];

    int nbAttempt = 1;
    int res = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);
    // ------------------------------------ Waiting the machine to turn off ------------------------------------------
    do
    {
        sleep(manager->probeInterval);

        //Clear the socket
        while (recv(fds[nbSockCreated-2].fd, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {}

        if (clientTargetIP.ipFormat == AF_INET)
        {
            if (send_arp(manager, clientTargetIP.ipStr))
            {
                log_fatal("%s: Error sending ARP packet, Wakupator could not verify the response.\n", clientHeader);
                continue;
            }

            log_info("%s: ARP Request sent to %s. (#%d)\n", clientHeader, clientTargetIP.ipStr, nbAttempt);
        }
        else
        {
            if (send_ns(manager, clientTargetIP.ipStr))
            {
                log_fatal("%s: Error sending ICMPv6 NS Request, Wakupator could not verify the response.\n", clientHeader);
                continue;
            }

            log_info("%s: ICMPv6 NS Request sent to %s. (#%d)\n", clientHeader, clientTargetIP.ipStr, nbAttempt);
        }

        nbAttempt++;

        //Waiting for arp/ns socket activity
        res = poll(&fds[nbSockCreated-2], 1, (int) manager->probeInterval * 1000);

        if (res > 0) {
            log_info("%s: Got a reply from the request. Retry in %ds.\n",
                            clientHeader, manager->probeInterval);
        }
        else if (res == 0)
            break;
        else {
            nbAttempt = -1;
            break;
        }

        //res != 0 mean got a reply to the ARP, so need to wait more time
    }while(nbAttempt <= nbMaxProbe);

    clock_gettime(CLOCK_MONOTONIC, &end);

    uint64_t timeElapsed = (uint64_t) (end.tv_sec - start.tv_sec);

    // ----------------------------------------- Result from waiting -------------------------------------------------
    //timeout
    if (nbAttempt == nbMaxProbe)
    {
        log_error("%s: The machine still appears to be powered on, canceling the IP address spoofing and "
                  "monitoring.", clientHeader);
    }
    else if (nbAttempt == -1) //Error while polling
    {
        log_fatal("%s: A fatal error occurred while polling the ARP/NS responses. IP spoofing and monitoring "
            "has been cancelled.", clientHeader);
    }
    else //The machine is off!
    {
        format_duration_hms(timeElapsed, timeBuf, sizeof(timeBuf));
        log_info("%s: The machine seems to be off in approximately %s.\n", clientHeader, timeBuf);
        log_info("%s: Start spoofing and monitoring IP addresses.\n", clientHeader);

        clock_gettime(CLOCK_MONOTONIC, &start);
        cl.timeStarted = start.tv_sec;
        // ----------- Spoofing IPs -----------
        spoof_client_ips(manager, &cl);

        char monitoring = 1;

        while (monitoring)
        {
            //----------- Clear the raw socket for ARP and NS detection -----------
            while (recv(fds[nbSockCreated-2].fd, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {}

            poll(fds, nbSockCreated, -1); //Waiting traffic

            //----------- traffic has been caught ------------

            remove_client_ips(manager, &cl);

            clock_gettime(CLOCK_MONOTONIC, &end);

            timeElapsed = (uint64_t) (end.tv_sec - start.tv_sec);

            //If the "traffic" is the master's notification, send only one WoL, and stop the thread.
            //We can't do a clean wake-up, because the system waits for the thread to stop quickly.
            if(fds[nbSockCreated-1].revents == POLLIN)
            {
                log_info("%s: Notification receive from main thread.\n", clientHeader);
                log_info("%s: Wake-On-Lan sent.\n", clientHeader);
                send_wake_on_lan(manager->mainRawSocket, manager->ifIndex, manager->ifMacRaw, cl.macRaw);
                monitoring = 0;
            }
            //If the traffic is an ARP/NS
            else if(fds[nbSockCreated-2].revents == POLLIN)
            {
                log_info("%s: the machine has been started manually.\n", clientHeader);
                monitoring = 0;
            }
            //Other "real" traffic monitored
            else
            {
                log_info("%s: traffic detected.\n", clientHeader);

                //Print packet Info
                for (int i = 0; i < nbSockCreated-2; i++)
                {
                    if (fds[i].revents & POLLIN)
                    {
                        unsigned char packet[65536];
                        struct sockaddr_ll saddr;
                        socklen_t saddrLen = sizeof(saddr);

                        const ssize_t packet_size = recvfrom(fds[i].fd, packet, sizeof(packet), 0,
                                                       (struct sockaddr *)&saddr, &saddrLen);

                        if (packet_size > 0)
                        {
                            const char* packet_info = print_ip_packet_info(packet, packet_size);

                            if (packet_info) {
                                log_info("%s: Packet Info: %s.\n", clientHeader, packet_info);
                                free((void*) packet_info);
                            }

                        }
                    }
                }

                nbAttempt = 1;
                res = 0;

                clock_gettime(CLOCK_MONOTONIC, &start);

                do //Attempt a Wake On LAN, and wait the machine to start
                {
                    //If we receive anything from the machine (arp, ns etc.), that means that the machine is up!
                    if(fds[nbSockCreated-2].revents == POLLIN)
                        break;

                    //Attempt a WoL
                    if (send_wake_on_lan(manager->mainRawSocket, manager->ifIndex, manager->ifMacRaw,cl.macRaw))
                    {
                        log_fatal("%s: Error sending the WoL packet, the machine could not start.\n", clientHeader);
                        continue;
                    }

                    log_info("%s: Wake-On-Lan sent. (#%d)\n", clientHeader, nbAttempt);

                    nbAttempt++;

                    //Waiting only for arp/ns socket activity
                    res = poll(&fds[nbSockCreated-2], 1, (int) manager->timeBtwAttempt * 1000);

                    //== 0 means no activity detected (= timeout), and no error
                }while(res == 0 && nbAttempt <= manager->nbAttempt);

                clock_gettime(CLOCK_MONOTONIC, &end);
                timeElapsed = (uint64_t) (end.tv_sec - start.tv_sec);
                format_duration_hms(timeElapsed, timeBuf, sizeof(timeBuf));

                //The machine has been started successfully (res record one activity)
                if(res != 0)
                {
                    log_info("%s: the machine has been started successfully. (%s)\n", clientHeader, timeBuf);
                    monitoring = 0;
                }
                else
                {
                    if(manager->keepClient == 1)
                    {
                        spoof_client_ips(manager, &cl);
                        log_info("%s: the machine does not appear to have started after %d attempts, monitoring resumes. (%s)\n", clientHeader, manager->nbAttempt, timeBuf);
                    }else
                    {
                        log_info("%s: the machine does not appear to have started after %d attempts. (%s)\n", clientHeader, manager->nbAttempt, timeBuf);
                        monitoring = 0;
                    }
                }

            }

        }//Monitoring loop

    }

    // --------------------------------------- Cleaning all resources ------------------------------------------------
    //Close all sockets created (but not the Master Notify)
    for (int i = 0; i < nbSockCreated - 1; ++i) {
        close(fds[i].fd);
    }

    if (unregister_client(manager, cl.macStr)) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        timeElapsed = (uint64_t) end.tv_sec - cl.timeStarted;
        format_duration_hms(timeElapsed, timeBuf, sizeof(timeBuf));
        log_info("%s: Has been removed from monitoring. Total monitoring duration: %s\n", clientHeader, timeBuf);
    }

    free(fds);
    return NULL;
}

void spoof_client_ips(const manager *mng, const client *cl)
{
    //Assign IP of the client on the host
    for (int j = 0; j < cl->countIp; ++j) {
        //TODO add Ip to the custom veth
        add_ip(mng->ifName, cl->ipPortInfo[j].ipStr);
    }
}

void remove_client_ips(const manager *mng, const client *cl)
{
    for (int i = 0; i < cl->countIp; ++i) {
        //TODO create a new virtual interface per client (to improve visibility)
        remove_ip(mng->ifName, cl->ipPortInfo[i].ipStr);
    }
}

int validate_client_ips(const client *cl)
{
    for (int i = 0; i < cl->countIp; ++i)
    {
        ip_search_result_t result;
        if (check_ip_exists(cl->ipPortInfo->ipStr, &result) == 1)
        {
            return MONITOR_IP_ALREADY_USED;
        }
    }
    return OK;
}

int create_raw_socket_arp_ns(const char macStr[18])
{
    const int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(rawSocket == -1)
        return -1;

    uint8_t macRaw[6];

    if (parse_mac(macStr, macRaw))
    {
        log_error("Error while parsing the MAC address\n");
        close(rawSocket);
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