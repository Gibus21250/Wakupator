//
// Created by Nathan on 02/09/2024.
//

#include <netinet/if_ether.h>
#include <malloc.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <pthread.h>

#include "wakupator/core/monitor.h"

#include <threads.h>

#include "wakupator/core/manager.h"

#include "wakupator/net/bpf.h"
#include "wakupator/net/net.h"
#include "wakupator/net/socket.h"

#include "wakupator/utils/utils.h"

#include "wakupator/log/log.h"
#include "wakupator/utils/net.h"

void *main_client_monitoring(void* args)
{

    //Shallow copy
    const main_monitor_args main_client_args = *(main_monitor_args*) args;
    manager *manager = main_client_args.manager;

    //Shallow copy of the client information
    client cl = *main_client_args.client;

    char client_header[sizeof(cl.mac_str) + sizeof(cl.name) + 16];
    snprintf(client_header, sizeof(client_header),"Client %s (%s)", cl.name, cl.mac_str);

    log_debug("%s: init monitor thread.\n", clientHeader);



    log_debug("%s: IP(s) provided can be spoofed.\n", clientHeader);

    //Array: count(IP with port(s) provided) + 2 (ARP/NS & Master Notify)
    //[fdIP1, fdIP2, ..., fdARP/NS, fdNotify]
    struct pollfd *fds = calloc(cl.countIp + 2, sizeof(struct pollfd));

    if(fds == NULL)
    {
        pthread_mutex_lock(registerMutex);
        *mainClientArgs.wakupator_code = OUT_OF_MEMORY;
        pthread_cond_signal(registerCond);
        pthread_mutex_unlock(registerMutex);
        return NULL;
    }

    uint32_t nbSockCreated = 0;

    //Create all socket needed: on per group IP/ports
    //(continue if no ports was provided)
    for (uint32_t i = 0; i < cl.countIp; ++i) {
        const ip_port_info *info = &cl.ipPortInfo[i];

        if (info->portCount == 0)
            continue;

        const int sock = create_raw_socket_filtered_ip_port(manager->if_index, info);

        if(sock == -1) //Error
        {
            for (uint32_t k = 0; k < nbSockCreated; ++k)
                close(fds[k].fd);

            pthread_mutex_lock(registerMutex);
            *mainClientArgs.wakupator_code = MONITOR_RAW_SOCKET_CREATION_ERROR;
            pthread_cond_signal(registerCond);
            pthread_mutex_unlock(registerMutex);
            free(fds);
            return NULL;
        }

        fds[nbSockCreated].fd = sock;
        fds[nbSockCreated].events = POLLIN;

        nbSockCreated++;

    }

    log_debug("%s: %d raw sockets created. (%d IP without ports provided)\n", clientHeader, nbSockCreated, cl.countIp - nbSockCreated);
    const int sock = create_raw_socket_any_traffic_from_mac(cl.mac_raw);

    //Create a raw socket to detect activity from the target interface.
    //(ARP/NS and all others)
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    //Adding at the last the pipe for handling master's notification
    //(close socket from a poll fd seems to not unlock the thread)
    fds[nbSockCreated].fd = manager->notify[0];
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    log_debug("%s: ARP/NS and Master Notify created.\n", clientHeader);

    // --------------------------------- Notify the master that everything is OK -------------------------------------
    log_debug("%s: Notify the master thread that everything is OK.\n", clientHeader);
    pthread_mutex_lock(registerMutex);
    *mainClientArgs.wakupator_code = OK;
    pthread_cond_signal(registerCond);
    pthread_mutex_unlock(registerMutex);

    sleep(1);

    log_info("%s: Waiting for the machine to stop completely before proceeding with the monitoring...\n",
                    clientHeader);

    const ip_port_info clientTargetIP = cl.ipPortInfo[0];

    log_info("%s: Using the IP %s as representative to check if the machine is off.\n",
                    clientHeader, clientTargetIP.ipStr);

    char buffer[1024];

    const uint16_t nbMaxProbe = manager->shutdownTimeout / manager->shutdownProbeInterval;

    struct timespec start, end;
    char timeBuf[64];

    int nbAttempt = 1;
    int res = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);
    // ------------------------------------ Waiting the machine to turn off ------------------------------------------
    do
    {
        sleep(manager->shutdownProbeInterval);

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
        res = poll(&fds[nbSockCreated-2], 1, (int) manager->shutdownProbeInterval * 1000);

        if (res > 0) {
            log_info("%s: Got a reply from the request. Retry in %ds.\n",
                            clientHeader, manager->shutdownProbeInterval);
        }
        else if (res == 0)
            break;
        else {
            nbAttempt = -1;
            break;
        }

        //res != 0 mean got a reply to the ARP/NS, so need to wait more
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
                    res = poll(&fds[nbSockCreated-2], 1, (int) manager->wolDelay * 1000);

                    //== 0 means no activity detected (= timeout), and no error
                }while(res == 0 && nbAttempt <= manager->wolMaxAttempts);

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
                    if(manager->wolKeepClient == 1)
                    {
                        spoof_client_ips(manager, &cl);
                        log_info("%s: the machine does not appear to have started after %d attempts, monitoring resumes. (%s)\n", clientHeader, manager->wolMaxAttempts, timeBuf);
                    }else
                    {
                        log_info("%s: the machine does not appear to have started after %d attempts. (%s)\n", clientHeader, manager->wolMaxAttempts, timeBuf);
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


    }
}
