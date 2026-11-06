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

static wakupator_code reply_to_probe(const manager *manager, const int fd, const ip_port_info *ip_info)
{
    unsigned char packet[256];
    const ssize_t size = recv(fd, packet, sizeof(packet), 0);

    //ARP Request captured
    if (ip_info->ip_format == AF_INET)
    {
        if (size < sizeof(arp_packet)) {
            return WK_MONITOR_ARP_REPLY_ERROR;
        }

        const arp_packet *arp_pkt = (arp_packet*) packet;

        if (send_arp_reply(manager->main_raw_socket, manager->if_mac_raw, arp_pkt, ip_info->ipv4))
            return WK_MONITOR_ARP_REPLY_ERROR;

        LOG_DEBUG("Reply to ARP packet\n");
    }
    else {

        if (size < sizeof(ns_packet)) {
            return WK_MONITOR_NS_REPLY_ERROR;
        }

        const ns_packet* ns_pkt = (ns_packet*) packet;

        if (send_ndp_na(manager->main_raw_socket, manager->if_mac_raw, ns_pkt, &ip_info->ipv6))
            return WK_MONITOR_NS_REPLY_ERROR;

        LOG_DEBUG("Reply to NS packet\n");

    }

    return WK_OK;
}

void *main_client_monitoring(void* args)
{

    //Shallow copy
    const main_monitor_args main_client_args = *(main_monitor_args*) args;
    manager *manager = main_client_args.manager;

    //Shallow copy of the client information
    client cl = *main_client_args.client;

    char client_header[sizeof(cl.mac_str) + sizeof(cl.name) + 16];
    snprintf(client_header, sizeof(client_header),"Client %s (%s)", cl.name, cl.mac_str);

    LOG_DEBUG("%s: init monitor thread.\n", client_header);

    typedef struct {
        uint32_t start;
        uint32_t end;
    } interval;

    const interval monitor_sockets_interval = {0, cl.count_ip - 1};
    const interval spoofing_sockets_interval = {cl.count_ip, cl.count_ip * 2 - 1};
    const uint32_t any_traffic_socket_id = cl.count_ip * 2;
    const uint32_t master_notify_socket_id = cl.count_ip * 2 + 1;
    const uint32_t monitor_and_spoof_socket_count = 2 * cl.count_ip;
    const uint32_t total_socket_count_id = monitor_and_spoof_socket_count + 2;

    //Array: size = [2 * count(IP provided) + 2 (ARP/NA sniffer & Master Notify)]
    //[fd(monitor1), fd(monitor2), ..., fd(spoofingIP1), fd(spoofingIP2), ..., fd(ARP/NA), fd(Notify)]
    struct pollfd *fds = malloc(total_socket_count_id * sizeof(struct pollfd));

    if(fds == NULL)
    {
        notify_master_thread(manager, main_client_args.wakupator_code, WK_OUT_OF_MEMORY);
        return NULL;
    }

    uint32_t skipped_creation = 0;

    // -------------- Create Monitoring sockets --------------
    // Which capture traffic designate to IP and port asked by the client.
    for (uint32_t i = 0; i < cl.count_ip; ++i) {
        const ip_port_info *info = &cl.ip_port_info[i];

        if (info->port_count == 0)
        {
            fds[i].fd = -1;
            fds[i].events = 0;
            fds[i].revents = 0;
            skipped_creation++;
            LOG_DEBUG("%s: Monitor raw socket disable for IP %s (no port provided).\n", client_header, info->ip_str, info->port_count);
            continue;
        }

        const int sock = create_raw_socket_filtered_ip_port(manager->if_index, info);

        if(sock == -1) //Error
        {
            for (uint32_t k = 0; k < i; ++k)
                close(fds[k].fd);

            free(fds);
            notify_master_thread(manager, main_client_args.wakupator_code, WK_MONITOR_RAW_SOCKET_MONITORING_CREATION_ERROR);

            return NULL;
        }

        fds[i].fd = sock;
        fds[i].events = POLLIN;

        LOG_DEBUG("%s: Monitor raw socket created for IP %s and %d port(s) provided.\n", client_header, info->ip_str, info->port_count);
    }

    LOG_DEBUG("%s: %d raw sockets created for monitoring. (%d IP(s) without ports provided)\n", client_header, cl.count_ip, skipped_creation);

    // -------------- Create Spoofing socket --------------
    // Which capture ARP Request and NS traffic designate to IP
    for (uint32_t i = cl.count_ip; i < 2*cl.count_ip; ++i) {
        const ip_port_info *info = &cl.ip_port_info[i-cl.count_ip];

        if (info->ip_format == AF_INET)
        {
            const int sock = create_raw_socket_arp_request(manager->if_index, info->ipv4, manager->if_mac_raw);

            if(sock == -1) //Error
            {
                for (uint32_t k = 0; k < i; ++k)
                    if (fds[k].fd != -1)
                        close(fds[k].fd);

                free(fds);
                notify_master_thread(manager, main_client_args.wakupator_code, WK_MONITOR_RAW_SOCKET_SPOOFING_CREATION_ERROR);
                return NULL;
            }

            fds[i].fd = sock;
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }
        else
        {
            const int sock = create_raw_socket_ns_request(manager->if_index, info->ipv6, manager->if_mac_raw);

            if(sock == -1) //Error
            {
                for (uint32_t k = 0; k < i; ++k)
                    if (fds[k].fd != -1)
                        close(fds[k].fd);

                free(fds);
                notify_master_thread(manager, main_client_args.wakupator_code, WK_MONITOR_RAW_SOCKET_SPOOFING_CREATION_ERROR);
                return NULL;
            }

            fds[i].fd = sock;
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }

        LOG_DEBUG("%s: Spoofing raw socket created for IP %s.\n", client_header, info->ip_str, info->port_count);

    }

    //-------------- Create Any Traffic socket --------------
    //Create a raw socket to detect any activity from the target interface.
    //(ARP/NA and all others)
    const int sock = create_raw_socket_any_traffic_from_mac(cl.mac_raw);

    if(sock == -1) //Error
    {
        for (uint32_t k = 0; k < 2*cl.count_ip; ++k)
            if (fds[k].fd != -1)
                close(fds[k].fd);

        free(fds);

        notify_master_thread(manager, main_client_args.wakupator_code, WK_MONITOR_RAW_SOCKET_ANY_TRAFFIC_CREATION_ERROR);
        return NULL;
    }

    fds[any_traffic_socket_id].fd = sock;
    fds[any_traffic_socket_id].events = POLLIN;

    LOG_DEBUG("%s: Any traffic raw socket created for %s\n", client_header, cl.mac_str);

    //-------------- Adding Master's Notification pipe --------------
    //Adding at the last the pipe for handling master's notification (when main process shutdown)
    fds[master_notify_socket_id].fd = manager->notify[0];
    fds[master_notify_socket_id].events = POLLIN;

    LOG_DEBUG("%s: Added master notify pipe to the pool\n", client_header);

    // --------------------------------- Notify the master that everything is OK -------------------------------------
    LOG_DEBUG("%s: Notify the master thread that everything is OK.\n", client_header);

    notify_master_thread(manager, main_client_args.wakupator_code, WK_OK);

    sleep(1);

    // ------------------------------------ Waiting the machine to turn off ------------------------------------------
    // We pick the first IP provided, and use it to probe the neighborhood, the reply is capture by the Any traffic
    //socket, meaning the machine is still on.
    log_info("%s: Waiting for the machine to stop completely before proceeding with the monitoring...\n",
                    client_header);

    const ip_port_info *client_target_ip = &cl.ip_port_info[0];

    log_info("%s: Using the IP %s as representative to check if the machine is off.\n",
                    client_header, client_target_ip->ip_str);

    const uint32_t max_shutdown_probe = manager->shutdown_timeout / manager->shutdown_probe_interval;

    struct timespec start, end;
    char str_time_buffer[64];

    int nb_shutdown_attempt = 1;
    int fd_poll_result = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);

    do
    {
        sleep(manager->shutdown_probe_interval);

        //Clear the "any traffic" socket
        clear_socket(fds[any_traffic_socket_id].fd);

        if (client_target_ip->ip_format == AF_INET)
        {
            if (send_arp_probe(manager->main_raw_socket, manager->if_mac_raw, client_target_ip->ipv4))
            {
                log_fatal("%s: Error sending ARP packet, Wakupator could not verify the response.\n", client_header);
                continue;
            }

            log_info("%s: ARP Request sent to %s. (#%d)\n", client_header, client_target_ip->ip_str, nb_shutdown_attempt);
        }
        else
        {
            if (send_ndp_ns(manager->main_raw_socket, manager->if_mac_raw, &manager->if_ipv6_link_local,
                &client_target_ip->ipv6))
            {
                log_fatal("%s: Error sending ICMPv6 NS Request, Wakupator could not verify the response.\n", client_header);
                continue;
            }

            log_info("%s: ICMPv6 NS Request sent to %s. (#%d)\n", client_header, client_target_ip->ip_str, nb_shutdown_attempt);
        }

        nb_shutdown_attempt++;

        //Waiting for "any traffic" socket activity
        fd_poll_result = poll(&fds[any_traffic_socket_id], 1, (int) manager->shutdown_probe_interval * 1000);

        if (fd_poll_result > 0) {
            log_info("%s: Got a reply from the request. Retry in %ds.\n",
                            client_header, manager->shutdown_probe_interval);
        }
        else if (fd_poll_result == 0)
            break;
        else {
            //res == -1 -> error, using nbShutdownAttempt to propagate the error
            nb_shutdown_attempt = -1;
            break;
        }
    }while(nb_shutdown_attempt <= max_shutdown_probe);

    // ----------------------------------------- Result from waiting -------------------------------------------------

    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t time_elapsed = (uint64_t) (end.tv_sec - start.tv_sec);

    //timeout
    if (nb_shutdown_attempt == max_shutdown_probe)
    {
        log_error("%s: The machine still appears to be powered on, canceling the IP address spoofing and "
                  "monitoring. If needed, you can increase maximum time with -st|--shutdown-timeout <time in s>.\n", client_header);
    }
    //Error while polling
    else if (nb_shutdown_attempt == -1)
    {
        log_fatal("%s: A fatal error occurred while polling the ARP/NS responses. IP spoofing and monitoring "
            "has been cancelled.", client_header);
    }
    // ------------------------------------------- Start Monitoring --------------------------------------------------
    else
    {
        format_duration_hms(time_elapsed, str_time_buffer, sizeof(str_time_buffer));
        log_info("%s: The machine seems to be off in approximately %s.\n", client_header, str_time_buffer);
        log_info("%s: Start spoofing and monitoring IP addresses.\n", client_header);

        unsigned char packet[256];

        clock_gettime(CLOCK_MONOTONIC, &start);
        cl.time_started = start.tv_sec;
        // ----------- Spoofing IPs -----------
        setup_spoofing_for_client(manager, &cl);

        char monitoring = 1;

        while (monitoring)
        {
            //-------------------- Clear the "any traffic" socket --------------------
            while (recv(fds[any_traffic_socket_id].fd, packet, sizeof(packet), MSG_DONTWAIT) > 0) {}

            //Waiting traffic on any socket
            poll(fds, total_socket_count_id, -1);

            // ----------------------------------- Activity on at least one socket -----------------------------------

            //----------- Notification from master ------------
            if(fds[master_notify_socket_id].revents == POLLIN)
            {
                //If the "traffic" is the master's notification, send only one WoL, and stop the thread.
                //We can't do a clean wake-up, because some system waits for the main thread to stop "quickly".
                log_info("%s: Notification receive from main thread.\n", client_header);
                log_info("%s: Wake-On-Lan sent.\n", client_header);
                send_wake_on_lan(manager->main_raw_socket, manager->if_mac_raw, cl.mac_raw);
                monitoring = 0;
            }
            //----------- "Any traffic" from the MAC (GARP, NA etc) ------------
            else if(fds[any_traffic_socket_id].revents == POLLIN)
            {
                log_info("%s: the machine has been started manually.\n", client_header);
                monitoring = 0;
            }
            //----------- Monitored traffic OR spoofing socket ------------
            else
            {
                int fd_index = -1;

                for (int i = 0; i < monitor_and_spoof_socket_count; i++) {
                    if (fds[i].revents & POLLIN) {
                        fd_index = i;
                        break;
                    }
                }

                const uint32_t ip_info_index = fd_index%cl.count_ip;

                // ---------  Traffic captured by monitor socket -----------
                if (fd_index >= monitor_sockets_interval.start && fd_index <= monitor_sockets_interval.end)
                {
                    int nb_wol_attempt = 1;
                    log_info("%s: traffic detected.\n", client_header);

                    // -- print packet info (IP src & dst, and port)
                    //TODO rendre plus lisible
                    struct sockaddr_ll source_addr;
                    socklen_t source_addr_length = sizeof(source_addr);

                    const ssize_t packet_size = recvfrom(fds[fd_index].fd, packet, sizeof(packet), 0,
                                                   (struct sockaddr *)&source_addr, &source_addr_length);
                    if (packet_size > 0)
                    {
                        const char* packet_info = print_ip_packet_info(packet, packet_size);

                        if (packet_info) {
                            log_info("%s: Packet Info: %s.\n", client_header, packet_info);
                            free((void*) packet_info);
                        }
                    }

                    clock_gettime(CLOCK_MONOTONIC, &start);
                    int machine_started = 0;

                    //Attempt a Wake On LAN, and wait the machine to start
                    do
                    {

                        //Attempt a WoL
                        if (send_wake_on_lan(manager->main_raw_socket, manager->if_mac_raw,cl.mac_raw))
                        {
                            log_fatal("%s: Error sending the WoL packet, the machine could not start.\n", client_header);
                            nb_wol_attempt++;
                            continue;
                        }

                        log_info("%s: Wake-On-Lan sent. (#%d)\n", client_header, nb_wol_attempt);
                        nb_wol_attempt++;

                        //We continue to reply to ARP/NS probe while starting the machine (it avoid stalled neighbor resolution when others machines probe while the starting process)
                        //+ "any traffic" activity, meaning the machine is successfully started.
                        //+ Master thread notification. (if wakupator is shutting down while the wake-up process)

                        const int64_t deadline_ms = now_ms() + (int64_t) manager->wol_delay * 1000;
                        int remaining_delay_wol = (int) manager->wol_delay * 1000;

                        while (remaining_delay_wol > 0)
                        {
                            fd_poll_result = poll(&fds[spoofing_sockets_interval.start], cl.count_ip + 2, remaining_delay_wol);

                            if (fd_poll_result > 0)
                            {
                                int fd_id = -1;
                                //Reverse lookup to prioritize "Any Socket" traffic rather than ARP/NS traffic
                                for (uint32_t i = total_socket_count_id-1; i >= spoofing_sockets_interval.start; i--) {
                                    if (fds[i].revents & POLLIN) {
                                        fd_id = (int) i;
                                        break;
                                    }
                                }
                                //If we receive anything from the machine, that means that the machine is up!
                                if (fd_id == any_traffic_socket_id) {
                                    machine_started = 1;
                                    break;
                                }

                                if (fd_id == master_notify_socket_id) {
                                    machine_started = -1;
                                    break;
                                }

                                LOG_DEBUG("%s: Activity captured while starting the machine. (fd_id=%d).\n", client_header, fd_id);

                                const uint32_t ip_info_id = fd_id%cl.count_ip;
                                const wakupator_code reply_code = reply_to_probe(manager, fds[fd_id].fd, &cl.ip_port_info[ip_info_id]);

                                if (reply_code == WK_MONITOR_ARP_REPLY_ERROR)
                                    log_error("%s: Error while replying to ARP request for %s.\n", client_header, cl.ip_port_info[ip_info_id].ip_str);
                                else if (reply_code == WK_MONITOR_NS_REPLY_ERROR)
                                    log_error("%s: Error while replying to NS for %s.\n", client_header,cl.ip_port_info[ip_info_id].ip_str);

                            }
                            remaining_delay_wol = (int) (deadline_ms - now_ms());
                        }

                        LOG_DEBUG("%s: WoL delay exceeds.\n", client_header);

                    }while(nb_wol_attempt <= manager->wol_max_attempts && machine_started == 0);

                    clock_gettime(CLOCK_MONOTONIC, &end);
                    time_elapsed = (uint64_t) (end.tv_sec - start.tv_sec);
                    format_duration_hms(time_elapsed, str_time_buffer, sizeof(str_time_buffer));

                    switch (machine_started) {
                        case -1: {
                                log_info("%s: Got a master thread notification while woken up client machine after %d WoL, aborting. (%s)\n", client_header, nb_wol_attempt, str_time_buffer);
                                monitoring = 0;
                            }
                            break;
                        //The machine isn't started despite the wake-up processing
                        case 0: {
                            if(manager->wol_keep_client == 1)
                            {
                                //Clear the socket to avoid to reply to any tcp retransmission
                                clear_socket(fds[ip_info_index].fd);
                                log_info("%s: the client machine doesn't appear to have started after %d attempts, monitoring resumes. (%s)\n", client_header, manager->wol_max_attempts, str_time_buffer);
                            }else
                            {
                                log_info("%s: the client machine doesn't appear to have started after %d attempts. (%s)\n", client_header, manager->wol_max_attempts, str_time_buffer);
                                monitoring = 0;
                            }
                            break;
                        }
                        case 1: {
                            log_info("%s: the client machine has been started successfully. (%s)\n", client_header, str_time_buffer);
                            monitoring = 0;
                        }
                            break;
                        default: ;
                    }
                }
                // ----- Traffic captured by spoofing socket (ARP/NS) -----
                else if (fd_index >= spoofing_sockets_interval.start && fd_index <= spoofing_sockets_interval.end)
                {

                    const wakupator_code reply_code = reply_to_probe(manager, fds[fd_index].fd, &cl.ip_port_info[ip_info_index]);

                    if (reply_code == WK_MONITOR_ARP_REPLY_ERROR)
                        log_error("%s: Error while replying to ARP request for %s.\n", client_header, cl.ip_port_info[ip_info_index].ip_str);
                    else if (reply_code == WK_MONITOR_NS_REPLY_ERROR)
                        log_error("%s: Error while replying to NS for %s.\n", client_header,cl.ip_port_info[ip_info_index].ip_str);
                }
                //Invalid fd index
                else
                {
                    LOG_DEBUG("%s: Invalid fd index from the poll. Got %d, max: %d\n", client_header, fd_index, total_socket_count_id);
                }
            }

        }//Monitoring loop

    }
    // --------------------------------------- Cleaning all resources ------------------------------------------------

    unset_spoofing_for_client(manager, &cl);

    //Close all sockets created (but not the Master Notify)
    for (int i = 0; i < total_socket_count_id - 1; ++i) {
        close(fds[i].fd);
    }

    unregister_client(manager, cl.mac_str);
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_elapsed = (uint64_t) end.tv_sec - cl.time_started;
    format_duration_hms(time_elapsed, str_time_buffer, sizeof(str_time_buffer));

    if(nb_shutdown_attempt != max_shutdown_probe)
        log_info("%s: Has been removed from monitoring. Total monitoring duration: %s\n", client_header, str_time_buffer);

    free(fds);
    return NULL;
}

void setup_spoofing_for_client(manager *manager, const client *cl)
{
    for (int i = 0; i < cl->count_ip; ++i) {
        modify_route(manager->if_index, cl->ip_port_info[i].ip_str, IP_OP_ADD);
        modify_neighbor(manager->if_index, cl->ip_port_info[i].ip_str, cl->mac_raw, IP_OP_ADD);
        if (cl->ip_port_info[i].ip_format == AF_INET6)
            add_mld_member(manager, cl->ip_port_info[i].ipv6);
    }
}

void unset_spoofing_for_client(manager *manager, const client *cl)
{
    for (int i = 0; i < cl->count_ip; ++i) {
        modify_route(manager->if_index, cl->ip_port_info[i].ip_str, IP_OP_REMOVE);
        modify_neighbor(manager->if_index, cl->ip_port_info[i].ip_str, cl->mac_raw, IP_OP_REMOVE);
        if (cl->ip_port_info[i].ip_format == AF_INET6)
            remove_mld_member(manager, cl->ip_port_info[i].ipv6);
    }
}
