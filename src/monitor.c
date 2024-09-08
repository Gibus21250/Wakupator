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
#include <sys/ioctl.h>

#include <netpacket/packet.h>
#include <net/if.h>
#include <errno.h>

#include "utils.h"
#include "monitor.h"
#include "bpf_utils.h"

void *main_client_monitoring(void* args)
{

    struct ethhdr *eth;
    struct iphdr *ip;
    struct ip6_hdr *ip6;
    struct tcphdr *tcp;

    main_client_args *mainClientArgs = (main_client_args*) args;
    struct managed_client *managedClient = mainClientArgs->managedClient;
    struct client* cl = mainClientArgs->client;

    printf("Thread Start to monitor %s\n", cl->mac);

    struct pollfd *fds = (struct pollfd*) calloc(cl->countIp, sizeof(struct pollfd));

    if(fds == NULL)
    {
        pthread_mutex_lock(mainClientArgs->notify);
        mainClientArgs->error = 1;
        pthread_cond_signal(mainClientArgs->cond);
        pthread_mutex_unlock(mainClientArgs->notify);
        return NULL;
    }

    char cmd[256];

    uint32_t nbSockCreated = 0;

    //Create all socket needed: on per group IP/ports
    for (uint32_t i = 0; i < cl->countIp; ++i) {
        ip_port_info *info = &cl->ipPortInfo[i];

        int sock = create_raw_filter_socket(info);
        if(sock == -1) //Error
        {
            for (uint32_t k = 0; k < nbSockCreated; ++k) {
                close(fds[k].fd);
            }
            pthread_mutex_lock(mainClientArgs->notify);
            mainClientArgs->error = 1;
            pthread_cond_signal(mainClientArgs->cond);
            pthread_mutex_unlock(mainClientArgs->notify);
            free(fds);
            return NULL;
        }
        //Adding the IP to the host
        snprintf(cmd, sizeof(cmd), "ip a add %s dev eth0", info->ipStr);

        if(system(cmd))
        {
            for (uint32_t k = 0; k < nbSockCreated; ++k) {
                close(fds[k].fd);
                snprintf(cmd, sizeof(cmd), "ip a del %s dev eth0", cl->ipPortInfo[i].ipStr);
            }
            pthread_mutex_lock(mainClientArgs->notify);
            mainClientArgs->error = 1;
            pthread_cond_signal(mainClientArgs->cond);
            pthread_mutex_unlock(mainClientArgs->notify);
            free(fds);
            //IP is already used, of other reason
            return NULL;
        }

        fds[nbSockCreated].fd = sock;
        fds[nbSockCreated].events = POLLIN;

        nbSockCreated++;

    }

    //Notify the master that everything is OK
    pthread_mutex_lock(mainClientArgs->notify);
    pthread_cond_signal(mainClientArgs->cond);
    pthread_mutex_unlock(mainClientArgs->notify);

    printf("Thread Waiting for network activity on %s\n", cl->mac);
    int ret = poll(fds, nbSockCreated, -1);

    //Error while waiting for network activity (example: closed socket bc shut down asked)
    if(ret < 0)
    {
        ret = errno;
        if(ret != POLLNVAL)
        {
            for (uint32_t k = 0; k < nbSockCreated; ++k) {
                close(fds[k].fd);
            }
        }
        //TODO modifier wake_up to create his own
        unregister_client(managedClient, cl->mac);
        return NULL;
    }

    for (int i = 0; i < nbSockCreated; i++) {
        if (fds[i].revents & POLLIN)
        {
            wake_up(cl->mac); //Wake up the dst!

            char buffer[1024];
            ssize_t bytes = recv(fds[i].fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes > 0) {
                // Pointer vers l'en-tête Ethernet
                eth = (struct ethhdr *)buffer;

                // Pointer vers l'en-tête IPv6 (couche 3)
                ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
                //ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

                // Pointer vers l'en-tête TCP (couche 4)
                tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

                // Afficher les détails du paquet
                print_packet_details_ipv6(eth, ip6, tcp);

                printf("New Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       eth->h_source[0], eth->h_source[1], eth->h_source[2],
                       eth->h_source[3], eth->h_source[4], eth->h_source[5]);

                printf("New Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                       eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
            } else if (bytes != 0) {
                printf("Connection closed.\n");
                close(fds[i].fd);
            } else {
                perror("recv failed");
            }
        }
    }


    for (int i = 0; i < nbSockCreated; ++i)
    {
        close(fds[i].fd);
        snprintf(cmd, sizeof(cmd), "ip a del %s dev eth0", cl->ipPortInfo[i].ipStr);
        system(cmd);
    }

    unregister_client(managedClient, cl->mac);

    free(fds);
    return NULL;
}

int create_raw_filter_socket(const ip_port_info *ipPortInfo)
{
    uint16_t etherType = ipPortInfo->ipFormat == AF_INET ? ETH_P_IP : ETH_P_IPV6;

    //Generate and prepare BPF asm for the kernel

    struct sock_filter *bpf_code = (struct sock_filter*) calloc(100, sizeof(struct sock_filter));

    uint32_t raw_ip[4];

    if(inet_pton((int) ipPortInfo->ipFormat, ipPortInfo->ipStr, raw_ip) != 1)
    {
        perror("inet_pton");
        free(bpf_code);
        return -1;
    }

    uint32_t codeSize = 0;
    //codeSize = filter_ether(bpf_code, codeSize, ETH_P_IPV6);

    if(etherType == ETH_P_IP)
        codeSize = filter_ipv4(bpf_code, codeSize, raw_ip[0], 14);
    else
        codeSize = filter_ipv6(bpf_code, codeSize, raw_ip, 14);

    codeSize = filter_protocol(bpf_code, codeSize, IPPROTO_TCP, ipPortInfo->ipFormat, 14);
    codeSize = filter_ports(bpf_code, codeSize, ipPortInfo->ports, ipPortInfo->portCount, 14 + (ipPortInfo->ipFormat==AF_INET?20:40));
    bpf_code[codeSize++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, -1); // last instr

    struct sock_fprog bpf = {
            .len = codeSize,
            .filter = bpf_code
    };

    int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(etherType));

    if(rawSocket == -1)
        return -1;

    // Apply BPF filter to the socket
    if (setsockopt(rawSocket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        perror("setsockopt");
        close(rawSocket);
        return -1;
    }

    free(bpf_code);

    return rawSocket;
}

void wake_up(const char *macStr)
{
    char frame[ETH_HLEN + 102];
    memset(frame, 0, ETH_HLEN + 102);

    unsigned char mac_bytes[6];
    sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);

    struct ethhdr *eth = (struct ethhdr *) frame;

    memcpy(&eth->h_dest, mac_bytes, 6);
    eth->h_proto = htons(0x0842);

    memset(frame + ETH_HLEN, 0xFF, 6);

    for (int i = 1; i <= 16; i++) {
        memcpy(frame + ETH_HLEN + i * 6, mac_bytes, 6);
    }
    //TODO handle failed
    //Now create a one use raw socket, a raw socket, who receive nothing (proto = 0)
    int rawSocket = socket(PF_PACKET, SOCK_RAW, 0);


    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    if (ioctl(rawSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror("Erreur lors de la récupération de l'index de l'interface");
        close(rawSocket);
        return;
    }

    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = ifr.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, eth->h_dest, 6);

    //Now send the packet through the lan
    if (sendto(rawSocket, frame, sizeof(frame), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("Erreur lors de l'envoi de la trame Ethernet");

    } else {
        printf("Paquet magique envoyé avec succès sur l'interface eth0.\n");
    }
    close(rawSocket);
}

void redirect_packet(void* packet, const char *macStr)
{

}

const char* get_monitor_error(CLIENT_MONITORING_CODE code)
{
    switch (code)
    {
        case MONITORING_OK: return "OK.";
        case MONITORING_MAC_ADDRESS_ALREADY_MONITORED: return "A client with this MAC address is already monitored.";
        case MONITORING_THREAD_CREATION_ERROR: return "Intern error while creating thread monitor.";
        case MONITORING_THREAD_INIT_ERROR: return "Error while init information for the thread monitor.";
    }
}