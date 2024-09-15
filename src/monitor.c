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

#include "utils.h"
#include "monitor.h"
#include "bpf_utils.h"

void *main_client_monitoring(void* args)
{

    main_client_args *mainClientArgs = (main_client_args*) args;
    struct manager *manager = mainClientArgs->managerMain;

    //Shallow copy of the client
    struct client cl = *mainClientArgs->client;

    printf("Thread Start to monitor %s\n", cl.mac);

    //+1 to handle notify on the pipe output of the master thread
    struct pollfd *fds = (struct pollfd*) calloc(cl.countIp + 1, sizeof(struct pollfd));

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
    for (uint32_t i = 0; i < cl.countIp; ++i) {
        ip_port_info *info = &cl.ipPortInfo[i];

        int sock = create_raw_filter_socket(info);

        if(sock == -1) //Error
        {
            for (uint32_t k = 0; k < nbSockCreated; ++k) {
                close(fds[k].fd);
                snprintf(cmd, sizeof(cmd), "ip a del %s dev eth0", cl.ipPortInfo[k].ipStr);
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
                snprintf(cmd, sizeof(cmd), "ip a del %s dev eth0", cl.ipPortInfo[k].ipStr);
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

    //Adding at the last the pipe for handling master notification (close socket from a pollfd seems to not unlock the thread)
    fds[nbSockCreated].fd = manager->notify[0];
    fds[nbSockCreated].events = POLLIN;

    //------------ Notify the master that everything is OK ------------
    pthread_mutex_lock(mainClientArgs->notify);
    pthread_cond_signal(mainClientArgs->cond);
    pthread_mutex_unlock(mainClientArgs->notify);

    printf("%s thread: Waiting for network activity.\n", cl.mac);
    poll(fds, nbSockCreated+1, -1);
    wake_up(manager->mainRawSocket, manager->ifIndex,cl.mac); //Wake up the dst!

    printf("%s thread: network activity detected.\n", cl.mac);
    printf("Client %s has been woke up\n", cl.mac);

    for (int i = 0; i < nbSockCreated; ++i)
    {

    }
    }

    unregister_client(manager, cl.mac);

    free(fds);
    destroy_client(&cl);
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

    //Sometimes, the time between socket creation and applying the filter, can catch some packets
    char buffer[2048];
    ssize_t len;

    //Clear if necessary
    while ((len = recv(rawSocket, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0);

    //Check if different error code returner
    if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        close(rawSocket);
        return -1;
    }

    return rawSocket;
}

void wake_up(const int rawSocket, const int ifIndex, const char *macStr)
{
    char frame[ETH_HLEN + 102];
    memset(frame, 0, ETH_HLEN + 102);

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

    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = ifIndex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, eth->h_dest, 6);

    //Now send the packet through the lan
    if (sendto(rawSocket, frame, sizeof(frame), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("Error while sending the WoL packet.");
    }
}

    close(rawSocket);
}

void redirect_packet(void* packet, const char *macStr)
{

}