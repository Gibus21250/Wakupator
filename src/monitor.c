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
#include "logger.h"

void *main_client_monitoring(void* args)
{

    main_client_args *mainClientArgs = (main_client_args*) args;
    struct manager *manager = mainClientArgs->managerMain;

    //Shallow copy of the client
    struct client cl = *mainClientArgs->client;

    log_debug("Init monitor thread for %s\n", cl.mac);

    //Manually verify IP
    int code = verify_ips(&cl);
    if(code != OK)
    {
        pthread_mutex_lock(mainClientArgs->notify);
        mainClientArgs->error = code;
        pthread_cond_signal(mainClientArgs->cond);
        pthread_mutex_unlock(mainClientArgs->notify);
        return NULL;
    }

    //+1 to handle notify on the pipe output of the master thread
    struct pollfd *fds = (struct pollfd*) calloc(cl.countIp + 1, sizeof(struct pollfd));

    if(fds == NULL)
    {
        pthread_mutex_lock(mainClientArgs->notify);
        mainClientArgs->error = OUT_OF_MEMORY;
        pthread_cond_signal(mainClientArgs->cond);
        pthread_mutex_unlock(mainClientArgs->notify);
        return NULL;
    }

    //Verify that all IP asked are not already assigned on the host

    char cmd[256];

    uint32_t nbSockCreated = 0;

    //Create all socket needed: on per group IP/ports
    for (uint32_t i = 0; i < cl.countIp; ++i) {
        ip_port_info *info = &cl.ipPortInfo[i];

        int sock = create_raw_filter_socket(info);

        if(sock == -1) //Error
        {
            for (uint32_t k = 0; k < nbSockCreated; ++k)
                close(fds[k].fd);

            pthread_mutex_lock(mainClientArgs->notify);
            mainClientArgs->error = MONITOR_RAW_SOCKET_CREATION_ERROR;
            pthread_cond_signal(mainClientArgs->cond);
            pthread_mutex_unlock(mainClientArgs->notify);
            free(fds);
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
    mainClientArgs->error = OK;
    pthread_mutex_unlock(mainClientArgs->notify);

    //------------ Waiting notify to start spoofing and monitoring ------------

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 10;

    //Wait a notification from the child thread, and this can time out
    //This call implicit atomically unlock the mutex, and lock it again after execution
    if(pthread_cond_timedwait(mainClientArgs->selfCond, mainClientArgs->selfNotify, &timeout))
    {
        free(fds);
        return NULL;
    }

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv6.conf.%s.accept_dad=0 > /dev/null 2>&1", manager->itName);
    system(cmd);

    //Assign IP off client on the host
    for (int j = 0; j < cl.countIp; ++j) {
        snprintf(cmd, sizeof(cmd), "ip a add %s dev %s", cl.ipPortInfo[j].ipStr, manager->itName);
        system(cmd);
    }

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv6.conf.%s.accept_dad=1 > /dev/null 2>&1", manager->itName);
    system(cmd);


    //------------ Waiting for traffic ------------

    log_debug("%s thread: Waiting for network activity.\n", cl.mac);
    poll(fds, nbSockCreated+1, -1); //Waiting traffic
    wake_up(manager->mainRawSocket, manager->ifIndex,cl.mac); //Wake up the dst!

    log_info("Client %s: traffic detected, woken up.\n", cl.mac);

    //remove all IP spoofed
    for (int j = 0; j < cl.countIp; ++j) {
        if(cl.ipPortInfo[j].ipFormat == AF_INET6)
            snprintf(cmd, sizeof(cmd), "ip a del %s/128 dev %s", cl.ipPortInfo[j].ipStr, manager->itName);
        else
            snprintf(cmd, sizeof(cmd), "ip a del %s/32 dev %s", cl.ipPortInfo[j].ipStr, manager->itName);

        system(cmd);
    }

    unregister_client(manager, cl.mac);

    free(fds);
    destroy_client(&cl);
    return NULL;
}

int verify_ips(const client *cl)
{
    char buffer[128];
    FILE *fp;

    for (int i = 0; i < cl->countIp; ++i) {

        snprintf(buffer, sizeof(buffer), "ip a | grep -w %s", cl->ipPortInfo[i].ipStr);

        fp = popen(buffer, "r");
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