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

    //Verify that all IP asked are not already assigned on the host
    int code = verify_ips(&cl);

    if(code != OK)
    {
        pthread_mutex_lock(mainClientArgs->notify);
        mainClientArgs->error = code;
        pthread_cond_signal(mainClientArgs->cond);
        pthread_mutex_unlock(mainClientArgs->notify);
        return NULL;
    }

    //Structure pollfd   + 2
    //[fdIP1, fdIP2, ..., fdARP/NS, fdNotify]
    struct pollfd *fds = (struct pollfd*) calloc(cl.countIp + 2, sizeof(struct pollfd));

    if(fds == NULL)
    {
        pthread_mutex_lock(mainClientArgs->notify);
        mainClientArgs->error = OUT_OF_MEMORY;
        pthread_cond_signal(mainClientArgs->cond);
        pthread_mutex_unlock(mainClientArgs->notify);
        return NULL;
    }

    char cmd[256];

    uint32_t nbSockCreated = 0;

    //Create all socket needed: on per group IP/ports
    for (uint32_t i = 0; i < cl.countIp; ++i) {
        ip_port_info *info = &cl.ipPortInfo[i];

        int sock = create_raw_filtered_socket(info);

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

    //Create a raw socket to detect if the client has been started manually
    fds[nbSockCreated].fd = create_raw_socket_arp_ns(cl.mac);
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    //Adding at the last the pipe for handling master notification (close socket from a pollfd seems to not unlock the thread)
    fds[nbSockCreated].fd = manager->notify[0];
    fds[nbSockCreated].events = POLLIN;
    nbSockCreated++;

    //------------ Notify the master that everything is OK ------------
    pthread_mutex_lock(mainClientArgs->notify);
    pthread_cond_signal(mainClientArgs->cond);
    mainClientArgs->error = OK;
    pthread_mutex_unlock(mainClientArgs->notify);

    //------------ Waiting notify from master to start spoofing and monitoring ------------

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 10;

    //Wait a notification from the child thread, and this can time out
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

    sleep(1);

    //----------- Clear the raw socket for ARP and NS detection -----------
    while ((recv(fds[nbSockCreated-2].fd, cmd, sizeof(cmd), MSG_DONTWAIT)) > 0);
    //------------ Waiting for traffic ------------

    log_info("Client [%s]: Monitoring started.\n", cl.mac);
    poll(fds, nbSockCreated, -1); //Waiting traffic

    //Wake up the machine
    wake_up(manager->mainRawSocket, manager->ifIndex,cl.mac);


    if(fds[nbSockCreated-2].revents == POLLIN)
        log_info("Client [%s]: the machine appears to have been started manually.\n", cl.mac);
    else
        log_info("Client [%s]: traffic detected, it was woken up.\n", cl.mac);


    //remove all IP spoofed
    for (int i = 0; i < cl.countIp; ++i) {
        if(cl.ipPortInfo[i].ipFormat == AF_INET6)
            snprintf(cmd, sizeof(cmd), "ip a del %s/128 dev %s", cl.ipPortInfo[i].ipStr, manager->itName);
        else
            snprintf(cmd, sizeof(cmd), "ip a del %s/32 dev %s", cl.ipPortInfo[i].ipStr, manager->itName);

        system(cmd);
        close(fds[i].fd);//Close the associated socket
    }

    //Close the raw socket for ARP/NS
    close(fds[nbSockCreated-1].fd);

    unregister_client(manager, cl.mac);

    free(fds);
    destroy_client(&cl);
    return NULL;
}

int verify_ips(const client *cl)
{
    char cmd[128];
    char buffer[1024];
    FILE *fp;

    for (int i = 0; i < cl->countIp; ++i) {


    snprintf(cmd, sizeof(cmd), "ip a | grep -w %s", cl->ipPortInfo->ipStr);

    fp = popen(cmd, "r");
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
    int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

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

    struct sock_filter *bpf_code = (struct sock_filter*) calloc(10, sizeof(struct sock_filter));

    if(bpf_code == NULL)
    {
        close(rawSocket);
        log_error("Error while creating the BPF prog");
        return -1;
    }


    uint32_t codeSize = 0;
    codeSize = filter_mac(bpf_code, codeSize, macRaw);
    bpf_code[codeSize++] = (struct sock_filter) BPF_STMT(BPF_RET + BPF_K, -1); // Accept

    struct sock_fprog bpf = {
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
    uint16_t etherType = ipPortInfo->ipFormat == AF_INET ? ETH_P_IP : ETH_P_IPV6;

    int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(etherType));

    if(rawSocket == -1)
        return -1;

    struct sock_fprog bpf = create_bpf_filter(ipPortInfo);

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
    char buffer[2048];
    ssize_t len;

    //Clear if necessary
    while ((len = recv(rawSocket, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0);

    //Check if different error code returner
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

    struct sock_filter *bpf_code = (struct sock_filter*) calloc(100, sizeof(struct sock_filter));

    if(bpf_code == NULL)
    {
        return res;
    }

    uint16_t etherType = ipPortInfo->ipFormat == AF_INET ? ETH_P_IP : ETH_P_IPV6;

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