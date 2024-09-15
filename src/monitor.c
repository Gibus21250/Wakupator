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

    char originalPacket[128];
    memset(&originalPacket, 0, 128);

    int size = 0;
    int trueTraffic = 0;
    //Remove all ip spoofed
    for (int i = 0; i < nbSockCreated; ++i)
    {
        if(fds[i].fd != -1)
        {
            if(fds[i].revents & POLLIN)
        {
            size = read(fds[i].fd, &originalPacket, 128);
            trueTraffic = 1;
        }
            close(fds[i].fd);
        }
        
        snprintf(cmd, sizeof(cmd), "ip a del %s dev eth0", cl.ipPortInfo[i].ipStr);
        system(cmd);

    }

    if(trueTraffic)
    {
        char copyPacket[128];
        memcpy(&copyPacket, originalPacket, 128);

        //Now sleep 10s
        sleep(10);

        for (int i = 0; i < nbSockCreated; ++i)
        {
            snprintf(cmd, sizeof(cmd), "ip a del %s dev eth0", cl.ipPortInfo[i].ipStr);
            system(cmd);
        }

        pthread_mutex_lock(&manager->lock);
        reply_syn_ack_ipv6(manager->mainRawSocket, manager->ifIndex, copyPacket, size);
        pthread_mutex_unlock(&manager->lock);


        sleep(10);

        pthread_mutex_lock(&manager->lock);
        struct sockaddr_ll sa;
        memset(&sa, 0, sizeof(struct sockaddr_ll));

        struct ethhdr *eth = (struct ethhdr *) originalPacket;

        sa.sll_ifindex = manager->ifIndex;
        sa.sll_halen = ETH_ALEN;
        memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);

        if (sendto(manager->mainRawSocket, originalPacket, size, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("Impossible to reply SYN ACK");
        }

        pthread_mutex_unlock(&manager->lock);
    }
    else
    {
        for (int i = 0; i < nbSockCreated; ++i)
        {
            snprintf(cmd, sizeof(cmd), "ip a del %s dev eth0", cl.ipPortInfo[i].ipStr);
            system(cmd);
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

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

unsigned short tcp6_checksum(struct ip6_hdr *iph, struct tcphdr *tcph, int len) {
    char buf[2048];
    struct pseudo_header {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t length;
        uint8_t zero[3];
        uint8_t next_header;
    } psh;

    memset(&psh, 0, sizeof(psh));

    psh.src = iph->ip6_src;
    psh.dst = iph->ip6_dst;
    psh.length = htonl(len);
    psh.next_header = IPPROTO_TCP;

    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), tcph, len);

    return checksum(buf, len + sizeof(psh));
}

void reply_syn_ack_ipv6(int rawSocket, int ifIndex, void *packet, int size) {

    char buffer[128];
    memset(buffer, 0, 128);

    memcpy(buffer, packet, 128);

    // headers
    struct ethhdr *eth = (struct ethhdr *) packet;
    struct ip6_hdr *new_iph = (struct ip6_hdr *) (packet + sizeof(struct ethhdr));
    struct tcphdr *new_tcph = (struct tcphdr *) (packet + sizeof(struct ip6_hdr) + sizeof(struct ethhdr));

    //ETH header
    //Swap MAC Address
    unsigned char macTmp[6];
    memcpy(macTmp, eth->h_dest, 6);
    memcpy(eth->h_dest, eth->h_source, 6);
    memcpy(eth->h_source, macTmp, 6);

    //IP6 header
    new_iph->ip6_flow = new_iph->ip6_flow; //Change that ?
    new_iph->ip6_vfc = 0x60;  // Version IPv6
    //new_iph->ip6_plen = htons(sizeof(struct tcphdr));
    new_iph->ip6_nxt = IPPROTO_TCP;
    new_iph->ip6_hlim = 64;
    //Swap IP dst/src
    struct in6_addr tmp = new_iph->ip6_src;
    new_iph->ip6_src =  new_iph->ip6_dst;
    new_iph->ip6_dst = tmp;

    //------- TCP header -------
    //Swap port
    uint16_t srcPort = new_tcph->source;
    new_tcph->source = new_tcph->dest;
    new_tcph->dest = srcPort;
    new_tcph->window =

    //Update SEQ value
    new_tcph->ack_seq = htonl(ntohl(new_tcph->seq) + 1);  // ACK for SYN
    new_tcph->seq = htonl(1234); //Fake seq value

    //Flags
    new_tcph->ack = 1;
    new_tcph->syn = 1;
    new_tcph->check = 0;
    new_tcph->check = tcp6_checksum(new_iph, new_tcph, 32);


    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));

    sa.sll_ifindex = ifIndex;
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);

    //printf("AFTER -----------------------------\n");
    //print_packet_details_ipv6(eth, new_iph, new_tcph);

    if (sendto(rawSocket, packet, size, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Impossible to reply SYN ACK");
    }

}

void redirect_packet(void* packet, const char *macStr)
{

}