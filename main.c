#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "utils.h"
#include "parser.h"
#include "core.h"
#include "monitor.h"

#define BUFFER_SIZE 2048

int server_fd = -1;

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM ||signal == SIGQUIT || signal == SIGABRT)
    {
        printf("\nSignal SIGINT catched, wake up all client\n");

        if (server_fd != -1) {
            close(server_fd);
            server_fd = -1;
        }
    }
}
void send_syn_ack_ipv6(void *packet) {

    //Now create a one use raw socket, a raw socket, who receive nothing (proto = 0)
    int rawSocket = socket(PF_PACKET, SOCK_RAW, 0);
    if(rawSocket == -1)//TODO handle failed, the target will not be woke up! (extreme rare scenario)
        return;

    char buffer[128];
    memset(buffer, 0, 128);

    memcpy(buffer, packet, 128);

    // headers
    struct ethhdr *eth = (struct ethhdr *) packet;
    struct ip6_hdr *new_iph = (struct ip6_hdr *) (packet + sizeof(struct ethhdr));
    struct tcphdr *new_tcph = (struct tcphdr *)(packet + sizeof(struct ip6_hdr) + sizeof(struct ethhdr));

    printf("BEFORE\n");
    print_packet_details_ipv6(eth, new_iph, new_tcph);

    unsigned char macTmp[6];
    memcpy(macTmp, eth->h_dest, 6);
    memcpy(eth->h_dest, eth->h_source, 6);
    memcpy(eth->h_source, macTmp, 6);

    new_iph->ip6_flow = new_iph->ip6_flow;
    new_iph->ip6_vfc = 0x60;  // Version IPv6
    new_iph->ip6_plen = htons(sizeof(struct tcphdr));
    new_iph->ip6_nxt = IPPROTO_TCP;
    new_iph->ip6_hlim = 64;  // Hop limit
    struct in6_addr tmp = new_iph->ip6_src;
    new_iph->ip6_src =  new_iph->ip6_dst; // Inverser l'adresse source et destination
    new_iph->ip6_dst = tmp;

    //TCP header
    uint16_t srcPort = new_tcph->source;
    new_tcph->source = new_tcph->dest;
    new_tcph->dest = srcPort;
    new_tcph->ack_seq = htonl(ntohl(new_tcph->seq) + 1);  // ACK for SYN
    new_tcph->seq = new_tcph->ack_seq;
    new_tcph->doff = 5;
    new_tcph->syn = 1;
    new_tcph->ack = 1;
    new_tcph->window = new_tcph->window;
    new_tcph->check = 0;
    new_tcph->urg_ptr = 0;

    // Calculer la somme de contrôle TCP
    new_tcph->check = tcp6_checksum(new_iph, new_tcph, sizeof(struct tcphdr));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    if (ioctl(rawSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror("Error while gather index of the interface.");
        close(rawSocket);
        return;
    }

    // Adresse de destination
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));

    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);

    printf("AFTER -----------------------------\n");
    print_packet_details_ipv6(eth, new_iph, new_tcph);


    sleep(10);
    // Envoyer le paquet
    if (sendto(rawSocket, packet, sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Erreur d'envoi du SYN-ACK IPv6");
    } else {
        printf("SYN-ACK IPv6 envoyé\n");
    }

    sleep(10);

    // Envoyer le paquet
    if (sendto(rawSocket, packet, sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Erreur d'envoi du SYN-ACK IPv6");
    } else {
        printf("SYN-ACK IPv6 envoyé\n");
    }

    close(rawSocket);
}


int test()
{
    uint16_t port = 25565;

    const ip_port_info ipPortInfo = {
        .ipStr = "2a02:8429:f0:c202:1::1234",
        .ipFormat = AF_INET6,
        .portCount = 1,
        .ports = &port
    };

    //Test fake SYN ACK
    int rawSocket = create_raw_filter_socket(&ipPortInfo);
    if(rawSocket == -1)//TODO handle failed, the target will not be woke up! (extreme rare scenario)
        return 1;

    char packet[128];

    int res = read(rawSocket, packet, 128);

    if(res != 0)
    {
        send_syn_ack_ipv6(packet);
    }

    close(rawSocket);


    return 0;
}

int wakupator_main(int argc, char **argv)
{

    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        fprintf(stderr, "Error while setup Signal handler.\n");
        return 1;
    }

    int client_fd;
    struct sockaddr_storage serverAddress;
    const int addrLen = sizeof(struct sockaddr_storage);

    server_fd = init_socket("2a02:8429:f0:c202:1::1234", 3717, SOCK_STREAM, IPPROTO_TCP, &serverAddress);

    if (bind(server_fd, (struct sockaddr *)&serverAddress, addrLen) < 0) {
        perror("Binding failed!\n");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 8) < 0) {
        perror("Init listen failed!\n");
        close(server_fd);
        return EXIT_FAILURE;
    }

    manager managedClient;
    init_manager(&managedClient);
    managedClient.mainRawSocket = socket(PF_PACKET, SOCK_RAW, 0);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    if (ioctl(managedClient.mainRawSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror("Error while gather index of the interface.");
        close(managedClient.mainRawSocket);
        return 1;
    }

    managedClient.ifIndex = ifr.ifr_ifindex;

    printf("Wakupator ready to register clients!\n");

    int running = 1;
    while(running)
    {
        char buffer[BUFFER_SIZE] = {0};

        if ((client_fd = accept(server_fd, (struct sockaddr *)&serverAddress, (socklen_t*) &addrLen)) < 0) {
            if(server_fd == -1)
            {
                printf("Wakupator's main server closed\n");
                running = 0;
            }
            else
                printf("Error while accept new client connexion, skipping\n");

            continue;
        }

        //Reading the JSON from the client
        read(client_fd, buffer, BUFFER_SIZE);
        printf("New registration received: %s\n", buffer);

        client cl;
        const char *message;

        CLIENT_PARSING_CODE code = parse_from_json(buffer, &cl);

        if(code != PARSING_OK) {
            message = get_parser_error(code);
            write(client_fd, message, strlen(message)+1);
            close(client_fd);
            continue;
        }

        printf("Parsing OK\n");

        MANAGER_CODE res =  register_client(&managedClient, &cl);

        message = get_monitor_error(res);
        write(client_fd, message, strlen(message)+1);

        if(res != MANAGER_OK) {
            close(client_fd);
            printf("Failed to register the client: %s\n", message);
            destroy_client(&cl);
            continue;
        }

        printf("Successfully register new client: %s, on\n", cl.mac);
        for (int i = 0; i < cl.countIp; ++i) {
            printf("\tIP: %s on [", cl.ipPortInfo[i].ipStr);
            for (int j = 0; j < cl.ipPortInfo[i].portCount; ++j) {
                if(j != cl.ipPortInfo[i].portCount - 1)
                    printf("%d, ", cl.ipPortInfo[i].ports[j]);
                else
                    printf("%d]\n", cl.ipPortInfo[i].ports[j]);
            }
        }
    }

    if(server_fd != -1)
        close(server_fd);

    destroy_manager(&managedClient);

    return 0;
}

int main(int argc, char **argv)
{
    return wakupator_main(argc, argv);
}
