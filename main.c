#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "utils.h"
#include "parser.h"
#include "core.h"

#define BUFFER_SIZE 2048

int server_fd = -1;

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM ||signal == SIGQUIT || signal == SIGABRT)
    {
        printf("\nSignal caught\n");

        if (server_fd != -1) {
            close(server_fd);
            server_fd = -1;
        }
    }
}

int wakupator_main()
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

    manager manager;
    init_manager(&manager);

    manager.mainRawSocket = socket(PF_PACKET, SOCK_RAW, 0);

    if(manager.mainRawSocket == -1)
    {
        perror("Error while creating the main raw socket.");
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    char *name = "eth0";

    strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
    if (ioctl(manager.mainRawSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror("Error while gather index of the interface.");
        return 1;
    }

    manager.ifIndex = ifr.ifr_ifindex;
    manager.itName = name;

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

        REGISTER_CODE code = parse_from_json(buffer, &cl);

        if(code != OK) {
            message = get_register_error(code);
            write(client_fd, message, strlen(message)+1);
            close(client_fd);
            continue;
        }

        printf("Parsing OK\n");

        REGISTER_CODE res =  register_client(&manager, &cl);

        message = get_register_error(res);
        write(client_fd, message, strlen(message)+1);

        if(res != OK) {
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

    destroy_manager(&manager);

    return 0;
}

int main(int argc, char **argv)
{
    return wakupator_main();
}
