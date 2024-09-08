#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>

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

int wakupator_main()
{

    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        fprintf(stderr, "Error while setup Signal handler.\n");
        return 1;
    }

    managed_client managedClient;
    init_managed_client(&managedClient);

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

        CLIENT_MONITORING_CODE res =  register_client(&managedClient, &cl);

        message = get_monitor_error(res);
        write(client_fd, message, strlen(message)+1);

        if(res != MONITORING_OK) {
            close(client_fd);
            printf("Failed to register the client: %s\n", message);
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

    destroy_managed_client(&managedClient);

    return 0;
}

int main(int argc, char **argv)
{
    return wakupator_main();
}
