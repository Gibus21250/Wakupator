#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "parser.h"
#include "core.h"
#include "monitor.h"

#define BUFFER_SIZE 2048

int wakupator_main()
{
    managed_client managedClient;
    init_managed_client(&managedClient);

    int server_fd, client_fd;
    struct sockaddr_storage serverAddress;
    const int addrLen = sizeof(struct sockaddr_storage);

    server_fd = init_socket("2a02:8429:f0:c202:1::1234", 3717, SOCK_STREAM, IPPROTO_TCP, &serverAddress);

    if (bind(server_fd, (struct sockaddr *)&serverAddress, addrLen) < 0) {
        perror("Binding failed!\n");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 8) < 0) {
        perror("Init listen failed!\n");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Wakupator ready to register clients!\n");

    while(1)
    {
        char buffer[BUFFER_SIZE] = {0};

        if ((client_fd = accept(server_fd, (struct sockaddr *)&serverAddress, (socklen_t*) &addrLen)) < 0) {
            perror("Accept new client connexion failed!\n");
            close(server_fd);
            exit(EXIT_FAILURE);
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

    destroy_managed_client(&managedClient);
    return 0;
}

int main(int argc, char **argv)
{
    return wakupator_main();
}
