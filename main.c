#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "utils.h"
#include "parser.h"
#include "core.h"
#include "logger.h"

#define BUFFER_SIZE 2048
int server_fd = -1;

void handle_signal() {
    log_info("System Signal caught.\n");
    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }
}

int wakupator_main(int argc, char **argv)
{
    int port = 13717;
    const char* ip = NULL;
    const char* ifName = "eth0";

    //------- PARSE ARGS -------
    if(argc < 3 || (argc-1)%2 == 1)
        log_info("Wakupator arguments:\n\t-H <IPv4/v6> (required)\n\t-p <port> (default: 13717)\n\t-e <interfaceName>\n");

    for (int i = 0; i < argc-1; i +=2)
    {
        if(strcmp(argv[i+1], "-H") == 0)
        {
            ip = argv[i+2];
        }
        else if(strcmp(argv[i+1], "-p") == 0)
        {
            char *endPtr;
            port = (int) strtol(argv[i+2], &endPtr, 10);

            if (*endPtr != '\0' || port <= 0 || port > 65535) {
                log_error("Error: invalid port '%s'.\n", argv[i+2]);
                return EXIT_FAILURE;
            }
        }else if(strcmp(argv[i+1], "-e") == 0)
        {
            ifName = argv[i+2];
        }
    }

    //------- PARSING OK -------
    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        log_fatal("Error while setup signal handler.\n");
        return EXIT_FAILURE;
    }
    if (signal(SIGTERM, handle_signal) == SIG_ERR) {
        log_fatal("Error while setup signal handler.\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_storage serverAddress;
    const int addrLen = sizeof(struct sockaddr_storage);

    server_fd = init_socket(ip, port, SOCK_STREAM, IPPROTO_TCP, &serverAddress);

    if(server_fd == -1)
    {
        log_fatal("Main server socket creation failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bind(server_fd, (struct sockaddr *)&serverAddress, addrLen) < 0) {
        log_fatal("Main server binding failed: %s\n", strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 8) < 0) {
        log_fatal("Main server listen failed: %s\n", strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    manager manager;
    REGISTER_CODE code = init_manager(&manager, ifName);

    if(code != OK)
    {
        log_fatal(get_register_message(code), strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    //Set parsed arguments to the manager
    manager.keepClient = keepClient;
    manager.nbAttempt = nbAttempt;
    manager.timeBtwAttempt = timeBtwAttempt;

    log_info("Ready to register clients!\n");

    int client_fd;
    int running = 1;

    while(running)
    {
        char buffer[BUFFER_SIZE] = {0};

        if ((client_fd = accept(server_fd, (struct sockaddr *)&serverAddress, (socklen_t*) &addrLen)) < 0) {
            if(server_fd == -1)
            {
                log_info("Main server closed.\n");
                running = 0;
            }
            else
                log_error("Error while accept new client connexion, skipping. (%s)\n", strerror(errno));

            continue;
        }

        //Reading the JSON from the client
        read(client_fd, buffer, BUFFER_SIZE);
        log_debug("New registration received: %s\n", buffer);

        client cl;
        const char *message;

        code = parse_from_json(buffer, &cl);

        if(code != OK) {
            message = get_register_message(code);
            write(client_fd, message, strlen(message)+1);
            log_debug("Error in the JSON of the client: %s\n", message);
            close(client_fd);
            continue;
        }

        log_debug("Parsing OK\n");

        code = register_client(&manager, &cl);

        message = get_register_message(code);
        write(client_fd, message, strlen(message)+1);
        close(client_fd); //close fd => close tcp

        if(code != OK) {
            log_debug("Failed to register the client: %s\n", message);
            destroy_client(&cl);
            continue;
        }

        //Notify the monitor thread to spoof IPs and start monitoring
        start_monitoring(&manager, cl.mac);

        char* info = get_client_str_info(&cl);
        if(info != NULL)
            log_info("New client registered: %s\n", info);
        free(info);

    }

    if(server_fd != -1)
        close(server_fd);

    destroy_manager(&manager);

    return 0;
}

int main(int argc, char **argv)
{
    init_log();
    int code = wakupator_main(argc, argv);
    close_log();
    return code;
}
