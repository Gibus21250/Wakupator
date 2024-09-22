#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
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

int wakupator_main()
{
    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        log_fatal("Error while setup signal handler.\n");
        return EXIT_FAILURE;
    }
    if (signal(SIGTERM, handle_signal) == SIG_ERR) {
        log_fatal("Error while setup signal handler.\n");
        return EXIT_FAILURE;
    }

    int client_fd;
    struct sockaddr_storage serverAddress;
    const int addrLen = sizeof(struct sockaddr_storage);

    server_fd = init_socket("2a02:8429:f0:c202:1::1234", 13717, SOCK_STREAM, IPPROTO_TCP, &serverAddress);

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
    init_manager(&manager);

    manager.mainRawSocket = socket(PF_PACKET, SOCK_RAW, 0);

    if(manager.mainRawSocket == -1)
    {
        log_fatal("Error while creating main raw socket.\n");
        close(server_fd);
        destroy_manager(&manager);
        return EXIT_FAILURE;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    char *name = "eth0";

    strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
    if (ioctl(manager.mainRawSocket, SIOCGIFINDEX, &ifr) < 0) {
        log_fatal("Error while gather index of the interface.\n", strerror(errno));
        close(server_fd);
        destroy_manager(&manager);
        return EXIT_FAILURE;
    }

    manager.ifIndex = ifr.ifr_ifindex;
    manager.itName = name;

    log_info("Ready to register clients!\n");

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

        REGISTER_CODE code = parse_from_json(buffer, &cl);

        if(code != OK) {
            message = get_register_error(code);
            write(client_fd, message, strlen(message)+1);
            log_debug("Error in the JSON of the client: %s\n", message);
            close(client_fd);
            continue;
        }

        log_debug("Parsing OK\n");

        REGISTER_CODE res = register_client(&manager, &cl);

        message = get_register_error(res);
        write(client_fd, message, strlen(message)+1);
        close(client_fd); //close fd => close tcp

        if(res != OK) {
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
    int code = wakupator_main();
    close_log();
    return code;
}
