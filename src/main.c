#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <net/if.h>

#include "wakupator/core/client.h"
#include "wakupator/core/core.h"
#include "wakupator/core/manager.h"

#include "wakupator/parser/parser.h"

#include "wakupator/utils/utils.h"

#include "wakupator/log/log.h"

#define BUFFER_SIZE 4096
int server_fd = -1;

void handle_signal(int signum) {
    log_info("System signal caught.\n");
    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }
}

const char help_message[] =
        "Usage: wakupator <-if|--interface-name> <if_name> [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  REQUIRED:\n"
        "\t-if, --interface-name <name>       Specify the network interface name used for spoofing and probing.\n"
        "\n"
        "  General parameters:\n"
        "\t-H,  --host <ip_address>           Set the host IP address. (IPv4 or IPv6, DEFAULT: 0.0.0.0)\n"
        "\t-p,  --port <port_number>          Define the port number. ([1-65535], DEFAULT: 13717)\n"
        "\n"
        "  Shutdown control parameters:\n"
        "\t-st, --shutdown-timeout <s>        Maximum time in seconds to wait for the machine to be offline before canceling IP spoofing and monitoring. (DEFAULT: 600, -1: inf)\n"
        "\t-spd, --shutdown-probe-delay <s>   Define the delay (seconds) between ARP (IPv4) and NS (IPv6) probes. (DEFAULT: 4)\n"
        "\n"
        "  Wake-up control parameters:\n"
        "\t-wma, --wol-max-attempts <number>  Define the maximum attemps of Wake-On-LAN. (DEFAULT: 3)\n"
        "\t-wd,  --wol-delay <s>              Define the time (seconds) between Wake-On-LAN attempts. (DEFAULT: 30)\n"
        "\t-wkc, --wol-keep-client <0|1>      Keep the client monitored if it doesn't start after maximum attempt(s). (0: False, 1: True, DEFAULT: 1)\n"
        "\t--help                             Display this help message.\n";

typedef struct wakupator_config {
    const char* ifName;
    const char* ip;
    uint16_t port;
    uint16_t wolKeepClient;
    uint32_t wolMaxAttempts;
    uint32_t wolDelay;
    uint16_t shutdownTimeout;
    uint16_t shutdownProbeInterval;
} wakupator_config;

typedef enum ARGS_PARSING_CODE {
    PARSING_OK = 0,
    PARSING_HELP,
    PARSING_ERROR
} ARGS_PARSING_CODE;

/**
 * Reformate arguments if they are parsed between single quote. (Exemple when remote debugging, or shell script launch etc)
 */
void format_quoted_arguments(const int argc, char **argv)
{

    //if one argument is between single quote
    if (argc < 2 || argv[1] == NULL || argv[1][0] != '\'') {
        return;
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i] == NULL) continue;

        const char *src = argv[i];
        char *dst = argv[i];

        while (*src) {
            if (*src != '\'') {
                *dst++ = *src;
            }
            src++;
        }
        *dst = '\0';
    }
}

ARGS_PARSING_CODE parse_arguments(const int argc, char **argv, wakupator_config *context)
{

    if(argc == 1 || strcmp(argv[1], "--help") == 0) {
        return PARSING_HELP;
    }

    for (int i = 1; i < argc-1; i +=2)
    {
        if(strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--host") == 0)
        {
            context->ip = argv[i+1];
        }
        else if(strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0)
        {
            char *endPtr;
            context->port = (int) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0' || context->port < 1 || context->port > 65535) {
                log_error("Error: invalid port '%s'.\n", argv[i+1]);
                return PARSING_ERROR;
            }
        }
        else if(strcmp(argv[i], "-if") == 0 || strcmp(argv[i], "--interface-name") == 0)
        {
            if(strlen(argv[i+1]) > IFNAMSIZ)
            {
                log_error("Error: invalid interface name '%s'.\n", argv[i+1]);
                return PARSING_ERROR;
            }
            context->ifName = argv[i+1];
        }
        else if(strcmp(argv[i], "-wma") == 0 || strcmp(argv[i], "--wol-max-attempts") == 0)
        {
            char *endPtr;
            context->wolMaxAttempts = (uint32_t) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0') {
                log_error("Error: invalid number attempt value '%s'.\n", argv[i+1]);
                return PARSING_ERROR;
            }
        }
        else if(strcmp(argv[i], "-wd") == 0 || strcmp(argv[i], "--wol-delay") == 0)
        {
            char *endPtr;
            context->wolDelay = (uint32_t) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0') {
                log_error("Error: invalid time between attempt value '%s'.\n", argv[i+1]);
                return PARSING_ERROR;
            }
        }
        else if(strcmp(argv[i], "-wkc") == 0 || strcmp(argv[i], "--wol-keep-client") == 0)
        {
            context->wolKeepClient = argv[i+1][0] == '0'?0:1;
        }
        else if(strcmp(argv[i], "-st") == 0 || strcmp(argv[i], "--shutdown-timeout") == 0)
        {
            char *endPtr;
            context->shutdownTimeout = (uint32_t) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0') {
                log_error("Error: invalid shutdown timeout value '%s'.\n", argv[i+1]);
                return PARSING_ERROR;
            }
        }
        else if(strcmp(argv[i], "-spd") == 0 || strcmp(argv[i], "--shutdown-probe-delay") == 0)
        {
            char *endPtr;
            context->shutdownProbeInterval = (uint32_t) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0') {
                log_error("Error: invalid probe interval value '%s'.\n", argv[i+1]);
                return PARSING_ERROR;
            }
        }else
        {
            log_error("Option not recognised: %s\n", argv[i]);
        }
    }

    return PARSING_OK;
}

int wakupator_main(const int argc, char **argv)
{

    wakupator_config config;

    config.ip = "0.0.0.0";
    config.ifName = NULL;
    config.port = 13717;
    config.wolMaxAttempts = 3;
    config.wolDelay = 30;
    config.wolKeepClient = 1;
    config.shutdownTimeout = 600;
    config.shutdownProbeInterval = 4;

    format_quoted_arguments(argc, argv);
    const int parseArgsRes = parse_arguments(argc, argv, &config);

    if (parseArgsRes == PARSING_ERROR)
        return EXIT_FAILURE;

    if (parseArgsRes == PARSING_HELP) {
        printf(help_message);
        return EXIT_SUCCESS;
    }


    if(config.ifName == NULL)
    {
        log_fatal("You need to bind Wakupator to a specific Interface with the option -if <ifName> or --interface-name <ifName> (exemple: eth0, enp5s0 etc)\n");
        return 0;
    }
    //------- PARSING OK -------

    //------- PRINT START INFO -------
    log_info("Starting Wakupator...");

    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        log_fatal("Error while setup signal handler.\n");
        return EXIT_FAILURE;
    }
    if (signal(SIGTERM, handle_signal) == SIG_ERR) {
        log_fatal("Error while setup signal handler.\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_storage serverAddress;
    int addrLen;

    server_fd = init_ip_socket(config.ip, config.port, SOCK_STREAM, IPPROTO_TCP, &serverAddress, &addrLen);

    if(server_fd == -1)
    {
        log_fatal("Main server socket creation failed. IP Format invalid: '%s'.\n", config.ip);
        return EXIT_FAILURE;
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, config.ifName, IFNAMSIZ-1);
    if(setsockopt(server_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)))
    {
        log_fatal("Impossible to bind the socket to the interface: '%s'.\n", config.ifName);
        close(server_fd);
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
    WAKUPATOR_CODE code = init_manager(&manager, config.ifName);

    if(code != OK)
    {
        log_fatal("%s\n", get_wakupator_message_code(code), strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    manager.wolKeepClient = (unsigned char) config.wolKeepClient;
    manager.wolMaxAttempts = config.wolMaxAttempts;
    manager.wolDelay = config.wolDelay;
    manager.shutdownTimeout = config.shutdownTimeout;
    manager.shutdownProbeInterval = config.shutdownProbeInterval;

    int client_fd;
    int running = 1;

    log_info("Started Wakupator bound to interface %s and listen on [%s]:%u\n", config.ifName, config.ip, config.port);
    log_info("Ready to register clients!\n");

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
        const ssize_t size = read(client_fd, buffer, BUFFER_SIZE);
        if (size <= 0) {
            if (size == 0)
                log_debug("Client disconnected before sending registration.\n");
            else
                log_error("Error while reading client: %s\n", strerror(errno));

            close(client_fd);
            continue;
        }

        log_debug("New registration received: %s\n", buffer);

        client cl;
        const char *message;

        code = create_client_from_json(buffer, &cl);

        if(code != OK) {
            message = get_wakupator_message_code(code);
            write(client_fd, message, strlen(message)+1);
            log_info("Error in the JSON of the client: %s\n", message);
            close(client_fd);
            continue;
        }

        log_debug("Parsing OK\n");

        /*
         * Two steps monitoring:
         * - register the client to the client manager
         * - Then start monitoring
         */

        code = register_client(&manager, &cl);

        message = get_wakupator_message_code(code);
        write(client_fd, message, strlen(message)+1);
        close(client_fd); //close fd => close tcp

        if(code != OK) {
            log_info("Failed to register the client: %s\n", message);
            destroy_client(&cl);
            continue;
        }

        char* info = get_client_str_info(&cl);
        if(info != NULL)
            log_info("New client registered: %s\n", info);
        free(info);

    }//Main loop

    if(server_fd != -1)
        close(server_fd);

    destroy_manager(&manager);

    return 0;
}

int main(const int argc, char **argv)
{
    const int code = wakupator_main(argc, argv);
    return code;
}