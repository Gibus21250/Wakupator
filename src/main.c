#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "wakupator/core/client.h"
#include "wakupator/core/core.h"

#include "wakupator/parser/parser.h"

#include "wakupator/utils/utils.h"

#include "wakupator/log/log.h"

#define BUFFER_SIZE 4096
int server_fd = -1;

const char* help_message =
        "Usage: wakupator -H|--host <ip_address> [OPTIONS]\n\n"
        "Options:\n"
        "  -H,  --host <ip_address>           (Required) Set the host IP address. (IPv4 or IPv6)\n"
        "  -p,  --port <port_number>          Set the port number (0-65535, DEFAULT: 13717)\n"
        "  -if, --interface-name <name>       Specify the network interface name. (DEFAULT: eth0)\n"
        "  -nb, --number-attempt <number>     Set the number of Wake-On-LAN attempts. (DEFAULT: 3)\n"
        "  -t,  --time-between-attempt <s>    Set the time in seconds between attempts. (DEFAULT: 30)\n"
        "  -kc, --keep-client <0|1>           Keep the client monitored if he doesn't start after <-nb> attempt(s). (0: No, 1: Yes, DEFAULT: 1)\n"
        "       --help                        Display this help message.\n\n"
        "Examples:\n"
        "  wakupator -H 192.168.0.37 -p 1234 -if eth2 -nb 5 -t 15 -kc 1\n"
        "  wakupator --host 2001:0db8:3c4d:c202:1::2222 --port 4321 --interface-name enp4s0 --number-attempt 6 --time-between-attempt 10 --keep-client 0\n";

void handle_signal() {
    log_info("System signal caught.\n");
    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }
}

int wakupator_main(const int argc, char **argv)
{
    int port = 13717;
    const char* ip = NULL;
    const char* ifName = "eth0";
    uint32_t nbAttempt = 3;
    uint32_t timeBtwAttempt = 30;
    char keepClient = 1;

    //------- PARSE ARGS -------

    for (int i = 1; i < argc-1; i +=2)
    {
        if(strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--host") == 0)
        {
            ip = argv[i+1];
        }
        else if(strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0)
        {
            char *endPtr;
            port = (int) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0' || port <= 0 || port > 65535) {
                log_error("Error: invalid port '%s'.\n", argv[i+1]);
                return EXIT_FAILURE;
            }
        }
        else if(strcmp(argv[i], "-if") == 0 || strcmp(argv[i], "--interface-name") == 0)
        {
            ifName = argv[i+1];
        }
        else if(strcmp(argv[i], "-nb") == 0 || strcmp(argv[i], "--number-attempt") == 0)
        {
            char *endPtr;
            nbAttempt = (uint32_t) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0') {
                log_error("Error: invalid number attempt value '%s'.\n", argv[i+1]);
                return EXIT_FAILURE;
            }
        }
        else if(strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--time-between-attempt") == 0)
        {
            char *endPtr;
            timeBtwAttempt = (uint32_t) strtol(argv[i+1], &endPtr, 10);

            if (*endPtr != '\0') {
                log_error("Error: invalid time between attempt value '%s'.\n", argv[i+1]);
                return EXIT_FAILURE;
            }
        }
        else if(strcmp(argv[i], "-kc") == 0 || strcmp(argv[i], "--keep-client") == 0)
        {
            keepClient = argv[i+1][0] == '0'?0:1;
        }
        else if(strcmp(argv[i], "--help") == 0)
        {
            log_info(help_message);
            return 0;
        }else
        {
            log_info("Option not recognised: %s", argv[i]);
            return 0;
        }
    }

    if(ip == NULL)
    {
        log_info("You need to bind Wakupator to an IP with the option -H <IPv4/v6> or --host <IPv4/v6>\n");
        return 0;
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
    int addrLen;

    server_fd = init_socket(ip, port, SOCK_STREAM, IPPROTO_TCP, &serverAddress, &addrLen);

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
    WAKUPATOR_CODE code = init_manager(&manager, ifName);

    if(code != OK)
    {
        log_fatal(get_wakupator_message_code(code), strerror(errno));
        close(server_fd);
        return EXIT_FAILURE;
    }

    //Set parsed arguments to the manager
    manager.keepClient = (unsigned char) keepClient;
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
        uint32_t size = read(client_fd, buffer, BUFFER_SIZE);
        if (size == 0)
            continue;

        log_debug("New registration received: %s\n", buffer);

        client cl;
        const char *message;

        code = parse_from_json(buffer, &cl);

        if(code != OK) {
            message = get_wakupator_message_code(code);
            write(client_fd, message, strlen(message)+1);
            log_debug("Error in the JSON of the client: %s\n", message);
            close(client_fd);
            continue;
        }

        log_debug("Parsing OK\n");

        code = register_client(&manager, &cl);

        message = get_wakupator_message_code(code);
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

int main(const int argc, char **argv)
{
    const int code = wakupator_main(argc, argv);
    return code;
}
