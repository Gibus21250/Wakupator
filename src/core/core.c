//
// Created by Nathan on 01/09/2024.
//
#include "wakupator/core/core.h"

const char* get_wakupator_message_code(const wakupator_code code)
{
    switch (code)
    {
        case WK_OK: return "OK.";
        case WK_OUT_OF_MEMORY: return "Out of memory on the host.";
        case WK_INVALID_ARGUMENT: return "Invalid argument.";

        case WK_MUTEX_CREATION_ERROR: return "Error while creating a mutex.";
        case WK_PIPE_CREATION_ERROR: return "Error while creating main pipe.";
        case WK_THREAD_LOCK_CREATION_ERROR: return "Error while creating a thread lock.";
        case WK_RAW_SOCKET_CREATION_ERROR: return "Error while creating a raw socket, do you have the permissions?";
        case WK_GATHER_INTERFACE_INDEX_ERROR: return "Error while gathering interface index, please verify the interface name.";
        case WK_GATHER_INTERFACE_MAC_ERROR: return "Error while gathering interface mac address.";

        case WK_PARSING_CJSON_ERROR: return "An error has been found in the JSON. Please check the types, key names and structure.";
        case WK_PARSING_INVALID_MAC_ADDRESS: return "Invalid MAC address format.";
        case WK_PARSING_INVALID_SHUTDOWN_TIME_FORMAT: return "Invalid Shutdown value format.";
        case WK_PARSING_INVALID_NAME_FORMAT: return "Invalid Name format.";
        case WK_PARSING_INVALID_NAME_TOO_LONG: return "Name value is too long (max 45 char).";
        case WK_PARSING_INVALID_IP_ADDRESS_FORMAT: return "Invalid IP address format.";
        case WK_PARSING_DUPLICATED_IP_ADDRESS: return "A duplicate IP has been found in the JSON, please merge all ports in an array for this IP.";
        case WK_PARSING_INVALID_PORT: return "Invalid port value.";

        case WK_MANAGER_MAC_ADDRESS_ALREADY_MONITORED: return "A client with this MAC address is already being monitored.";
        case WK_MANAGER_MONITOR_THREAD_CREATION_ERROR: return "Internal error when creating the monitor thread.";
        case WK_MANAGER_MONITOR_THREAD_INIT_ERROR: return "Error during initialisation of information for the monitor thread.";
        case WK_MANAGER_MONITOR_THREAD_INIT_TIMEOUT: return "The initialization state of the monitor thread has taken too long.";
        case WK_MANAGER_IP6_NOT_AVAILABLE: return "IPv6 is not available on this instance of Wakupator.";
        case WK_MANAGER_CLIENT_NOT_FOUND: return "Client not found.";

        case WK_MONITOR_RAW_SOCKET_MONITORING_CREATION_ERROR: return "Error when creating a raw socket monitoring traffic for the client.";
        case WK_MONITOR_RAW_SOCKET_SPOOFING_CREATION_ERROR: return "Error when creating a raw socket for spoofing IP for the client.";
        case WK_MONITOR_RAW_SOCKET_ANY_TRAFFIC_CREATION_ERROR: return "Error when creating a raw socket for capturing any traffic of client's MAC.";
        case WK_MONITOR_IP_ALREADY_USED: return "A client has already registered one of the requested IP addresses.";
        case WK_MONITOR_ARP_REPLY_ERROR: return "Error while responding with an ARP Reply.";
        case WK_MONITOR_NS_REPLY_ERROR: return "Error while responding with a NS.";
        default: return "";
    }
}