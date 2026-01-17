//
// Created by Nathan on 01/09/2024.
//
#include "wakupator/core/core.h"

const char* get_wakupator_message_code(const WAKUPATOR_CODE code)
{
    switch (code)
    {
        case OK: return "OK.";
        case OUT_OF_MEMORY: return "Out of memory on the host.";

        case INIT_MUTEX_CREATION_ERROR: return "Error while creating a mutex.";
        case INIT_PIPE_CREATION_ERROR: return "Error while creating main pipe.";
        case INIT_RAW_SOCKET_CREATION_ERROR: return "Error while creating a raw socket, did you have the permissions ?.";
        case INIT_INTERFACE_GATHER_ERROR: return "Error while gathering interface information, please verify the interface name.";

        case PARSING_CJSON_ERROR: return "An error has been found in the JSON. Please check the types, key names and structure.";
        case PARSING_INVALID_MAC_ADDRESS: return "Invalid MAC address format.";
        case PARSING_INVALID_SHUTDOWN_TIME_FORMAT: return "Invalid Shutdown value format.";
        case PARSING_INVALID_NAME_FORMAT: return "Invalid Name format.";
        case PARSING_INVALID_NAME_TOO_LONG: return "Name value is too long (max 45 char).";
        case PARSING_INVALID_IP_ADDRESS: return "Invalid IP address format.";
        case PARSING_DUPLICATED_IP_ADDRESS: return "A duplicate IP has been found in the JSON, please merge all ports in an array for this IP.";
        case PARSING_INVALID_PORT: return "Invalid port value.";

        case MANAGER_MAC_ADDRESS_ALREADY_MONITORED: return "A client with this MAC address is already being monitored.";
        case MANAGER_THREAD_CREATION_ERROR: return "Internal error when creating the monitor thread.";
        case MANAGER_THREAD_INIT_ERROR: return "Error during initialisation of information for the monitor thread.";
        case MANAGER_THREAD_INIT_TIMEOUT: return "The initialization state of the monitor thread has taken too long.";

        case MONITOR_DAD_ERROR: return "Unable to temporarily disable the IPv6 duplicate address detector.";
        case MONITOR_CHECK_IP_ERROR: return "Error when executing the IP duplication verification command.";
        case MONITOR_RAW_SOCKET_CREATION_ERROR: return "Error when creating a raw socket for the client.";
        case MONITOR_IP_ALREADY_USED: return "A client has already registered one of the requested IP addresses.";
    }
    return "";
}