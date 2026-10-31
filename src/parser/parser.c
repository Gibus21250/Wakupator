//
// Created by Nathan on 02/09/2024.
//
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <cJSON/cJSON.h>

#include "wakupator/parser/parser.h"

#include "wakupator/net/net.h"

wakupator_code create_client_from_json(const char *json_raw, client* client)
{
    cJSON *json = cJSON_Parse(json_raw);
    if (json == NULL)
        return WK_PARSING_CJSON_ERROR;

    //Init the client struct
    client->mac_str[0] = 0;
    client->mac_raw[0] = 0;
    client->name[0] = 0;
    client->ip_port_info = NULL;
    client->count_ip = 0;
    client->time_started = 0;

    //----- Parse MAC address (STR and RAW) -----
    const cJSON *mac = cJSON_GetObjectItemCaseSensitive(json, "mac");

    if (!cJSON_IsString(mac) || verify_mac_format(mac->valuestring))
    {
        cJSON_Delete(json);
        return WK_PARSING_INVALID_MAC_ADDRESS;
    }

    strcpy(client->mac_str, mac->valuestring);

    if (str_to_raw_mac(client->mac_str, client->mac_raw))
    {
        cJSON_Delete(json);
        return WK_PARSING_INVALID_MAC_ADDRESS;
    }

    //----- Parse Name (STR) -----
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "name");

    if (!cJSON_IsString(name))
    {
        cJSON_Delete(json);
        return WK_PARSING_INVALID_NAME_FORMAT;
    }

    if (strlen(name->valuestring) > sizeof(client->name)-1) {
        cJSON_Delete(json);
        return WK_PARSING_INVALID_NAME_TOO_LONG;
    }

    strcpy(client->name, name->valuestring);

    //----- Parse IP and PORT -----
    const cJSON *monitor_array = cJSON_GetObjectItemCaseSensitive(json, "monitor");

    if(!cJSON_IsArray(monitor_array))
    {
        cJSON_Delete(json);
        return WK_PARSING_CJSON_ERROR;
    }

    const int monitor_count = cJSON_GetArraySize(monitor_array);

    if(monitor_count == 0)
    {
        cJSON_Delete(json);
        return WK_PARSING_CJSON_ERROR;
    }

    client->ip_port_info = (ip_port_info*) calloc(monitor_count, sizeof(ip_port_info));

    if(client->ip_port_info == NULL)
    {
        cJSON_Delete(json);
        return WK_OUT_OF_MEMORY;
    }

    //----- ----- Verify uniqueness of each IP ----- -----
    for (int i = 0; i < monitor_count; ++i)
    {
        const cJSON *monitor_item = cJSON_GetArrayItem(monitor_array, i);
        const cJSON *ip = cJSON_GetObjectItemCaseSensitive(monitor_item, "ip");

        if (!cJSON_IsString(ip))
        {
            destroy_client(client);
            cJSON_Delete(json);
            return WK_PARSING_INVALID_IP_ADDRESS_FORMAT;
        }

        for (int j = i+1; j < monitor_count; ++j)
        {
            const cJSON *monitor_item2 = cJSON_GetArrayItem(monitor_array, j);
            const cJSON *ip2 = cJSON_GetObjectItemCaseSensitive(monitor_item2, "ip");

            if (!cJSON_IsString(ip2))
            {
                destroy_client(client);
                cJSON_Delete(json);
                return WK_PARSING_INVALID_IP_ADDRESS_FORMAT;
            }

            //Same IP asked in 2 different monitor object
            if(strcmp(ip->valuestring, ip2->valuestring) == 0)
            {
                destroy_client(client);
                cJSON_Delete(json);
                return WK_PARSING_DUPLICATED_IP_ADDRESS;
            }
        }
    }

    //For each ip:[ports] object
    for (int i = 0; i < monitor_count; ++i)
    {
        const cJSON *monitor_item = cJSON_GetArrayItem(monitor_array, i);
        const cJSON *ip = cJSON_GetObjectItemCaseSensitive(monitor_item, "ip");

        const int af = strchr(ip->valuestring, ':') != 0?AF_INET6:AF_INET;

        client->count_ip++;

        if (af == AF_INET)
        {
            client->ip_port_info[i].ip_format = AF_INET;

            if(inet_pton(AF_INET, ip->valuestring, &client->ip_port_info[i].ipv4) != 1)
            {
                destroy_client(client);
                cJSON_Delete(json);
                return WK_PARSING_INVALID_IP_ADDRESS_FORMAT;
            }
        }
        else
        {
            client->ip_port_info[i].ip_format = AF_INET6;

            if(inet_pton(AF_INET6, ip->valuestring, &client->ip_port_info[i].ipv6) != 1)
            {
                destroy_client(client);
                cJSON_Delete(json);
                return WK_PARSING_INVALID_IP_ADDRESS_FORMAT;
            }

        }

        strcpy(client->ip_port_info[i].ip_str, ip->valuestring);

        //Parse all ports for this IP
        const cJSON *ports_array = cJSON_GetObjectItemCaseSensitive(monitor_item, "port");

        if (!cJSON_IsArray(ports_array))
        {
            destroy_client(client);
            cJSON_Delete(json);
            return WK_PARSING_CJSON_ERROR;
        }

        const int port_count = cJSON_GetArraySize(ports_array);

        client->ip_port_info[i].port_count = 0;
        client->ip_port_info[i].ports = NULL;

        //Parse each ports (if available)
        if(port_count != 0)
        {

            client->ip_port_info[i].ports = (uint16_t *) malloc(port_count * sizeof(uint16_t));

            if(client->ip_port_info[i].ports == NULL)
            {
                destroy_client(client);
                cJSON_Delete(json);
                return WK_OUT_OF_MEMORY;
            }

            client->ip_port_info[i].port_count = port_count;

            //For each port
            for (int j = 0; j < port_count; ++j) {
                const cJSON *port = cJSON_GetArrayItem(ports_array, j);

                if (!cJSON_IsNumber(port))
                {
                    destroy_client(client);
                    cJSON_Delete(json);
                    return WK_PARSING_INVALID_PORT;
                }

                if(port->valueint < 0 || port->valueint > (uint16_t)-1)
                {
                    destroy_client(client);
                    cJSON_Delete(json);
                    return WK_PARSING_INVALID_PORT;
                }

                client->ip_port_info[i].ports[j] = port->valueint;

            }
        }
    }

    cJSON_Delete(json);
    return WK_OK;
}

int verify_mac_format(const char *str_mac)
{
    if (strlen(str_mac) != 17)
        return 1;

    for (int i = 0; i < 17; i++) {
        const char c = str_mac[i];
        if (i % 3 == 2) {
            if (c != ':') {
                return 1;
            }
        } else {
            if (!(isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return 1;
            }
        }
    }

    return 0;
}