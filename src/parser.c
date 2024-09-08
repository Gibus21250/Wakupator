//
// Created by Nathan on 02/09/2024.
//
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "cJSON/cJSON.h"

#include "parser.h"

CLIENT_PARSING_CODE parse_from_json(const char *json_raw, client* client)
{
    cJSON *json = cJSON_Parse(json_raw);
    if (json == NULL)
        return PARSING_CJSON_ERROR;

    char rawIpStorage_Temp[16];


    //Init the client struct
    client->mac[0] = 0;
    client->ipPortInfo = NULL;
    client->countIp = 0;

    cJSON *mac = cJSON_GetObjectItemCaseSensitive(json, "mac");

    //Check for MAC address validity
    if (!cJSON_IsString(mac) || (mac->valuestring == NULL) || verify_mac_format(mac->valuestring))
    {
        cJSON_Delete(json);
        return PARSING_INVALID_MAC_ADDRESS;
    }

    memcpy(client->mac, mac->valuestring, 18 * sizeof(char));

    //Now extract all ip and ports asked for monitoring
    const cJSON *monitor_array = cJSON_GetObjectItemCaseSensitive(json, "monitor");

    if(!cJSON_IsArray(monitor_array))
    {
        cJSON_Delete(json);
        return PARSING_CJSON_ERROR;
    }

    int monitor_count = cJSON_GetArraySize(monitor_array);

    if(monitor_count == 0)
    {
        cJSON_Delete(json);
        return PARSING_CJSON_ERROR;
    }

    client->ipPortInfo = (ip_port_info*) calloc(monitor_count, sizeof(ip_port_info));

    if(client->ipPortInfo == NULL)
    {
        cJSON_Delete(json);
        return PARSING_OUT_OF_MEMORY;
    }

    //For each ip:[ports] object
    for (int i = 0; i < monitor_count; ++i)
    {
        cJSON *monitor_item = cJSON_GetArrayItem(monitor_array, i);
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(monitor_item, "ip");

        if (!cJSON_IsString(ip) && (ip->valuestring == NULL))
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_CJSON_ERROR;
        }

        int AF = strchr(ip->valuestring, ':') != 0?AF_INET6:AF_INET;

        client->countIp++;

        client->ipPortInfo[i].ipFormat = AF;

        //If inet_pton works fine, we can admit that the format is conformed
        if(inet_pton(AF, ip->valuestring, &rawIpStorage_Temp) != 1)
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_INVALID_IP_ADDRESS;
        }

        client->ipPortInfo[i].ipStr = (char*) malloc((strlen(ip->valuestring) + 1) * sizeof(char));

        if(client->ipPortInfo[i].ipStr == NULL)
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_OUT_OF_MEMORY;
        }

        strcpy(client->ipPortInfo[i].ipStr, ip->valuestring);

        //Ports asked to be managed for the ip asked
        cJSON *ports_array = cJSON_GetObjectItemCaseSensitive(monitor_item, "port");

        if (!cJSON_IsArray(ports_array))
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_CJSON_ERROR;
        }

        int port_count = cJSON_GetArraySize(ports_array);

        if(port_count == 0)
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_INVALID_PORT;
        }

        client->ipPortInfo[i].portCount = port_count;
        client->ipPortInfo[i].ports = (uint16_t *) malloc(port_count * sizeof(uint16_t));

        if(client->ipPortInfo[i].ports == NULL)
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_OUT_OF_MEMORY;
        }

        //For each port
        for (int j = 0; j < port_count; ++j) {
            cJSON *port = cJSON_GetArrayItem(ports_array, j);

            if (!cJSON_IsNumber(port))
            {
                destroy_client(client);
                cJSON_Delete(json);
                return PARSING_INVALID_PORT;
            }

            if(port->valueint < 0 || port->valueint > (uint16_t)-1)
            {
                destroy_client(client);
                cJSON_Delete(json);
                return PARSING_INVALID_PORT;
            }

            client->ipPortInfo[i].ports[j] = port->valueint;

        }
    }

    cJSON_Delete(json);
    return PARSING_OK;
}

int verify_mac_format(const char *strMac)
{
    if (strlen(strMac) != 17)
        return 1;

    for (int i = 0; i < 17; i++) {
        char c = strMac[i];
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

const char* get_parser_error(CLIENT_PARSING_CODE code)
{
    switch (code)
    {
        case PARSING_OK: return "OK.";
        case PARSING_CJSON_ERROR: return "An error was find in the JSON. Please verify types, keynames and structure.";
        case PARSING_INVALID_MAC_ADDRESS: return "Invalid MAC address format.";
        case PARSING_INVALID_IP_ADDRESS: return "Invalid IP address format.";
        case PARSING_INVALID_PORT: return "Invalid port value.";
        case PARSING_OUT_OF_MEMORY: return "Out of memory on the host.";
    }
}