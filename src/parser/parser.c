//
// Created by Nathan on 02/09/2024.
//
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <cJSON/cJSON.h>

#include "wakupator/parser/parser.h"

WAKUPATOR_CODE create_client_from_json(const char *json_raw, client* client)
{
    cJSON *json = cJSON_Parse(json_raw);
    if (json == NULL)
        return PARSING_CJSON_ERROR;

    //Init the client struct
    client->mac[0] = 0;
    client->name[0] = 0;
    client->ipPortInfo = NULL;
    client->countIp = 0;
    client->shutdownTime = 0;

    const cJSON *mac = cJSON_GetObjectItemCaseSensitive(json, "mac");

    //Check for MAC address validity
    if (!cJSON_IsString(mac) || (mac->valuestring == NULL) || verify_mac_format(mac->valuestring))
    {
        cJSON_Delete(json);
        return PARSING_INVALID_MAC_ADDRESS;
    }

    memcpy(client->mac, mac->valuestring, sizeof(client->mac));

    //Check if shutdown_time provided:
    const cJSON *shutdownTime = cJSON_GetObjectItemCaseSensitive(json, "shutdown_time");

    if (!cJSON_IsNull(shutdownTime) && !cJSON_IsNumber(shutdownTime))
    {
        cJSON_Delete(json);
        return PARSING_INVALID_SHUTDOWN_TIME_FORMAT;
    }

    client->shutdownTime = shutdownTime->valueint;

    const cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "name");

    //Check for Name validity
    if (!cJSON_IsString(name) || (name->valuestring == NULL))
    {
        cJSON_Delete(json);
        return PARSING_INVALID_NAME_FORMAT;
    }

    if (strlen(name->valuestring) > sizeof(client->name)-1) {
        cJSON_Delete(json);
        return PARSING_INVALID_NAME_TOO_LONG;
    }

    memcpy(client->name, name->valuestring, sizeof(client->name));

    //Now extract all ip and ports asked for monitoring
    const cJSON *monitor_array = cJSON_GetObjectItemCaseSensitive(json, "monitor");

    if(!cJSON_IsArray(monitor_array))
    {
        cJSON_Delete(json);
        return PARSING_CJSON_ERROR;
    }

    const int monitor_count = cJSON_GetArraySize(monitor_array);

    if(monitor_count == 0)
    {
        cJSON_Delete(json);
        return PARSING_CJSON_ERROR;
    }

    client->ipPortInfo = (ip_port_info*) calloc(monitor_count, sizeof(ip_port_info));

    if(client->ipPortInfo == NULL)
    {
        cJSON_Delete(json);
        return OUT_OF_MEMORY;
    }

    //Check uniqueness of IPs
    for (int i = 0; i < monitor_count; ++i)
    {
        const cJSON *monitor_item = cJSON_GetArrayItem(monitor_array, i);
        const cJSON *ip = cJSON_GetObjectItemCaseSensitive(monitor_item, "ip");

        if (!cJSON_IsString(ip) && (ip->valuestring == NULL))
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_INVALID_IP_ADDRESS;
        }

        for (int j = i+1; j < monitor_count; ++j)
        {
            const cJSON *monitor_item2 = cJSON_GetArrayItem(monitor_array, j);
            const cJSON *ip2 = cJSON_GetObjectItemCaseSensitive(monitor_item2, "ip");

            if (!cJSON_IsString(ip2) && (ip2->valuestring == NULL))
            {
                destroy_client(client);
                cJSON_Delete(json);
                return PARSING_INVALID_IP_ADDRESS;
            }

            //Same IP asked in 2 different monitor object
            if(strcmp(ip->valuestring, ip2->valuestring) == 0)
            {
                destroy_client(client);
                cJSON_Delete(json);
                return PARSING_DUPLICATED_IP_ADDRESS;
            }
        }
    }

    char rawIpStorage_Temp[16];

    //For each ip:[ports] object
    for (int i = 0; i < monitor_count; ++i)
    {
        const cJSON *monitor_item = cJSON_GetArrayItem(monitor_array, i);
        const cJSON *ip = cJSON_GetObjectItemCaseSensitive(monitor_item, "ip");

        const int AF = strchr(ip->valuestring, ':') != 0?AF_INET6:AF_INET;

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
            return OUT_OF_MEMORY;
        }

        strcpy(client->ipPortInfo[i].ipStr, ip->valuestring);

        //Ports asked to be managed for the ip asked
        const cJSON *ports_array = cJSON_GetObjectItemCaseSensitive(monitor_item, "port");

        if (!cJSON_IsArray(ports_array))
        {
            destroy_client(client);
            cJSON_Delete(json);
            return PARSING_CJSON_ERROR;
        }

        const int port_count = cJSON_GetArraySize(ports_array);

        client->ipPortInfo[i].portCount = port_count;
        client->ipPortInfo[i].ports = NULL;

        //Parse each ports (if available)
        if(port_count != 0)
        {

            client->ipPortInfo[i].ports = (uint16_t *) malloc(port_count * sizeof(uint16_t));

            if(client->ipPortInfo[i].ports == NULL)
            {
                destroy_client(client);
                cJSON_Delete(json);
                return OUT_OF_MEMORY;
            }

            //For each port
            for (int j = 0; j < port_count; ++j) {
                const cJSON *port = cJSON_GetArrayItem(ports_array, j);

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
    }

    cJSON_Delete(json);
    return OK;
}

int verify_mac_format(const char *strMac)
{
    if (strlen(strMac) != 17)
        return 1;

    for (int i = 0; i < 17; i++) {
        const char c = strMac[i];
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