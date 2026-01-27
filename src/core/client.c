//
// Created by Nathan on 09/09/2024.
//
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "wakupator/core/client.h"
#include "wakupator/log/log.h"

void destroy_client(client *cl)
{
    for (int i = 0; i < cl->countIp; ++i)
    {
        free(cl->ipPortInfo[i].ipStr);
        free(cl->ipPortInfo[i].ports);
    }
    free(cl->ipPortInfo);

    memset(cl, 0, sizeof(client));
}

char *get_client_str_info(const client *cl)
{

    //Count allocation size needed
    size_t size = 0;

    size += snprintf(NULL, 0, "%s (%s)\n", cl->name, cl->macStr);
    size += snprintf(NULL, 0, "\tMonitored IP/port(s):\n");

    for (int i = 0; i < cl->countIp; ++i) {
        size += snprintf(NULL, 0, "\t\t- %s on port: [", cl->ipPortInfo[i].ipStr);

        for (int j = 0; j < cl->ipPortInfo[i].portCount; ++j)
        {
            if (j != cl->ipPortInfo[i].portCount - 1)
                size += snprintf(NULL, 0, "%d, ", cl->ipPortInfo[i].ports[j]);
            else //last one
                size += snprintf(NULL, 0, "%d", cl->ipPortInfo[i].ports[j]);
        }
        size += snprintf(NULL, 0, "]\n");
    }

    char *buffer = malloc(size + 1);

    if (!buffer) {
        log_error("Out of memory\n");
        return NULL;
    }

    size_t offset = snprintf(buffer, size + 1, "%s (%s)\n", cl->name, cl->macStr);
    offset += snprintf(buffer + offset, size + 1, "\tMonitored IP/port(s):\n");

    for (int i = 0; i < cl->countIp; ++i) {
        offset += snprintf(buffer + offset, size + 1 - offset, "\t\t- %s on port: [", cl->ipPortInfo[i].ipStr);

        for (int j = 0; j < cl->ipPortInfo[i].portCount; ++j)
        {
            if (j != cl->ipPortInfo[i].portCount - 1)
                offset += snprintf(buffer + offset, size + 1 - offset, "%d, ", cl->ipPortInfo[i].ports[j]);
            else //last one
                offset += snprintf(buffer + offset, size + 1 - offset, "%d", cl->ipPortInfo[i].ports[j]);
        }
        offset += snprintf(buffer + offset, size + 1 - offset, "]\n");
    }

    return buffer;
}
