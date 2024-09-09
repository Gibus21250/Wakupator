//
// Created by Nathan on 09/09/2024.
//
#include <stdlib.h>
#include <string.h>

#include "client.h"

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
