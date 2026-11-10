//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_PARSER_H
#define WAKUPATOR_PARSER_H

#include "wakupator/core/core.h"
#include "wakupator/core/client.h"

wakupator_code create_client_from_json(const char *json_raw, client *client);

int verify_mac_format(const char *str_mac);

#endif //WAKUPATOR_PARSER_H
