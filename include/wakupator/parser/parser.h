//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_PARSER_H
#define WAKUPATOR_PARSER_H

#include "wakupator/core/core.h"

WAKUPATOR_CODE create_client_from_json(const char *json_raw, client *client);

int verify_mac_format(const char *strMac);

#endif //WAKUPATOR_PARSER_H
