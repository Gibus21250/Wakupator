//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_PARSER_H
#define WAKUPATOR_PARSER_H

#include "core.h"

typedef enum CLIENT_PARSING_CODE {
    PARSING_OK = 0,
    PARSING_CJSON_ERROR,
    PARSING_INVALID_MAC_ADDRESS,
    PARSING_INVALID_IP_ADDRESS,
    PARSING_INVALID_PORT,
    PARSING_OUT_OF_MEMORY
} CLIENT_PARSING_CODE;

CLIENT_PARSING_CODE parse_from_json(const char *json_raw, client *client);
const char* get_parser_error(CLIENT_PARSING_CODE code);

int verify_mac_format(const char *strMac);

#endif //WAKUPATOR_PARSER_H
