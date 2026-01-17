//
// Created by Nathan on 02/09/2024.
//

#ifndef WAKUPATOR_MONITOR_H
#define WAKUPATOR_MONITOR_H

#include "wakupator/core/manager.h"

typedef struct main_monitor_args {
    manager *managerMain;               //Pointer to the manager struct
    client *client;                     //Pointer to the client
    WAKUPATOR_CODE *wakupator_code;     //Pointer to return code (! invalid just before the main while)
} main_monitor_args;

void *main_client_monitoring(void* args);

int create_raw_filtered_socket(const ip_port_info *ipPortInfo);

int create_raw_socket_arp_ns(const char macStr[18]);

struct sock_fprog create_bpf_filter(const ip_port_info *ipPortInfo);

void spoof_ips(const manager *mng, const client *cl);
void remove_ips(const manager *mng, const client *cl);

int verify_ips(const client *cl);

void wake_up(int rawSocket, int ifIndex, const char *macStr);

#endif //WAKUPATOR_MONITOR_H
