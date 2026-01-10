#ifndef NET_H
#define NET_H
#include <net/if.h>
#include <stdint.h>

int add_ip(const char* ifName, const char* ip_str);
int remove_ip(const char* ifName, const char* ip_str);

typedef struct {
    int found;
    char ifname[IFNAMSIZ];
    uint32_t ifindex;
} ip_search_result_t;

int check_ip_exists(const char *ip_str, ip_search_result_t *result);

#endif //NET_H
