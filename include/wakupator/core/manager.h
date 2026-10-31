#ifndef WAKUPATOR_MANAGER_H
#define WAKUPATOR_MANAGER_H
#include <stdint.h>
#include <bits/pthreadtypes.h>
#include <netinet/in.h>

#include "client.h"
#include "core.h"

typedef struct client_thread_monitor_info {
    client cl;
    pthread_t thread;
} thread_monitor_info;

typedef struct manager {

    // ------ Self filled Data ------

        //All clients infos
        uint32_t client_capacity;                    //Size of the client buffer
        uint32_t client_count;                       //Number of client monitored identified by mac address
        thread_monitor_info *client_thread_infos;    //Array of all client thread info

        pthread_mutex_t lock;                        //Lock used when manipulating the struct
        pthread_mutex_t registering_mutex;           //Mutex used by master and child thread when init the monitoring thread
        pthread_cond_t registering_cond;             //Cond used by master and child thread when init the monitoring thread
        int notify[2];                               //Pipe used to unlock all client's thread

        //Manager options
        int main_raw_socket;                         //Raw socket used by threads to send raw packets (WoL, arp, NS etc)
        int if_index;                                //Index of the interface
        const char *if_name;                         //Char* name of the interface
        uint8_t if_mac_raw[6];                       //Raw mac address of the manager interface

        //IPv6
        struct in6_addr if_ipv6_link_local;           //IPv6 LL Address
        uint8_t has_ipv6;                             //Has IPv6
        int mld_socket;                               //IPv6 DGRAM socket used to (un)subscribe MLD
        mld_member_info *mld_members;                 //Array to keep traces of which multicast IPv6 are registered
        uint32_t mld_capacity;                        //Capacity of the mld buffer
        uint32_t mld_count;                           //Number of different multicast IPv6 subscribed

    // ------ Manually filled Data ------

    // Wake up parameters
    uint8_t wol_keep_client;                      //What to do when the machine didn't seems to start after nbAttempt
    uint16_t wol_max_attempts;                    //Number of WoL attempt to wake up the machine
    uint32_t wol_delay;                           //Time in seconds between each WoL attempt

    // Shutdown parameters
    uint32_t shutdown_timeout;                    //Timeout in seconds waiting the machine to shut down
    uint32_t shutdown_probe_interval;             //Interval between each ARP/NS probe

} manager;

WAKUPATOR_CODE init_manager(manager *manager, const char* ifName);
void destroy_manager(manager *mng_client);

wakupator_code init_manager(manager *manager, const char* if_name);
void destroy_manager(manager *manager);

wakupator_code register_client(manager *manager, client *new_client);
wakupator_code unregister_client(manager *manager, const char* str_mac);

// ------     MLD IPv6      ------
wakupator_code add_mld_member(manager *manager, struct in6_addr addr);
wakupator_code remove_mld_member(manager *manager, struct in6_addr addr);

#endif //WAKUPATOR_MANAGER_H