#include "wakupator/utils/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#define BUFFER_SIZE 8192

typedef enum {
    IP_OP_ADD,
    IP_OP_REMOVE
} ip_operation_t;

int modify_ip_on_interface(const char* ifName, const char* ip_str, const ip_operation_t operation) {

    const int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Error while creating raw socket for Netlink.");
        return -1;
    }

    //Bind to NetLink
    struct sockaddr_nl local = {
        .nl_family = AF_NETLINK
    };

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        perror("Error while binding raw socket for Netlink.");
        close(sock);
        return -1;
    }

    char buf[BUFFER_SIZE] = {0};

    //NetLink header
    struct nlmsghdr *nlh = (struct nlmsghdr*) buf;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)(buf + sizeof(struct nlmsghdr));

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    if (operation == IP_OP_ADD) {
        nlh->nlmsg_type = RTM_NEWADDR;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    } else {  // IP_OP_REMOVE
        nlh->nlmsg_type = RTM_DELADDR;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    }

    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    ifa->ifa_family = strchr(ip_str, ':') ? AF_INET6 : AF_INET;
    ifa->ifa_prefixlen = (ifa->ifa_family == AF_INET) ? 32 : 128;
    ifa->ifa_scope = 0;
    ifa->ifa_index = if_nametoindex(ifName);

    if (ifa->ifa_index == 0) {
        fprintf(stderr, "Invalid interface name: %s.\n", ifName);
        close(sock);
        return -1;
    }

    // IP struct
    void* addr_buf = NULL;
    int addr_len = 0;

    if (ifa->ifa_family == AF_INET) {
        struct in_addr* ip = malloc(sizeof(struct in_addr));
        if (inet_pton(AF_INET, ip_str, ip) != 1) {
            fprintf(stderr, "Invalid IPv4 address: %s.\n", ip_str);
            free(ip);
            close(sock);
            return -1;
        }
        addr_buf = ip;
        addr_len = sizeof(struct in_addr);
    } else {
        struct in6_addr* ip6 = malloc(sizeof(struct in6_addr));
        if (inet_pton(AF_INET6, ip_str, ip6) != 1) {
            fprintf(stderr, "Invalid IPv6 address: %s.\n", ip_str);
            free(ip6);
            close(sock);
            return -1;
        }
        addr_buf = ip6;
        addr_len = sizeof(struct in6_addr);
    }

    //Prepare RTA struct and copy IP binary
    struct rtattr *rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(addr_len);
    memcpy(RTA_DATA(rta), addr_buf, addr_len);
    free(addr_buf);

    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_LENGTH(addr_len);

    //If IPv6 and adding, disable DAD for this IP and adjust header len
    if (ifa->ifa_family == AF_INET6 && operation == IP_OP_ADD) {
        struct rtattr* rta_flags = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
        const uint32_t flags = IFA_F_NODAD;

        rta_flags->rta_type = IFA_FLAGS;
        rta_flags->rta_len = RTA_LENGTH(sizeof(uint32_t));
        memcpy(RTA_DATA(rta_flags), &flags, sizeof(uint32_t));

        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_LENGTH(sizeof(uint32_t));
    }

    // Prepare to send
    struct sockaddr_nl kernel = {
        .nl_family = AF_NETLINK
    };

    struct iovec iov = {
        .iov_base = nlh,
        .iov_len = nlh->nlmsg_len
    };

    const struct msghdr msg = {
        .msg_name = &kernel,
        .msg_namelen = sizeof(kernel),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    // Send message
    if (sendmsg(sock, &msg, 0) < 0) {
        perror("Error while sending the message to Netlink");
        close(sock);
        return -1;
    }

    // "Control" ACK
    const ssize_t len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) {
        perror("Error while receiving the message to Netlink");
        close(sock);
        return -1;
    }

    struct nlmsghdr *h = (struct nlmsghdr*) buf;
    //Should be all the time true (because of ACK asked)
    if (h->nlmsg_type == NLMSG_ERROR) {
        const struct nlmsgerr *err = NLMSG_DATA(h);
        //True error ?
        if (err->error) {
            const char* op_name = (operation == IP_OP_ADD) ? "adding" : "removing";
            fprintf(stderr, "Error while %s IP: %s\n", op_name, strerror(-err->error));
            close(sock);
            return -1;
        }
    }

    close(sock);
    return 0;
}

int add_ip(const char* ifName, const char* ip_str) {
    return modify_ip_on_interface(ifName, ip_str, IP_OP_ADD);
}

int remove_ip(const char* ifName, const char* ip_str){
    return modify_ip_on_interface(ifName, ip_str, IP_OP_REMOVE);
}

int check_ipv4_exists(const char *ip_str, ip_search_result_t *result) {
    int sock;
    struct sockaddr_nl sa;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;
    char buffer[BUFFER_SIZE];
    ssize_t len;
    struct nlmsghdr *nlh;
    struct in_addr target_addr;

    if (result) {
        result->found = 0;
        result->ifindex = -1;
        memset(result->ifname, 0, sizeof(result->ifname));
    }else
        return -1;

    if (inet_pton(AF_INET, ip_str, &target_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ip_str);
        return -1;
    }

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Error while creating raw socket for Netlink.");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Error while binding raw socket for Netlink.");
        close(sock);
        return -1;
    }

    // Prepare request RTM_GETADDR
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.ifa.ifa_family = AF_INET;

    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("Error while sending request to Netlink.");
        close(sock);
        return -1;
    }

    // Loop through all response
    while (1) {
        len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("Error while receiving request response from Netlink");
            close(sock);
            return -1;
        }

        if (len == 0) {
            break;
        }

        // Parsing
        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {

            //End
            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return result->found;
            }

            //Error
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Error Netlink\n");
                close(sock);
                return -1;
            }

            if (nlh->nlmsg_type != RTM_NEWADDR) {
                continue;
            }

            struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
            struct rtattr *rta = IFA_RTA(ifa);
            int rtl = IFA_PAYLOAD(nlh);

            // Parsing attributes
            while (RTA_OK(rta, rtl)) {
                if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
                    struct in_addr *addr = (struct in_addr *)RTA_DATA(rta);

                    // Compare with target IP
                    if (memcmp(addr, &target_addr, sizeof(struct in_addr)) == 0) {
                        result->found = 1;
                        result->ifindex = ifa->ifa_index;
                        if_indextoname(ifa->ifa_index, result->ifname);
                        close(sock);
                        return 1; //Founded
                    }
                }
                rta = RTA_NEXT(rta, rtl);
            }
        }
    }

    close(sock);
    return 0;
}

int check_ipv6_exists(const char *ip_str, ip_search_result_t *result) {
    int sock;
    struct sockaddr_nl sa;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;
    char buffer[BUFFER_SIZE];
    ssize_t len;
    struct nlmsghdr *nlh;
    struct in6_addr target_addr;

    if (inet_pton(AF_INET6, ip_str, &target_addr) != 1) {
        fprintf(stderr, "Invalid IPv6 address: %s\n", ip_str);
        return -1;
    }

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Error while creating raw socket for Netlink.");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Error while binding raw socket for Netlink.");
        close(sock);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.ifa.ifa_family = AF_INET6;

    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("Error while sending request to Netlink.");
        close(sock);
        return -1;
    }

    if (result) {
        result->found = 0;
        result->ifindex = -1;
        memset(result->ifname, 0, sizeof(result->ifname));
    }

    while (1) {
        len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("Error while receiving request to Netlink.");
            close(sock);
            return -1;
        }

        if (len == 0) {
            break;
        }

        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return result ? result->found : 0;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Error Netlink\n");
                close(sock);
                return -1;
            }

            if (nlh->nlmsg_type != RTM_NEWADDR) {
                continue;
            }

            struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
            struct rtattr *rta = IFA_RTA(ifa);
            int rtl = IFA_PAYLOAD(nlh);

            while (RTA_OK(rta, rtl)) {
                if (rta->rta_type == IFA_ADDRESS) {
                    struct in6_addr *addr = (struct in6_addr *)RTA_DATA(rta);

                    if (memcmp(addr, &target_addr, sizeof(struct in6_addr)) == 0) {
                        if (result) {
                            result->found = 1;
                            result->ifindex = ifa->ifa_index;
                            if_indextoname(ifa->ifa_index, result->ifname);
                        }
                        close(sock);
                        return 1;
                    }
                }
                rta = RTA_NEXT(rta, rtl);
            }
        }
    }

    close(sock);
    return 0;
}

/**
 *
 * @param ip_str Char format of the target IP
 * @param result Struct filled to store the result
 * @return -1 if error, 0 if not found and 1 if found
 */
int check_ip_exists(const char *ip_str, ip_search_result_t *result) {
    if (strchr(ip_str, ':') != NULL) {
        return check_ipv6_exists(ip_str, result);
    } else {
        return check_ipv4_exists(ip_str, result);
    }
}