#define _GNU_SOURCE
#include "test_pkt.h"
#include <string.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bits/time.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "wakupator/net/net.h"

ssize_t wk_pkt_arp(uint8_t *buf, size_t cap, uint16_t op, const uint8_t src_mac[6],
                   const char *sender_ip, const char *target_ip)
{
    size_t total = sizeof(struct ethhdr) + sizeof(struct ether_arp);
    if (total > cap) return -1;

    struct ethhdr *eth = (struct ethhdr *)buf;
    memset(eth->h_dest, 0xff, 6);                 /* broadcast */
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(eth + 1);
    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETH_P_IP);
    arp->arp_hln = 6;
    arp->arp_pln = 4;
    arp->arp_op  = htons(op);
    memcpy(arp->arp_sha, src_mac, 6);
    inet_pton(AF_INET, sender_ip, arp->arp_spa);
    memset(arp->arp_tha, 0, 6);
    inet_pton(AF_INET, target_ip, arp->arp_tpa);
    return (ssize_t)total;
}

ssize_t wk_pkt_ns(uint8_t *buf, size_t cap, const uint8_t src_mac[6],
                  const char *src_ip6, const char *target_ip6)
{
    /* 4 (type, code, checksum) + 4 (reserved) + 16 (target) + 8 (SLLA option) */
    enum { ICMP_LEN = 32 };
    const size_t total = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + ICMP_LEN;
    if (total > cap) return -1;

    struct in6_addr src, target, dst = {0};
    inet_pton(AF_INET6, src_ip6, &src);
    inet_pton(AF_INET6, target_ip6, &target);

    /* Solicited-node multicast: ff02::1:ffXX:XXXX (XX:XXXX = last 24 bits of target) */
    dst.s6_addr[0] = 0xff; dst.s6_addr[1] = 0x02;
    dst.s6_addr[11] = 0x01; dst.s6_addr[12] = 0xff;
    memcpy(&dst.s6_addr[13], &target.s6_addr[13], 3);

    struct ethhdr *eth = (struct ethhdr *)buf;
    eth->h_dest[0] = 0x33; eth->h_dest[1] = 0x33; eth->h_dest[2] = 0xff;
    memcpy(&eth->h_dest[3], &target.s6_addr[13], 3);   /* multicast MAC */
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IPV6);

    struct ip6_hdr *ip6 = (struct ip6_hdr *)(eth + 1);
    memset(ip6, 0, sizeof *ip6);
    ip6->ip6_vfc  = 0x60;
    ip6->ip6_plen = htons(ICMP_LEN);
    ip6->ip6_nxt  = IPPROTO_ICMPV6;
    ip6->ip6_hlim = 255;
    ip6->ip6_src  = src;
    ip6->ip6_dst  = dst;

    uint8_t *icmp = (uint8_t *)(ip6 + 1);
    memset(icmp, 0, ICMP_LEN);
    icmp[0] = ND_NEIGHBOR_SOLICIT;          /* 135 */
    memcpy(icmp + 8, &target, 16);
    icmp[24] = 1; //option: source LLA
    icmp[25] = 1; //option length
    memcpy(icmp + 26, src_mac, 6);

    uint16_t sum = htons(icmp6_checksum(&src, &dst, icmp, ICMP_LEN));
    memcpy(icmp + 2, &sum, 2);
    return (ssize_t)total;
}

static int open_bound(const char *ifname, uint16_t proto)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(proto));
    if (fd < 0) return -1;
    struct sockaddr_ll sll = { .sll_family   = AF_PACKET,
                               .sll_protocol = htons(proto),
                               .sll_ifindex  = (int) if_nametoindex(ifname) };
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) { close(fd); return -1; }
    return fd;
}

int wk_open_tx(const char *ifname) { return open_bound(ifname, 0); }
int wk_open_rx(const char *ifname, uint16_t ethertype) { return open_bound(ifname, ethertype); }

int wk_send(int fd, const char *ifname, const void *buf, size_t len)
{
    struct sockaddr_ll sll = { .sll_family = AF_PACKET,
                               .sll_ifindex = (int) if_nametoindex(ifname) };
    return sendto(fd, buf, len, 0, (struct sockaddr *)&sll, sizeof sll)
           == (ssize_t)len ? 0 : -1;
}

ssize_t wk_recv_ex(int fd, void *buf, size_t cap, int timeout_ms, int keep_outgoing)
{
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, timeout_ms);
        if (r == 0) return 0;
        if (r < 0)  return -1;
        struct sockaddr_ll sll; socklen_t sl = sizeof sll;
        ssize_t n = recvfrom(fd, buf, cap, 0, (struct sockaddr *)&sll, &sl);
        if (n < 0) return -1;
        if (!keep_outgoing && sll.sll_pkttype == PACKET_OUTGOING) continue;
        return n;
    }
}

static long now_ms(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

ssize_t wk_recv_match(int fd, void *buf, size_t cap, int timeout_ms,
                      wk_pred_fn pred, void *ctx)
{
    const long deadline = now_ms() + timeout_ms;
    for (;;) {
        long left = deadline - now_ms();
        if (left < 0) left = 0;
        ssize_t n = wk_recv(fd, buf, cap, (int)left);
        if (n <= 0) return n;
        if (pred(buf, (size_t)n, ctx)) return n;
        if (left == 0) return 0;
    }
}

ssize_t wk_recv(int fd, void *buf, size_t cap, int timeout_ms)
{
    return wk_recv_ex(fd, buf, cap, timeout_ms, 0);
}

void wk_drain(int fd)
{
    uint8_t tmp[2048];
    while (wk_recv(fd, tmp, sizeof tmp, 0) > 0) {}
}