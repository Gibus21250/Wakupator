#pragma once
#include <stdint.h>
#include <sys/types.h>

/* Inject 'pkt' through veth1 and check that the filtered socket 'rx'
 * receives exactly this packet. 'what' is the message to describe what is currently tested.
 */
void wk_expect_captured(int tx, int rx, const char *what,
                        const uint8_t *pkt, ssize_t len);

/* Inject 'bad', then 'good'. The first packet received must be 'good':
 * Sending 'bad' first, proves that it was dropped by the filter.
 */
void wk_expect_dropped(int tx, int rx, const char *what,
                       const uint8_t *bad, ssize_t nbad,
                       const uint8_t *good, ssize_t ngood);