#include "test_expect.h"
#include "test_env.h"
#include "test_pkt.h"

#include <string.h>

#include "wk_test.h"

static void inject(int tx, const char *what, const uint8_t *pkt, ssize_t len)
{
    if (len <= 0 || wk_send(tx, WK_VETH_B, pkt, len) != 0)
        WK_FAIL("[%s] cannot inject the packet", what);
}

void wk_expect_captured(int tx, int rx, const char *what, const uint8_t *pkt, ssize_t len)
{
    uint8_t got[2048];
    wk_drain(rx);
    inject(tx, what, pkt, len);

    ssize_t n = wk_recv(rx, got, sizeof got, 300);
    if (n <= 0)
        WK_FAIL("[%s] expected the packet to be captured, got nothing", what);
    if (n != len || memcmp(got, pkt, len) != 0)
        WK_FAIL("[%s] captured a packet different from the one sent", what);
    WK_LOG("captured : %s", what);
}

void wk_expect_dropped(int tx, int rx, const char *what, const uint8_t *bad, ssize_t nbad,
                       const uint8_t *good, ssize_t ngood)
{
    uint8_t got[2048];
    wk_drain(rx);
    inject(tx, what, bad, nbad);
    inject(tx, what, good, ngood);

    ssize_t n = wk_recv(rx, got, sizeof got, 300);
    if (n <= 0)
        WK_FAIL("[%s] the reference packet was not captured (filter or env broken)", what);
    if (n != ngood || memcmp(got, good, ngood) != 0)
        WK_FAIL("[%s] expected to be dropped, but it was captured", what);
    WK_LOG("dropped  : %s", what);
}