#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "wakupator/net/net.h"

/*
 * Notes:
 * "endianness is the order in which bytes within a word data type" (Wikipedia)
 * Network words are in Big endian. (words mean "value larger than one byte")
 * e.g:
 * The value byte (uint8_t): 113 (0x71). In memory, the value is the same independently of endianness.
 * The value short (uint16_t): 4660 (0x1234). In memory, value is store differently dependently of the endianness:
 * - little endian: memory view: 0x3412 (meaning, the least significant byte first)
 * - big endian: memory view: 0x1234 (meaning, the most significant byte first)
*/

//Convert the ck in host to network endianness (Big endian), and memcpy it into icmp fake layer
static void put_checksum(uint8_t *icmp, const uint16_t ck_host)
{
    const uint16_t be = htons(ck_host);
    memcpy(icmp + 2, &be, 2);
}

int main(void)
{
    struct in6_addr lo = IN6ADDR_LOOPBACK_INIT;

    //Fake icmp. Byte per byte:
    //(type)
    //(code)
    //(Checksum[0])
    //(Checksum[1])
    //Content... "random" here
    uint8_t icmp[8] = {128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01};

    /* Host endianness */
    const uint16_t ck = icmp6_checksum(&lo, &lo, icmp, sizeof icmp);
    assert(ck == 0x6D86);

    /* Compare ck memcpy into icmp */
    put_checksum(icmp, ck);
    assert(icmp[2] == 0x6D && icmp[3] == 0x86);

    /* checksum(checksum(X)) == 0 */
    assert(icmp6_checksum(&lo, &lo, icmp, sizeof icmp) == 0);

    /* 4. Odd length */
    uint8_t odd[9] = {128, 0, 0, 0, 1, 2, 3, 4, 5};
    put_checksum(odd, icmp6_checksum(&lo, &lo, odd, sizeof odd));
    assert(icmp6_checksum(&lo, &lo, odd, sizeof odd) == 0);

    /* 5. Unaligned buffer */
    uint8_t raw[16] = {0};
    uint8_t *un = raw + 1;
    memcpy(un, icmp, sizeof icmp);
    un[2] = un[3] = 0;
    assert(icmp6_checksum(&lo, &lo, un, sizeof icmp) == ck);
    return 0;
}