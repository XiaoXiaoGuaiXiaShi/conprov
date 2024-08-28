#ifndef __UTILS_H
#define __UTILS_H

#include <stdint.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <zlib.h>
#include <arpa/inet.h>
#include <stddef.h>
#include "shared/prov_struct.h"

#define LSM_LIST "/sys/kernel/security/lsm"

// 字符串转数字
long String2Int(char *str);

#define hexifyBound(in) (in * 2 + 1)
size_t hexify(uint8_t *in, size_t in_size, char *out, size_t out_size);
#define encode64Bound(in) (4 * ((in + 2) / 3) + 1)
int base64encode(const void *data_buf, size_t dataLength, char *result, size_t resultSize);

#define PROV_ID_STR_LEN encode64Bound(PROV_IDENTIFIER_BUFFER_LENGTH)
#define ID_ENCODE base64encode
#define TAINT_ENCODE hexify
#define TAINT_STR_LEN hexifyBound(PROV_N_BYTES)

#define DECIMAL 10
#define OCTAL 8
#define HEX 16
char *ulltoa(uint64_t value, char *string, int radix);
char *utoa(uint32_t value, char *string, int radix);
char *itoa(int32_t a, char *string, int radix);
char *lltoa(int64_t a, char *string, int radix);

// just wrap inet_pton
static inline uint32_t ipv4str_to_uint32(const char *str)
{
    struct in_addr addr;
    inet_pton(AF_INET, str, &addr);
    return (uint32_t)addr.s_addr;
}

static __thread char __addr[INET_ADDRSTRLEN];
// just wrap inet_ntop
static inline const char *uint32_to_ipv4str(uint32_t v)
{
    inet_ntop(AF_INET, &v, __addr, INET_ADDRSTRLEN);
    return __addr;
}

union mask
{
    uint32_t value;
    uint8_t buffer[4];
};

#define reverse_byte(b) (b * 0x0202020202ULL & 0x010884422010ULL) % 1023

static inline uint32_t uint32_to_ipv4mask(uint32_t n)
{
    int i;
    union mask m;
    if (n > 32)
    {
        return 0xFFFFFFFF;
    }

    m.value = (uint32_t)(((uint64_t)1 << n) - 1);
    for (i = 0; i < 4; i++)
    {
        m.buffer[i] = reverse_byte(m.buffer[i]);
    }
    return m.value;
}

static inline uint8_t count_set_bits(uint32_t n)
{
    uint8_t count = 0;
    while (n)
    {
        count += n & 1;
        n >>= 1;
    }
    return count;
}

// from http://creativeandcritical.net/str-replace-c
static inline char *repl_str(const char *str, const char *from, const char *to)
{

    /* Adjust each of the below values to suit your needs. */

    /* Increment positions cache size initially by this number. */
    size_t cache_sz_inc = 16;
    /* Thereafter, each time capacity needs to be increased,
     * multiply the increment by this factor. */
    const size_t cache_sz_inc_factor = 3;
    /* But never increment capacity by more than this number. */
    const size_t cache_sz_inc_max = 1048576;

    char *pret;
    char *ret = NULL;
    const char *pstr2;
    const char *pstr = str;
    size_t i;
    size_t count = 0;
    size_t *pos_cache_tmp;
    size_t *pos_cache = NULL;
    size_t cache_sz = 0;
    size_t cpylen;
    size_t orglen;
    size_t retlen;
    size_t tolen;
    size_t fromlen = strlen(from);

    /* Find all matches and cache their positions. */
    while ((pstr2 = strstr(pstr, from)) != NULL)
    {
        count++;

        /* Increase the cache size when necessary. */
        if (cache_sz < count)
        {
            cache_sz += cache_sz_inc;
            pos_cache_tmp = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
            if (pos_cache_tmp == NULL)
            {
                goto end_repl_str;
            }
            else
                pos_cache = pos_cache_tmp;
            cache_sz_inc *= cache_sz_inc_factor;
            if (cache_sz_inc > cache_sz_inc_max)
            {
                cache_sz_inc = cache_sz_inc_max;
            }
        }

        pos_cache[count - 1] = pstr2 - str;
        pstr = pstr2 + fromlen;
    }

    orglen = pstr - str + strlen(pstr);

    /* Allocate memory for the post-replacement string. */
    if (count > 0)
    {
        tolen = strlen(to);
        retlen = orglen + (tolen - fromlen) * count;
    }
    else
        retlen = orglen;
    ret = malloc(retlen + 1);
    if (ret == NULL)
    {
        goto end_repl_str;
    }

    if (count == 0)
    {
        /* If no matches, then just duplicate the string. */
        strcpy(ret, str);
    }
    else
    {
        /* Otherwise, duplicate the string whilst performing
         * the replacements using the position cache. */
        pret = ret;
        memcpy(pret, str, pos_cache[0]);
        pret += pos_cache[0];
        for (i = 0; i < count; i++)
        {
            memcpy(pret, to, tolen);
            pret += tolen;
            pstr = str + pos_cache[i] + fromlen;
            cpylen = (i == count - 1 ? orglen : pos_cache[i + 1]) - pos_cache[i] - fromlen;
            memcpy(pret, pstr, cpylen);
            pret += cpylen;
        }
        ret[retlen] = '\0';
    }

end_repl_str:
    /* Free the cache and return the post-replacement string,
     * which will be NULL in the event of an error. */
    free(pos_cache);
    return ret;
}

#endif