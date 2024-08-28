#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "usr/utils.h"

long String2Int(char *str)
{
    char flag = '+';
    long res = 0;

    if (*str == '-')
    {
        ++str;      
        flag = '-'; 
    }
    while (*str >= 48 && *str <= 57)
    {
        res = 10 * res + *str++ - 48; 
    }

    if (flag == '-') 
    {
        res = -res;
    }

    return res;
}

static const char map[16 + 1] = "0123456789ABCDEF";

size_t hexify(uint8_t *in, size_t in_size, char *out, size_t out_size)
{
    if (in_size == 0 || out_size == 0)
        return 0;

    size_t bytes_written = 0;
    size_t i = 0;
    while (i < in_size && (i * 2 + (2 + 1)) <= out_size)
    {
        uint8_t high_nibble = (in[i] & 0xF0) >> 4;
        *out = map[high_nibble];
        out++;

        uint8_t low_nibble = in[i] & 0x0F;
        *out = map[low_nibble];
        out++;

        i++;

        bytes_written += 2;
    }
    *out = '\0';

    return bytes_written;
}

static const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// from https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64#C
int base64encode(const void *data_buf, size_t dataLength, char *result, size_t resultSize)
{
    const uint8_t *data = (const uint8_t *)data_buf;
    size_t resultIndex = 0;
    size_t x;
    uint32_t n = 0;
    int padCount = dataLength % 3;
    uint8_t n0;
    uint8_t n1;
    uint8_t n2;
    uint8_t n3;

    /* increment over the length of the string, three characters at a time */
    for (x = 0; x < dataLength; x += 3)
    {
        /* these three 8-bit (ASCII) characters become one 24-bit number */
        n = ((uint32_t)data[x]) << 16; // parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

        if ((x + 1) < dataLength)
            n += ((uint32_t)data[x + 1]) << 8; // parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

        if ((x + 2) < dataLength)
            n += data[x + 2];

        /* this 24-bit number gets separated into four 6-bit numbers */
        n0 = (uint8_t)(n >> 18) & 63;
        n1 = (uint8_t)(n >> 12) & 63;
        n2 = (uint8_t)(n >> 6) & 63;
        n3 = (uint8_t)n & 63;

        /*
         * if we have one byte available, then its encoding is spread
         * out over two characters
         */
        if (resultIndex >= resultSize)
            return 1; /* indicate failure: buffer too small */
        result[resultIndex++] = base64chars[n0];
        if (resultIndex >= resultSize)
            return 1; /* indicate failure: buffer too small */
        result[resultIndex++] = base64chars[n1];

        /*
         * if we have only two bytes available, then their encoding is
         * spread out over three chars
         */
        if ((x + 1) < dataLength)
        {
            if (resultIndex >= resultSize)
                return 1; /* indicate failure: buffer too small */
            result[resultIndex++] = base64chars[n2];
        }

        /*
         * if we have all three bytes available, then their encoding is spread
         * out over four characters
         */
        if ((x + 2) < dataLength)
        {
            if (resultIndex >= resultSize)
                return 1; /* indicate failure: buffer too small */
            result[resultIndex++] = base64chars[n3];
        }
    }

    /*
     * create and add padding that is required if we did not have a multiple of 3
     * number of characters available
     */
    if (padCount > 0)
    {
        for (; padCount < 3; padCount++)
        {
            if (resultIndex >= resultSize)
                return 1; /* indicate failure: buffer too small */
            result[resultIndex++] = '=';
        }
    }
    if (resultIndex >= resultSize)
        return -1; /* indicate failure: buffer too small */
    result[resultIndex] = 0;
    return 0; /* indicate success */
}

char *ulltoa(uint64_t value, char *string, int radix)
{
    char *dst;
    char digits[65];
    int i;
    int n;

    dst = string;
    if (radix < 2 || radix > 36)
    {
        *dst = 0;
        return (string);
    }
    i = 0;
    do
    {
        n = value % radix;
        digits[i++] = (n < 10 ? (char)n + '0' : (char)n - 10 + 'a');
        value /= radix;
    } while (value != 0);
    while (i > 0)
        *dst++ = digits[--i];
    *dst = 0;
    return (string);
}

char *utoa(uint32_t value, char *string, int radix)
{
    char *dst;
    char digits[33];
    int i;
    int n;

    dst = string;
    if (radix < 2 || radix > 36)
    {
        *dst = 0;
        return (string);
    }
    i = 0;
    do
    {
        n = value % radix;
        digits[i++] = (n < 10 ? (char)n + '0' : (char)n - 10 + 'a');
        value /= radix;
    } while (value != 0);
    while (i > 0)
        *dst++ = digits[--i];
    *dst = 0;
    return (string);
}

/**
 * C++ version 0.4 char* style "itoa":
 * Written by Lukás Chmela
 * Released under GPLv3.
 */
char *itoa(int32_t value, char *result, int base)
{
    // check that the base if valid
    if (base < 2 || base > 36)
    {
        *result = '\0';
        return result;
    }

    char *ptr = result;
    char *ptr1 = result;
    char tmp_char;
    int32_t tmp_value;

    do
    {
        tmp_value = value;
        value /= base;
        *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
    } while (value);

    // Apply negative sign
    if (tmp_value < 0)
        *ptr++ = '-';
    *ptr-- = '\0';
    while (ptr1 < ptr)
    {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    return result;
}

char *lltoa(int64_t value, char *result, int base)
{
    // check that the base if valid
    if (base < 2 || base > 36)
    {
        *result = '\0';
        return result;
    }

    char *ptr = result;
    char *ptr1 = result;
    char tmp_char;
    int64_t tmp_value;

    do
    {
        tmp_value = value;
        value /= base;
        *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
    } while (value);

    // Apply negative sign
    if (tmp_value < 0)
        *ptr++ = '-';
    *ptr-- = '\0';
    while (ptr1 < ptr)
    {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    return result;
}
