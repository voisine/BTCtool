//
//  ZNBase58.c
//  zinc
//
//  Created by Aaron Voisine on 9/15/15.
//

#include "ZNBase58.h"
#include "ZNCrypto.h"
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// base58 and base58check encoding: https://en.bitcoin.it/wiki/Base58Check_encoding

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t ZNBase58Encode(char *str, size_t strLen, const uint8_t *data, size_t dataLen)
{
    static char chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t i, j, len, zcount = 0, bufLen = dataLen*138/100 + 1;
    uint8_t _buf[0x1000], *buf = (bufLen <= 0x1000) ? _buf : malloc(bufLen);
    unsigned carry;
    
    assert(data != NULL);
    while (zcount < dataLen && data && data[zcount] == 0) zcount++; // count leading zeroes
    bufLen = (dataLen - zcount)*138/100 + 1; // log(256)/log(58), rounded up
    memset(buf, 0, bufLen);
    
    for (i = zcount; data && i < dataLen; i++) {
        carry = data[i];
        
        for (j = bufLen; j > 0; j--) {
            carry += (unsigned)buf[j - 1] << 8;
            buf[j - 1] = carry % 58;
            carry /= 58;
        }
        
        zn_mem_clean(&carry, sizeof(carry));
    }
    
    i = 0;
    while (i < bufLen && buf[i] == 0) i++; // skip leading zeroes
    len = (zcount + bufLen - i) + 1;

    if (str && len <= strLen) {
        while (zcount-- > 0) *(str++) = chars[0];
        while (i < bufLen) *(str++) = chars[buf[i++]];
        *str = '\0';
    }
    
    zn_mem_clean(buf, bufLen);
    if (buf != _buf) free(buf);
    return (! str || len <= strLen) ? len : 0;
}

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t ZNBase58Decode(uint8_t *data, size_t dataLen, const char *str)
{
    static const int8_t map[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
                                  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
                                  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
                                  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
                                  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1 };
    size_t i = 0, j, len, zcount = 0, bufLen = (str) ? strlen(str)*733/1000 + 1 : 0;
    uint8_t _buf[0x1000], *buf = (bufLen <= 0x1000) ? _buf : malloc(bufLen);
    int carry;
    
    assert(str != NULL);
    while (str && str[zcount] == '1') zcount++; // count leading zeroes
    if (str) str += zcount;
    bufLen = (str) ? strlen(str)*733/1000 + 1 : 0; // log(58)/log(256), rounded up
    memset(buf, 0, bufLen);
    
    while (str && *str) {
        carry = ((size_t)*str < sizeof(map)) ? map[*(str++)] : -1;
        if (carry == -1) break; // invalid base58 digit
        
        for (j = bufLen; j > 0; j--) {
            carry += (int)buf[j - 1]*58;
            buf[j - 1] = carry & 0xff;
            carry >>= 8;
        }
        
        zn_mem_clean(&carry, sizeof(carry));
    }
    
    while (i < bufLen && buf[i] == 0) i++; // skip leading zeroes
    len = zcount + bufLen - i;

    if (data && len <= dataLen) {
        if (zcount > 0) memset(data, 0, zcount);
        memcpy(data + zcount, buf + i, bufLen - i);
    }

    zn_mem_clean(buf, bufLen);
    if (buf != _buf) free(buf);
    return (! data || len <= dataLen) ? len : 0;
}

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t ZNBase58CheckEncode(char *str, size_t strLen, const uint8_t *data, size_t dataLen)
{
    size_t len = 0, bufLen = dataLen + 256/8;
    uint8_t _buf[0x1000], *buf = (bufLen <= 0x1000) ? _buf : malloc(bufLen);

    assert(buf != NULL);
    assert(data != NULL || dataLen == 0);

    if (data || dataLen == 0) {
        memcpy(buf, data, dataLen);
        ZNSHA256_2(buf + dataLen, data, dataLen);
        len = ZNBase58Encode(str, strLen, buf, dataLen + 4);
    }
    
    zn_mem_clean(buf, bufLen);
    if (buf != _buf) free(buf);
    return len;
}

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t ZNBase58CheckDecode(uint8_t *data, size_t dataLen, const char *str)
{
    size_t len, bufLen = (str) ? strlen(str) : 0;
    uint8_t md[256/8], _buf[0x1000], *buf = (bufLen <= 0x1000) ? _buf : malloc(bufLen);

    assert(str != NULL);
    assert(buf != NULL);
    len = ZNBase58Decode(buf, bufLen, str);
    
    if (len >= 4) {
        len -= 4;
        ZNSHA256_2(md, buf, len);
        if (memcmp(buf + len, md, sizeof(uint32_t)) != 0) len = 0; // verify checksum
        if (data && len <= dataLen) memcpy(data, buf, len);
    }
    else len = 0;
    
    zn_mem_clean(buf, bufLen);
    if (buf != _buf) free(buf);
    return (! data || len <= dataLen) ? len : 0;
}
