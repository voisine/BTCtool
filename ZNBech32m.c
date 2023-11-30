//
//  ZNBech32m.c
//  zinc
//
//  Created by Aaron Voisine on 1/20/18.
//

#include "ZNBech32m.h"
#include "ZNAddress.h"
#include "ZNCrypto.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// bech32 address format: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
// bech32m format for v1+: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

#define ZN_BECH32M_CONST 0x2bc830a3

#define zn_polymod(x) ((((x) & 0x1ffffff) << 5) ^ (-(((x) >> 25) & 1) & 0x3b6a57b2) ^\
                       (-(((x) >> 26) & 1) & 0x26508e6d) ^ (-(((x) >> 27) & 1) & 0x1ea119fa) ^\
                       (-(((x) >> 28) & 1) & 0x3d4233dd) ^ (-(((x) >> 29) & 1) & 0x2a1462b3))

// returns the number of bytes written to data (maximum of 42)
size_t ZNBech32mDecode(char hrp[84], uint8_t data[42], const char *addr)
{
    static const int8_t map[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
                                  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
                                   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
                                  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
                                   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1 };
    uint8_t ver, buf[52], upper = 0, lower = 0;
    uint32_t chk = 1;
    size_t x, i, j, bufLen, addrLen, sep;
    int c;

    assert(hrp != NULL);
    assert(data != NULL);
    assert(addr != NULL);
    
    for (i = 0; addr && addr[i]; i++) {
        if (addr[i] < 33 || addr[i] > 126) return 0;
        if (addr[i] >= 'a' && addr[i] <= 'z') lower = 1;
        if (addr[i] >= 'A' && addr[i] <= 'Z') upper = 1;
    }

    addrLen = sep = i;
    while (sep > 0 && addr[sep] != '1') sep--;
    if (addrLen < 8 || addrLen > 90 || sep < 1 || sep + 2 + 6 > addrLen || (upper && lower)) return 0;
    for (i = 0; i < sep; i++) chk = zn_polymod(chk) ^ ((uint32_t)(addr[i] | 0x20) >> 5);
    chk = zn_polymod(chk);
    for (i = 0; i < sep; i++) chk = zn_polymod(chk) ^ (addr[i] & 0x1f);
    memset(buf, 0, sizeof(buf));
    c = ((size_t)addr[sep + 1] < sizeof(map)) ? map[addr[sep + 1]] : -1;
    chk = zn_polymod(chk) ^ (uint32_t)c;
    ver = c & 0xff;

    for (i = sep + 2, j = 0; i < addrLen; i++, j++) {
        c = ((size_t)addr[i] < sizeof(map)) ? map[addr[i]] : -1;
        if (c == -1) return 0; // invalid bech32 digit
        chk = zn_polymod(chk) ^ (uint32_t)c;
        if (i + 6 >= addrLen) continue;
        x = (j % 8)*5 - ((j % 8)*5/8)*8;
        buf[(j/8)*5 + (j % 8)*5/8] |= (c << 3) >> x;
        if (x > 3) buf[(j/8)*5 + (j % 8)*5/8 + 1] |= c << (11 - x);
    }
        
    bufLen = (addrLen - (sep + 2 + 6))*5/8;
    if (ver > 16 || bufLen < 2 || bufLen > 40) return 0; // verify version and bufLen
    if ((ver == 0 && chk != 1) || (ver > 0 && chk != ZN_BECH32M_CONST)) return 0; // verify checksum
    x = (addrLen - sep)*5 % 8;
    if (x > 4 || map[addr[addrLen - 7]] & (0xff >> (8 - x))) return 0; // verify padding
    if (hrp == NULL || data == NULL || sep >= 84 || bufLen + 2 > 42) return 0; // sanity checks
    for (i = 0; i < sep; i++) hrp[i] = addr[i] | 0x20;
    hrp[sep] = '\0';
    data[0] = (ver == 0) ? ZN_OP_0 : ver + ZN_OP_1 - 1;
    data[1] = bufLen & 0xff;
    memcpy(data + 2, buf, bufLen);
    return (size_t)(2 + bufLen);
}

// data must contain a valid BIP141 witness program
// returns the number of bytes written to addr (maximum of 91)
size_t ZNBech32mEncode(char addr[91], const char *hrp, const uint8_t *data)
{
    static const unsigned char chars[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint8_t buf[91], a, b = 0;
    size_t i, j, x, len;
    uint32_t ver, c = 0, chk = 1;

    assert(addr != NULL);
    assert(hrp != NULL);
    assert(data != NULL);
    
    for (i = 0; hrp && hrp[i]; i++) {
        if (i > 83 || hrp[i] < 33 || hrp[i] > 126 || (hrp[i] >= 'A' && hrp[i] <= 'Z')) return 0;
        chk = zn_polymod(chk) ^ (uint32_t)(hrp[i] >> 5);
        buf[i] = (uint8_t)hrp[i];
    }
    
    chk = zn_polymod(chk);
    for (j = 0; j < i; j++) chk = zn_polymod(chk) ^ (hrp[j] & 0x1f);
    buf[i++] = '1';
    if (i < 1 || data == NULL || (data[0] > ZN_OP_0 && data[0] < ZN_OP_1)) return 0;
    ver = (data[0] >= ZN_OP_1) ? data[0] + 1 - ZN_OP_1 : 0;
    len = data[1];
    if (ver > 16 || len < 2 || len > 40 || i + 1 + len + 6 >= 91) return 0;
    chk = zn_polymod(chk) ^ ver;
    buf[i++] = chars[ver];
    
    for (j = 0; j <= len; j++) {
        a = b;
        b = (j < len) ? data[2 + j] : 0;
        x = (j % 5)*8 - ((j % 5)*8/5)*5;
        c = ((a << (5 - x)) | (b >> (3 + x))) & 0x1f;
        if (j < len || j % 5 > 0) { chk = zn_polymod(chk) ^ c; buf[i++] = chars[c]; }
        if (x >= 2) c = (b >> (x - 2)) & 0x1f;
        if (x >= 2 && j < len) { chk = zn_polymod(chk) ^ c; buf[i++] = chars[c]; }
    }
    
    for (j = 0; j < 6; j++) chk = zn_polymod(chk);
    chk ^= (ver == 0) ? 1 : ZN_BECH32M_CONST;
    for (j = 0; j < 6; ++j) buf[i++] = chars[(chk >> ((5 - j)*5)) & 0x1f]; // append checksum
    buf[i++] = '\0';
    if (addr) memcpy(addr, buf, i);
    return i;
}

