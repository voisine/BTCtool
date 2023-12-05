//
//  test.c
//  zinc
//
//  Created by Aaron Voisine on 8/14/15.
//

#include "ZNCrypto.h"
#include "ZNArray.h"
#include "ZNKey.h"
#include "ZNAddress.h"
#include "ZNBase58.h"
#include "ZNBech32m.h"
#include "ZNBIP38Key.h"
#include "ZNTransaction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#pragma clang diagnostic ignored "-Wcomma"

//#define ZN_SKIP_BIP38 1
#define ZN_TEST_NO_MAIN 1

#ifdef __ANDROID__
#include <android/log.h>
#define fprintf(...) __android_log_print(ANDROID_LOG_ERROR, "zinc", _zn_va_rest(__VA_ARGS__, NULL))
#define printf(...) __android_log_print(ANDROID_LOG_INFO, "zinc", __VA_ARGS__)
#endif

#define zn_test(condition, ...) _zn_test(condition, _zn_va_first(__VA_ARGS__, NULL), _zn_va_rest(__VA_ARGS__, NULL))
#define _zn_test(condition, descr, ...)\
        (condition ? fprintf(stderr, "\n***FAILED*** %s: "descr, __func__, __VA_ARGS__), 1 : 0)
#define _zn_va_first(first, ...) first
#define _zn_va_rest(first, ...) __VA_ARGS__

#define zn_hex(u) ((const char[]){\
    _zn_hexc((u)[ 0] >> 4), _zn_hexc((u)[ 0]), _zn_hexc((u)[ 1] >> 4), _zn_hexc((u)[ 1]),\
    _zn_hexc((u)[ 2] >> 4), _zn_hexc((u)[ 2]), _zn_hexc((u)[ 3] >> 4), _zn_hexc((u)[ 3]),\
    _zn_hexc((u)[ 4] >> 4), _zn_hexc((u)[ 4]), _zn_hexc((u)[ 5] >> 4), _zn_hexc((u)[ 5]),\
    _zn_hexc((u)[ 6] >> 4), _zn_hexc((u)[ 6]), _zn_hexc((u)[ 7] >> 4), _zn_hexc((u)[ 7]),\
    _zn_hexc((u)[ 8] >> 4), _zn_hexc((u)[ 8]), _zn_hexc((u)[ 9] >> 4), _zn_hexc((u)[ 9]),\
    _zn_hexc((u)[10] >> 4), _zn_hexc((u)[10]), _zn_hexc((u)[11] >> 4), _zn_hexc((u)[11]),\
    _zn_hexc((u)[12] >> 4), _zn_hexc((u)[12]), _zn_hexc((u)[13] >> 4), _zn_hexc((u)[13]),\
    _zn_hexc((u)[14] >> 4), _zn_hexc((u)[14]), _zn_hexc((u)[15] >> 4), _zn_hexc((u)[15]),\
    _zn_hexc((u)[16] >> 4), _zn_hexc((u)[16]), _zn_hexc((u)[17] >> 4), _zn_hexc((u)[17]),\
    _zn_hexc((u)[18] >> 4), _zn_hexc((u)[18]), _zn_hexc((u)[19] >> 4), _zn_hexc((u)[19]),\
    _zn_hexc((u)[20] >> 4), _zn_hexc((u)[20]), _zn_hexc((u)[21] >> 4), _zn_hexc((u)[21]),\
    _zn_hexc((u)[22] >> 4), _zn_hexc((u)[22]), _zn_hexc((u)[23] >> 4), _zn_hexc((u)[23]),\
    _zn_hexc((u)[24] >> 4), _zn_hexc((u)[24]), _zn_hexc((u)[25] >> 4), _zn_hexc((u)[25]),\
    _zn_hexc((u)[26] >> 4), _zn_hexc((u)[26]), _zn_hexc((u)[27] >> 4), _zn_hexc((u)[27]),\
    _zn_hexc((u)[28] >> 4), _zn_hexc((u)[28]), _zn_hexc((u)[29] >> 4), _zn_hexc((u)[29]),\
    _zn_hexc((u)[30] >> 4), _zn_hexc((u)[30]), _zn_hexc((u)[31] >> 4), _zn_hexc((u)[31]), '\0' })

#define _zn_hexc(u) (((u) & 0x0f) + ((((u) & 0x0f) <= 9) ? '0' : 'a' - 0x0a))

#define _zn_hexu(c) ((c) >= '0' && (c) <= '9' ? (c) - '0' : (c) >= 'A' && (c) <= 'F' ? (c) + 0xa - 'A' :\
                     (c) >= 'a' && (c) <= 'f' ? (c) + 0xa - 'a' : -1)

static uint8_t *ZNHexStr(uint8_t *buf, const char *hex, size_t *len)
{
    uint8_t *b;
    
    for (b = buf; hex[0] && hex[1]; hex += 2) *(b++) = (uint8_t)((_zn_hexu(hex[0]) << 4) + _zn_hexu(hex[1]));
    if (len) *len = (size_t)(b - buf);
    return buf;
}

static int ZNAddressEq(const char addr[75], const char otherAddr[75])
{
    return (addr == otherAddr || strncmp(addr, otherAddr, 75) == 0);
}

static int ZNIntsTests(void)
{
    // test endianess
    
    int r = 0;
    union {
        uint8_t u8[8];
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    } x = {{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }};
    
    r += zn_test((zn_be16(x.u8) != 0x0102), "zn_be16() test");
    r += zn_test((zn_le16(x.u8) != 0x0201), "zn_le16() test");
    r += zn_test((zn_be32(x.u8) != 0x01020304), "zn_be32() test");
    r += zn_test((zn_le32(x.u8) != 0x04030201), "zn_le32() test");
    r += zn_test((zn_be64(x.u8) != 0x0102030405060708), "zn_be64() test");
    r += zn_test((zn_le64(x.u8) != 0x0807060504030201), "zn_le64() test");

    zn_be16set(x.u8, 0x0201);
    r += zn_test((x.u8[0] != 0x02 || x.u8[1] != 0x01), "zn_be16set() test");

    zn_le16set(x.u8, 0x0201);
    r += zn_test((x.u8[0] != 0x01 || x.u8[1] != 0x02), "zn_le16set() test");

    zn_be32set(x.u8, 0x04030201);
    r += zn_test((x.u8[0] != 0x04 || x.u8[1] != 0x03 || x.u8[2] != 0x02 || x.u8[3] != 0x01), "zn_be32set() test");

    zn_le32set(x.u8, 0x04030201);
    r += zn_test((x.u8[0] != 0x01 || x.u8[1] != 0x02 || x.u8[2] != 0x03 || x.u8[3] != 0x04), "zn_le32set() test");

    zn_be64set(x.u8, 0x0807060504030201);
    r += zn_test((x.u8[0] != 0x08 || x.u8[1] != 0x07 || x.u8[2] != 0x06 || x.u8[3] != 0x05 ||
        x.u8[4] != 0x04 || x.u8[5] != 0x03 || x.u8[6] != 0x02 || x.u8[7] != 0x01), "zn_be64set() test");

    zn_le64set(x.u8, 0x0807060504030201);
    r += zn_test((x.u8[0] != 0x01 || x.u8[1] != 0x02 || x.u8[2] != 0x03 || x.u8[3] != 0x04 ||
        x.u8[4] != 0x05 || x.u8[5] != 0x06 || x.u8[6] != 0x07 || x.u8[7] != 0x08), "zn_le64set() test");
    
    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNArrayTests(void)
{
    int r = 0;
    int *a = NULL, b[] = { 1, 2, 3 }, c[] = { 3, 2 };
    size_t i;
    
    a = zn_array_new(sizeof(*a), 0);   // [ ]
    r += zn_test((zn_array_count(a) != 0), "zn_array_new() test");

    zn_array_add(a, 0);                // [ 0 ]
    r += zn_test((zn_array_count(a) != 1 || a[0] != 0), "zn_array_add() test");

    zn_array_add_array(a, b, 3);       // [ 0, 1, 2, 3 ]
    r += zn_test((zn_array_count(a) != 4 || a[3] != 3), "zn_array_add_array() test");

    zn_array_insert(a, 0, 1);          // [ 1, 0, 1, 2, 3 ]
    r += zn_test((zn_array_count(a) != 5 || a[0] != 1), "zn_array_insert() test");

    zn_array_insert_array(a, 0, c, 2); // [ 3, 2, 1, 0, 1, 2, 3 ]
    r += zn_test((zn_array_count(a) != 7 || a[0] != 3), "zn_array_insert_array() test");

    zn_array_rm_range(a, 0, 4);        // [ 1, 2, 3 ]
    r += zn_test((zn_array_count(a) != 3 || a[0] != 1), "zn_array_rm_range() test");

    printf("\n");
    for (i = 0; i < zn_array_count(a); i++) {
        printf("%i, ", a[i]);          // 1, 2, 3,
    }
    printf("\n");

    zn_array_insert_array(a, 3, c, 2); // [ 1, 2, 3, 3, 2 ]
    r += zn_test((zn_array_count(a) != 5 || a[4] != 2), "zn_array_insert_array() test 2");
    
    zn_array_insert(a, 5, 1);          // [ 1, 2, 3, 3, 2, 1 ]
    r += zn_test((zn_array_count(a) != 6 || a[5] != 1), "zn_array_insert() test 2");
    
    zn_array_rm(a, 0);                 // [ 2, 3, 3, 2, 1 ]
    r += zn_test((zn_array_count(a) != 5 || a[0] != 2), "zn_array_rm() test");

    zn_array_rm_last(a);               // [ 2, 3, 3, 2 ]
    r += zn_test((zn_array_count(a) != 4 || a[0] != 2), "zn_array_rm_last() test");
    
    zn_array_clear(a);                 // [ ]
    r += zn_test((zn_array_count(a) != 0), "zn_array_clear() test");

    zn_array_free(a);
    
    printf("                                    ");
    return r;
}

static size_t ZNIntHash(const void *i)
{
    return (size_t)((0x811C9dc5 ^ *(const unsigned *)i)*0x01000193); // (FNV_offset xor i)*FNV_prime
}

static int ZNIntEq(const void *a, const void *b)
{
    return (*(const int *)a == *(const int *)b);
}

static int ZNBase58Tests(void)
{
    int r = 0;
    char *s;
    
    s = "#&$@*^(*#!^"; // test bad input
    
    uint8_t buf1[ZNBase58Decode(NULL, 0, s)];
    size_t len1 = ZNBase58Decode(buf1, sizeof(buf1), s);

    r += zn_test((len1 != 0), "ZNBase58Decode() test 1");

    uint8_t buf2[ZNBase58Decode(NULL, 0, "")];
    size_t len2 = ZNBase58Decode(buf2, sizeof(buf2), "");
    
    r += zn_test((len2 != 0), "ZNBase58Decode() test 2");
    
    s = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    uint8_t buf3[ZNBase58Decode(NULL, 0, s)];
    size_t len3 = ZNBase58Decode(buf3, sizeof(buf3), s);
    char str3[ZNBase58Encode(NULL, 0, buf3, len3)];
    
    ZNBase58Encode(str3, sizeof(str3), buf3, len3);
    r += zn_test((strcmp(str3, s) != 0), "ZNBase58Decode() test 3");

    s = "1111111111111111111111111111111111111111111111111111111111111111111";

    uint8_t buf4[ZNBase58Decode(NULL, 0, s)];
    size_t len4 = ZNBase58Decode(buf4, sizeof(buf4), s);
    char str4[ZNBase58Encode(NULL, 0, buf4, len4)];
    
    ZNBase58Encode(str4, sizeof(str4), buf4, len4);
    r += zn_test((strcmp(str4, s) != 0), "ZNBase58Decode() test 4");

    s = "111111111111111111111111111111111111111111111111111111111111111111z";

    uint8_t buf5[ZNBase58Decode(NULL, 0, s)];
    size_t len5 = ZNBase58Decode(buf5, sizeof(buf5), s);
    char str5[ZNBase58Encode(NULL, 0, buf5, len5)];
    
    ZNBase58Encode(str5, sizeof(str5), buf5, len5);
    r += zn_test((strcmp(str5, s) != 0), "ZNBase58Decode() test 5");

    s = "z";
    
    uint8_t buf6[ZNBase58Decode(NULL, 0, s)];
    size_t len6 = ZNBase58Decode(buf6, sizeof(buf6), s);
    char str6[ZNBase58Encode(NULL, 0, buf6, len6)];
    
    ZNBase58Encode(str6, sizeof(str6), buf6, len6);
    r += zn_test((strcmp(str6, s) != 0), "ZNBase58Decode() test 6");

    s = NULL;
    
    char s1[ZNBase58CheckEncode(NULL, 0, (uint8_t *)s, 0)];
    size_t l1 = ZNBase58CheckEncode(s1, sizeof(s1), (uint8_t *)s, 0);
    uint8_t b1[ZNBase58CheckDecode(NULL, 0, s1)];
    
    l1 = ZNBase58CheckDecode(b1, sizeof(b1), s1);
    r += zn_test((l1 != 0), "ZNBase58CheckDecode() test 1");

    s = "";

    char s2[ZNBase58CheckEncode(NULL, 0, (uint8_t *)s, 0)];
    size_t l2 = ZNBase58CheckEncode(s2, sizeof(s2), (uint8_t *)s, 0);
    uint8_t b2[ZNBase58CheckDecode(NULL, 0, s2)];
    
    l2 = ZNBase58CheckDecode(b2, sizeof(b2), s2);
    r += zn_test((l2 != 0), "ZNBase58CheckDecode() test 2");
    
    s = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    char s3[ZNBase58CheckEncode(NULL, 0, (uint8_t *)s, 21)];
    size_t l3 = ZNBase58CheckEncode(s3, sizeof(s3), (uint8_t *)s, 21);
    uint8_t b3[ZNBase58CheckDecode(NULL, 0, s3)];
    
    l3 = ZNBase58CheckDecode(b3, sizeof(b3), s3);
    r += zn_test((l3 != 21 || memcmp(s, b3, l3) != 0), "ZNBase58CheckDecode() test 3");

    s = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    
    char s4[ZNBase58CheckEncode(NULL, 0, (uint8_t *)s, 21)];
    size_t l4 = ZNBase58CheckEncode(s4, sizeof(s4), (uint8_t *)s, 21);
    uint8_t b4[ZNBase58CheckDecode(NULL, 0, s4)];
    
    l4 = ZNBase58CheckDecode(b4, sizeof(b4), s4);
    r += zn_test((l4 != 21 || memcmp(s, b4, l4) != 0), "ZNBase58CheckDecode() test 4");

    s = "\x05\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    
    char s5[ZNBase58CheckEncode(NULL, 0, (uint8_t *)s, 21)];
    size_t l5 = ZNBase58CheckEncode(s5, sizeof(s5), (uint8_t *)s, 21);
    uint8_t b5[ZNBase58CheckDecode(NULL, 0, s5)];
    
    l5 = ZNBase58CheckDecode(b5, sizeof(b5), s5);
    r += zn_test((l5 != 21 || memcmp(s, b5, l5) != 0), "ZNBase58CheckDecode() test 5");

    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNBech32mTests(void)
{
    int r = 0;
    uint8_t b[52];
    char h[84];
    char addr[91];
    size_t l;
    
    char s1[] = "\x00\x14\x75\x1e\x76\xe8\x19\x91\x96\xd4\x54\x94\x1c\x45\xd1\xb3\xa3\x23\xf1\x43\x3b\xd6";
    l = ZNBech32mDecode(h, b, "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
    r += zn_test((l != sizeof(s1) - 1 || strcmp(h, "bc") || memcmp(s1, b, l)), "ZNBech32mDecode() test 1");
    
    l = ZNBech32mDecode(h, b, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    r += zn_test((l != sizeof(s1) - 1 || strcmp(h, "bc") || memcmp(s1, b, l)), "ZNBech32mDecode() test 2");

    l = ZNBech32mEncode(addr, "bc", b);
    r += zn_test((l == 0 || strcmp(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")), "ZNBech32mEncode() test 2");

    char s3[] = "\x00\x20\x18\x63\x14\x3c\x14\xc5\x16\x68\x04\xbd\x19\x20\x33\x56\xda\x13\x6c\x98\x56\x78\xcd\x4d\x27"
    "\xa1\xb8\xc6\x32\x96\x04\x90\x32\x62";
    l = ZNBech32mDecode(h, b, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7");
    r += zn_test((l != sizeof(s3) - 1 || strcmp(h, "tb") || memcmp(s3, b, l)), "ZNBech32mDecode() test 3");

    l = ZNBech32mEncode(addr, "tb", b);
    r += zn_test((l == 0 || strcmp(addr, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")),
                 "ZNBech32mEncode() test 3");

    char s4[] = "\x51\x28\x75\x1e\x76\xe8\x19\x91\x96\xd4\x54\x94\x1c\x45\xd1\xb3\xa3\x23\xf1\x43\x3b\xd6\x75\x1e\x76"
    "\xe8\x19\x91\x96\xd4\x54\x94\x1c\x45\xd1\xb3\xa3\x23\xf1\x43\x3b\xd6";
    l = ZNBech32mDecode(h, b, "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y");
    r += zn_test((l != sizeof(s4) - 1 || strcmp(h, "bc") || memcmp(s4, b, l)), "ZNBech32mDecode() test 4");

    l = ZNBech32mEncode(addr, "bc", b);
    r += zn_test((l == 0 || strcmp(addr, "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")),
                 "ZNBech32mEncode() test 4");

    char s5[] = "\x60\x02\x75\x1e";
    l = ZNBech32mDecode(h, b, "BC1SW50QGDZ25J");
    r += zn_test((l != sizeof(s5) - 1 || strcmp(h, "bc") || memcmp(s5, b, l)), "ZNBech32mDecode() test 5");

    l = ZNBech32mEncode(addr, "bc", b);
    r += zn_test((l == 0 || strcmp(addr, "bc1sw50qgdz25j")), "ZNBech32mEncode() test 5");

    char s6[] = "\x52\x10\x75\x1e\x76\xe8\x19\x91\x96\xd4\x54\x94\x1c\x45\xd1\xb3\xa3\x23";
    l = ZNBech32mDecode(h, b, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs");
    r += zn_test((l != sizeof(s6) - 1 || strcmp(h, "bc") || memcmp(s6, b, l)), "ZNBech32mDecode() test 6");

    l = ZNBech32mEncode(addr, "bc", b);
    r += zn_test((l == 0 || strcmp(addr, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs")), "ZNBech32mEncode() test 6");

    char s7[] = "\x00\x20\x00\x00\x00\xc4\xa5\xca\xd4\x62\x21\xb2\xa1\x87\x90\x5e\x52\x66\x36\x2b\x99\xd5\xe9\x1c\x6c"
    "\xe2\x4d\x16\x5d\xab\x93\xe8\x64\x33";
    l = ZNBech32mDecode(h, b, "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy");
    r += zn_test((l != sizeof(s7) - 1 || strcmp(h, "tb") || memcmp(s7, b, l)), "ZNBech32mDecode() test 7");

    l = ZNBech32mEncode(addr, "tb", b);
    r += zn_test((l == 0 || strcmp(addr, "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy")),
                 "ZNBech32mEncode() test 7");

    char s8[] = "\x51\x20\x00\x00\x00\xc4\xa5\xca\xd4\x62\x21\xb2\xa1\x87\x90\x5e\x52\x66\x36\x2b\x99\xd5\xe9\x1c\x6c"
    "\xe2\x4d\x16\x5d\xab\x93\xe8\x64\x33";
    l = ZNBech32mDecode(h, b, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c");
    r += zn_test((l != sizeof(s8) - 1 || strcmp(h, "tb") || memcmp(s8, b, l)), "ZNBech32mDecode() test 8");

    l = ZNBech32mEncode(addr, "tb", b);
    r += zn_test((l == 0 || strcmp(addr, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c")),
                 "ZNBech32mEncode() test 8");

    char s9[] = "\x51\x20\x79\xbe\x66\x7e\xf9\xdc\xbb\xac\x55\xa0\x62\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb\x2d\xce\x28"
    "\xd9\x59\xf2\x81\x5b\x16\xf8\x17\x98";
    l = ZNBech32mDecode(h, b, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
    r += zn_test((l != sizeof(s9) - 1 || strcmp(h, "bc") || memcmp(s9, b, l)), "ZNBech32mDecode() test 9");

    l = ZNBech32mEncode(addr, "bc", b);
    r += zn_test((l == 0 || strcmp(addr, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")),
                 "ZNBech32mEncode() test 9");

    l = ZNBech32mDecode(h, b, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd");
    r += zn_test((l != 0), "ZNBech32mDecode() test 10"); // Invalid checksum (Bech32 instead of Bech32m)

    l = ZNBech32mDecode(h, b, "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf");
    r += zn_test((l != 0), "ZNBech32mDecode() test 11"); // Invalid checksum (Bech32 instead of Bech32m)

    l = ZNBech32mDecode(h, b, "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL");
    r += zn_test((l != 0), "ZNBech32mDecode() test 12"); // Invalid checksum (Bech32 instead of Bech32m)

    l = ZNBech32mDecode(h, b, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh");
    r += zn_test((l != 0), "ZNBech32mDecode() test 13"); // Invalid checksum (Bech32 instead of Bech32m)

    l = ZNBech32mDecode(h, b, "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47");
    r += zn_test((l != 0), "ZNBech32mDecode() test 14"); // Invalid checksum (Bech32 instead of Bech32m)

    l = ZNBech32mDecode(h, b, "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4");
    r += zn_test((l != 0), "ZNBech32mDecode() test 15"); // Invalid character in checksum

    l = ZNBech32mDecode(h, b, "bc1pw5dgrnzv");
    r += zn_test((l != 0), "ZNBech32mDecode() test 16"); // Invalid program length (1 byte)

    l = ZNBech32mDecode(h, b, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav");
    r += zn_test((l != 0), "ZNBech32mDecode() test 17"); // Invalid program length (41 bytes)

    l = ZNBech32mDecode(h, b, "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq");
    r += zn_test((l != 0), "ZNBech32mDecode() test 18"); // Mixed case

    l = ZNBech32mDecode(h, b, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf");
    r += zn_test((l != 0), "ZNBech32mDecode() test 19"); // zero padding of more than 4 bits

    l = ZNBech32mDecode(h, b, "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j");
    r += zn_test((l != 0), "ZNBech32mDecode() test 20"); // Non-zero padding in 8-to-5 conversion

    l = ZNBech32mDecode(h, b, "bc1gmk9yu");
    r += zn_test((l != 0), "ZNBech32mDecode() test 21"); // Empty data section
    
    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNHashTests(void)
{
    // test sha1
    
    int r = 0;
    uint8_t md[64];
    char *s;
    
    s = "Free online SHA1 Calculator, type text here...";
    ZNSHA1(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x6f\xc2\xe2\x51\x72\xcb\x15\x19\x3c\xb1\xc6\xd4\x8f\x60\x7d\x42\xc1\xd2\xa2\x15", md, 20)),
                 "ZNSHA1() test 1");
        
    s = "this is some text to test the sha1 implementation with more than 64bytes of data since it's internal digest "
        "buffer is 64bytes in size";
    ZNSHA1(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x08\x51\x94\x65\x8a\x92\x35\xb2\x95\x1a\x83\xd1\xb8\x26\xb9\x87\xe9\x38\x5a\xa3", md, 20)),
                 "ZNSHA1() test 2");
        
    s = "123456789012345678901234567890123456789012345678901234567890";
    ZNSHA1(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x24\x5b\xe3\x00\x91\xfd\x39\x2f\xe1\x91\xf4\xbf\xce\xc2\x2d\xcb\x30\xa0\x3a\xe6", md, 20)),
                 "ZNSHA1() test 3");
    
    // a message exactly 64bytes long (internal buffer size)
    s = "1234567890123456789012345678901234567890123456789012345678901234";
    ZNSHA1(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xc7\x14\x90\xfc\x24\xaa\x3d\x19\xe1\x12\x82\xda\x77\x03\x2d\xd9\xcd\xb3\x31\x03", md, 20)),
                 "ZNSHA1() test 4");
    
    s = ""; // empty
    ZNSHA1(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09", md, 20)),
                 "ZNSHA1() test 5");
    
    s = "a";
    ZNSHA1(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x86\xf7\xe4\x37\xfa\xa5\xa7\xfc\xe1\x5d\x1d\xdc\xb9\xea\xea\xea\x37\x76\x67\xb8", md, 20)),
                 "ZNSHA1() test 6");

    // test sha256
    
    s = "Free online SHA256 Calculator, type text here...";
    ZNSHA256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x43\xfd\x9d\xeb\x93\xf6\xe1\x4d\x41\x82\x66\x04\x51\x4e\x3d\x78\x73\xa5\x49\xac"
                         "\x87\xae\xbe\xbf\x3d\x1c\x10\xad\x6e\xb0\x57\xd0", md, 32)), "ZNSHA256() test 1");
        
    s = "this is some text to test the sha256 implementation with more than 64bytes of data since it's internal "
        "digest buffer is 64bytes in size";
    ZNSHA256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x40\xfd\x09\x33\xdf\x2e\x77\x47\xf1\x9f\x7d\x39\xcd\x30\xe1\xcb\x89\x81\x0a\x7e"
                         "\x47\x06\x38\xa5\xf6\x23\x66\x9f\x3d\xe9\xed\xd4", md, 32)), "ZNSHA256() test 2");
    
    s = "123456789012345678901234567890123456789012345678901234567890";
    ZNSHA256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xde\xcc\x53\x8c\x07\x77\x86\x96\x6a\xc8\x63\xb5\x53\x2c\x40\x27\xb8\x58\x7f\xf4"
                         "\x0f\x6e\x31\x03\x37\x9a\xf6\x2b\x44\xea\xe4\x4d", md, 32)), "ZNSHA256() test 3");
    
    // a message exactly 64bytes long (internal buffer size)
    s = "1234567890123456789012345678901234567890123456789012345678901234";
    ZNSHA256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x67\x64\x91\x96\x5e\xd3\xec\x50\xcb\x7a\x63\xee\x96\x31\x54\x80\xa9\x5c\x54\x42"
                         "\x6b\x0b\x72\xbc\xa8\xa0\xd4\xad\x12\x85\xad\x55", md, 32)), "ZNSHA256() test 4");
    
    s = ""; // empty
    ZNSHA256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4"
                         "\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", md, 32)), "ZNSHA256() test 5");
    
    s = "a";
    ZNSHA256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d\xa7\x86\xef\xf8"
                         "\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb", md, 32)), "ZNSHA256() test 6");

    // test sha512
    
    s = "Free online SHA512 Calculator, type text here...";
    ZNSHA512(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x04\xf1\x15\x41\x35\xee\xcb\xe4\x2e\x9a\xdc\x8e\x1d\x53\x2f\x9c\x60\x7a\x84\x47"
                         "\xb7\x86\x37\x7d\xb8\x44\x7d\x11\xa5\xb2\x23\x2c\xdd\x41\x9b\x86\x39\x22\x4f\x78\x7a\x51"
                         "\xd1\x10\xf7\x25\x91\xf9\x64\x51\xa1\xbb\x51\x1c\x4a\x82\x9e\xd0\xa2\xec\x89\x13\x21\xf3",
                         md, 64)), "ZNSHA512() test 1");
    
    s = "this is some text to test the sha512 implementation with more than 128bytes of data since it's internal "
        "digest buffer is 128bytes in size";
    ZNSHA512(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x9b\xd2\xdc\x7b\x05\xfb\xbe\x99\x34\xcb\x32\x89\xb6\xe0\x6b\x8c\xa9\xfd\x7a\x55"
                         "\xe6\xde\x5d\xb7\xe1\xe4\xee\xdd\xc6\x62\x9b\x57\x53\x07\x36\x7c\xd0\x18\x3a\x44\x61\xd7"
                         "\xeb\x2d\xfc\x6a\x27\xe4\x1e\x8b\x70\xf6\x59\x8e\xbc\xc7\x71\x09\x11\xd4\xfb\x16\xa3\x90",
                         md, 64)), "ZNSHA512() test 2");
    
    s = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"
        "8901234567890";
    ZNSHA512(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x0d\x9a\x7d\xf5\xb6\xa6\xad\x20\xda\x51\x9e\xff\xda\x88\x8a\x73\x44\xb6\xc0\xc7"
                         "\xad\xcc\x8e\x2d\x50\x4b\x4a\xf2\x7a\xaa\xac\xd4\xe7\x11\x1c\x71\x3f\x71\x76\x95\x39\x62"
                         "\x94\x63\xcb\x58\xc8\x61\x36\xc5\x21\xb0\x41\x4a\x3c\x0e\xdf\x7d\xc6\x34\x9c\x6e\xda\xf3",
                         md, 64)), "ZNSHA512() test 3");
    
    //exactly 128bytes (internal buf size)
    s = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"
        "890123456789012345678";
    ZNSHA512(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x22\x2b\x2f\x64\xc2\x85\xe6\x69\x96\x76\x9b\x5a\x03\xef\x86\x3c\xfd\x3b\x63\xdd"
                         "\xb0\x72\x77\x88\x29\x16\x95\xe8\xfb\x84\x57\x2e\x4b\xfe\x5a\x80\x67\x4a\x41\xfd\x72\xee"
                         "\xb4\x85\x92\xc9\xc7\x9f\x44\xae\x99\x2c\x76\xed\x1b\x0d\x55\xa6\x70\xa8\x3f\xc9\x9e\xc6",
                         md, 64)), "ZNSHA512() test 4");
    
    s = ""; // empty
    ZNSHA512(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05"
                         "\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83"
                         "\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e",
                         md, 64)), "ZNSHA512() test 5");
    
    s = "a";
    ZNSHA512(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x1f\x40\xfc\x92\xda\x24\x16\x94\x75\x09\x79\xee\x6c\xf5\x82\xf2\xd5\xd7\xd2\x8e"
                         "\x18\x33\x5d\xe0\x5a\xbc\x54\xd0\x56\x0e\x0f\x53\x02\x86\x0c\x65\x2b\xf0\x8d\x56\x02\x52"
                         "\xaa\x5e\x74\x21\x05\x46\xf3\x69\xfb\xbb\xce\x8c\x12\xcf\xc7\x95\x7b\x26\x52\xfe\x9a\x75",
                         md, 64)), "ZNSHA512() test 6");
    
    // test ripemd160
    
    s = "Free online RIPEMD160 Calculator, type text here...";
    ZNRMD160(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x95\x01\xa5\x6f\xb8\x29\x13\x2b\x87\x48\xf0\xcc\xc4\x91\xf0\xec\xbc\x7f\x94\x5b", md, 20)),
                 "ZNRMD160() test 1");
    
    s = "this is some text to test the ripemd160 implementation with more than 64bytes of data since it's internal "
        "digest buffer is 64bytes in size";
    ZNRMD160(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x44\x02\xef\xf4\x21\x57\x10\x6a\x5d\x92\xe4\xd9\x46\x18\x58\x56\xfb\xc5\x0e\x09", md, 20)),
                 "ZNRMD160() test 2");
    
    s = "123456789012345678901234567890123456789012345678901234567890";
    ZNRMD160(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x00\x26\x3b\x99\x97\x14\xe7\x56\xfa\x5d\x02\x81\x4b\x84\x2a\x26\x34\xdd\x31\xac", md, 20)),
                 "ZNRMD160() test 3");
    
    // a message exactly 64bytes long (internal buffer size)
    s = "1234567890123456789012345678901234567890123456789012345678901234";
    ZNRMD160(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xfa\x8c\x1a\x78\xeb\x76\x3b\xb9\x7d\x5e\xa1\x4c\xe9\x30\x3d\x1c\xe2\xf3\x34\x54", md, 20)),
                 "ZNRMD160() test 4");
    
    s = ""; // empty
    ZNRMD160(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31", md, 20)),
                 "ZNRMD160() test 5");
    
    s = "a";
    ZNRMD160(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe", md, 20)),
                 "ZNRMD160() test 6");

    // test md5
    
    s = "Free online MD5 Calculator, type text here...";
    ZNMD5(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x0b\x3b\x20\xea\xf1\x69\x64\x62\xf5\x0d\x1a\x3b\xbd\xd3\x0c\xef",
                    md, 16)), "ZNMD5() test 1");
    
    s = "this is some text to test the md5 implementation with more than 64bytes of data since it's internal digest "
        "buffer is 64bytes in size";
    ZNMD5(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x56\xa1\x61\xf2\x41\x50\xc6\x2d\x78\x57\xb7\xf3\x54\x92\x7e\xbe", md, 16)),
                 "ZNMD5() test 2");
    
    s = "123456789012345678901234567890123456789012345678901234567890";
    ZNMD5(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xc5\xb5\x49\x37\x7c\x82\x6c\xc3\x71\x24\x18\xb0\x64\xfc\x41\x7e", md, 16)),
                 "ZNMD5() test 3");
    
    // a message exactly 64bytes long (internal buffer size)
    s = "1234567890123456789012345678901234567890123456789012345678901234";
    ZNMD5(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xeb\x6c\x41\x79\xc0\xa7\xc8\x2c\xc2\x82\x8c\x1e\x63\x38\xe1\x65", md, 16)),
                 "ZNMD5() test 4");
    
    s = ""; // empty
    ZNMD5(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e", md, 16)),
                 "ZNMD5() test 5");
    
    s = "a";
    ZNMD5(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61", md, 16)),
                 "ZNMD5() test 6");
    
    // test sha3-256
    
    s = "";
    ZNSHA3_256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xa7\xff\xc6\xf8\xbf\x1e\xd7\x66\x51\xc1\x47\x56\xa0\x61\xd6\x62\xf5\x80\xff\x4d\xe4"
                         "\x3b\x49\xfa\x82\xd8\x0a\x4b\x80\xf8\x43\x4a", md, 32)), "SHA3-256() test 7");
    
    s = "abc";
    ZNSHA3_256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd\x85\x5f\x08\x6e\x3e"
                         "\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32", md, 32)), "SHA3-256() test 8");
    
    s =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    ZNSHA3_256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\x91\x6f\x60\x61\xfe\x87\x97\x41\xca\x64\x69\xb4\x39\x71\xdf\xdb\x28\xb1\xa3\x2d\xc3"
                         "\x6c\xb3\x25\x4e\x81\x2b\xe2\x7a\xad\x1d\x18", md, 32)), "SHA3-256() test 9");
    
    // test keccak-256
    
    s = "";
    ZNKeccak256(md, (const uint8_t *)s, strlen(s));
    r += zn_test((memcmp("\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6\x53\xca"
                         "\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70", md, 32)), "Keccak-256() test 1");
    
    // test murmurHash3-x86_32
    
    r += zn_test((ZNMurmur3_32((const uint8_t *)"", 0, 0) != 0), "ZNMurmur3_32() test 1");

    r += zn_test((ZNMurmur3_32((const uint8_t *)"\xFF\xFF\xFF\xFF", 4, 0) != 0x76293b50), "ZNMurmur3_32() test 2");
    
    r += zn_test((ZNMurmur3_32((const uint8_t *)"\x21\x43\x65\x87", 4, 0x5082edee) != 0x2362f9de),
                 "ZNMurmur3_32() test 3");
    
    r += zn_test((ZNMurmur3_32((const uint8_t *)"\x00", 1, 0) != 0x514e28b7), "ZNMurmur3_32() test 4");
    
    // test sipHash-64

    const uint8_t k[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    const uint8_t d[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    r += zn_test((ZNSip64(k, d, 0) != 0x726fdb47dd0e0e31), "ZNSip64() test 1");

    r += zn_test((ZNSip64(k, d, 1) != 0x74f839c593dc67fd), "ZNSip64() test 2");

    r += zn_test((ZNSip64(k, d, 8) != 0x93f5f5799a932462), "ZNSip64() test 3");

    r += zn_test((ZNSip64(k, d, 15) != 0xa129ca6149be45e5), "ZNSip64() test 4");

    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNMacTests(void)
{
    int r = 0;

    // test hmac
    
    const uint8_t k1[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    d1[] = "Hi There";
    uint8_t mac[64];
    
    ZNHMAC(mac, ZNSHA224, 224/8, k1, sizeof(k1) - 1, d1, sizeof(d1) - 1);
    r += zn_test((memcmp("\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba"
                         "\x4f\x53\x68\x4b\x22", mac, 28) != 0), "ZNHMAC() sha224 test 1");

    ZNHMAC(mac, ZNSHA256, 256/8, k1, sizeof(k1) - 1, d1, sizeof(d1) - 1);
    r += zn_test((memcmp("\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d"
                         "\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", mac, 32) != 0), "ZNHMAC() sha256 test 1");

    ZNHMAC(mac, ZNSHA384, 384/8, k1, sizeof(k1) - 1, d1, sizeof(d1) - 1);
    r += zn_test((memcmp("\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e"
                         "\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa"
                         "\x9c\xb6", mac, 48) != 0), "ZNHMAC() sha384 test 1");

    ZNHMAC(mac, ZNSHA512, 512/8, k1, sizeof(k1) - 1, d1, sizeof(d1) - 1);
    r += zn_test((memcmp("\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2"
                         "\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3"
                         "\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54", mac, 64) != 0),
                 "ZNHMAC() sha512 test 1");

    const uint8_t k2[] = "Jefe",
    d2[] = "what do ya want for nothing?";

    ZNHMAC(mac, ZNSHA224, 224/8, k2, sizeof(k2) - 1, d2, sizeof(d2) - 1);
    r += zn_test((memcmp("\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e\x6d\x0f\x8b\xbe\xa2\xa3\x9e\x61\x48"
                         "\x00\x8f\xd0\x5e\x44", mac, 28) != 0), "ZNHMAC() sha224 test 2");
    
    ZNHMAC(mac, ZNSHA256, 256/8, k2, sizeof(k2) - 1, d2, sizeof(d2) - 1);
    r += zn_test((memcmp("\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39"
                         "\x83\x9d\xec\x58\xb9\x64\xec\x38\x43", mac, 32) != 0), "ZNHMAC() sha256 test 2");
    
    ZNHMAC(mac, ZNSHA384, 384/8, k2, sizeof(k2) - 1, d2, sizeof(d2) - 1);
    r += zn_test((memcmp("\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\x9c\x7e\xf4\x64\xf5\xa0\x1b"
                         "\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2"
                         "\x16\x49", mac, 48) != 0), "ZNHMAC() sha384 test 2");
    
    ZNHMAC(mac, ZNSHA512, 512/8, k2, sizeof(k2) - 1, d2, sizeof(d2) - 1);
    r += zn_test((memcmp("\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\x87\xbd\x64\x22\x2e\x83\x1f"
                         "\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0"
                         "\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37", mac, 64) != 0),
                 "ZNHMAC() sha512 test 2");
    
    // test poly1305

    const uint8_t key1[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    msg1[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0";
    
    ZNPoly1305(mac, key1, msg1, sizeof(msg1) - 1);
    r += zn_test((memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", mac, 16) != 0), "ZNPoly1305() test 1");

    const uint8_t key2[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a"
    "\x86\x3e",
    msg2[] = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF "
    "Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF "
    "Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic "
    "communications made at any time or place, which are addressed to";

    ZNPoly1305(mac, key2, msg2, sizeof(msg2) - 1);
    r += zn_test((memcmp("\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e", mac, 16) != 0),
                 "ZNPoly1305() test 2");

    const uint8_t key3[] = "\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0",
    msg3[] = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF "
    "Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF "
    "Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic "
    "communications made at any time or place, which are addressed to";

    ZNPoly1305(mac, key3, msg3, sizeof(msg3) - 1);
    r += zn_test((memcmp("\xf3\x47\x7e\x7c\xd9\x54\x17\xaf\x89\xa6\xb8\x79\x4c\x31\x0c\xf0", mac, 16) != 0),
                 "ZNPoly1305() test 3");
    
    const uint8_t key4[] = "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0\x47\x39\x17\xc1\x40\x2b"
    "\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0",
    msg4[] = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\n"
    "And the mome raths outgrabe.";

    ZNPoly1305(mac, key4, msg4, sizeof(msg4) - 1);
    r += zn_test((memcmp("\x45\x41\x66\x9a\x7e\xaa\xee\x61\xe7\x08\xdc\x7c\xbc\xc5\xeb\x62", mac, 16) != 0),
                 "ZNPoly1305() test 4");

    const uint8_t key5[] = "\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    msg5[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

    ZNPoly1305(mac, key5, msg5, sizeof(msg5) - 1);
    r += zn_test((memcmp("\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", mac, 16) != 0), "ZNPoly1305() test 5");

    const uint8_t key6[] = "\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    "\xFF\xFF",
    msg6[] = "\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    
    ZNPoly1305(mac, key6, msg6, sizeof(msg6) - 1);
    r += zn_test((memcmp("\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", mac, 16) != 0), "ZNPoly1305() test 6");

    const uint8_t key7[] = "\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    msg7[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xF0\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    "\xFF\xFF\xFF\xFF\xFF\xFF\x11\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    
    ZNPoly1305(mac, key7, msg7, sizeof(msg7) - 1);
    r += zn_test((memcmp("\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", mac, 16) != 0), "ZNPoly1305() test 7");

    const uint8_t key8[] = "\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    msg8[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFB\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE"
    "\xFE\xFE\xFE\xFE\xFE\xFE\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
    
    ZNPoly1305(mac, key8, msg8, sizeof(msg8) - 1);
    r += zn_test((memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", mac, 16) != 0), "ZNPoly1305() test 8");

    const uint8_t key9[] = "\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    msg9[] = "\xFD\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    
    ZNPoly1305(mac, key9, msg9, sizeof(msg9) - 1);
    r += zn_test((memcmp("\xFA\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", mac, 16) != 0),
                 "ZNPoly1305() test 9");

    const uint8_t key10[] = "\x01\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    msg10[] = "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\0\0\0\0\0\0\0\0\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    
    ZNPoly1305(mac, key10, msg10, sizeof(msg10) - 1);
    r += zn_test((memcmp("\x14\0\0\0\0\0\0\0\x55\0\0\0\0\0\0\0", mac, 16) != 0), "ZNPoly1305() test 10");

    const uint8_t key11[] = "\x01\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    msg11[] = "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\0\0\0\0\0\0\0\0\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0";
    
    ZNPoly1305(mac, key11, msg11, sizeof(msg11) - 1);
    r += zn_test((memcmp("\x13\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", mac, 16) != 0), "ZNPoly1305() test 11");
    
    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNDrbgTests(void)
{
    int r = 0;
    const uint8_t seed1[] = "\xa7\x6e\x77\xa9\x69\xab\x92\x64\x51\x81\xf0\x15\x78\x02\x52\x37\x46\xc3\x4b\xf3\x21\x86"
    "\x76\x41", nonce1[] = "\x05\x1e\xd6\xba\x39\x36\x80\x33\xad\xc9\x3d\x4e";
    uint8_t out[2048/8], K[512/8], V[512/8];
    
    ZNHMACDRBG(out, 896/8, K, V, ZNSHA224, 224/8, seed1, sizeof(seed1) - 1, nonce1, sizeof(nonce1) - 1, NULL, 0);
    ZNHMACDRBG(out, 896/8, K, V, ZNSHA224, 224/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\x89\x25\x98\x7d\xb5\x56\x6e\x60\x52\x0f\x09\xbd\xdd\xab\x48\x82\x92\xbe\xd9\x2c\xd3\x85\xe5\xb6\xfc"
               "\x22\x3e\x19\x19\x64\x0b\x4e\x34\xe3\x45\x75\x03\x3e\x56\xc0\xa8\xf6\x08\xbe\x21\xd3\xd2\x21\xc6\x7d"
               "\x39\xab\xec\x98\xd8\x13\x12\xf3\xa2\x65\x3d\x55\xff\xbf\x44\xc3\x37\xc8\x2b\xed\x31\x4c\x21\x1b\xe2"
               "\x3e\xc3\x94\x39\x9b\xa3\x51\xc4\x68\x7d\xce\x64\x9e\x7c\x2a\x1b\xa7\xb0\xb5\xda\xb1\x25\x67\x1b\x1b"
               "\xcf\x90\x08\xda\x65\xca\xd6\x12\xd9\x5d\xdc\x92", out, 896/8) != 0), "ZNHMACDRBG() test 1");

    const uint8_t seed2[] = "\xf6\xe6\x8b\xb0\x58\x5c\x84\xd7\xb9\xf1\x75\x79\xad\x9b\x9a\x8a\xa2\x66\x6a\xbf\x4e\x8b"
    "\x44\xa3", nonce2[] = "\xa4\x33\x11\xd5\x78\x42\xef\x09\x6b\x66\xfa\x5e",
    ps2[] = "\x2f\x50\x7e\x12\xd6\x8a\x88\x0f\xa7\x0d\x6e\x5e\x54\x39\x15\x38\x17\x32\x97\x81\x4e\x06\xd7\xfd";

    ZNHMACDRBG(out, 896/8, K, V, ZNSHA224, 224/8, seed2, sizeof(seed2) - 1, nonce2, sizeof(nonce2) - 1,
               ps2, sizeof(ps2) - 1);
    ZNHMACDRBG(out, 896/8, K, V, ZNSHA224, 224/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\x10\xc2\xf9\x3c\xa9\x9a\x8e\x8e\xcf\x22\x54\x00\xc8\x04\xa7\xb3\x68\xd9\x3c\xee\x3b\xfa\x6f\x44\x59"
               "\x20\xa6\xa9\x12\xd2\x68\xd6\x91\xf1\x78\x8b\xaf\x01\x3f\xb1\x68\x50\x1c\xa1\x56\xb5\x71\xba\x04\x7d"
               "\x8d\x02\x9d\xc1\xc1\xee\x07\xfc\xa5\x0a\xf6\x99\xc5\xbc\x2f\x79\x0a\xcf\x27\x80\x41\x51\x81\x41\xe7"
               "\xdc\x91\x64\xc3\xe5\x71\xb2\x65\xfb\x89\x54\x26\x1d\x92\xdb\xf2\x0a\xe0\x2f\xc2\xb7\x80\xc0\x18\xb6"
               "\xb5\x4b\x43\x20\xf2\xb8\x9d\x34\x33\x07\xfb\xb2", out, 896/8) != 0), "ZNHMACDRBG() test 2");

    const uint8_t seed3[] = "\xca\x85\x19\x11\x34\x93\x84\xbf\xfe\x89\xde\x1c\xbd\xc4\x6e\x68\x31\xe4\x4d\x34\xa4\xfb"
    "\x93\x5e\xe2\x85\xdd\x14\xb7\x1a\x74\x88",
    nonce3[] = "\x65\x9b\xa9\x6c\x60\x1d\xc6\x9f\xc9\x02\x94\x08\x05\xec\x0c\xa8";
    
    ZNHMACDRBG(out, 1024/8, K, V, ZNSHA256, 256/8, seed3, sizeof(seed3) - 1, nonce3, sizeof(nonce3) - 1, NULL, 0);
    ZNHMACDRBG(out, 1024/8, K, V, ZNSHA256, 256/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\xe5\x28\xe9\xab\xf2\xde\xce\x54\xd4\x7c\x7e\x75\xe5\xfe\x30\x21\x49\xf8\x17\xea\x9f\xb4\xbe\xe6\xf4"
               "\x19\x96\x97\xd0\x4d\x5b\x89\xd5\x4f\xbb\x97\x8a\x15\xb5\xc4\x43\xc9\xec\x21\x03\x6d\x24\x60\xb6\xf7"
               "\x3e\xba\xd0\xdc\x2a\xba\x6e\x62\x4a\xbf\x07\x74\x5b\xc1\x07\x69\x4b\xb7\x54\x7b\xb0\x99\x5f\x70\xde"
               "\x25\xd6\xb2\x9e\x2d\x30\x11\xbb\x19\xd2\x76\x76\xc0\x71\x62\xc8\xb5\xcc\xde\x06\x68\x96\x1d\xf8\x68"
               "\x03\x48\x2c\xb3\x7e\xd6\xd5\xc0\xbb\x8d\x50\xcf\x1f\x50\xd4\x76\xaa\x04\x58\xbd\xab\xa8\x06\xf4\x8b"
               "\xe9\xdc\xb8", out, 1024/8) != 0), "ZNHMACDRBG() test 3");

    const uint8_t seed4[] = "\x5c\xac\xc6\x81\x65\xa2\xe2\xee\x20\x81\x2f\x35\xec\x73\xa7\x9d\xbf\x30\xfd\x47\x54\x76"
    "\xac\x0c\x44\xfc\x61\x74\xcd\xac\x2b\x55",
    nonce4[] = "\x6f\x88\x54\x96\xc1\xe6\x3a\xf6\x20\xbe\xcd\x9e\x71\xec\xb8\x24",
    ps4[] = "\xe7\x2d\xd8\x59\x0d\x4e\xd5\x29\x55\x15\xc3\x5e\xd6\x19\x9e\x9d\x21\x1b\x8f\x06\x9b\x30\x58\xca\xa6\x67"
    "\x0b\x96\xef\x12\x08\xd0";
    
    ZNHMACDRBG(out, 1024/8, K, V, ZNSHA256, 256/8, seed4, sizeof(seed4) - 1, nonce4, sizeof(nonce4) - 1,
               ps4, sizeof(ps4) - 1);
    ZNHMACDRBG(out, 1024/8, K, V, ZNSHA256, 256/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\xf1\x01\x2c\xf5\x43\xf9\x45\x33\xdf\x27\xfe\xdf\xbf\x58\xe5\xb7\x9a\x3d\xc5\x17\xa9\xc4\x02\xbd\xbf"
               "\xc9\xa0\xc0\xf7\x21\xf9\xd5\x3f\xaf\x4a\xaf\xdc\x4b\x8f\x7a\x1b\x58\x0f\xca\xa5\x23\x38\xd4\xbd\x95"
               "\xf5\x89\x66\xa2\x43\xcd\xcd\x3f\x44\x6e\xd4\xbc\x54\x6d\x9f\x60\x7b\x19\x0d\xd6\x99\x54\x45\x0d\x16"
               "\xcd\x0e\x2d\x64\x37\x06\x7d\x8b\x44\xd1\x9a\x6a\xf7\xa7\xcf\xa8\x79\x4e\x5f\xbd\x72\x8e\x8f\xb2\xf2"
               "\xe8\xdb\x5d\xd4\xff\x1a\xa2\x75\xf3\x58\x86\x09\x8e\x80\xff\x84\x48\x86\x06\x0d\xa8\xb1\xe7\x13\x78"
               "\x46\xb2\x3b", out, 1024/8) != 0), "ZNHMACDRBG() test 4");

    const uint8_t seed5[] = "\xa1\xdc\x2d\xfe\xda\x4f\x3a\x11\x24\xe0\xe7\x5e\xbf\xbe\x5f\x98\xca\xc1\x10\x18\x22\x1d"
    "\xda\x3f\xdc\xf8\xf9\x12\x5d\x68\x44\x7a",
    nonce5[] = "\xba\xe5\xea\x27\x16\x65\x40\x51\x52\x68\xa4\x93\xa9\x6b\x51\x87";
    
    ZNHMACDRBG(out, 1536/8, K, V, ZNSHA384, 384/8, seed5, sizeof(seed5) - 1, nonce5, sizeof(nonce5) - 1, NULL, 0);
    ZNHMACDRBG(out, 1536/8, K, V, ZNSHA384, 384/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\x22\x82\x93\xe5\x9b\x1e\x45\x45\xa4\xff\x9f\x23\x26\x16\xfc\x51\x08\xa1\x12\x8d\xeb\xd0\xf7\xc2\x0a"
               "\xce\x83\x7c\xa1\x05\xcb\xf2\x4c\x0d\xac\x1f\x98\x47\xda\xfd\x0d\x05\x00\x72\x1f\xfa\xd3\xc6\x84\xa9"
               "\x92\xd1\x10\xa5\x49\xa2\x64\xd1\x4a\x89\x11\xc5\x0b\xe8\xcd\x6a\x7e\x8f\xac\x78\x3a\xd9\x5b\x24\xf6"
               "\x4f\xd8\xcc\x4c\x8b\x64\x9e\xac\x2b\x15\xb3\x63\xe3\x0d\xf7\x95\x41\xa6\xb8\xa1\xca\xac\x23\x89\x49"
               "\xb4\x66\x43\x69\x4c\x85\xe1\xd5\xfc\xbc\xd9\xaa\xae\x62\x60\xac\xee\x66\x0b\x8a\x79\xbe\xa4\x8e\x07"
               "\x9c\xeb\x6a\x5e\xaf\x49\x93\xa8\x2c\x3f\x1b\x75\x8d\x7c\x53\xe3\x09\x4e\xea\xc6\x3d\xc2\x55\xbe\x6d"
               "\xcd\xcc\x2b\x51\xe5\xca\x45\xd2\xb2\x06\x84\xa5\xa8\xfa\x58\x06\xb9\x6f\x84\x61\xeb\xf5\x1b\xc5\x15"
               "\xa7\xdd\x8c\x54\x75\xc0\xe7\x0f\x2f\xd0\xfa\xf7\x86\x9a\x99\xab\x6c", out, 1536/8) != 0),
               "ZNHMACDRBG() test 5");

    const uint8_t seed6[] = "\x2c\xd9\x68\xba\xcd\xa2\xbc\x31\x4d\x2f\xb4\x1f\xe4\x33\x54\xfb\x76\x11\x34\xeb\x19\xee"
    "\xc6\x04\x31\xe2\xf3\x67\x55\xb8\x51\x26",
    nonce6[] = "\xe3\xde\xdf\x2a\xf9\x38\x2a\x1e\x65\x21\x43\xe9\x52\x21\x2d\x39",
    ps6[] = "\x59\xfa\x82\x35\x10\x88\x21\xac\xcb\xd3\xc1\x4e\xaf\x76\x85\x6d\x6a\x07\xf4\x33\x83\xdb\x4c\xc6\x03\x80"
    "\x40\xb1\x88\x10\xd5\x3c";

    ZNHMACDRBG(out, 1536/8, K, V, ZNSHA384, 384/8, seed6, sizeof(seed6) - 1, nonce6, sizeof(nonce6) - 1,
               ps6, sizeof(ps6) - 1);
    ZNHMACDRBG(out, 1536/8, K, V, ZNSHA384, 384/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\x06\x05\x1c\xe6\xb2\xf1\xc3\x43\x78\xe0\x8c\xaf\x8f\xe8\x36\x20\x1f\xf7\xec\x2d\xb8\xfc\x5a\x25\x19"
               "\xad\xd2\x52\x4d\x90\x47\x01\x94\xb2\x47\xaf\x3a\x34\xa6\x73\x29\x8e\x57\x07\x0b\x25\x6f\x59\xfd\x09"
               "\x86\x32\x76\x8e\x2d\x55\x13\x7d\x6c\x17\xb1\xa5\x3f\xe4\x5d\x6e\xd0\xe3\x1d\x49\xe6\x48\x20\xdb\x14"
               "\x50\x14\xe2\xf0\x38\xb6\x9b\x72\x20\xe0\x42\xa8\xef\xc9\x89\x85\x70\x6a\xb9\x63\x54\x51\x23\x0a\x12"
               "\x8a\xee\x80\x1d\x4e\x37\x18\xff\x59\x51\x1c\x3f\x3f\xf1\xb2\x0f\x10\x97\x74\xa8\xdd\xc1\xfa\xdf\x41"
               "\xaf\xcc\x13\xd4\x00\x96\xd9\x97\x94\x88\x57\xa8\x94\xd0\xef\x8b\x32\x35\xc3\x21\x3b\xa8\x5c\x50\xc2"
               "\xf3\xd6\x1b\x0d\x10\x4e\xcc\xfc\xf3\x6c\x35\xfe\x5e\x49\xe7\x60\x2c\xb1\x53\x3d\xe1\x2f\x0b\xec\x61"
               "\x3a\x0e\xd9\x63\x38\x21\x95\x7e\x5b\x7c\xb3\x2f\x60\xb7\xc0\x2f\xa4", out, 1536/8) != 0),
               "ZNHMACDRBG() test 6");

    const uint8_t seed7[] = "\x35\x04\x9f\x38\x9a\x33\xc0\xec\xb1\x29\x32\x38\xfd\x95\x1f\x8f\xfd\x51\x7d\xfd\xe0\x60"
    "\x41\xd3\x29\x45\xb3\xe2\x69\x14\xba\x15",
    nonce7[] = "\xf7\x32\x87\x60\xbe\x61\x68\xe6\xaa\x9f\xb5\x47\x84\x98\x9a\x11";
    
    ZNHMACDRBG(out, 2048/8, K, V, ZNSHA512, 512/8, seed7, sizeof(seed7) - 1, nonce7, sizeof(nonce7) - 1, NULL, 0);
    ZNHMACDRBG(out, 2048/8, K, V, ZNSHA512, 512/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\xe7\x64\x91\xb0\x26\x0a\xac\xfd\xed\x01\xad\x39\xfb\xf1\xa6\x6a\x88\x28\x4c\xaa\x51\x23\x36\x8a\x2a"
               "\xd9\x33\x0e\xe4\x83\x35\xe3\xc9\xc9\xba\x90\xe6\xcb\xc9\x42\x99\x62\xd6\x0c\x1a\x66\x61\xed\xcf\xaa"
               "\x31\xd9\x72\xb8\x26\x4b\x9d\x45\x62\xcf\x18\x49\x41\x28\xa0\x92\xc1\x7a\x8d\xa6\xf3\x11\x3e\x8a\x7e"
               "\xdf\xcd\x44\x27\x08\x2b\xd3\x90\x67\x5e\x96\x62\x40\x81\x44\x97\x17\x17\x30\x3d\x8d\xc3\x52\xc9\xe8"
               "\xb9\x5e\x7f\x35\xfa\x2a\xc9\xf5\x49\xb2\x92\xbc\x7c\x4b\xc7\xf0\x1e\xe0\xa5\x77\x85\x9e\xf6\xe8\x2d"
               "\x79\xef\x23\x89\x2d\x16\x7c\x14\x0d\x22\xaa\xc3\x2b\x64\xcc\xdf\xee\xe2\x73\x05\x28\xa3\x87\x63\xb2"
               "\x42\x27\xf9\x1a\xc3\xff\xe4\x7f\xb1\x15\x38\xe4\x35\x30\x7e\x77\x48\x18\x02\xb0\xf6\x13\xf3\x70\xff"
               "\xb0\xdb\xea\xb7\x74\xfe\x1e\xfb\xb1\xa8\x0d\x01\x15\x4a\x94\x59\xe7\x3a\xd3\x61\x10\x8b\xbc\x86\xb0"
               "\x91\x4f\x09\x51\x36\xcb\xe6\x34\x55\x5c\xe0\xbb\x26\x36\x18\xdc\x5c\x36\x72\x91\xce\x08\x25\x51\x89"
               "\x87\x15\x4f\xe9\xec\xb0\x52\xb3\xf0\xa2\x56\xfc\xc3\x0c\xc1\x45\x72\x53\x1c\x96\x28\x97\x36\x39\xbe"
               "\xda\x45\x6f\x2b\xdd\xf6", out, 2048/8) != 0), "ZNHMACDRBG() test 7");

    const uint8_t seed8[] = "\x73\x52\x9b\xba\x71\xa3\xd4\xb4\xfc\xf9\xa7\xed\xee\xd2\x69\xdb\xdc\x37\x48\xb9\x0d\xf6"
    "\x8c\x0d\x00\xe2\x45\xde\x54\x69\x8c\x77",
    nonce8[] = "\x22\xe2\xd6\xe2\x45\x01\x21\x2b\x6f\x05\x8e\x7c\x54\x13\x80\x07",
    ps8[] = "\xe2\xcc\x19\xe3\x15\x95\xd0\xe4\xde\x9e\x8b\xd3\xb2\x36\xde\xc2\xd4\xb0\x32\xc3\xdd\x5b\xf9\x89\x1c\x28"
    "\x4c\xd1\xba\xc6\x7b\xdb";
    
    ZNHMACDRBG(out, 2048/8, K, V, ZNSHA512, 512/8, seed8, sizeof(seed8) - 1, nonce8, sizeof(nonce8) - 1,
               ps8, sizeof(ps8) - 1);
    ZNHMACDRBG(out, 2048/8, K, V, ZNSHA512, 512/8, NULL, 0, NULL, 0, NULL, 0);
    r += zn_test((memcmp(
               "\x1a\x73\xd5\x8b\x73\x42\xc3\xc9\x33\xe3\xba\x15\xee\xdd\x82\x70\x98\x86\x91\xc3\x79\x4b\x45\xaa\x35"
               "\x85\x70\x39\x15\x71\x88\x1c\x0d\x9c\x42\x89\xe5\xb1\x98\xdb\x55\x34\xc3\xcb\x84\x66\xab\x48\x25\x0f"
               "\xa6\x7f\x24\xcb\x19\xb7\x03\x8e\x46\xaf\x56\x68\x7b\xab\x7e\x5d\xe3\xc8\x2f\xa7\x31\x2f\x54\xdc\x0f"
               "\x1d\xc9\x3f\x5b\x03\xfc\xaa\x60\x03\xca\xe2\x8d\x3d\x47\x07\x36\x8c\x14\x4a\x7a\xa4\x60\x91\x82\x2d"
               "\xa2\x92\xf9\x7f\x32\xca\xf9\x0a\xe3\xdd\x3e\x48\xe8\x08\xae\x12\xe6\x33\xaa\x04\x10\x10\x6e\x1a\xb5"
               "\x6b\xc0\xa0\xd8\x0f\x43\x8e\x9b\x34\x92\xe4\xa3\xbc\x88\xd7\x3a\x39\x04\xf7\xdd\x06\x0c\x48\xae\x8d"
               "\x7b\x12\xbf\x89\xa1\x95\x51\xb5\x3b\x3f\x55\xa5\x11\xd2\x82\x0e\x94\x16\x40\xc8\x45\xa8\xa0\x46\x64"
               "\x32\xc5\x85\x0c\x5b\x61\xbe\xc5\x27\x26\x02\x52\x11\x25\xad\xdf\x67\x7e\x94\x9b\x96\x78\x2b\xc0\x1a"
               "\x90\x44\x91\xdf\x08\x08\x9b\xed\x00\x4a\xd5\x6e\x12\xf8\xea\x1a\x20\x08\x83\xad\x72\xb3\xb9\xfa\xe1"
               "\x2b\x4e\xb6\x5d\x5c\x2b\xac\xb3\xce\x46\xc7\xc4\x84\x64\xc9\xc2\x91\x42\xfb\x35\xe7\xbc\x26\x7c\xe8"
               "\x52\x29\x6a\xc0\x42\xf9", out, 2048/8) != 0), "ZNHMACDRBG() test 8");
 
    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNChachaTests(void)
{
    int r = 0;
    const uint8_t key[] = "\0\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16"
    "\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    iv[] = "\0\0\0\x4a\0\0\0\0",
    msg[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen "
    "would be it.",
    cipher[] = "\x6e\x2e\x35\x9a\x25\x68\xf9\x80\x41\xba\x07\x28\xdd\x0d\x69\x81\xe9\x7e\x7a\xec\x1d\x43\x60\xc2\x0a"
    "\x27\xaf\xcc\xfd\x9f\xae\x0b\xf9\x1b\x65\xc5\x52\x47\x33\xab\x8f\x59\x3d\xab\xcd\x62\xb3\x57\x16\x39\xd6\x24\xe6"
    "\x51\x52\xab\x8f\x53\x0c\x35\x9f\x08\x61\xd8\x07\xca\x0d\xbf\x50\x0d\x6a\x61\x56\xa3\x8e\x08\x8a\x22\xb6\x5e\x52"
    "\xbc\x51\x4d\x16\xcc\xf8\x06\x81\x8c\xe9\x1a\xb7\x79\x37\x36\x5a\xf9\x0b\xbf\x74\xa3\x5b\xe6\xb4\x0b\x8e\xed\xf2"
    "\x78\x5e\x42\x87\x4d";
    uint8_t out[sizeof(msg) - 1];

    ZNChacha20(out, key, iv, msg, sizeof(msg) - 1, 1);
    r += zn_test((memcmp(cipher, out, sizeof(out)) != 0), "ZNChacha20() cipher test 0");

    ZNChacha20(out, key, iv, out, sizeof(out), 1);
    r += zn_test((memcmp(msg, out, sizeof(out)) != 0), "ZNChacha20() de-cipher test 0");

    const uint8_t key1[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    iv1[] = "\0\0\0\0\0\0\0\0",
    msg1[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0",
    cipher1[] = "\x76\xb8\xe0\xad\xa0\xf1\x3d\x90\x40\x5d\x6a\xe5\x53\x86\xbd\x28\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa8"
    "\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\xd8\x4a\x37\x6a\x43\xb8\xf4\x15"
    "\x18\xa1\x1c\xc3\x87\xb6\x69\xb2\xee\x65\x86";
    uint8_t out1[sizeof(msg1) - 1];
    
    ZNChacha20(out1, key1, iv1, msg1, sizeof(msg1) - 1, 0);
    r += zn_test((memcmp(cipher1, out1, sizeof(out1)) != 0), "ZNChacha20() cipher test 1");
    
    ZNChacha20(out1, key1, iv1, out1, sizeof(out1), 0);
    r += zn_test((memcmp(msg1, out1, sizeof(out1)) != 0), "ZNChacha20() de-cipher test 1");

    const uint8_t key2[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01",
    iv2[] = "\0\0\0\0\0\0\0\x02",
    msg2[] = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF "
    "Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF "
    "Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic "
    "communications made at any time or place, which are addressed to",
    cipher2[] = "\xa3\xfb\xf0\x7d\xf3\xfa\x2f\xde\x4f\x37\x6c\xa2\x3e\x82\x73\x70\x41\x60\x5d\x9f\x4f\x4f\x57\xbd\x8c"
    "\xff\x2c\x1d\x4b\x79\x55\xec\x2a\x97\x94\x8b\xd3\x72\x29\x15\xc8\xf3\xd3\x37\xf7\xd3\x70\x05\x0e\x9e\x96\xd6\x47"
    "\xb7\xc3\x9f\x56\xe0\x31\xca\x5e\xb6\x25\x0d\x40\x42\xe0\x27\x85\xec\xec\xfa\x4b\x4b\xb5\xe8\xea\xd0\x44\x0e\x20"
    "\xb6\xe8\xdb\x09\xd8\x81\xa7\xc6\x13\x2f\x42\x0e\x52\x79\x50\x42\xbd\xfa\x77\x73\xd8\xa9\x05\x14\x47\xb3\x29\x1c"
    "\xe1\x41\x1c\x68\x04\x65\x55\x2a\xa6\xc4\x05\xb7\x76\x4d\x5e\x87\xbe\xa8\x5a\xd0\x0f\x84\x49\xed\x8f\x72\xd0\xd6"
    "\x62\xab\x05\x26\x91\xca\x66\x42\x4b\xc8\x6d\x2d\xf8\x0e\xa4\x1f\x43\xab\xf9\x37\xd3\x25\x9d\xc4\xb2\xd0\xdf\xb4"
    "\x8a\x6c\x91\x39\xdd\xd7\xf7\x69\x66\xe9\x28\xe6\x35\x55\x3b\xa7\x6c\x5c\x87\x9d\x7b\x35\xd4\x9e\xb2\xe6\x2b\x08"
    "\x71\xcd\xac\x63\x89\x39\xe2\x5e\x8a\x1e\x0e\xf9\xd5\x28\x0f\xa8\xca\x32\x8b\x35\x1c\x3c\x76\x59\x89\xcb\xcf\x3d"
    "\xaa\x8b\x6c\xcc\x3a\xaf\x9f\x39\x79\xc9\x2b\x37\x20\xfc\x88\xdc\x95\xed\x84\xa1\xbe\x05\x9c\x64\x99\xb9\xfd\xa2"
    "\x36\xe7\xe8\x18\xb0\x4b\x0b\xc3\x9c\x1e\x87\x6b\x19\x3b\xfe\x55\x69\x75\x3f\x88\x12\x8c\xc0\x8a\xaa\x9b\x63\xd1"
    "\xa1\x6f\x80\xef\x25\x54\xd7\x18\x9c\x41\x1f\x58\x69\xca\x52\xc5\xb8\x3f\xa3\x6f\xf2\x16\xb9\xc1\xd3\x00\x62\xbe"
    "\xbc\xfd\x2d\xc5\xbc\xe0\x91\x19\x34\xfd\xa7\x9a\x86\xf6\xe6\x98\xce\xd7\x59\xc3\xff\x9b\x64\x77\x33\x8f\x3d\xa4"
    "\xf9\xcd\x85\x14\xea\x99\x82\xcc\xaf\xb3\x41\xb2\x38\x4d\xd9\x02\xf3\xd1\xab\x7a\xc6\x1d\xd2\x9c\x6f\x21\xba\x5b"
    "\x86\x2f\x37\x30\xe3\x7c\xfd\xc4\xfd\x80\x6c\x22\xf2\x21";
    uint8_t out2[sizeof(msg2) - 1];
    
    ZNChacha20(out2, key2, iv2, msg2, sizeof(msg2) - 1, 1);
    r += zn_test((memcmp(cipher2, out2, sizeof(out2)) != 0), "ZNChacha20() cipher test 2");
    
    ZNChacha20(out2, key2, iv2, out2, sizeof(out2), 1);
    r += zn_test((memcmp(msg2, out2, sizeof(out2)) != 0), "ZNChacha20() de-cipher test 2");
    
    const uint8_t key3[] = "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0\x47\x39\x17\xc1\x40\x2b"
    "\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0",
    iv3[] = "\0\0\0\0\0\0\0\x02",
    msg3[] = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\n"
    "And the mome raths outgrabe.",
    cipher3[] = "\x62\xe6\x34\x7f\x95\xed\x87\xa4\x5f\xfa\xe7\x42\x6f\x27\xa1\xdf\x5f\xb6\x91\x10\x04\x4c\x0d\x73\x11"
    "\x8e\xff\xa9\x5b\x01\xe5\xcf\x16\x6d\x3d\xf2\xd7\x21\xca\xf9\xb2\x1e\x5f\xb1\x4c\x61\x68\x71\xfd\x84\xc5\x4f\x9d"
    "\x65\xb2\x83\x19\x6c\x7f\xe4\xf6\x05\x53\xeb\xf3\x9c\x64\x02\xc4\x22\x34\xe3\x2a\x35\x6b\x3e\x76\x43\x12\xa6\x1a"
    "\x55\x32\x05\x57\x16\xea\xd6\x96\x25\x68\xf8\x7d\x3f\x3f\x77\x04\xc6\xa8\xd1\xbc\xd1\xbf\x4d\x50\xd6\x15\x4b\x6d"
    "\xa7\x31\xb1\x87\xb5\x8d\xfd\x72\x8a\xfa\x36\x75\x7a\x79\x7a\xc1\x88\xd1";
    uint8_t out3[sizeof(msg3) - 1];
    
    ZNChacha20(out3, key3, iv3, msg3, sizeof(msg3) - 1, 42);
    r += zn_test((memcmp(cipher3, out3, sizeof(out3)) != 0), "ZNChacha20() cipher test 3");
    
    ZNChacha20(out3, key3, iv3, out3, sizeof(out3), 42);
    r += zn_test((memcmp(msg3, out3, sizeof(out3)) != 0), "ZNChacha20() de-cipher test 3");

    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNAuthEncryptTests(void)
{
    int r = 0;
    const uint8_t msg1[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future,"
    " sunscreen would be it.",
    ad1[] = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
    key1[] = "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99"
    "\x9a\x9b\x9c\x9d\x9e\x9f",
    nonce1[] = "\x07\x00\x00\x00\x40\x41\x42\x43\x44\x45\x46\x47",
    cipher1[] = "\xd3\x1a\x8d\x34\x64\x8e\x60\xdb\x7b\x86\xaf\xbc\x53\xef\x7e\xc2\xa4\xad\xed\x51\x29\x6e\x08\xfe\xa9"
    "\xe2\xb5\xa7\x36\xee\x62\xd6\x3d\xbe\xa4\x5e\x8c\xa9\x67\x12\x82\xfa\xfb\x69\xda\x92\x72\x8b\x1a\x71\xde\x0a\x9e"
    "\x06\x0b\x29\x05\xd6\xa5\xb6\x7e\xcd\x3b\x36\x92\xdd\xbd\x7f\x2d\x77\x8b\x8c\x98\x03\xae\xe3\x28\x09\x1b\x58\xfa"
    "\xb3\x24\xe4\xfa\xd6\x75\x94\x55\x85\x80\x8b\x48\x31\xd7\xbc\x3f\xf4\xde\xf0\x8e\x4b\x7a\x9d\xe5\x76\xd2\x65\x86"
    "\xce\xc6\x4b\x61\x16\x1a\xe1\x0b\x59\x4f\x09\xe2\x6a\x7e\x90\x2e\xcb\xd0\x60\x06\x91";
    uint8_t out1[16 + sizeof(msg1) - 1];
    size_t len;

    len = ZNChacha20Poly1305AEADEncrypt(out1, sizeof(out1), key1, nonce1, msg1, sizeof(msg1) - 1, ad1, sizeof(ad1) - 1);
    r += zn_test((len != sizeof(cipher1) - 1 || memcmp(cipher1, out1, len) != 0),
                 "ZNChacha20Poly1305AEADEncrypt() cipher test 1");
    
    len = ZNChacha20Poly1305AEADDecrypt(out1, sizeof(out1), key1, nonce1, cipher1, sizeof(cipher1) - 1, ad1,
                                        sizeof(ad1) - 1);
    r += zn_test((len != sizeof(msg1) - 1 || memcmp(msg1, out1, len) != 0),
                 "ZNChacha20Poly1305AEADDecrypt() cipher test 1");
    
    const uint8_t msg2[] = "Internet-Drafts are draft documents valid for a maximum of six months and may be updated, "
    "replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference "
    "material or to cite them other than as /“work in progress./”",
    ad2[] = "\xf3\x33\x88\x86\0\0\0\0\0\0\x4e\x91",
    key2[] = "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca"
    "\x5c\xbc\x20\x70\x75\xc0",
    nonce2[] = "\0\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08",
    cipher2[] = "\x64\xa0\x86\x15\x75\x86\x1a\xf4\x60\xf0\x62\xc7\x9b\xe6\x43\xbd\x5e\x80\x5c\xfd\x34\x5c\xf3\x89\xf1"
    "\x08\x67\x0a\xc7\x6c\x8c\xb2\x4c\x6c\xfc\x18\x75\x5d\x43\xee\xa0\x9e\xe9\x4e\x38\x2d\x26\xb0\xbd\xb7\xb7\x3c\x32"
    "\x1b\x01\x00\xd4\xf0\x3b\x7f\x35\x58\x94\xcf\x33\x2f\x83\x0e\x71\x0b\x97\xce\x98\xc8\xa8\x4a\xbd\x0b\x94\x81\x14"
    "\xad\x17\x6e\x00\x8d\x33\xbd\x60\xf9\x82\xb1\xff\x37\xc8\x55\x97\x97\xa0\x6e\xf4\xf0\xef\x61\xc1\x86\x32\x4e\x2b"
    "\x35\x06\x38\x36\x06\x90\x7b\x6a\x7c\x02\xb0\xf9\xf6\x15\x7b\x53\xc8\x67\xe4\xb9\x16\x6c\x76\x7b\x80\x4d\x46\xa5"
    "\x9b\x52\x16\xcd\xe7\xa4\xe9\x90\x40\xc5\xa4\x04\x33\x22\x5e\xe2\x82\xa1\xb0\xa0\x6c\x52\x3e\xaf\x45\x34\xd7\xf8"
    "\x3f\xa1\x15\x5b\x00\x47\x71\x8c\xbc\x54\x6a\x0d\x07\x2b\x04\xb3\x56\x4e\xea\x1b\x42\x22\x73\xf5\x48\x27\x1a\x0b"
    "\xb2\x31\x60\x53\xfa\x76\x99\x19\x55\xeb\xd6\x31\x59\x43\x4e\xce\xbb\x4e\x46\x6d\xae\x5a\x10\x73\xa6\x72\x76\x27"
    "\x09\x7a\x10\x49\xe6\x17\xd9\x1d\x36\x10\x94\xfa\x68\xf0\xff\x77\x98\x71\x30\x30\x5b\xea\xba\x2e\xda\x04\xdf\x99"
    "\x7b\x71\x4d\x6c\x6f\x2c\x29\xa6\xad\x5c\xb4\x02\x2b\x02\x70\x9b\xee\xad\x9d\x67\x89\x0c\xbb\x22\x39\x23\x36\xfe"
    "\xa1\x85\x1f\x38";
    uint8_t out2[sizeof(cipher2) - 1];

    len = ZNChacha20Poly1305AEADDecrypt(out2, sizeof(out2), key2, nonce2, cipher2, sizeof(cipher2) - 1, ad2,
                                        sizeof(ad2) - 1);
    r += zn_test((len != sizeof(msg2) - 1 || memcmp(msg2, out2, len) != 0),
                 "ZNChacha20Poly1305AEADDecrypt() cipher test 2");

    len = ZNChacha20Poly1305AEADEncrypt(out2, sizeof(out2), key2, nonce2, msg2, sizeof(msg2) - 1, ad2, sizeof(ad2) - 1);
    r += zn_test((len != sizeof(cipher2) - 1 || memcmp(cipher2, out2, len) != 0),
                 "ZNChacha20Poly1305AEADEncrypt() cipher test 2");

    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNAesTests(void)
{
    int r = 0;
    
    const uint8_t iv[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
    const uint8_t plain[] = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03"
    "\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f"
    "\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
    uint8_t buf[sizeof(plain)];
    uint8_t key1[32] = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const uint8_t cipher1[] = "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97";
    const uint8_t in1[] = "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce\x98\x06\xf6\x6b\x79\x70\xfd"
    "\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab\x1e\x03\x1d"
    "\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee";
    
    memcpy(buf, plain, 16);
    ZNAESECBEncrypt(buf, key1, 16);
    r += zn_test((memcmp(buf, cipher1, 16) != 0), "ZNAESECBEncrypt() test 1");

    memcpy(buf, cipher1, 16);
    ZNAESECBDecrypt(buf, key1, 16);
    r += zn_test((memcmp(buf, plain, 16) != 0), "ZNAESECBDecrypt() test 1");

    ZNAESCTR(buf, key1, 16, iv, in1, 64);
    r += zn_test((memcmp(buf, plain, 64) != 0), "ZNAESCTR() test 1");
    
    uint8_t key2[32] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b"
    "\x7b\x00\x00\x00\x00\x00\x00\x00\x00";
    const uint8_t cipher2[] = "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc";
    const uint8_t in2[] = "\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b\x09\x03\x39\xec\x0a\xa6\xfa"
    "\xef\xd5\xcc\xc2\xc6\xf4\xce\x8e\x94\x1e\x36\xb2\x6b\xd1\xeb\xc6\x70\xd1\xbd\x1d\x66\x56\x20\xab\xf7\x4f\x78\xa7"
    "\xf6\xd2\x98\x09\x58\x5a\x97\xda\xec\x58\xc6\xb0\x50";
    
    memcpy(buf, plain, 16);
    ZNAESECBEncrypt(buf, key2, 24);
    r += zn_test((memcmp(buf, cipher2, 16) != 0), "ZNAESECBEncrypt() test 2");

    memcpy(buf, cipher2, 16);
    ZNAESECBDecrypt(buf, key2, 24);
    r += zn_test((memcmp(buf, plain, 16) != 0), "ZNAESECBDecrypt() test 2");

    ZNAESCTR(buf, key2, 24, iv, in2, 64);
    r += zn_test((memcmp(buf, plain, 64) != 0), "ZNAESCTR() test 2");

    uint8_t key3[32] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08"
    "\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    const uint8_t cipher3[] = "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8";
    const uint8_t in3[] = "\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28\xf4\x43\xe3\xca\x4d\x62\xb5"
    "\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d\xdf\xc9\xc5"
    "\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79\x41\xa6";
    
    memcpy(buf, plain, 16);
    ZNAESECBEncrypt(buf, key3, 32);
    r += zn_test((memcmp(buf, cipher3, 16) != 0), "ZNAESECBEncrypt() test 3");

    memcpy(buf, cipher3, 16);
    ZNAESECBDecrypt(buf, key3, 32);
    r += zn_test((memcmp(buf, plain, 16) != 0), "ZNAESECBDecrypt() test 3");

    ZNAESCTR(buf, key3, 32, iv, in3, 64);
    r += zn_test((memcmp(buf, plain, 64) != 0), "ZNAESCTR() test 3");
    
    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNKDFTests(void)
{
    int r = 0;
    uint8_t dk[64];
        
    ZNPBKDF2(dk, 64, ZNSHA256, 256/8, (uint8_t *)"passwd", strlen("passwd"), (uint8_t *)"salt", strlen("salt"), 1);
    r += zn_test((memcmp(dk, "\x55\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44\xb6\x05"
                             "\xf9\x41\x85\x21\x6d\xde\x04\x65\xe6\x8b\x9d\x57\xc2\x0d\xac\xbc"
                             "\x49\xca\x9c\xcc\xf1\x79\xb6\x45\x99\x16\x64\xb3\x9d\x77\xef\x31"
                             "\x7c\x71\xb8\x45\xb1\xe3\x0b\xd5\x09\x11\x20\x41\xd3\xa1\x97\x83", 64) != 0),
                 "ZNPBKDF2() test1");
    
    ZNPBKDF2(dk, 64, ZNSHA256, 256/8, (uint8_t *)"Password", strlen("Password"), (uint8_t *)"NaCl", strlen("NaCl"),
             80000);
    r += zn_test((memcmp(dk, "\x4d\xdc\xd8\xf6\x0b\x98\xbe\x21\x83\x0c\xee\x5e\xf2\x27\x01\xf9"
                             "\x64\x1a\x44\x18\xd0\x4c\x04\x14\xae\xff\x08\x87\x6b\x34\xab\x56"
                             "\xa1\xd4\x25\xa1\x22\x58\x33\x54\x9a\xdb\x84\x1b\x51\xc9\xb3\x17"
                             "\x6a\x27\x2b\xde\xbb\xa1\xd0\x78\x47\x8f\x62\xb3\x97\xf3\x3c\x8d", 64) != 0),
                 "ZNPBKDF2() test2");
    
    ZNScrypt(dk, 64, (uint8_t *)"", 0, (uint8_t *)"", 0, 16, 1, 1);
    r += zn_test((memcmp(dk, "\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97"
                             "\xf1\x6b\x48\x44\xe3\x07\x4a\xe8\xdf\xdf\xfa\x3f\xed\xe2\x14\x42"
                             "\xfc\xd0\x06\x9d\xed\x09\x48\xf8\x32\x6a\x75\x3a\x0f\xc8\x1f\x17"
                             "\xe8\xd3\xe0\xfb\x2e\x0d\x36\x28\xcf\x35\xe2\x0c\x38\xd1\x89\x06", 64) != 0),
                 "ZNScrypt() test1");

    ZNScrypt(dk, 64, (uint8_t *)"password", 8, (uint8_t *)"NaCl", 4, 1024, 8, 16);
    r += zn_test((memcmp(dk, "\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7\x19\x0d\x01\xe9\xfe"
                             "\x7c\x6a\xd7\xcb\xc8\x23\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62"
                             "\x2e\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27\x9d\x98\x30\xda"
                             "\xc7\x27\xaf\xb9\x4a\x83\xee\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40", 64) != 0),
                 "ZNScrypt() test2");

    ZNScrypt(dk, 64, (uint8_t *)"pleaseletmein", 13, (uint8_t *)"SodiumChloride", 14, 16384, 8, 1);
    r += zn_test((memcmp(dk, "\x70\x23\xbd\xcb\x3a\xfd\x73\x48\x46\x1c\x06\xcd\x81\xfd\x38\xeb"
                             "\xfd\xa8\xfb\xba\x90\x4f\x8e\x3e\xa9\xb5\x43\xf6\x54\x5d\xa1\xf2"
                             "\xd5\x43\x29\x55\x61\x3f\x0f\xcf\x62\xd4\x97\x05\x24\x2a\x9a\xf9"
                             "\xe6\x1e\x85\xdc\x0d\x65\x1e\x40\xdf\xcf\x01\x7b\x45\x57\x58\x87", 64) != 0),
                 "ZNScrypt() test3");
               
    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNKeyTests(void)
{
    int r = 0;
    ZNKey key, key2;
    char addr[75];
    char *msg;
    uint8_t md[32];
    uint8_t sig[72], pubKey[65];
    size_t sigLen, pkLen;
    ZNAddrParams params = ZNMainNetParams;

    r += zn_test((ZNPrivKeyIsValid("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRz", params)),
                 "ZNPrivKeyIsValid() test 0");

    // mini private key format
    r += zn_test((! ZNPrivKeyIsValid("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy", params)),
                 "ZNPrivKeyIsValid() test 1");

    ZNKeySetPrivKey(&key, "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy", params);
    ZNKeyLegacyAddr(&key, addr, params);
    printf("\nprivKey:S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy = %s", addr);
    r += zn_test((! ZNAddressEq(addr, "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW")), "ZNKeySetPrivKey() test 1");

    ZNKeyLegacyAddr(&key, addr, ZNTestNetParams);
    printf("\nprivKey:S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy = %s", addr);
    r += zn_test((! ZNAddressEq(addr, "ms8fwvXzrCoyatnGFRaLbepSqwGRxVJQF1")), "ZNKeySetPrivKey() test 2");

    // old mini private key format
    r += zn_test((! ZNPrivKeyIsValid("SzavMBLoXU6kDrqtUVmffv", params)),
                 "ZNPrivKeyIsValid() test 2");

    ZNKeySetPrivKey(&key, "SzavMBLoXU6kDrqtUVmffv", params);
    ZNKeyLegacyAddr(&key, addr, params);
    printf("\nprivKey:SzavMBLoXU6kDrqtUVmffv = %s", addr);
    r += zn_test((! ZNAddressEq(addr, "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj")), "ZNKeySetPrivKey() test 3");

    ZNKeyLegacyAddr(&key, addr, ZNTestNetParams);
    printf("\nprivKey:SzavMBLoXU6kDrqtUVmffv = %s", addr);
    r += zn_test((! ZNAddressEq(addr, "mrhzp5mstA4Midx85EeCjuaUAAGANMFmRP")), "ZNKeySetPrivKey() test 4");

    // uncompressed private key
    r += zn_test((! ZNPrivKeyIsValid("5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF", params)),
                 "ZNPrivKeyIsValid() test 3");
        
    ZNKeySetPrivKey(&key, "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF", params);
    ZNKeyLegacyAddr(&key, addr, params);
    printf("\nprivKey:5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF = %s", addr);
    r += zn_test((! ZNAddressEq(addr, "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj")), "ZNKeySetPrivKey() test 3");
    
    // uncompressed private key export
    char privKey1[54];
    
    ZNKeyPrivKey(&key, privKey1, params);
    printf("\nprivKey:%s", privKey1);
    r += zn_test((strcmp(privKey1, "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF") != 0),
                 "ZNKeyPrivKey() test 1");
    
    // compressed private key
    r += zn_test((! ZNPrivKeyIsValid("KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params)),
                 "ZNPrivKeyIsValid() test 4");
        
    ZNKeySetPrivKey(&key, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    ZNKeyLegacyAddr(&key, addr, params);
    printf("\nprivKey:KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL = %s", addr);
    r += zn_test((! ZNAddressEq(addr, "1JMsC6fCtYWkTjPPdDrYX3we2aBrewuEM3")), "ZNKeySetPrivKey() test 4");
    
    // compressed private key export
    char privKey2[54];
        
    ZNKeyPrivKey(&key, privKey2, params);
    printf("\nprivKey:%s", privKey2);
    r += zn_test((strcmp(privKey2, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL") != 0),
                 "ZNKeyPrivKey() test 2");

    // pubkey match
    ZNKey prvKeyX1, prvKeyX2;
    ZNKey pubKeyX1, pubKeyX2;

    ZNKeyClean(&prvKeyX1); ZNKeyClean(&prvKeyX2);
    ZNKeySetPrivKey(&prvKeyX1, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    ZNKeySetPrivKey(&prvKeyX2, "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF", params);
    ZNKeyPubKey(&prvKeyX1, pubKeyX1.pubKey);
    ZNKeyPubKey(&prvKeyX2, pubKeyX2.pubKey);
    r += zn_test((memcmp(prvKeyX1.pubKey + 1, prvKeyX2.pubKey + 1, 32) == 0), "ZNKeySetPrivKey() test 5.2");

    ZNKeyClean(&prvKeyX1); ZNKeyClean(&prvKeyX2);
    ZNKeySetPrivKey(&prvKeyX1, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    ZNKeySetPrivKey(&prvKeyX2, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    prvKeyX1.compressed = 0;
    prvKeyX2.compressed = 0;
    ZNKeyPubKey(&prvKeyX1, pubKeyX1.pubKey);
    ZNKeyPubKey(&prvKeyX2, pubKeyX2.pubKey);
    r += zn_test((memcmp(prvKeyX1.pubKey + 1, prvKeyX2.pubKey + 1, 32) != 0), "ZNKeySetPrivKey() test 5.3.1");
    ZNKeySetPubKey(&pubKeyX1, prvKeyX1.pubKey, 65);
    ZNKeySetPubKey(&pubKeyX2, prvKeyX2.pubKey, 65);
    r += zn_test((memcmp(pubKeyX1.pubKey + 1, pubKeyX2.pubKey + 1, 32) != 0), "ZNKeySetPubKey() test 5.3.2");

    ZNKeyClean(&prvKeyX1); ZNKeyClean(&prvKeyX2);
    ZNKeySetPrivKey(&prvKeyX1, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    ZNKeySetPrivKey(&prvKeyX2, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    prvKeyX1.compressed = 0;
    prvKeyX2.compressed = 1;
    ZNKeyPubKey(&prvKeyX1, pubKeyX1.pubKey);
    ZNKeyPubKey(&prvKeyX2, pubKeyX2.pubKey);
    r += zn_test((memcmp(prvKeyX1.pubKey + 1, prvKeyX2.pubKey + 1, 32) != 0), "ZNKeySetPrivKey() test 5.3.1");
    ZNKeySetPubKey(&pubKeyX1, prvKeyX1.pubKey, 65);
    ZNKeySetPubKey(&pubKeyX2, prvKeyX2.pubKey, 33);
    r += zn_test((memcmp(pubKeyX1.pubKey + 1, pubKeyX2.pubKey + 1, 32) != 0), "ZNKeySetPubKey() test 5.3.2");

    ZNKeyClean(&prvKeyX1); ZNKeyClean(&prvKeyX2);
    ZNKeySetPrivKey(&prvKeyX1, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    ZNKeySetPrivKey(&prvKeyX2, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    prvKeyX1.compressed = 1;
    prvKeyX2.compressed = 0;
    ZNKeyPubKey(&prvKeyX1, pubKeyX1.pubKey);
    ZNKeyPubKey(&prvKeyX2, pubKeyX2.pubKey);
    r += zn_test((memcmp(prvKeyX1.pubKey + 1, prvKeyX2.pubKey + 1, 32) != 0), "ZNKeySetPrivKey() test 5.3.1");
    ZNKeySetPubKey(&pubKeyX1, prvKeyX1.pubKey, 33);
    ZNKeySetPubKey(&pubKeyX2, prvKeyX2.pubKey, 65);
    r += zn_test((memcmp(pubKeyX1.pubKey + 1, pubKeyX2.pubKey + 1, 32) != 0), "ZNKeyPrivKey() test 5.3.2");

    ZNKeyClean(&prvKeyX1); ZNKeyClean(&prvKeyX2);
    ZNKeySetPrivKey(&prvKeyX1, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    ZNKeySetPrivKey(&prvKeyX2, "KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", params);
    prvKeyX1.compressed = 1;
    prvKeyX2.compressed = 1;
    ZNKeyPubKey(&prvKeyX1, pubKeyX1.pubKey);
    ZNKeyPubKey(&prvKeyX2, pubKeyX2.pubKey);
    r += zn_test((memcmp(prvKeyX1.pubKey + 1, prvKeyX2.pubKey + 1, 32) != 0), "ZNKeyPrivKey() test 5.3.1");
    ZNKeySetPubKey(&pubKeyX1, prvKeyX1.pubKey, 33);
    ZNKeySetPubKey(&pubKeyX2, prvKeyX2.pubKey, 33);
    r += zn_test((memcmp(pubKeyX1.pubKey + 1, pubKeyX2.pubKey + 1, 32) != 0), "ZNKeyPrivKey() test 5.3.2");

    // signing
    ZNKeySetSecret(&key, (uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 1);
    msg = "Everything should be made as simple as possible, but not simpler.";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));

    sigLen = ZNKeySign(&key, sig, md);
    
    char sig1[] = "\x30\x44\x02\x20\x33\xa6\x9c\xd2\x06\x54\x32\xa3\x0f\x3d\x1c\xe4\xeb\x0d\x59\xb8\xab\x58\xc7\x4f\x27"
    "\xc4\x1a\x7f\xdb\x56\x96\xad\x4e\x61\x08\xc9\x02\x20\x6f\x80\x79\x82\x86\x6f\x78\x5d\x3f\x64\x18\xd2\x41\x63\xdd"
    "\xae\x11\x7b\x7d\xb4\xd5\xfd\xf0\x07\x1d\xe0\x69\xfa\x54\x34\x22\x62";

    r += zn_test((sigLen != sizeof(sig1) - 1 || memcmp(sig, sig1, sigLen) != 0), "ZNKeySign() test 1");

    r += zn_test((! ZNKeyVerify(&key, md, sig, sigLen)), "ZNKeyVerify() test 1");

    ZNKeySetSecret(&key, (uint8_t *)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6"
                   "\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x40", 1);
    msg = "Equations are more important to me, because politics is for the present, but an equation is something for "
    "eternity.";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeySign(&key, sig, md);
    
    char sig2[] = "\x30\x44\x02\x20\x54\xc4\xa3\x3c\x64\x23\xd6\x89\x37\x8f\x16\x0a\x7f\xf8\xb6\x13\x30\x44\x4a\xbb\x58"
    "\xfb\x47\x0f\x96\xea\x16\xd9\x9d\x4a\x2f\xed\x02\x20\x07\x08\x23\x04\x41\x0e\xfa\x6b\x29\x43\x11\x1b\x6a\x4e\x0a"
    "\xaa\x7b\x7d\xb5\x5a\x07\xe9\x86\x1d\x1f\xb3\xcb\x1f\x42\x10\x44\xa5";

    r += zn_test((sigLen != sizeof(sig2) - 1 || memcmp(sig, sig2, sigLen) != 0), "ZNKeySign() test 2");
    
    r += zn_test((! ZNKeyVerify(&key, md, sig, sigLen)), "ZNKeyVerify() test 2");

    ZNKeySetSecret(&key, (uint8_t *)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6"
                   "\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x40", 1);
    msg = "Not only is the Universe stranger than we think, it is stranger than we can think.";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeySign(&key, sig, md);
    
    char sig3[] = "\x30\x45\x02\x21\x00\xff\x46\x6a\x9f\x1b\x7b\x27\x3e\x2f\x4c\x3f\xfe\x03\x2e\xb2\xe8\x14\x12\x1e\xd1"
    "\x8e\xf8\x46\x65\xd0\xf5\x15\x36\x0d\xab\x3d\xd0\x02\x20\x6f\xc9\x5f\x51\x32\xe5\xec\xfd\xc8\xe5\xe6\xe6\x16\xcc"
    "\x77\x15\x14\x55\xd4\x6e\xd4\x8f\x55\x89\xb7\xdb\x77\x71\xa3\x32\xb2\x83";
    
    r += zn_test((sigLen != sizeof(sig3) - 1 || memcmp(sig, sig3, sigLen) != 0), "ZNKeySign() test 3");
    
    r += zn_test((! ZNKeyVerify(&key, md, sig, sigLen)), "ZNKeyVerify() test 3");

    ZNKeySetSecret(&key, (uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 1);
    msg = "How wonderful that we have met with a paradox. Now we have some hope of making progress.";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeySign(&key, sig, md);
    
    char sig4[] = "\x30\x45\x02\x21\x00\xc0\xda\xfe\xc8\x25\x1f\x1d\x50\x10\x28\x9d\x21\x02\x32\x22\x0b\x03\x20\x2c\xba"
    "\x34\xec\x11\xfe\xc5\x8b\x3e\x93\xa8\x5b\x91\xd3\x02\x20\x75\xaf\xdc\x06\xb7\xd6\x32\x2a\x59\x09\x55\xbf\x26\x4e"
    "\x7a\xaa\x15\x58\x47\xf6\x14\xd8\x00\x78\xa9\x02\x92\xfe\x20\x50\x64\xd3";
    
    r += zn_test((sigLen != sizeof(sig4) - 1 || memcmp(sig, sig4, sigLen) != 0), "ZNKeySign() test 4");
    
    r += zn_test((! ZNKeyVerify(&key, md, sig, sigLen)), "ZNKeyVerify() test 4");

    ZNKeySetSecret(&key, (uint8_t *)"\x69\xec\x59\xea\xa1\xf4\xf2\xe3\x6b\x63\x97\x16\xb7\xc3\x0c\xa8\x6d\x9a\x53\x75"
                   "\xc7\xb3\x8d\x89\x18\xbd\x9c\x0e\xbc\x80\xba\x64", 1);
    msg = "Computer science is no more about computers than astronomy is about telescopes.";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeySign(&key, sig, md);
    
    char sig5[] = "\x30\x44\x02\x20\x71\x86\x36\x35\x71\xd6\x5e\x08\x4e\x7f\x02\xb0\xb7\x7c\x3e\xc4\x4f\xb1\xb2\x57\xde"
    "\xe2\x62\x74\xc3\x8c\x92\x89\x86\xfe\xa4\x5d\x02\x20\x0d\xe0\xb3\x8e\x06\x80\x7e\x46\xbd\xa1\xf1\xe2\x93\xf4\xf6"
    "\x32\x3e\x85\x4c\x86\xd5\x8a\xbd\xd0\x0c\x46\xc1\x64\x41\x08\x5d\xf6";
    
    r += zn_test((sigLen != sizeof(sig5) - 1 || memcmp(sig, sig5, sigLen) != 0), "ZNKeySign() test 5");
    
    r += zn_test((! ZNKeyVerify(&key, md, sig, sigLen)), "ZNKeyVerify() test 5");

    ZNKeySetSecret(&key, (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x72\x46\x17\x4a\xb1\xe9"
                   "\x2e\x91\x49\xc6\xe4\x46\xfe\x19\x4d\x07\x26\x37", 1);

    msg = "...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not"
    " learning anywhere near enough";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeySign(&key, sig, md);
    
    char sig6[] = "\x30\x45\x02\x21\x00\xfb\xfe\x50\x76\xa1\x58\x60\xba\x8e\xd0\x0e\x75\xe9\xbd\x22\xe0\x5d\x23\x0f\x02"
    "\xa9\x36\xb6\x53\xeb\x55\xb6\x1c\x99\xdd\xa4\x87\x02\x20\x0e\x68\x88\x0e\xbb\x00\x50\xfe\x43\x12\xb1\xb1\xeb\x08"
    "\x99\xe1\xb8\x2d\xa8\x9b\xaa\x5b\x89\x5f\x61\x26\x19\xed\xf3\x4c\xbd\x37";
    
    r += zn_test((sigLen != sizeof(sig6) - 1 || memcmp(sig, sig6, sigLen) != 0), "ZNKeySign() test 6");
    
    r += zn_test((! ZNKeyVerify(&key, md, sig, sigLen)), "ZNKeyVerify() test 6");

    ZNKeySetSecret(&key, (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                   "\x00\x05\x69\x16\xd0\xf9\xb3\x1d\xc9\xb6\x37\xf3", 1);
    msg = "The question of whether computers can think is like the question of whether submarines can swim.";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeySign(&key, sig, md);
    
    char sig7[] = "\x30\x45\x02\x21\x00\xcd\xe1\x30\x2d\x83\xf8\xdd\x83\x5d\x89\xae\xf8\x03\xc7\x4a\x11\x9f\x56\x1f\xba"
    "\xef\x3e\xb9\x12\x9e\x45\xf3\x0d\xe8\x6a\xbb\xf9\x02\x20\x06\xce\x64\x3f\x50\x49\xee\x1f\x27\x89\x04\x67\xb7\x7a"
    "\x6a\x8e\x11\xec\x46\x61\xcc\x38\xcd\x8b\xad\xf9\x01\x15\xfb\xd0\x3c\xef";
    
    r += zn_test((sigLen != sizeof(sig7) - 1 || memcmp(sig, sig7, sigLen) != 0), "ZNKeySign() test 7");
    
    r += zn_test((! ZNKeyVerify(&key, md, sig, sigLen)), "ZNKeyVerify() test 7");
    
    // compact signing
    ZNKeySetSecret(&key, (uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 1);
    msg = "foo";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeyCompactSign(&key, sig, md);
    ZNKeyRecoverPubKey(&key2, md, sig);
    pkLen = ZNKeyPubKey(&key2, pubKey);
    
    uint8_t pubKey1[65];
    size_t pkLen1 = ZNKeyPubKey(&key, pubKey1);
    
    r += zn_test((pkLen1 != pkLen || memcmp(pubKey, pubKey1, pkLen) != 0), "ZNKeyCompactSign() test 1");

    ZNKeySetSecret(&key, (uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 0);
    msg = "foo";
    ZNSHA256(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNKeyCompactSign(&key, sig, md);
    ZNKeyRecoverPubKey(&key2, md, sig);
    pkLen = ZNKeyPubKey(&key2, pubKey);
    
    uint8_t pubKey2[65];
    size_t pkLen2 = ZNKeyPubKey(&key, pubKey2);
    
    r += zn_test((pkLen2 != pkLen || memcmp(pubKey, pubKey2, pkLen) != 0), "ZNKeyCompactSign() test 2");

    // compact pubkey recovery
    pkLen = ZNBase58Decode(pubKey, sizeof(pubKey), "26wZYDdvpmCrYZeUcxgqd1KquN4o6wXwLomBW5SjnwUqG");
    msg = "i am a test signed string";
    ZNSHA256_2(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNBase58Decode(sig, sizeof(sig),
                           "3kq9e842BzkMfbPSbhKVwGZgspDSkz4YfqjdBYQPWDzqd77gPgR1zq4XG7KtAL5DZTcfFFs2iph4urNyXeBkXsEYY");
    ZNKeyRecoverPubKey(&key2, md, sig);
    uint8_t pubKey3[65];
    size_t pkLen3 = ZNKeyPubKey(&key2, pubKey3);

    r += zn_test((pkLen3 != pkLen || memcmp(pubKey, pubKey3, pkLen) != 0), "ZNPubKeyRecover() test 1");

    pkLen = ZNBase58Decode(pubKey, sizeof(pubKey), "26wZYDdvpmCrYZeUcxgqd1KquN4o6wXwLomBW5SjnwUqG");
    msg = "i am a test signed string do de dah";
    ZNSHA256_2(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNBase58Decode(sig, sizeof(sig),
                           "3qECEYmb6x4X22sH98Aer68SdfrLwtqvb5Ncv7EqKmzbxeYYJ1hU9irP6R5PeCctCPYo5KQiWFgoJ3H5MkuX18gHu");
    
    ZNKeyRecoverPubKey(&key2, md, sig);
    uint8_t pubKey4[65];
    size_t pkLen4 = ZNKeyPubKey(&key2, pubKey4);
    
    r += zn_test((pkLen4 != pkLen || memcmp(pubKey, pubKey4, pkLen) != 0), "ZNPubKeyRecover() test 2");

    pkLen = ZNBase58Decode(pubKey, sizeof(pubKey), "gpRv1sNA3XURB6QEtGrx6Q18DZ5cSgUSDQKX4yYypxpW");
    msg = "i am a test signed string";
    ZNSHA256_2(md, (const uint8_t *)msg, strlen(msg));
    sigLen = ZNBase58Decode(sig, sizeof(sig),
                           "3oHQhxq5eW8dnp7DquTCbA5tECoNx7ubyiubw4kiFm7wXJF916SZVykFzb8rB1K6dEu7mLspBWbBEJyYk79jAosVR");
    
    ZNKeyRecoverPubKey(&key2, md, sig);
    uint8_t pubKey5[65];
    size_t pkLen5 = ZNKeyPubKey(&key2, pubKey5);
    
    r += zn_test((pkLen5 != pkLen || memcmp(pubKey, pubKey5, pkLen) != 0), "ZNPubKeyRecover() test 3");
    
    // paper wallet key pair
    ZNKeySetSecret(&key, (const uint8_t *)"12345678901234567890123456789012", 1);
    
    ZNKeyPrivKey(&key, privKey1, params);
    printf("\nprivKey:%s", privKey1);
    // compressed private key
    r += zn_test((! ZNPrivKeyIsValid(privKey1, params)), "ZNPrivKeyIsValid() test 8");
    ZNKeyLegacyAddr(&key, addr, params);
    printf("\nprivKey:%s = %s", privKey1, addr);

    printf("\n                                    ");
    return r;
}

#if ! ZN_SKIP_BIP38
static int ZNBIP38KeyTests(void)
{
    int r = 0;
    ZNKey key;
    char privKey[55], bip38Key[61];
    ZNAddrParams params = ZNMainNetParams;
    
    // non EC multiplied, uncompressed
    r += zn_test((! ZNKeySetPrivKey(&key, "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", params) ||
                  ! ZNKeyBIP38Key(&key, bip38Key, "TestingOneTwoThree", params) ||
                  strncmp(bip38Key, "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
                          sizeof(bip38Key)) != 0), "ZNKeyBIP38Key() test 1");

    r += zn_test((! ZNKeySetBIP38Key(&key, "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
                                     "TestingOneTwoThree", params) || ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 1");

    printf("\nprivKey:%s", privKey);

    r += zn_test((! ZNKeySetPrivKey(&key, "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", params) ||
                  ! ZNKeyBIP38Key(&key, bip38Key, "Satoshi", params) ||
                  strncmp(bip38Key, "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
                          sizeof(bip38Key)) != 0), "ZNKeyBIP38Key() test 2");

    r += zn_test((! ZNKeySetBIP38Key(&key, "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq", "Satoshi",
                                     params) || ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 2");

    printf("\nprivKey:%s", privKey);
    
    // non EC multiplied, compressed
    r += zn_test((! ZNKeySetPrivKey(&key, "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP", params) ||
                  ! ZNKeyBIP38Key(&key, bip38Key, "TestingOneTwoThree", params) ||
                  strncmp(bip38Key, "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
                          sizeof(bip38Key)) != 0), "ZNKeyBIP38Key() test 3");

    r += zn_test((! ZNKeySetBIP38Key(&key, "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
                                     "TestingOneTwoThree", params) || ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 3");

    printf("\nprivKey:%s", privKey);

    r += zn_test((! ZNKeySetPrivKey(&key, "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7", params) ||
                  ! ZNKeyBIP38Key(&key, bip38Key, "Satoshi", params) ||
                  strncmp(bip38Key, "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
                          sizeof(bip38Key)) != 0), "ZNKeyBIP38Key() test 4");

    r += zn_test((! ZNKeySetBIP38Key(&key, "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7", "Satoshi",
                                     params) || ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 4");

    printf("\nprivKey:%s", privKey);

    // EC multiplied, uncompressed, no lot/sequence number
    r += zn_test((! ZNKeySetBIP38Key(&key, "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
                                     "TestingOneTwoThree", params) || ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 5");

    printf("\nprivKey:%s", privKey);

    r += zn_test((! ZNKeySetBIP38Key(&key, "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd", "Satoshi",
                                     params) || ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 6");

    printf("\nprivKey:%s", privKey);
    
    // EC multiplied, uncompressed, with lot/sequence number
    r += zn_test((! ZNKeySetBIP38Key(&key, "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j", "MOLON LABE",
                                     params) || ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 7");

    printf("\nprivKey:%s", privKey);

    r += zn_test((! ZNKeySetBIP38Key(&key, "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
                                     "\u039c\u039f\u039b\u03a9\u039d \u039b\u0391\u0392\u0395", params) ||
                  ! ZNKeyPrivKey(&key, privKey, params) ||
                  strncmp(privKey, "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D", sizeof(privKey)) != 0),
                 "ZNKeySetBIP38Key() test 8");

    printf("\nprivKey:%s", privKey);
    
//    // password NFC unicode normalization test
//    r += zn_test((! ZNKeySetBIP38Key(&key, "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
//                                     "\u03D2\u0301\0\U00010400\U0001F4A9", params) ||
//                  ! ZNKeyPrivKey(&key, privKey, params) ||
//                  strncmp(privKey, "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4", sizeof(privKey)) != 0),
//                 "ZNKeySetBIP38Key() test 9");
//
//    printf("\nprivKey:%s", privKey);

    // incorrect password test
    r += zn_test((ZNKeySetBIP38Key(&key, "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn", "foobar",
                                   params)), "ZNKeySetBIP38Key() test 10");

    printf("\n                                    ");
    return r;
}
#endif // ! ZN_SKIP_BIP38

static int ZNAddressTests(void)
{
    int r = 0;
    uint8_t secret[32] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01";
    ZNKey k;
    char addr[75], addr2[75];
    ZNAddrParams params = ZNMainNetParams;
    
    ZNKeySetSecret(&k, secret, 1);
    r += zn_test((! ZNKeyAddress(&k, addr, params)), "ZNKeyAddress()");

    uint8_t script[42];
    size_t scriptLen = ZNAddressScriptPubKey(script, addr, params);
    
    ZNAddressFromScriptPubKey(addr2, params, script, scriptLen);
    r += zn_test((! ZNAddressEq(addr, addr2)), "ZNAddressFromScriptPubKey() test 1");
    
    char addr3[75];
    char script2[] = "\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    r += zn_test((! ZNAddressFromScriptPubKey(addr3, params, (uint8_t *)script2, sizeof(script2) - 1)),
                 "ZNAddressFromScriptPubKey() test 2");

    uint8_t script3[42];
    size_t script3Len = ZNAddressScriptPubKey(script3, addr3, params);

    r += zn_test((script3Len != sizeof(script2) - 1 || memcmp(script2, script3, sizeof(script2) - 1)),
                 "ZNAddressScriptPubKey() test");

    uint8_t wit[] = "\x01\0\x21\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    uint8_t sig[] = "\x16\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    uint8_t script4[] = "\xa9\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x87";
    char addr4[75], addr5[75];
    
    ZNKeyPubKey(&k, &wit[3]);
    ZNKeyHash160(&k, &sig[3]);
    ZNHash160(&script4[2], &sig[1], sizeof(sig) - 2);
    ZNAddressFromScriptPubKey(addr4, params, script4, sizeof(script4) - 1);
    ZNAddressFromScriptSig(addr5, params, sig, sizeof(sig) - 1);
    r += zn_test((! ZNAddressEq(addr4, addr5)), "ZNAddressFromScriptSig() test");

    char addr6[75];
    ZNAddressFromWitness(addr6, params, wit, sizeof(wit) - 1);
    r += zn_test((! ZNAddressEq(addr, addr6)), "ZNAddressFromWitness() test 1");
    
    uint8_t wit2[] = "\0\x01\0\x47\x51\x21\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x21\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x52\xae";
    uint8_t script5[] = "\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    char addr7[75], addr8[75];
    
    ZNSHA256(&script5[2], &wit2[4], sizeof(wit2) - 5);
    ZNAddressFromScriptPubKey(addr7, params, script5, sizeof(script5) - 1);
    ZNAddressFromWitness(addr8, params, wit2, sizeof(wit2) - 1);
    r += zn_test((! ZNAddressEq(addr7, addr8)), "ZNAddressFromWitness() test 2");

    // Invalid human-readable part
    r += zn_test(ZNAddressIsValid("tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
                                  ZNTestNetParams), "ZNAddressIsValid() test 1");
    
    // Invalid program length for witness version 0 (per BIP141)
    r += zn_test(ZNAddressIsValid("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", params), "ZNAddressIsValid() test 2");

    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

static int ZNTransactionTests(void)
{
    int r = 0;
    uint8_t secret[32] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01",
            inHash[32] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01";
    ZNKey k[2];
    char address[75], addr[75];
    ZNAddrParams params = ZNMainNetParams;
    
    memset(&k[0], 0, sizeof(k[0])); // test with array of keys where first key is empty/invalid
    ZNKeySetSecret(&k[1], secret, 1);
    ZNKeyLegacyAddr(&k[1], address, params);

    uint8_t script[42];
    size_t scriptLen = ZNAddressScriptPubKey(script, address, params);
    ZNTransaction *tx = ZNTransactionNew();
    
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddOutput(tx, 100000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 4900000000, script, scriptLen);
    
    uint8_t buf[ZNTransactionSerialize(tx, NULL, 0)]; // test serializing/parsing unsigned tx
    size_t len = ZNTransactionSerialize(tx, buf, sizeof(buf));
    
    r += zn_test((len == 0), "ZNTransactionSerialize() test 0");
    zn_ref_release(tx);
    tx = ZNTransactionParse(buf, len, NULL);
    
    r += zn_test((! tx || tx->inCount != 1 || tx->outCount != 2), "ZNTransactionParse() test 0");
    if (! tx) return r;
    
    ZNTransactionSign(tx, 0, k, 2);
    ZNAddressFromScriptSig(addr, params, tx->inputs[0].scriptSig, tx->inputs[0].sigLen);
    r += zn_test((! ZNTransactionIsSigned(tx) || ! ZNAddressEq(address, addr)), "ZNTransactionSign() test 1");

    uint8_t buf2[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len2 = ZNTransactionSerialize(tx, buf2, sizeof(buf2));

    zn_ref_release(tx);
    tx = ZNTransactionParse(buf2, len2, NULL);

    r += zn_test((! tx || ! ZNTransactionIsSigned(tx)), "ZNTransactionParse() test 1");
    if (! tx) return r;
    
    uint8_t buf3[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len3 = ZNTransactionSerialize(tx, buf3, sizeof(buf3));
    
    r += zn_test((len2 != len3 || memcmp(buf2, buf3, len2) != 0), "ZNTransactionSerialize() test 1");

    zn_ref_release(tx);
    
    tx = ZNTransactionNew();
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionSign(tx, 0, k, 2);
    ZNAddressFromScriptSig(addr, params, tx->inputs[tx->inCount - 1].scriptSig, tx->inputs[tx->inCount - 1].sigLen);
    r += zn_test((! ZNTransactionIsSigned(tx) || ! ZNAddressEq(address, addr)), "ZNTransactionSign() test 2");

    uint8_t buf4[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len4 = ZNTransactionSerialize(tx, buf4, sizeof(buf4));
    
    zn_ref_release(tx);
    tx = ZNTransactionParse(buf4, len4, NULL);
    r += zn_test((! tx || ! ZNTransactionIsSigned(tx)), "ZNTransactionParse() test 2");
    if (! tx) return r;

    uint8_t buf5[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len5 = ZNTransactionSerialize(tx, buf5, sizeof(buf5));
    
    r += zn_test((len4 != len5 || memcmp(buf4, buf5, len4) != 0), "ZNTransactionSerialize() test 2");
    zn_ref_release(tx);

    ZNKeyAddress(&k[1], addr, params);
    
    uint8_t wscript[42];
    size_t wscriptLen = ZNAddressScriptPubKey(wscript, addr, params);

    tx = ZNTransactionNew();
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, wscript, wscriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, wscript, wscriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, wscript, wscriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, wscript, wscriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, wscript, wscriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddInput(tx, inHash, 0, 1, script, scriptLen, NULL, 0, NULL, 0, ZN_TXIN_SEQUENCE);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionAddOutput(tx, 1000000, script, scriptLen);
    ZNTransactionSign(tx, 0, k, 2);
    ZNAddressFromScriptSig(addr, params, tx->inputs[tx->inCount - 1].scriptSig, tx->inputs[tx->inCount - 1].sigLen);
    r += zn_test((! ZNTransactionIsSigned(tx) || ! ZNAddressEq(address, addr) || tx->inputs[1].sigLen > 0 ||
                  tx->inputs[1].witLen == 0), "ZNTransactionSign() test 3");
    
    uint8_t buf6[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len6 = ZNTransactionSerialize(tx, buf6, sizeof(buf6));
    
    zn_ref_release(tx);
    tx = ZNTransactionParse(buf6, len6, NULL);
    r += zn_test((! tx || ! ZNTransactionIsSigned(tx)), "ZNTransactionParse() test 3");
    if (! tx) return r;
    
    uint8_t buf7[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len7 = ZNTransactionSerialize(tx, buf7, sizeof(buf7));
    
    r += zn_test((len6 != len7 || memcmp(buf6, buf7, len6) != 0), "ZNTransactionSerialize() test 3");
    zn_ref_release(tx);
    
    tx = ZNTransactionNew();
    ZNTransactionAddInput(tx, (uint8_t *)"\xff\xf7\xf7\x88\x1a\x80\x99\xaf\xa6\x94\x0d\x42\xd1\xe7\xf6\x36\x2b\xec\x38"
                          "\x17\x1e\xa3\xed\xf4\x33\x54\x1d\xb4\xe4\xad\x96\x9f", 0, 625000000,
                          (uint8_t *)"\x21\x03\xc9\xf4\x83\x6b\x9a\x4f\x77\xfc\x0d\x81\xf7\xbc\xb0\x1b\x7f\x1b\x35\x91"
                          "\x68\x64\xb9\x47\x6c\x24\x1c\xe9\xfc\x19\x8b\xd2\x54\x32\xac", 35,
                          (uint8_t *)"\x48\x30\x45\x02\x21\x00\x8b\x9d\x1d\xc2\x6b\xa6\xa9\xcb\x62\x12\x7b\x02\x74\x2f"
                          "\xa9\xd7\x54\xcd\x3b\xeb\xf3\x37\xf7\xa5\x5d\x11\x4c\x8e\x5c\xdd\x30\xbe\x02\x20\x40\x52\x9b"
                          "\x19\x4b\xa3\xf9\x28\x1a\x99\xf2\xb1\xc0\xa1\x9c\x04\x89\xbc\x22\xed\xe9\x44\xcc\xf4\xec\xba"
                          "\xb4\xcc\x61\x8e\xf3\xed\x01", 73, (uint8_t *)"", 0, 0xffffffee);
    ZNTransactionAddInput(tx, (uint8_t *)"\xef\x51\xe1\xb8\x04\xcc\x89\xd1\x82\xd2\x79\x65\x5c\x3a\xa8\x9e\x81\x5b\x1b"
                          "\x30\x9f\xe2\x87\xd9\xb2\xb5\x5d\x57\xb9\x0e\xc6\x8a", 1, 600000000,
                          (uint8_t *)"\x00\x14\x1d\x0f\x17\x2a\x0e\xcb\x48\xae\xe1\xbe\x1f\x26\x87\xd2\x96\x3a\xe3\x3f"
                          "\x71\xa1", 22, NULL, 0, NULL, 0, 0xffffffff);
    ZNTransactionAddOutput(tx, 0x06b22c20, (uint8_t *)"\x76\xa9\x14\x82\x80\xb3\x7d\xf3\x78\xdb\x99\xf6\x6f\x85\xc9"
                           "\x5a\x78\x3a\x76\xac\x7a\x6d\x59\x88\xac", 25);
    ZNTransactionAddOutput(tx, 0x0d519390, (uint8_t *)"\x76\xa9\x14\x3b\xde\x42\xdb\xee\x7e\x4d\xbe\x6a\x21\xb2\xd5"
                           "\x0c\xe2\xf0\x16\x7f\xaa\x81\x59\x88\xac", 25);
    tx->lockTime = 0x00000011;
    ZNKeySetSecret(k, (uint8_t *)"\x61\x9c\x33\x50\x25\xc7\xf4\x01\x2e\x55\x6c\x2a\x58\xb2\x50\x6e\x30\xb8\x51\x1b\x53"
                   "\xad\xe9\x5e\xa3\x16\xfd\x8c\x32\x86\xfe\xb9", 1);
    ZNTransactionSign(tx, 0, k, 1);
    
    uint8_t buf8[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len8 = ZNTransactionSerialize(tx, buf8, sizeof(buf8));
    char buf9[] = "\x01\x00\x00\x00\x00\x01\x02\xff\xf7\xf7\x88\x1a\x80\x99\xaf\xa6\x94\x0d\x42\xd1\xe7\xf6\x36\x2b\xec"
    "\x38\x17\x1e\xa3\xed\xf4\x33\x54\x1d\xb4\xe4\xad\x96\x9f\x00\x00\x00\x00\x49\x48\x30\x45\x02\x21\x00\x8b\x9d\x1d"
    "\xc2\x6b\xa6\xa9\xcb\x62\x12\x7b\x02\x74\x2f\xa9\xd7\x54\xcd\x3b\xeb\xf3\x37\xf7\xa5\x5d\x11\x4c\x8e\x5c\xdd\x30"
    "\xbe\x02\x20\x40\x52\x9b\x19\x4b\xa3\xf9\x28\x1a\x99\xf2\xb1\xc0\xa1\x9c\x04\x89\xbc\x22\xed\xe9\x44\xcc\xf4\xec"
    "\xba\xb4\xcc\x61\x8e\xf3\xed\x01\xee\xff\xff\xff\xef\x51\xe1\xb8\x04\xcc\x89\xd1\x82\xd2\x79\x65\x5c\x3a\xa8\x9e"
    "\x81\x5b\x1b\x30\x9f\xe2\x87\xd9\xb2\xb5\x5d\x57\xb9\x0e\xc6\x8a\x01\x00\x00\x00\x00\xff\xff\xff\xff\x02\x20\x2c"
    "\xb2\x06\x00\x00\x00\x00\x19\x76\xa9\x14\x82\x80\xb3\x7d\xf3\x78\xdb\x99\xf6\x6f\x85\xc9\x5a\x78\x3a\x76\xac\x7a"
    "\x6d\x59\x88\xac\x90\x93\x51\x0d\x00\x00\x00\x00\x19\x76\xa9\x14\x3b\xde\x42\xdb\xee\x7e\x4d\xbe\x6a\x21\xb2\xd5"
    "\x0c\xe2\xf0\x16\x7f\xaa\x81\x59\x88\xac\x00\x02\x47\x30\x44\x02\x20\x36\x09\xe1\x7b\x84\xf6\xa7\xd3\x0c\x80\xbf"
    "\xa6\x10\xb5\xb4\x54\x2f\x32\xa8\xa0\xd5\x44\x7a\x12\xfb\x13\x66\xd7\xf0\x1c\xc4\x4a\x02\x20\x57\x3a\x95\x4c\x45"
    "\x18\x33\x15\x61\x40\x6f\x90\x30\x0e\x8f\x33\x58\xf5\x19\x28\xd4\x3c\x21\x2a\x8c\xae\xd0\x2d\xe6\x7e\xeb\xee\x01"
    "\x21\x02\x54\x76\xc2\xe8\x31\x88\x36\x8d\xa1\xff\x3e\x29\x2e\x7a\xca\xfc\xdb\x35\x66\xbb\x0a\xd2\x53\xf6\x2f\xc7"
    "\x0f\x07\xae\xee\x63\x57\x11\x00\x00\x00";
    
    zn_ref_release(tx);
    
    r += zn_test((len8 != sizeof(buf9) - 1 || memcmp(buf8, buf9, len8)), "ZNTransactionSign() test 4");

    char buf0[] = "\x01\x00\x00\x00\x00\x01\x01\x7b\x03\x2f\x6a\x65\x1c\x7d\xcb\xcf\xb7\x8d\x81\x7b\x30\x3b\xe8\xd2\x0a"
    "\xfa\x22\x90\x16\x18\xb5\x17\xf2\x17\x55\xa7\xcd\x8d\x48\x01\x00\x00\x00\x23\x22\x00\x20\xe0\x62\x7b\x64\x74\x59"
    "\x05\x64\x6f\x27\x6f\x35\x55\x02\xa4\x05\x30\x58\xb6\x4e\xdb\xf2\x77\x11\x92\x49\x61\x1c\x98\xda\x41\x69\xff\xff"
    "\xff\xff\x02\x0c\xf9\x62\x01\x00\x00\x00\x00\x17\xa9\x14\x24\x31\x57\xd5\x78\xbd\x92\x8a\x92\xe0\x39\xe8\xd4\xdb"
    "\xbb\x29\x44\x16\x93\x5c\x87\xf3\xbe\x2a\x00\x00\x00\x00\x00\x19\x76\xa9\x14\x48\x38\x0b\xc7\x60\x5e\x91\xa3\x8f"
    "\x8d\x7b\xa0\x1a\x27\x95\x41\x6b\xf9\x2d\xde\x88\xac\x04\x00\x47\x30\x44\x02\x20\x5f\x5d\xe6\x88\x96\xca\x3e\xdf"
    "\x97\xe3\xea\x1f\xd3\x51\x39\x03\x53\x7f\xd5\xf2\xe0\xb3\x66\x1d\x6c\x61\x7b\x1c\x48\xfc\x69\xe1\x02\x20\x0e\x0f"
    "\x20\x59\x51\x3b\xe9\x31\x83\x92\x9c\x7d\x3e\x2d\xe0\xe9\xc7\x08\x57\x06\xa8\x8e\x8f\x74\x6e\x8f\x5a\xa7\x13\xd2"
    "\x7a\x52\x01\x47\x30\x44\x02\x20\x50\xd8\xec\xb9\xcd\x7f\xda\xcb\x6d\x63\x51\xde\xc2\xbc\x5b\x37\x16\x32\x8e\xf2"
    "\xc4\x46\x6d\xb4\x4b\xdd\x34\xa6\x57\x29\x2b\x8c\x02\x20\x68\x50\x1b\xf8\x18\x12\xad\x8e\x3e\xd9\xdf\x24\x35\x4c"
    "\x37\x19\x23\xa0\x7d\xc9\x66\xa6\xe4\x14\x63\x59\x47\x74\xd0\x09\x16\x9e\x01\x69\x52\x21\x03\xb8\xe1\x38\xed\x70"
    "\x23\x2c\x9c\xbd\x1b\x90\x28\x12\x10\x64\x23\x6a\xf1\x2d\xbe\x98\x64\x1c\x3f\x74\xfa\x13\x16\x6f\x27\x2f\x58\x21"
    "\x03\xf6\x6e\xe7\xc8\x78\x17\xd3\x24\x92\x1e\xdc\x3f\x7d\x77\x26\xde\x5a\x18\xcf\xed\x05\x7e\x5a\x50\xe7\xc7\x4e"
    "\x2a\xe7\xe0\x5a\xd7\x21\x02\xa7\xbf\x21\x58\x2d\x71\xe5\xda\x5c\x3b\xc4\x3e\x84\xc8\x8f\xdf\x32\x80\x3a\xa4\x72"
    "\x0e\x1c\x1a\x9d\x08\xaa\xb5\x41\xa4\xf3\x31\x53\xae\x00\x00\x00\x00";
    
    tx = ZNTransactionParse((uint8_t *)buf0, sizeof(buf0) - 1, NULL);
    
    uint8_t buf1[ZNTransactionSerialize(tx, NULL, 0)];
    size_t len0 = ZNTransactionSerialize(tx, buf1, sizeof(buf1));

    zn_ref_release(tx);
    
    r += zn_test((len0 != sizeof(buf0) - 1 || memcmp(buf0, buf1, len0) != 0), "ZNTransactionSerialize() test 4");

    // coinbase input ::
    // "transactions/bitcoin-mainnet:4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b?include_raw=true"
    char buf10[] =
    "\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x4d\x04\xff\xff\x00\x1d\x01\x04\x45\x54\x68\x65\x20\x54\x69"
    "\x6d\x65\x73\x20\x30\x33\x2f\x4a\x61\x6e\x2f\x32\x30\x30\x39\x20\x43\x68\x61\x6e\x63\x65\x6c\x6c\x6f\x72\x20\x6f"
    "\x6e\x20\x62\x72\x69\x6e\x6b\x20\x6f\x66\x20\x73\x65\x63\x6f\x6e\x64\x20\x62\x61\x69\x6c\x6f\x75\x74\x20\x66\x6f"
    "\x72\x20\x62\x61\x6e\x6b\x73\xff\xff\xff\xff\x01\x00\xf2\x05\x2a\x01\x00\x00\x00\x43\x41\x04\x67\x8a\xfd\xb0\xfe"
    "\x55\x48\x27\x19\x67\xf1\xa6\x71\x30\xb7\x10\x5c\xd6\xa8\x28\xe0\x39\x09\xa6\x79\x62\xe0\xea\x1f\x61\xde\xb6\x49"
    "\xf6\xbc\x3f\x4c\xef\x38\xc4\xf3\x55\x04\xe5\x1e\xc1\x12\xde\x5c\x38\x4d\xf7\xba\x0b\x8d\x57\x8a\x4c\x70\x2b\x6b"
    "\xf1\x1d\x5f\xac\x00\x00\x00\x00";

    ZNTransaction *txCoinbase = ZNTransactionParse((uint8_t *) buf10, sizeof(buf10) - 1, NULL);

    if (1 == txCoinbase->inCount) {
        ZNTxInput txInput0 = txCoinbase->inputs[0];
        r += zn_test((memcmp(txInput0.txHash, ZN_HASH_NONE, sizeof(txInput0.txHash)) != 0),
                     "ZNTransaction w/ Coinbase input txHash not empty test 5");
    }

    zn_ref_release(txCoinbase);
    
    if (r) fprintf(stderr, "\n                                    ");
    return r;
}

// TODO: test standard free transaction no change
// TODO: test free transaction who's inputs are too new to hit min free priority
// TODO: test transaction with change below min allowable output
// TODO: test gap limit with gaps in address chain less than the limit
// TODO: test removing a transaction that other transansactions depend on
// TODO: test tx ordering for multiple tx with same block height
// TODO: port all applicable tests from bitcoinj and bitcoincore

int ZNRunTests(void)
{
    int fail = 0;
    
    printf("ZNIntsTests...                      ");
    printf("%s\n", (ZNIntsTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNArrayTests...                     ");
    printf("%s\n", (ZNArrayTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNBase58Tests...                    ");
    printf("%s\n", (ZNBase58Tests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNBech32mTests...                   ");
    printf("%s\n", (ZNBech32mTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNHashTests...                      ");
    printf("%s\n", (ZNHashTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNMacTests...                       ");
    printf("%s\n", (ZNMacTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNDrbgTests...                      ");
    printf("%s\n", (ZNDrbgTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNChachaTests...                    ");
    printf("%s\n", (ZNChachaTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNAuthEncryptTests...               ");
    printf("%s\n", (ZNAuthEncryptTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNAesTests...                       ");
    printf("%s\n", (ZNAesTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNKDFTests...                       ");
    printf("%s\n", (ZNKDFTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNKeyTests...                       ");
    printf("%s\n", (ZNKeyTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNBIP38KeyTests...                  ");
#if ZN_SKIP_BIP38
    printf("SKIPPED\n");
#else
    printf("%s\n", (ZNBIP38KeyTests() == 0) ? "success" : (fail++, "***FAIL***"));
#endif
    printf("ZNAddressTests...                   ");
    printf("%s\n", (ZNAddressTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("ZNTransactionTests...               ");
    printf("%s\n", (ZNTransactionTests() == 0) ? "success" : (fail++, "***FAIL***"));
    printf("\n");
    
    if (fail > 0) printf("%d TEST FUNCTION(S) ***FAILED***\n", fail);
    else printf("ALL TESTS PASSED\n");
    
    return (fail == 0);
}

#ifndef ZN_TEST_NO_MAIN
int main(int argc, const char *argv[])
{
    int r = ZNRunTests();

    return (r) ? 0 : 1;
}
#endif
