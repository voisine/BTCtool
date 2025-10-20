//
//  ZNKey.c
//  zinc
//
//  Created by Aaron Voisine on 8/19/15.
//

#define _POSIX_C_SOURCE 200112L

#include "ZNKey.h"
#include "ZNBase58.h"
#include "ZNCrypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#define DETERMINISTIC          1
#define USE_BASIC_CONFIG       1
#define ENABLE_MODULE_RECOVERY 1

#pragma clang diagnostic push
#pragma GCC diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-function"
#include "secp256k1/src/secp256k1.c"
#include "secp256k1/src/precomputed_ecmult.c"
#include "secp256k1/src/precomputed_ecmult_gen.c"
#pragma clang diagnostic pop
#pragma GCC diagnostic pop

#ifndef CLOCK_PROCESS_CPUTIME_ID
#ifndef CLOCK_MONOTONIC
#define CLOCK_PROCESS_CPUTIME_ID CLOCK_REALTIME
#else
#define CLOCK_PROCESS_CPUTIME_ID CLOCK_MONOTONIC
#endif // CLOCK_MONOTONIC
#endif // CLOCK_PROCESS_CPUTIME_ID

// applies zn_mem_clean() to an argument list of variable references (up to 6 references)
#define zn_var_clean(...) _zn_v_c(__VA_ARGS__, (int *)0, (int *)0, (int *)0, (int *)0, (int *)0, (int *)0)
#define _zn_v_c(a, b, c, d, e, f, ...) do { _zn_vc(a); _zn_vc(b); _zn_vc(c); _zn_vc(d); _zn_vc(e); _zn_vc(f); } while(0)
#define _zn_vc(a) if (a) zn_mem_clean((a), sizeof(*(a)))

// collect cpu timing jitter entropy: https://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html
// returns true on success
int ZNEntropy(uint8_t buf[32])
{
    static volatile uint8_t m[64*32]; // volatile type prevents memory access being optimized out
    int j, i = 0, ml = 0, s = 0;
    uint64_t b[4], t, p = 0, d = 0, d2 = 0, e[5] = { 0, 0, 0, 0, 0 };
    struct timespec ts;
        
    // one bit of entropy per iteration, with a "safety factor" of 64, per NIST SP 800-90B
    // fail after 31 "stuck" iterations, to ensure alpha = 2^-30 as recommended in FIPS 140-2
    while (i <= 256 + 64 && s < 31) {
        for (j = 0; j < 128; j++) { // memory access time jitter
            m[ml]++;
            ml = (ml + 31) % (64*32);
        }
        
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
        t = (uint64_t)ts.tv_sec*1000000000 + (uint64_t)ts.tv_nsec;
        d2 = (t - p) - d;
        d = t - p;
        p = t;
        s = (! d || ! d2 || d == *e || d2 == d - *e) ? s + 1 : 0; // skip "stuck" duplicate times or time deltas
        if (! s) *e = d;
        ZNSHA3_256((uint8_t *)(s ? b : e + 1), (uint8_t *)e, sizeof(e)); // hash time jitter
        if (! s) i++;
    }
    
    if (! s && buf) memcpy(buf, e + 1, 32);
    zn_var_clean(&ts, &t, &p, &d, &d2);
    zn_mem_clean(e, sizeof(e));
    zn_mem_clean(b, sizeof(b));
    return (! s);
}

// psudo-random number generator
uint64_t ZNRand(uint64_t upperBound)
{
    static uint64_t z[8], k[4], c;
    static pid_t pid = 0;
    struct timespec ts;
    uint64_t n, r, o[8];
    pid_t p = getpid();
    int fd;

    clock_gettime(CLOCK_REALTIME, &ts);
    n = (uint64_t)ts.tv_sec*1000000000 + (uint64_t)ts.tv_nsec;
    zn_mem_clean(&ts, sizeof(ts));
    if (upperBound == 0) upperBound = UINT64_MAX;

    do { // to avoid modulo bias, find a rand value not less than (UINT64_MAX + 1) % upperBound
        if (p != pid || (c & 0xffffffff) == 0) { // re-seed on fork, or when counter wraps
            pid = p;
            c = (c & 0xffffffff) | ((uint64_t)p << 32);
            fd = open("/dev/urandom", O_RDONLY, 0);
            if (fd >= 0) { while (read(fd, o, 32) < 0 && errno == EINTR) (void)0; close(fd); }
            ZNEntropy((uint8_t *)o + 32); // if /dev/urandom, or entropy collection fail, o has uninitialized stack data
            ZNChacha20((uint8_t *)k, (uint8_t *)k, (uint8_t *)&n, (uint8_t *)o, 32, c++);
            ZNChacha20((uint8_t *)k, (uint8_t *)k, (uint8_t *)&n, (uint8_t *)o + 32, 32, c++);
        }

        ZNChacha20((uint8_t *)o, (uint8_t *)k, (uint8_t *)&n, (uint8_t *)z, 64, c++);
        r = o[0]; k[0] ^= o[1]; k[1] ^= o[2]; k[2] ^= o[3]; k[3] ^= o[4];
    } while (r < ((UINT64_MAX - upperBound) + 1) % upperBound);
    
    zn_mem_clean(o, sizeof(o));
    zn_mem_clean(&n, sizeof(n));
    return r % upperBound;
}

static secp256k1_context *_znCtx = NULL;

static void _ZNCtxInit(void)
{
    if (! _znCtx) _znCtx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

// adds 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int ZNSecp256k1ModAdd(uint8_t a[32], const uint8_t b[32])
{
    _ZNCtxInit();
    return secp256k1_ec_seckey_tweak_add(_znCtx, a, b);
}

// multiplies 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int ZNSecp256k1ModMul(uint8_t a[32], const uint8_t b[32])
{
    _ZNCtxInit();
    return secp256k1_ec_seckey_tweak_mul(_znCtx, a, b);
}

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in ec-point p (33 bytes)
// returns true on success
int ZNSecp256k1PointGen(uint8_t p[33], const uint8_t i[32])
{
    secp256k1_pubkey pubkey;
    size_t pLen = 33;
    
    _ZNCtxInit();
    return (secp256k1_ec_pubkey_create(_znCtx, &pubkey, i) &&
            secp256k1_ec_pubkey_serialize(_znCtx, p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// multiplies secp256k1 generator by 256bit big endian int i and adds the result to ec-point p (33 bytes)
// returns true on success
int ZNSecp256k1PointAdd(uint8_t p[33], const uint8_t i[32])
{
    secp256k1_pubkey pubkey;
    size_t pLen = 33;
    
    _ZNCtxInit();
    return (secp256k1_ec_pubkey_parse(_znCtx, &pubkey, p, 33) &&
            secp256k1_ec_pubkey_tweak_add(_znCtx, &pubkey, i) &&
            secp256k1_ec_pubkey_serialize(_znCtx, p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// multiplies secp256k1 ec-point p by 256bit big endian int i and stores the result in p (33 bytes)
// returns true on success
int ZNSecp256k1PointMul(uint8_t p[33], const uint8_t i[32])
{
    secp256k1_pubkey pubkey;
    size_t pLen = 33;
    
    _ZNCtxInit();
    return (secp256k1_ec_pubkey_parse(_znCtx, &pubkey, p, 33) &&
            secp256k1_ec_pubkey_tweak_mul(_znCtx, &pubkey, i) &&
            secp256k1_ec_pubkey_serialize(_znCtx, p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// returns true if privKey is a valid private key
// supported formats are wallet import format (WIF), mini private key format, or hex string
int ZNPrivKeyIsValid(const char *privKey, ZNAddrParams params)
{
    uint8_t data[34];
    size_t dataLen, strLen;
    char s[32];
    int r = 0;
    
    assert(privKey != NULL);
    dataLen = ZNBase58CheckDecode(data, sizeof(data), privKey);
    strLen = strlen(privKey);
    
    if (dataLen == 33 || dataLen == 34) { // wallet import format: https://en.bitcoin.it/wiki/Wallet_import_format
        r = (data[0] == params.privKeyPrefix);
    }
    else if ((strLen == 30 || strLen == 22) && privKey[0] == 'S') { // mini private key format
        strncpy(s, privKey, sizeof(s));
        s[strLen] = '?';
        ZNSHA256(data, (uint8_t *)s, strLen + 1);
        zn_mem_clean(s, sizeof(s));
        r = (data[0] == 0);
    }
    else r = (strspn(privKey, "0123456789ABCDEFabcdef") == 64); // hex encoded key
    
    zn_mem_clean(data, sizeof(data));
    return r;
}

// assigns secret to key and returns true on success
int ZNKeySetSecret(ZNKey *key, const uint8_t secret[32], int compressed)
{
    assert(key != NULL);
    assert(secret != NULL);
    ZNKeyClean(key);
    memcpy(key->secret, secret, 32);
    key->compressed = compressed;
    _ZNCtxInit();
    return secp256k1_ec_seckey_verify(_znCtx, key->secret);
}

// assigns privKey to key and returns true on success
// privKey must be wallet import format (WIF), mini private key format, or hex string
int ZNKeySetPrivKey(ZNKey *key, const char *privKey, ZNAddrParams params)
{
    size_t len = strlen(privKey);
    uint8_t data[34];
    int r = 0;
    
    assert(key != NULL);
    assert(privKey != NULL);
    
    if ((len == 30 || len == 22) && privKey[0] == 'S') { // mini private key format
        if (! ZNPrivKeyIsValid(privKey, params)) return 0;
        ZNSHA256(data, (const uint8_t *)privKey, strlen(privKey));
        r = ZNKeySetSecret(key, data, 0);
    }
    else {
        len = ZNBase58CheckDecode(data, sizeof(data), privKey);
        if (len == 0 || len == 28) len = ZNBase58Decode(data, sizeof(data), privKey);

        if (len < 32 || len > 34) { // treat as hex string
            for (len = 0; privKey[len*2] && privKey[len*2 + 1] && len < sizeof(data); len++) {
                if (sscanf(privKey + len*2, "%2hhx", data + len) != 1) break;
            }
        }

        if ((len == 33 || len == 34) && data[0] == params.privKeyPrefix) {
            r = ZNKeySetSecret(key, data + 1, (len == 34) ? data[33] : 0);
        }
        else if (len == 32) {
            r = ZNKeySetSecret(key, data, 0);
        }
    }

    zn_mem_clean(data, sizeof(data));
    return r;
}

// assigns DER encoded pubKey to key and returns true on success
int ZNKeySetPubKey(ZNKey *key, const uint8_t *pubKey, size_t pkLen)
{
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    assert(pubKey != NULL);
    assert(pkLen == 33 || pkLen == 65);
    ZNKeyClean(key);
    memcpy(key->pubKey, pubKey, pkLen);
    key->compressed = (pkLen <= 33);
    _ZNCtxInit();
    return secp256k1_ec_pubkey_parse(_znCtx, &pk, key->pubKey, pkLen);
}

// returns true if key contains a valid private key
int ZNKeyIsPrivKey(const ZNKey *key)
{
    assert(key != NULL);
    _ZNCtxInit();
    return secp256k1_ec_seckey_verify(_znCtx, key->secret);
}

// writes the WIF private key to privKey
// returns the number of bytes writen or 0 on failure, maximum is 53 bytes
size_t ZNKeyPrivKey(const ZNKey *key, char privKey[53], ZNAddrParams params)
{
    uint8_t data[34];
    size_t r = 0;
    
    assert(key != NULL);
    assert(privKey != NULL);
    _ZNCtxInit();
    
    if (secp256k1_ec_seckey_verify(_znCtx, key->secret)) {
        data[0] = params.privKeyPrefix;
        memcpy(data + 1, key->secret, 32);
        if (key->compressed) data[33] = key->compressed;
        r = ZNBase58CheckEncode(privKey, 53, data, (key->compressed) ? 34 : 33);
        zn_mem_clean(data, sizeof(data));
    }
    
    return r;
}

// writes the DER encoded public key to pubKey65
// returns number of bytes written or 0 on failure, maximum is 65 bytes
size_t ZNKeyPubKey(ZNKey *key, uint8_t pubKey[65])
{
    static uint8_t empty[65]; // static vars initialize to zero
    size_t size = (key->compressed) ? 33 : 65;
    secp256k1_pubkey pk;

    assert(key != NULL);
    
    if (memcmp(key->pubKey, empty, size) == 0) {
        _ZNCtxInit();

        if (secp256k1_ec_pubkey_create(_znCtx, &pk, key->secret)) {
            secp256k1_ec_pubkey_serialize(_znCtx, key->pubKey, &size, &pk,
                                          (key->compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
        }
        else size = 0;
    }

    if (pubKey) memcpy(pubKey, key->pubKey, size);
    return size;
}

// writes the ripemd160 hash of the sha256 hash of the public key to md20
// returns number of bytes written, maximum is 20 bytes
size_t ZNKeyHash160(ZNKey *key, uint8_t md[20])
{
    size_t len;
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    assert(md != NULL);
    len = ZNKeyPubKey(key, NULL);
    _ZNCtxInit();
    if (len > 0 && ! secp256k1_ec_pubkey_parse(_znCtx, &pk, key->pubKey, len)) len = 0;
    if (len > 0) ZNHash160(md, key->pubKey, len);
    return len;
}

// writes the bech32 pay-to-witness-pubkey-hash address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t ZNKeyAddress(ZNKey *key, char addr[75], ZNAddrParams params)
{
    uint8_t hash[20];
    
    assert(key != NULL);
    return (ZNKeyHash160(key, hash)) ? ZNAddressFromPKH(addr, params, hash) : 0;
}

// writes the legacy pay-to-pubkey-hash bitcoin address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t ZNKeyLegacyAddr(ZNKey *key, char addr[36], ZNAddrParams params)
{
    uint8_t data[21];

    assert(key != NULL);
    data[0] = params.pubKeyPrefix;
    ZNKeyHash160(key, data + 1);
    return (ZNKeyHash160(key, data + 1)) ? ZNBase58CheckEncode(addr, 36, data, sizeof(data)) : 0;
}

// signs md with key and writes signature to sig in DER format
// returns the number of bytes written or 0 on failure, maximum is 72 bytes
size_t ZNKeySign(const ZNKey *key, uint8_t sig[72], const uint8_t md[32])
{
    secp256k1_ecdsa_signature s;
    size_t sigLen = 72;
    
    assert(key != NULL);
    assert(sig != NULL);
    assert(md != NULL);
    _ZNCtxInit();
    
    if (sig && secp256k1_ecdsa_sign(_znCtx, &s, md, key->secret, secp256k1_nonce_function_rfc6979, NULL)) {
        if (! secp256k1_ecdsa_signature_serialize_der(_znCtx, sig, &sigLen, &s)) sigLen = 0;
    }
    else sigLen = 0;

    return sigLen;
}

// returns true if the signature for md is verified to have been made by key
int ZNKeyVerify(ZNKey *key, const uint8_t md[32], const void *sig, size_t sigLen)
{
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature s;
    size_t len;
    int r = 0;
    
    assert(key != NULL);
    assert(sig != NULL);
    assert(sigLen > 0);
    len = ZNKeyPubKey(key, NULL);
    _ZNCtxInit();
    
    if (len > 0 && secp256k1_ec_pubkey_parse(_znCtx, &pk, key->pubKey, len) &&
        secp256k1_ecdsa_signature_parse_der(_znCtx, &s, sig, sigLen)) {
        if (secp256k1_ecdsa_verify(_znCtx, &s, md, &pk) == 1) r = 1; // success is 1, all other values are fail
    }
    
    return r;
}

// Pieter Wuille's compact signature encoding used for bitcoin message signing
// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
// returns the number of bytes written to compactSig, or 0 on failure, maximum is 65 bytes
size_t ZNKeyCompactSign(const ZNKey *key, uint8_t compactSig[65], const uint8_t md[32])
{
    size_t sigLen = 0;
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature s;

    assert(key != NULL);
    assert(compactSig != NULL);
    assert(md != NULL);
    _ZNCtxInit();
    
    if (compactSig && secp256k1_ec_seckey_verify(_znCtx, key->secret) && // can't sign with a public key
        secp256k1_ecdsa_sign_recoverable(_znCtx, &s, md, key->secret, secp256k1_nonce_function_rfc6979, NULL) &&
        secp256k1_ecdsa_recoverable_signature_serialize_compact(_znCtx, compactSig + 1, &recid, &s)) {
        compactSig[0] = 27 + (recid & 0xff) + (key->compressed ? 4 : 0);
        sigLen = 65;
    }
    
    return sigLen;
}

// assigns pubKey recovered from compactSig to key and returns true on success
int ZNKeyRecoverPubKey(ZNKey *key, const uint8_t md[32], const uint8_t compactSig[65])
{
    int r = 0, compressed = 0, recid = 0;
    uint8_t pubKey[65];
    size_t len = sizeof(pubKey);
    secp256k1_ecdsa_recoverable_signature s;
    secp256k1_pubkey pk;

    assert(key != NULL);
    assert(md != NULL);
    assert(compactSig != NULL);
    if (compactSig[0] - 27 >= 4) compressed = 1;
    recid = (compactSig[0] - 27) % 4;
    _ZNCtxInit();

    if (secp256k1_ecdsa_recoverable_signature_parse_compact(_znCtx, &s, compactSig + 1, recid) &&
        secp256k1_ecdsa_recover(_znCtx, &pk, &s, md) &&
        secp256k1_ec_pubkey_serialize(_znCtx, pubKey, &len, &pk,
                                      (compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))) {
        r = ZNKeySetPubKey(key, pubKey, len);
    }

    return r;
}

// write an ECDH shared secret between privKey amd pubKey to buf
void ZNKeyECDH(const ZNKey *privKey, uint8_t buf[32], ZNKey *pubKey)
{
    uint8_t p[65];
    size_t pLen = ZNKeyPubKey(pubKey, p);
    
    assert(privKey != NULL);
    if (pLen == 65) p[0] = (p[64] % 2) ? 0x03 : 0x02; // convert to compressed pubkey format
    ZNSecp256k1PointMul(p, privKey->secret); // calculate shared secret ec-point
    memcpy(buf, p + 1, 32); // unpack the x coordinate
    zn_mem_clean(p, sizeof(p));
}

// wipes key material from key
void ZNKeyClean(ZNKey *key)
{
    assert(key != NULL);
    zn_mem_clean(key, sizeof(*key));
}
