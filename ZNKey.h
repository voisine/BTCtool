//
//  ZNKey.h
//  zinc
//
//  Created by Aaron Voisine on 8/19/15.
//

#ifndef ZNKey_h
#define ZNKey_h

#include "ZNAddress.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// collect cpu timing jitter entropy: https://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html
// returns true on success
int ZNEntropy(uint8_t buf[32]);

// psudo-random number generator
uint64_t ZNRand(uint64_t upperBound);

// adds 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int ZNSecp256k1ModAdd(uint8_t a[32], const uint8_t b[32]);

// multiplies 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int ZNSecp256k1ModMul(uint8_t a[32], const uint8_t b[32]);

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in ec-point p (33 bytes)
// returns true on success
int ZNSecp256k1PointGen(uint8_t p[33], const uint8_t i[32]);

// multiplies secp256k1 generator by 256bit big endian int i and adds the result to ec-point p (33 bytes)
// returns true on success
int ZNSecp256k1PointAdd(uint8_t p[33], const uint8_t i[32]);

// multiplies secp256k1 ec-point p by 256bit big endian int i and stores the result in p (33 bytes)
// returns true on success
int ZNSecp256k1PointMul(uint8_t p[33], const uint8_t i[32]);

// returns true if privKey is a valid private key
// supported formats are wallet import format (WIF), mini private key format, or hex string
int ZNPrivKeyIsValid(const char *privKey, ZNAddrParams params);

typedef struct {
    uint8_t secret[32];
    uint8_t pubKey[65];
    int compressed;
} ZNKey;

// assigns secret to key and returns true on success
int ZNKeySetSecret(ZNKey *key, const uint8_t secret[32], int compressed);

// assigns privKey to key and returns true on success
// privKey must be wallet import format (WIF), mini private key format, or hex string
int ZNKeySetPrivKey(ZNKey *key, const char *privKey, ZNAddrParams params);

// assigns DER encoded pubKey to key and returns true on success
int ZNKeySetPubKey(ZNKey *key, const uint8_t *pubKey, size_t pkLen);

// returns true if key contains a valid private key
int ZNKeyIsPrivKey(const ZNKey *key);
    
// writes the WIF private key to privKey
// returns the number of bytes writen or 0 on failure, maximum is 53 bytes
size_t ZNKeyPrivKey(const ZNKey *key, char privKey[53], ZNAddrParams params);

// writes the DER encoded public key to pubKey
// returns number of bytes written or 0 on failure, maximum is 65 bytes
size_t ZNKeyPubKey(ZNKey *key, uint8_t pubKey[65]);

// writes the ripemd160 hash of the sha256 hash of the public key to md
// returns number of bytes written, maximum is 20 bytes
size_t ZNKeyHash160(ZNKey *key, uint8_t md[20]);

// writes the bech32 pay-to-witness-pubkey-hash bitcoin address for key to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNKeyAddress(ZNKey *key, char addr[75], ZNAddrParams params);

// writes the legacy pay-to-pubkey-hash address for key to addr
// returns the number of bytes written, maximum is 36 bytes
size_t ZNKeyLegacyAddr(ZNKey *key, char addr[36], ZNAddrParams params);
    
// signs md with key and writes signature to sig in DER format
// returns the number of bytes written or 0 on failure, maximum is 72 bytes
size_t ZNKeySign(const ZNKey *key, uint8_t sig[72], const uint8_t md[32]);

// returns true if the DER-encoded signature for md is verified to have been made by key
int ZNKeyVerify(ZNKey *key, const uint8_t md[32], const void *sig, size_t sigLen);

// Pieter Wuille's compact signature encoding used for bitcoin message signing
// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
// returns the number of bytes written to compactSig, or 0 on failure, maximum is 65 bytes
size_t ZNKeyCompactSign(const ZNKey *key, uint8_t compactSig[65], const uint8_t md[32]);

// assigns pubKey recovered from compactSig to key and returns true on success
int ZNKeyRecoverPubKey(ZNKey *key, const uint8_t md[20], const uint8_t compactSig[65]);

// write an ECDH shared secret between privKey and pubKey to buf
void ZNKeyECDH(const ZNKey *privKey, uint8_t buf[32], ZNKey *pubKey);

// wipes key material from key
void ZNKeyClean(ZNKey *key);

#ifdef __cplusplus
}
#endif

#endif // ZNKey_h
