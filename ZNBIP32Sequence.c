//
//  ZNBIP32Sequence.c
//  zinc
//
//  Created by Aaron Voisine on 8/19/15.
//

#include "ZNBIP32Sequence.h"
#include "ZNCrypto.h"
#include "ZNBase58.h"
#include <string.h>
#include <assert.h>

#define ZN_BIP32_SEED_KEY "Bitcoin seed"
#define ZN_BIP32_XPRV     "\x04\x88\xAD\xE4"
#define ZN_BIP32_XPUB     "\x04\x88\xB2\x1E"

#define be32(x) (union { uint8_t u8[4]; uint32_t u32; }){{ (x)>>24, ((x)>>16) & 0xff, ((x)>>8) & 0xff, (x) & 0xff }}.u32
#define le32(x) (union { uint8_t u8[4]; uint32_t u32; }){{ (x) & 0xff, ((x)>>8) & 0xff, ((x)>>16) & 0xff, (x)>>24 }}.u32

// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

// Private parent key -> private child key
//
// CKDpriv((kpar, cpar), i) -> (ki, ci) computes a child extended private key from the parent extended private key:
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
//       (Note: The 0x00 pads the private key to make it 33 bytes long.)
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key ki is parse256(IL) + kpar (mod n).
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i
//   (Note: this has probability lower than 1 in 2^127.)
//
static void _CKDpriv(uint8_t k[32], uint8_t c[32], uint32_t i)
{
    uint8_t I[64], buf[33 + sizeof(i)];
    
    if (i & ZN_BIP32_HARD) {
        buf[0] = 0;
        memcpy(buf + 1, k, 32);
    }
    else ZNSecp256k1PointGen(buf, k);
    
    i = be32(i);
    memcpy(buf + 33, &i, sizeof(i));
    ZNHMAC(I, ZNSHA512, sizeof(I), c, 32, buf, sizeof(buf)); // I = HMAC-SHA512(c, k|P(k) || i)
    ZNSecp256k1ModAdd(k, I); // k = IL + k (mod n)
    memcpy(c, I + 32, 32); // c = IR
    zn_mem_clean(I, sizeof(I));
    zn_mem_clean(buf, sizeof(buf));
}

// Public parent key -> public child key
//
// CKDpub((Kpar, cpar), i) -> (Ki, ci) computes a child extended public key from the parent extended public key.
// It is only defined for non-hardened child keys.
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): return failure
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key Ki is point(parse256(IL)) + Kpar.
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or Ki is the point at infinity, the resulting key is invalid, and one should proceed with
//   the next value for i.
//
static void _CKDpub(uint8_t K[33], uint8_t c[32], uint32_t i)
{
    uint8_t I[64], buf[33 + sizeof(i)];

    if ((i & ZN_BIP32_HARD) != ZN_BIP32_HARD) { // can't derive private child key from public parent key
        memcpy(buf, K, 33);
        i = be32(i);
        memcpy(buf + 33, &i, sizeof(i));
        ZNHMAC(I, ZNSHA512, sizeof(I), c, 32, buf, sizeof(buf)); // I = HMAC-SHA512(c, P(K) || i)
        memcpy(c, I + 32, 32); // c = IR
        ZNSecp256k1PointAdd(K, I); // K = P(IL) + K
        zn_mem_clean(I, sizeof(I));
        zn_mem_clean(buf, sizeof(buf));
    }
}

// returns the master public key for the default BIP32 wallet layout - derivation path N(m/0H)
ZNMasterPubKey ZNBIP32MasterPubKey(const uint8_t *seed, size_t seedLen)
{
    ZNMasterPubKey mpk = ZN_MASTER_PUBKEY_NONE;
    uint8_t I[64], *secret = I, *chain = I + 32;
    ZNKey key;

    assert(seed != NULL || seedLen == 0);
    
    if (seed || seedLen == 0) {
        ZNHMAC(I, ZNSHA512, sizeof(I), (uint8_t *)ZN_BIP32_SEED_KEY, strlen(ZN_BIP32_SEED_KEY), seed, seedLen);
        ZNKeySetSecret(&key, secret, 1);
        ZNKeyHash160(&key, (uint8_t *)&mpk.fingerPrint);
        _CKDpriv(secret, chain, 0 | ZN_BIP32_HARD); // path m/0H
        memcpy(mpk.chainCode, chain, sizeof(mpk.chainCode));
        ZNKeySetSecret(&key, secret, 1);
        zn_mem_clean(I, sizeof(I));
        ZNKeyPubKey(&key, mpk.pubKey); // path N(m/0H)
        ZNKeyClean(&key);
    }
    
    return mpk;
}

// writes the public key for path N(mpk/chain/index) to pubKey
// returns number of bytes written, maximum is 33
size_t ZNBIP32PubKey(uint8_t pubKey[33], ZNMasterPubKey mpk, uint32_t chain, uint32_t index)
{
    uint8_t chainCode[32];
    
    assert(pubKey != NULL);
    assert(memcmp(&mpk, &ZN_MASTER_PUBKEY_NONE, sizeof(mpk)) != 0);
    memcpy(chainCode, mpk.chainCode, sizeof(chainCode));
    
    if (pubKey) {
        memcpy(pubKey, mpk.pubKey, sizeof(mpk.pubKey));
        _CKDpub(pubKey, chainCode, chain); // path N(m/0H/chain)
        _CKDpub(pubKey, chainCode, index); // index'th key in chain
        zn_mem_clean(chainCode, sizeof(chainCode));
    }
    
    return (pubKey) ? 33 : 0;
}

// sets the private key for path m/0H/chain/index to key
void ZNBIP32PrivKey(ZNKey *key, const uint8_t *seed, size_t seedLen, uint32_t chain, uint32_t index)
{
    ZNBIP32PrivKeyPath(key, seed, seedLen, 3, (const uint32_t []){ 0 | ZN_BIP32_HARD, chain, index });
}

// sets the private key for path m/child[0]/child[1]...child[depth-1]/chain/index to each element in keys
void ZNBIP32PrivKeyList(ZNKey keys[], size_t keysCount, const uint8_t *seed, size_t seedLen, int depth,
                        const uint32_t child[], uint32_t chain, const uint32_t indexes[])
{
    uint8_t I[64], s[32], c[32], *secret = I, *chainCode = I + 32;
    size_t i;
    
    assert(keys != NULL || keysCount == 0);
    assert(seed != NULL || seedLen == 0);
    assert(indexes != NULL || keysCount == 0);
    
    if (keys && keysCount > 0 && (seed || seedLen == 0) && indexes) {
        ZNHMAC(I, ZNSHA512, sizeof(I), (const uint8_t *)ZN_BIP32_SEED_KEY, strlen(ZN_BIP32_SEED_KEY), seed, seedLen);

        for (i = 0; i < (size_t)depth; i++) {
            _CKDpriv(secret, chainCode, child[i]); // path m/child[0]/child[1]...child[depth-1]
        }
        
        _CKDpriv(secret, chainCode, chain); // path m/child[0]/child[1]...child[depth-1]/chain
    
        for (i = 0; i < keysCount; i++) {
            memcpy(s, secret, sizeof(s));
            memcpy(c, chainCode, sizeof(c));
            _CKDpriv(s, c, indexes[i]); // index'th key in chain
            ZNKeySetSecret(&keys[i], s, 1);
        }
        
        zn_mem_clean(I, sizeof(I));
        zn_mem_clean(c, sizeof(c));
        zn_mem_clean(s, sizeof(s));
    }
}

// sets the private key for the specified path to key
// depth is the number of arguments used to specify the path
void ZNBIP32PrivKeyPath(ZNKey *key, const uint8_t *seed, size_t seedLen, int depth, const uint32_t child[])
{
    uint8_t I[64], *secret = I, *chainCode = &I[32];
    int i;
    
    assert(key != NULL);
    assert(seed != NULL || seedLen == 0);
    assert(depth >= 0);
    
    if (key && (seed || seedLen == 0)) {
        ZNHMAC(I, ZNSHA512, sizeof(I), (const uint8_t *)ZN_BIP32_SEED_KEY, strlen(ZN_BIP32_SEED_KEY), seed, seedLen);
     
        for (i = 0; i < depth; i++) {
            _CKDpriv(secret, chainCode, child[i]);
        }
        
        ZNKeySetSecret(key, secret, 1);
        zn_mem_clean(I, sizeof(I));
    }
}

// helper function for serializing BIP32 master public/private keys to standard export format
static size_t _ZNBIP32Serialize(char str[113], uint8_t depth, uint32_t fingerprint, uint32_t child, uint8_t chain[32],
                                const uint8_t *key, size_t keyLen)
{
    uint8_t data[4 + sizeof(depth) + sizeof(fingerprint) + sizeof(child) + 32 + 33];
    size_t len;
    
    memcpy(data, (keyLen < 33 ? ZN_BIP32_XPRV : ZN_BIP32_XPUB), 4);
    data[4] = depth;
    fingerprint = be32(fingerprint);
    memcpy(data + 5, &fingerprint, sizeof(fingerprint));
    child = be32(child);
    memcpy(data + 9, &child, sizeof(child));
    memcpy(data + 13, chain, 32);
    data[sizeof(data) - 33] = 0;
    memcpy(data + (sizeof(data) - keyLen), key, keyLen);
    len = ZNBase58CheckEncode(str, 115, data, sizeof(data));
    zn_mem_clean(data, sizeof(data));
    return len;
}

// writes the base58check encoded serialized master private key (xprv) to str
// returns number of bytes written including NULL terminator, maximum is 113 bytes
size_t ZNBIP32SerializeMasterPrivKey(char str[113], const uint8_t *seed, size_t seedLen)
{
    uint8_t I[64];
    size_t len;
    
    assert(seed != NULL);
    assert(seedLen > 0);
    ZNHMAC(I, ZNSHA512, sizeof(I), (const uint8_t *)ZN_BIP32_SEED_KEY, strlen(ZN_BIP32_SEED_KEY), seed, seedLen);
    len = _ZNBIP32Serialize(str, 0, 0, 0, &I[32], I, 32);
    zn_mem_clean(I, sizeof(I));
    return len;
}

// writes the base58check encoded serialized master public key (xpub) to str
// returns number of bytes written including NULL terminator, maximum is 113 bytes
size_t ZNBIP32SerializeMasterPubKey(char str[113], ZNMasterPubKey mpk)
{
    return _ZNBIP32Serialize(str, 1, mpk.fingerPrint, 0 | ZN_BIP32_HARD, mpk.chainCode, mpk.pubKey, 33);
}

// returns a master public key given a base58check encoded serialized master public key (xpub)
ZNMasterPubKey ZNBIP32ParseMasterPubKey(const char *str)
{
    ZNMasterPubKey mpk = ZN_MASTER_PUBKEY_NONE;
    uint8_t data[4 + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + 32 + 33];
    size_t dataLen = ZNBase58CheckDecode(data, sizeof(data), str);
    
    if (dataLen == sizeof(data) && memcmp(data, ZN_BIP32_XPUB, 4) == 0) {
        memcpy(&mpk.fingerPrint, data + 5, sizeof(mpk.fingerPrint));
        mpk.fingerPrint = be32(mpk.fingerPrint);
        memcpy(mpk.chainCode, data + 13, sizeof(mpk.chainCode));
        memcpy(mpk.pubKey, data + 45, sizeof(mpk.pubKey));
    }
    
    return mpk;
}

// key used for authenticated API calls, i.e. bitauth: https://github.com/bitpay/bitauth - path m/1H/0
void ZNBIP32APIAuthKey(ZNKey *key, const uint8_t *seed, size_t seedLen)
{
    ZNBIP32PrivKeyPath(key, seed, seedLen, 2, (const uint32_t []){ 1 | ZN_BIP32_HARD, 0 });
}

// key used for BitID: https://github.com/bitid/bitid/blob/master/BIP_draft.md
void ZNBIP32BitIDKey(ZNKey *key, const uint8_t *seed, size_t seedLen, uint32_t index, const char *uri)
{
    size_t uriLen = strlen(uri);
    uint8_t data[sizeof(index) + uriLen];
    uint32_t hash[8];
    
    assert(key != NULL);
    assert(seed != NULL || seedLen == 0);
    
    if (key && (seed || seedLen == 0) && uri) {
        index = le32(index);
        memcpy(data, &index, sizeof(index));
        memcpy(data + sizeof(index), uri, uriLen);
        ZNSHA256((uint8_t *)hash, data, sizeof(data));
        ZNBIP32PrivKeyPath(key, seed, seedLen, 5, (const uint32_t []){ 13 | ZN_BIP32_HARD,
            le32(hash[0]) | ZN_BIP32_HARD, le32(hash[1]) | ZN_BIP32_HARD,
            le32(hash[2]) | ZN_BIP32_HARD, le32(hash[3]) | ZN_BIP32_HARD }); // path m/13H/aH/bH/cH/dH
    }
}

