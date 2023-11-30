//
//  ZNBIP38Key.c
//  zinc
//
//  Created by Aaron Voisine on 9/7/15.
//

#include "ZNBIP38Key.h"
#include "ZNAddress.h"
#include "ZNCrypto.h"
#include "ZNBase58.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define ZN_NOEC_PREFIX      0x0142
#define ZN_EC_PREFIX        0x0143
#define ZN_NOEC_FLAG        (0x80 | 0x40)
#define ZN_COMPRESSED_FLAG  0x20
#define ZN_LOTSEQUENCE_FLAG 0x04
#define ZN_INVALID_FLAG     (0x10 | 0x08 | 0x02 | 0x01)
#define ZN_SCRYPT_N         16384
#define ZN_SCRYPT_R         8
#define ZN_SCRYPT_P         8
#define ZN_SCRYPT_EC_N      1024
#define ZN_SCRYPT_EC_R      1
#define ZN_SCRYPT_EC_P      1

// BIP38 is a method for encrypting private keys with a passphrase
// https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

static void _ZNBIP38DerivePassfactor(uint8_t passfactor[32], uint8_t flag, const uint8_t *entropy,
                                     const char *passphrase)
{
    size_t len = strlen(passphrase);
    uint8_t prefactor[32], d[sizeof(prefactor) + sizeof(uint64_t)];
    
    ZNScrypt(prefactor, sizeof(prefactor), (const uint8_t *)passphrase, len, entropy,
             (flag & ZN_LOTSEQUENCE_FLAG) ? 4 : 8, ZN_SCRYPT_N, ZN_SCRYPT_R, ZN_SCRYPT_P);
    
    if (flag & ZN_LOTSEQUENCE_FLAG) { // passfactor = SHA256(SHA256(prefactor + entropy))
        memcpy(d, prefactor, sizeof(prefactor));
        memcpy(d + sizeof(prefactor), entropy, sizeof(uint64_t));
        ZNSHA256_2(passfactor, d, sizeof(d));
        zn_mem_clean(d, sizeof(d));
    }
    else memcpy(passfactor, prefactor, sizeof(prefactor));
    
    zn_mem_clean(&len, sizeof(len));
    zn_mem_clean(prefactor, sizeof(prefactor));
}

static void _ZNBIP38DeriveKey(uint8_t derived[64], const uint8_t passpoint[33], const uint8_t addresshash[4],
                              const uint8_t entropy[8])
{
    uint8_t salt[sizeof(uint32_t) + sizeof(uint64_t)];
    
    memcpy(salt, addresshash, sizeof(uint32_t));
    memcpy(salt + sizeof(uint32_t), entropy, sizeof(uint64_t)); // salt = addresshash + entropy
    ZNScrypt(derived, 64, passpoint, 33, salt, sizeof(salt), ZN_SCRYPT_EC_N, ZN_SCRYPT_EC_R, ZN_SCRYPT_EC_P);
    zn_mem_clean(salt, sizeof(salt));
}

int ZNBIP38KeyIsValid(const char *bip38Key)
{
    uint8_t data[39], flag;
    int prefix, r = 0;
    
    assert(bip38Key != NULL);
    if (ZNBase58CheckDecode(data, sizeof(data), bip38Key) != 39) return 0; // invalid length
    prefix = data[0] << 8 | data[1];
    flag = data[2];
    
    if (prefix == ZN_NOEC_PREFIX) { // non EC multiplied key
        r = ((flag & ZN_NOEC_FLAG) == ZN_NOEC_FLAG && (flag & ZN_LOTSEQUENCE_FLAG) == 0 &&
             (flag & ZN_INVALID_FLAG) == 0);
    }
    else if (prefix == ZN_EC_PREFIX) { // EC multiplied key
        r = ((flag & ZN_NOEC_FLAG) == 0 && (flag & ZN_INVALID_FLAG) == 0);
    }
    
    return r;
}

// decrypts a BIP38 key using the given passphrase and returns false if passphrase is incorrect
// passphrase must be unicode NFC normalized: http://www.unicode.org/reports/tr15/#Norm_Forms
int ZNKeySetBIP38Key(ZNKey *key, const char *bip38Key, const char *passphrase, ZNAddrParams params)
{
    int prefix, r = 1;
    uint8_t flag, data[39], passpoint[33], passfactor[32], factorb[32], hash[32];
    uint64_t seedb[3], derived[8], secret[4], encrypted[4];
    const uint8_t *entropy, *addresshash;
    char address[36];

    assert(key != NULL);
    assert(bip38Key != NULL);
    assert(passphrase != NULL); 
    if (ZNBase58CheckDecode(data, sizeof(data), bip38Key) != 39) return 0; // invalid length
    prefix = data[0] << 8 | data[1];
    flag = data[2];
    addresshash = data + 3;
    
    if (prefix == ZN_NOEC_PREFIX) { // non EC multiplied key
        // data = prefix + flag + addresshash + encrypted1 + encrypted2
        memcpy(encrypted, data + 7, sizeof(encrypted));
        ZNScrypt((uint8_t *)derived, sizeof(derived), (const uint8_t *)passphrase, strlen(passphrase),
                 addresshash, sizeof(uint32_t), ZN_SCRYPT_N, ZN_SCRYPT_R, ZN_SCRYPT_P);
        
        ZNAESECBDecrypt((uint8_t *)encrypted, (uint8_t *)(derived + 4), 32);
        secret[0] = encrypted[0] ^ derived[0];
        secret[1] = encrypted[1] ^ derived[1];
        
        ZNAESECBDecrypt((uint8_t *)(encrypted + 2), (uint8_t *)(derived + 4), 32);
        secret[2] = encrypted[2] ^ derived[2];
        secret[3] = encrypted[3] ^ derived[3];
        zn_mem_clean(derived, sizeof(derived));
        zn_mem_clean(encrypted, sizeof(encrypted));
    }
    else if (prefix == ZN_EC_PREFIX) { // EC multipled key
        // data = prefix + flag + addresshash + entropy + encrypted1[0...7] + encrypted2
        entropy = data + 7;
        memset(encrypted, 0, 16);
        memcpy(encrypted + 2, data + 23, 16);
        _ZNBIP38DerivePassfactor(passfactor, flag, entropy, passphrase);
        ZNSecp256k1PointGen(passpoint, passfactor); // passpoint = G*passfactor
        _ZNBIP38DeriveKey((uint8_t *)derived, passpoint, addresshash, entropy);
        zn_mem_clean(passpoint, sizeof(passpoint));
        memcpy(encrypted, data + 15, sizeof(uint64_t));

        // encrypted2 = (encrypted1[8...15] + seedb[16...23]) xor derived1[16...31]
        ZNAESECBDecrypt((uint8_t *)(encrypted + 2), (uint8_t *)(derived + 4), 32);
        encrypted[1] = encrypted[2] ^ derived[2];
        seedb[2] = encrypted[3] ^ derived[3];

        // encrypted1 = seedb[0...15] xor derived1[0...15]
        ZNAESECBDecrypt((uint8_t *)encrypted, (uint8_t *)(derived + 4), 32);
        seedb[0] = encrypted[0] ^ derived[0];
        seedb[1] = encrypted[1] ^ derived[1];
        zn_mem_clean(derived, sizeof(derived));
        zn_mem_clean(encrypted, sizeof(encrypted));
        
        ZNSHA256_2((uint8_t *)factorb, (uint8_t *)seedb, sizeof(seedb)); // factorb = SHA256(SHA256(seedb))
        zn_mem_clean(seedb, sizeof(seedb));
        memcpy(secret, passfactor, sizeof(secret));
        ZNSecp256k1ModMul((uint8_t *)secret, factorb); // secret = passfactor*factorb mod N
        zn_mem_clean(passfactor, sizeof(passfactor));
        zn_mem_clean(factorb, sizeof(factorb));
    }
    
    ZNKeySetSecret(key, (uint8_t *)secret, flag & ZN_COMPRESSED_FLAG);
    zn_mem_clean(secret, sizeof(secret));
    ZNKeyLegacyAddr(key, address, params);
    ZNSHA256_2(hash, (uint8_t *)address, strlen(address));
    if (! address[0] || memcmp(hash, addresshash, sizeof(uint32_t)) != 0) r = 0;
    return r;
}

// generates an "intermediate code" for an EC multiply mode key
// salt should be 64bits of random data
// passphrase must be unicode NFC normalized
// returns number of bytes written to code including NULL terminator, maximum is 73 bytes
size_t ZNKeyBIP38ItermediateCode(char code[73], uint64_t salt, const char *passphrase)
{
    // TODO: XXX implement
    return 0;
}

// generates an "intermediate code" for an EC multiply mode key with a lot and sequence number
// lot must be less than 1048576, sequence must be less than 4096, and salt should be 32bits of random data
// passphrase must be unicode NFC normalized
// returns number of bytes written to code including NULL terminator, maximum is 73 bytes
size_t ZNKeyBIP38ItermediateCodeLS(char code[73], uint32_t lot, uint16_t sequence, uint32_t salt,
                                   const char *passphrase)
{
    // TODO: XXX implement
    return 0;
}

// generates a BIP38 key from an "intermediate code" and 24 bytes of cryptographically random data (seedb)
// compressed indicates if compressed pubKey format should be used for the bitcoin address
void ZNKeySetBIP38ItermediateCode(ZNKey *key, const char *code, const uint8_t seedb[24], int compressed)
{
    // TODO: XXX implement
}

// encrypts key with passphrase
// passphrase must be unicode NFC normalized
// returns number of bytes written to bip38Key including NULL terminator or total bip38KeyLen needed if bip38Key is NULL
size_t ZNKeyBIP38Key(ZNKey *key, char bip38Key[61], const char *passphrase, ZNAddrParams params)
{
    uint16_t prefix = ZN_NOEC_PREFIX;
    uint8_t salt[32], buf[39], flag = ZN_NOEC_FLAG;
    char address[36];
    uint64_t derived[8], encrypted[4];
    
    assert(bip38Key != NULL);
    assert(key != NULL && ZNKeyIsPrivKey(key));
    assert(passphrase != NULL);
    if (key->compressed) flag |= ZN_COMPRESSED_FLAG;
    ZNKeyLegacyAddr(key, address, params);
    ZNSHA256_2(salt, (uint8_t *)address, strlen(address));
    ZNScrypt((uint8_t *)derived, sizeof(derived), (const uint8_t *)passphrase, strlen(passphrase), salt, 4,
             ZN_SCRYPT_N, ZN_SCRYPT_R, ZN_SCRYPT_P);
    
    // enctryped1 = AES256Encrypt(privkey[0...15] xor derived1[0...15], derived2)
    encrypted[0] = ((uint64_t *)key->secret)[0] ^ derived[0];
    encrypted[1] = ((uint64_t *)key->secret)[1] ^ derived[1];
    ZNAESECBEncrypt((uint8_t *)encrypted, (uint8_t *)(derived + 4), 32);

    // encrypted2 = AES256Encrypt(privkey[16...31] xor derived1[16...31], derived2)
    encrypted[2] = ((uint64_t *)key->secret)[2] ^ derived[2];
    encrypted[3] = ((uint64_t *)key->secret)[3] ^ derived[3];
    ZNAESECBEncrypt((uint8_t *)(encrypted + 2), (uint8_t *)(derived + 4), 32);
    
    buf[0] = prefix >> 8;
    buf[1] = prefix & 0xff;
    buf[2] = flag;
    memcpy(buf + 3, salt, 4);
    memcpy(buf + 7, encrypted, sizeof(encrypted));
    return ZNBase58CheckEncode(bip38Key, 61, buf, 39);
}
