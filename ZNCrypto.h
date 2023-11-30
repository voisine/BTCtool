//
//  ZNCrypto.h
//  zinc
//
//  Created by Aaron Voisine on 8/8/15.
//

#ifndef ZNCrypto_h
#define ZNCrypto_h

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// zeros out memory in a way that can't be optimized out by the compiler
#define zn_mem_clean(ptr, len)\
    do { void *(*volatile const _zn_p)(void *, int, size_t) = memset; _zn_p(ptr, 0, len); } while(0)

// sha-1 - not recommended for cryptographic use
void ZNSHA1(uint8_t md[20], const uint8_t *data, size_t dataLen);

// sha-256: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
void ZNSHA256(uint8_t md[32], const uint8_t *data, size_t dataLen);

void ZNSHA224(uint8_t md[28], const uint8_t *data, size_t dataLen);

// double-sha-256 = sha-256(sha-256(x))
void ZNSHA256_2(uint8_t md[32], const uint8_t *data, size_t dataLen);

void ZNSHA384(uint8_t md[48], const uint8_t *data, size_t dataLen);

void ZNSHA512(uint8_t md[64], const uint8_t *data, size_t dataLen);

// ripemd-160: http://homes.esat.kuleuven.be/~bosselae/ripemd160.html
void ZNRMD160(uint8_t md[20], const uint8_t *data, size_t dataLen);

// bitcoin hash-160 = ripemd-160(sha-256(x))
void ZNHash160(uint8_t md[20], const uint8_t *data, size_t dataLen);

// sha3-256: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
void ZNSHA3_256(uint8_t md[32], const uint8_t *data, size_t dataLen);

// keccak-256: https://keccak.team/files/Keccak-submission-3.pdf
void ZNKeccak256(uint8_t md[32], const uint8_t *data, size_t dataLen);

// md5 - for non-cryptographic use only
void ZNMD5(uint8_t md[16], const uint8_t *data, size_t dataLen);

// murmurHash3 (x86_32): https://code.google.com/p/smhasher/ - for non-cryptographic use only
uint32_t ZNMurmur3_32(const uint8_t *data, size_t dataLen, uint32_t seed);

// fnv-1a hash: http://www.isthe.com/chongo/tech/comp/fnv/ - fast non-cryptographic hash, suitable for hashtables
uint32_t ZNFNV1a32(const uint8_t *data, size_t dataLen);

// sipHash-64: https://131002.net/siphash
uint64_t ZNSip64(const uint8_t key[16], const uint8_t *data, size_t dataLen);

// hash-based message authentication code (HMAC): https://datatracker.ietf.org/doc/html/rfc2104
void ZNHMAC(uint8_t *mac, void (*hash)(uint8_t [], const uint8_t *, size_t), size_t hashLen,
            const uint8_t *key, size_t keyLen, const uint8_t *data, size_t dataLen);

// hmac-drbg with no prediction resistance or additional input
// K and V must point to buffers of size hashLen, and ps (personalization string) may be NULL
// to generate additional drbg output, use K and V from the previous call, and set seed, nonce and ps to NULL
void ZNHMACDRBG(uint8_t *buf, size_t bufLen, uint8_t *K, uint8_t *V, void (*hash)(uint8_t [], const uint8_t *, size_t),
                size_t hashLen, const uint8_t *seed, size_t seedLen, const uint8_t *nonce, size_t nonceLen,
                const uint8_t *ps, size_t psLen);

// poly1305 authenticator: https://tools.ietf.org/html/rfc7539
// NOTE: must use constant time mem comparison when verifying mac to defend against timing attacks
void ZNPoly1305(uint8_t mac[16], const uint8_t key[32], const uint8_t *data, size_t dataLen);

// chacha20 stream cipher: https://cr.yp.to/chacha.html
void ZNChacha20(uint8_t *buf, const uint8_t key[32], const uint8_t iv[8], const uint8_t *data, size_t dataLen,
                uint64_t counter);
    
// chacha20-poly1305 authenticated encryption with associated data (AEAD): https://tools.ietf.org/html/rfc7539
size_t ZNChacha20Poly1305AEADEncrypt(uint8_t *buf, size_t bufLen, const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *data, size_t dataLen, const uint8_t *ad, size_t adLen);

size_t ZNChacha20Poly1305AEADDecrypt(uint8_t *buf, size_t bufLen, const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *data, size_t dataLen, const uint8_t *ad, size_t adLen);
    
// aes-ecb block cipher
void ZNAESECBEncrypt(uint8_t buf[16], const uint8_t *key, size_t keyLen);

void ZNAESECBDecrypt(uint8_t buf[16], const uint8_t *key, size_t keyLen);

// aes-ctr stream cipher encrypt/decrypt
void ZNAESCTR(uint8_t *buf, const uint8_t *key, size_t keyLen, const uint8_t iv[16],
              const uint8_t *data, size_t dataLen);

// pbkdf2 key derivation: https://www.ietf.org/rfc/rfc2898.txt
void ZNPBKDF2(uint8_t *dk, size_t dkLen, void (*hash)(uint8_t [], const uint8_t *, size_t), size_t hashLen,
              const uint8_t *pw, size_t pwLen, const uint8_t *salt, size_t saltLen, unsigned rounds);

// scrypt key derivation: http://www.tarsnap.com/scrypt.html
void ZNScrypt(uint8_t *dk, size_t dkLen, const uint8_t *pw, size_t pwLen, const uint8_t *salt, size_t saltLen,
              unsigned n, unsigned r, unsigned p);

#ifdef __cplusplus
}
#endif

#endif // ZNCrypto_h
