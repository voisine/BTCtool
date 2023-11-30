//
//  ZNAddress.h
//  zinc
//
//  Created by Aaron Voisine on 9/18/15.
//

#ifndef ZNAddress_h
#define ZNAddress_h

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// bitcoin address prefixes
#define ZN_PUBKEY       0
#define ZN_PUBKEY_TEST  111
#define ZN_SCRIPT       5
#define ZN_SCRIPT_TEST  196
#define ZN_PRIVKEY      128
#define ZN_PRIVKEY_TEST 239
#define ZN_BECH32       "bc"
#define ZN_BECH32_TEST  "tb"

// bitcoin script opcodes: https://en.bitcoin.it/wiki/Script#Constants
#define ZN_OP_0           0x00
#define ZN_OP_PUSHDATA1   0x4c
#define ZN_OP_PUSHDATA2   0x4d
#define ZN_OP_PUSHDATA4   0x4e
#define ZN_OP_1NEGATE     0x4f
#define ZN_OP_1           0x51
#define ZN_OP_16          0x60
#define ZN_OP_VERIFY      0x69
#define ZN_OP_RETURN      0x6a
#define ZN_OP_DUP         0x76
#define ZN_OP_EQUAL       0x87
#define ZN_OP_EQUALVERIFY 0x88
#define ZN_OP_HASH160     0xa9
#define ZN_OP_CHECKSIG    0xac

#define ZN_HASH_NONE (uint8_t [])ZN_HASH_ZERO
#define ZN_HASH_ZERO { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
#define zn_hash_const(h) { (h)[ 0], (h)[ 1], (h)[ 2], (h)[ 3], (h)[ 4], (h)[ 5], (h)[ 6], (h)[ 7], (h)[ 8], (h)[ 9],\
                           (h)[10], (h)[11], (h)[12], (h)[13], (h)[14], (h)[15], (h)[16], (h)[17], (h)[18], (h)[19],\
                           (h)[20], (h)[21], (h)[22], (h)[23], (h)[24], (h)[25], (h)[26], (h)[27], (h)[28], (h)[29],\
                           (h)[30], (h)[31] }

#define zn_le16(x) ((uint16_t)((x)[0] | ((x)[1] << 8)))
#define zn_be16(x) ((uint16_t)(((x)[0] << 8) | (x)[1]))
#define zn_le32(x) ((uint32_t)(zn_le16(x) | (zn_le16((x) + 2) << 16)))
#define zn_be32(x) ((uint32_t)((zn_be16(x) << 16) | zn_be16((x) + 2)))
#define zn_le64(x) (zn_le32(x) | ((uint64_t)zn_le32((x) + 4) << 32))
#define zn_be64(x) (((uint64_t)zn_be32(x) << 32) | zn_be32((x) + 4))

#define zn_le16set(x, u) ((x)[0] = (u) & 0xff, (x)[1] = ((u) >> 8) & 0xff)
#define zn_be16set(x, u) ((x)[0] = ((u) >> 8) & 0xff, (x)[1] = (u) & 0xff)
#define zn_le32set(x, u) (zn_le16set(x, u), zn_le16set((x) + 2, (u) >> 16))
#define zn_be32set(x, u) (zn_be16set(x, (u) >> 16), zn_be16set((x) + 2, u))
#define zn_le64set(x, u) (zn_le32set(x, u), zn_le32set((x) + 4, (u) >> 32))
#define zn_be64set(x, u) (zn_be32set(x, (u) >> 32), zn_be32set((x) + 4, u))

// reads a uint8_t from buf at offset off and stores the new offset in off
uint8_t ZNUInt8(const uint8_t *buf, size_t bufLen, size_t *off);

// writes a uint8_t to buf at offset off and stores the new offset in off
void ZNUInt8Set(uint8_t *buf, size_t bufLen, uint8_t u, size_t *off);

// reads a uint16_t from buf at offset off and stores the new offset in off
uint16_t ZNUInt16(const uint8_t *buf, size_t bufLen, size_t *off);

// writes a uint16_t to buf at offset off and stores the new offset in off
void ZNUInt16Set(uint8_t *buf, size_t bufLen, uint16_t u, size_t *off);

// reads a uint32_t from buf at offset off and stores the new offset in off
uint32_t ZNUInt32(const uint8_t *buf, size_t bufLen, size_t *off);

// writes a uint32_t to buf at offset off and stores the new offset in off
void ZNUInt32Set(uint8_t *buf, size_t bufLen, uint32_t u, size_t *off);

// reads a uint64_t from buf at offset off and stores the new offset in off
uint64_t ZNUInt64(const uint8_t *buf, size_t bufLen, size_t *off);

// writes a uint64_t to buf at offset off and stores the new offset in off
void ZNUInt64Set(uint8_t *buf, size_t bufLen, uint64_t u, size_t *off);

// reads a varint from buf at offset off and stores the new offset in off
uint64_t ZNVarInt(const uint8_t *buf, size_t bufLen, size_t *off);

// writes i to buf as a varint at offset off and stores the new offset in off
void ZNVarIntSet(uint8_t *buf, size_t bufLen, uint64_t i, size_t *off);

// returns the number of bytes needed to encode i as a varint
size_t ZNVarIntSize(uint64_t i);

// reads dataLen bytes from buf at offset off and writes them to data unless data is NULL
// stores the new offset in off and returns a pointer to the bytes read from buf
const uint8_t *ZNData(uint8_t *data, size_t dataLen, const uint8_t *buf, size_t bufLen, size_t *off);

// writes dataLen bytes from data to buf at offset off and stores the new offset in off
void ZNDataSet(uint8_t *buf, size_t bufLen, const uint8_t *data, size_t dataLen, size_t *off);

// parses script and writes an array of pointers to the script elements (opcodes and data pushes) to elems
// returns the total number of elements contained in script
size_t ZNScriptElements(const uint8_t *elems[], size_t elemsCount, const uint8_t *script, size_t scriptLen);

// given a data push script element, returns a pointer to the start of the data and writes its length to dataLen
const uint8_t *ZNScriptData(const uint8_t *elem, size_t *dataLen);

// writes a data push script element to script
// returns the number of bytes written, or scriptLen needed if script is NULL
size_t ZNScriptPushData(uint8_t *script, size_t scriptLen, const uint8_t *data, size_t dataLen);

// returns true if script contains a known valid scriptPubKey
int ZNScriptPubKeyIsValid(const uint8_t *script, size_t scriptLen);

// returns a pointer to the 20byte pubkey hash, or NULL if none
const uint8_t *ZNScriptPubKeyPKH(const uint8_t *script, size_t scriptLen);
  
// writes the 20 byte pubkey hash from signature to pkh and returns the number of bytes written
size_t ZNScriptSigPKH(uint8_t pkh[20], const uint8_t *signature, size_t sigLen);
  
// writes the 20 byte pubkey hash from witness to pkh and returns the number of bytes written
size_t ZNWitnessPKH(uint8_t pkh[20], const uint8_t *witness, size_t witLen);
   
typedef struct ZNAddrParamsStruct {
    uint8_t pubKeyPrefix;
    uint8_t scriptPrefix;
    uint8_t privKeyPrefix;
    const char *bech32Prefix;
} ZNAddrParams;

// writes the bitcoin address for a scriptPubKey to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromScriptPubKey(char addr[75], ZNAddrParams params, const uint8_t *script, size_t scriptLen);

// writes the bitcoin address for a scriptSig to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromScriptSig(char addr[75], ZNAddrParams params, const uint8_t *script, size_t scriptLen);

// writes the bitcoin address for a witness to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromWitness(char addr[75], ZNAddrParams params, const uint8_t *witness, size_t witLen);

// writes the bech32 pay-to-witness-pubkey-hash address for a 20 byte pubkey hash to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromPKH(char addr[75], ZNAddrParams params, const uint8_t pkh[20]);

// writes the scriptPubKey for addr to script
// returns the number of bytes written, maximum is 42 bytes
size_t ZNAddressScriptPubKey(uint8_t script[42], const char *addr, ZNAddrParams params);

// writes the 20 byte pubkey hash from addr to pkh and returns the number of bytes written
size_t ZNAddressPKH(uint8_t pkh[20], const char *addr, ZNAddrParams params);

// returns true if addr is a valid bitcoin address
int ZNAddressIsValid(const char *addr, ZNAddrParams params);

// returns a hash value for addr suitable for use in a hashtable
static size_t ZNAddressHash(const char addr[75])
{
    size_t h = 0x811C9dc5; // FNV_offset
    
    while (*addr) h = (h ^ (size_t)*(addr++))*0x01000193; // (hash xor octet)*FNV_prime
    return h;
}

// true if addr and otherAddr are equal
static int ZNAddressEq(const char addr[75], const char otherAddr[75])
{
    return (addr == otherAddr || strncmp(addr, otherAddr, 75) == 0);
}

#ifdef __cplusplus
}
#endif

#endif // ZNAddress_h
