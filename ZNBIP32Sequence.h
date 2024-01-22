//
//  ZNBIP32Sequence.h
//  zinc
//
//  Created by Aaron Voisine on 8/19/15.
//

#ifndef ZNBIP32Sequence_h
#define ZNBIP32Sequence_h

#include "ZNKey.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

#define ZN_BIP32_HARD 0x80000000

#define ZN_CHAIN_EXTERNAL 0
#define ZN_CHAIN_INTERNAL 1

#define ZN_GAP_LIMIT_EXTERNAL 10
#define ZN_GAP_LIMIT_INTERNAL 5

typedef struct {
    uint32_t fingerPrint;
    uint8_t chainCode[32];
    uint8_t pubKey[33];
} ZNMasterPubKey;

#define ZN_MASTER_PUBKEY_NONE ((const ZNMasterPubKey) { 0,\
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },\
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } })

// returns the master public key for the default BIP32 wallet layout - derivation path N(m/0H)
ZNMasterPubKey ZNBIP32MasterPubKey(const uint8_t *seed, size_t seedLen);

// returns the master public key for path N(m/child[0]/child[1]...child[depth-1])
ZNMasterPubKey ZNBIP32MasterPubKeyPath(const uint8_t *seed, size_t seedLen, int depth, const uint32_t child[]);

// writes the public key for path N(mpk/chain/index) to pubKey
// returns number of bytes written, maximum is 33
size_t ZNBIP32PubKey(uint8_t pubKey[33], ZNMasterPubKey mpk, uint32_t chain, uint32_t index);

// sets the private key for path m/0H/chain/index to key
void ZNBIP32PrivKey(ZNKey *key, const uint8_t *seed, size_t seedLen, uint32_t chain, uint32_t index);

// sets the private key for path m/child[0]/child[1]...child[depth-1]/chain/index to each element in keys
void ZNBIP32PrivKeyList(ZNKey keys[], size_t keysCount, const uint8_t *seed, size_t seedLen, int depth,
                        const uint32_t child[], uint32_t chain, const uint32_t indexes[]);
    
// sets the private key for path m/child[0]/child[1]...child[depth-1] to key
void ZNBIP32PrivKeyPath(ZNKey *key, const uint8_t *seed, size_t seedLen, int depth, const uint32_t child[]);

// writes the base58check encoded serialized master private key (xprv) to str
// returns number of bytes written including NULL terminator, maximum is 113 bytes
size_t ZNBIP32SerializeMasterPrivKey(char str[113], const uint8_t *seed, size_t seedLen);

// writes the base58check encoded serialized master public key (xpub) to str, using the default derivation path N(m/0H)
// returns number of bytes written including NULL terminator, maximum is 113 bytes
size_t ZNBIP32SerializeMasterPubKey(char str[113], ZNMasterPubKey mpk);

// writes the base58check encoded serialized master public key (xpub) to str
// depth is the is the depth of the path used to derive mpk, and child is the final path element used to derive mpk
// returns number of bytes written including NULL terminator, maximum is 113 bytes
size_t ZNBIP32SerializeMasterPubKeyPath(char str[113], ZNMasterPubKey mpk, int depth, uint32_t child);

// returns a master public key given a base58check encoded serialized master public key (xpub)
ZNMasterPubKey ZNBIP32ParseMasterPubKey(const char *str);

// key used for authenticated API calls, i.e. bitauth: https://github.com/bitpay/bitauth - path m/1H/0
void ZNBIP32APIAuthKey(ZNKey *key, const uint8_t *seed, size_t seedLen);

// key used for BitID: https://github.com/bitid/bitid/blob/master/BIP_draft.md
void ZNBIP32BitIDKey(ZNKey *key, const uint8_t *seed, size_t seedLen, uint32_t index, const char *uri);

#ifdef __cplusplus
}
#endif

#endif // ZNBIP32Sequence_h
