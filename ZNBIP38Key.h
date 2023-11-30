//
//  ZNBIP38Key.h
//  zinc
//
//  Created by Aaron Voisine on 9/7/15.
//

#ifndef ZNBIP38Key_h
#define ZNBIP38Key_h

#include "ZNKey.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// BIP38 is a method for encrypting private keys with a passphrase
// https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

int ZNBIP38KeyIsValid(const char *bip38Key);

// decrypts a BIP38 key using the given passphrase and returns false if passphrase is incorrect
// passphrase must be unicode NFC normalized: http://www.unicode.org/reports/tr15/#Norm_Forms
int ZNKeySetBIP38Key(ZNKey *key, const char *bip38Key, const char *passphrase, ZNAddrParams params);

// generates an "intermediate code" for an EC multiply mode key
// salt should be 64bits of random data
// passphrase must be unicode NFC normalized
// returns number of bytes written to code including NULL terminator, maximum is 73 bytes
size_t ZNKeyBIP38ItermediateCode(char code[73], uint64_t salt, const char *passphrase);

// generates an "intermediate code" for an EC multiply mode key with a lot and sequence number
// lot must be less than 1048576, sequence must be less than 4096, and salt should be 32bits of random data
// passphrase must be unicode NFC normalized
// returns number of bytes written to code including NULL terminator, maximum is 73 bytes
size_t ZNKeyBIP38ItermediateCodeLS(char code[73], uint32_t lot, uint16_t sequence, uint32_t salt,
                                   const char *passphrase);

// generates a BIP38 key from an "intermediate code" and 24 bytes of cryptographically random data (seedb)
// compressed indicates if compressed pubKey format should be used for the bitcoin address
void ZNKeySetBIP38ItermediateCode(ZNKey *key, const char *code, const uint8_t seedb[24], int compressed);

// encrypts key with passphrase
// passphrase must be unicode NFC normalized
// returns number of bytes written to bip38Key including NULL terminator, maximum is 61 bytes
size_t ZNKeyBIP38Key(ZNKey *key, char bip38Key[61], const char *passphrase, ZNAddrParams params);

#ifdef __cplusplus
}
#endif

#endif // ZNBIP38Key_h
