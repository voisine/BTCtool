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

// encrypts key with passphrase
// passphrase must be unicode NFC normalized
// returns number of bytes written to bip38Key including NULL terminator, maximum is 61 bytes
size_t ZNKeyBIP38Key(ZNKey *key, char bip38Key[61], const char *passphrase, ZNAddrParams params);

#ifdef __cplusplus
}
#endif

#endif // ZNBIP38Key_h
