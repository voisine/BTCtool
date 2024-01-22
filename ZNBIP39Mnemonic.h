//
//  ZNBIP39Mnemonic.h
//  zinc
//
//  Created by Aaron Voisine on 9/7/15.
//

#ifndef ZNBIP39Mnemonic_h
#define ZNBIP39Mnemonic_h

// BIP39 is method for generating a deterministic wallet seed from a mnemonic phrase
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

#define BIP39_CREATION_TIME  1388534400 // oldest possible BIP39 phrase creation time, in seconds after unix epoch
#define BIP39_WORDLIST_COUNT 2048       // number of words in a BIP39 wordlist

#include "ZNBIP39WordsEn.h"
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// returns number of bytes written to phrase including NULL terminator, maximum is 216
size_t ZNBIP39Encode(char phrase[216], const char *wordList[], const uint8_t *data, size_t dataLen);

// returns number of bytes written to data, maximum is 32
size_t ZNBIP39Decode(uint8_t data[32], const char *wordList[], const char *phrase);

// verifies that all phrase words are contained in wordlist and checksum is valid
int ZNBIP39PhraseIsValid(const char *wordList[], const char *phrase);

// key must hold 64 bytes (512 bits), phrase and passphrase must be unicode NFKD normalized
// http://www.unicode.org/reports/tr15/#Norm_Forms
// BUG: does not currently support passphrases containing NULL characters
void ZNBIP39DeriveKey(uint8_t key[64], const char *phrase, const char *passphrase);

#ifdef __cplusplus
}
#endif

#endif // ZNBIP39Mnemonic_h
