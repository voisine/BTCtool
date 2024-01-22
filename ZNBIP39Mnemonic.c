//
//  ZNBIP39Mnemonic.c
//  zinc
//
//  Created by Aaron Voisine on 9/7/15.

#include "ZNBIP39Mnemonic.h"
#include "ZNCrypto.h"
#include "ZNAddress.h"
#include <string.h>
#include <assert.h>

// returns number of bytes written to phrase including NULL terminator
size_t ZNBIP39Encode(char phrase[216], const char *wordList[], const uint8_t *data, size_t dataLen)
{
    uint32_t x;
    uint8_t buf[64];
    const char *word;
    size_t i, len = 0;

    assert(data != NULL || dataLen == 0);
    assert(dataLen > 0 && dataLen <= 32 && (dataLen % 4) == 0);
    if (! wordList) wordList = ZNBIP39WordsEn;
    if (! data || dataLen > 32 || (dataLen % 4) != 0) return 0; // data length must be a multiple of 32 bits
    
    memcpy(buf, data, dataLen);
    ZNSHA256(&buf[dataLen], data, dataLen); // append SHA256 checksum

    for (i = 0; i < dataLen*3/4; i++) {
        x = zn_be32(&buf[i*11/8]);
        word = wordList[(x >> (32 - (11 + ((i*11) % 8)))) % BIP39_WORDLIST_COUNT];
        if (i > 0 && phrase && len < 216) phrase[len] = ' ';
        if (i > 0) len++;
        if (phrase && len < 216) strncpy(&phrase[len], word, 216 - len);
        len += strlen(word);
    }

    zn_mem_clean(&word, sizeof(word));
    zn_mem_clean(&x, sizeof(x));
    zn_mem_clean(buf, sizeof(buf));
    return len + 1;
}

// returns number of bytes written to data
size_t ZNBIP39Decode(uint8_t data[32], const char *wordList[], const char *phrase)
{
    uint32_t x, y, count = 0, idx[24], i;
    uint8_t b = 0, hash[32];
    const char *word = phrase;
    size_t r = 0;

    assert(phrase != NULL);
    if (! wordList) wordList = ZNBIP39WordsEn;
    
    while (word && *word && count < 24) {
        for (i = 0, idx[count] = INT32_MAX; i < BIP39_WORDLIST_COUNT; i++) { // not fast, but simple and correct
            if (strncmp(word, wordList[i], strlen(wordList[i])) != 0 ||
                (word[strlen(wordList[i])] != ' ' && word[strlen(wordList[i])] != '\0')) continue;
            idx[count] = i;
            break;
        }
        
        if (idx[count] == INT32_MAX) break; // phrase contains unknown word
        count++;
        word = strchr(word, ' ');
        if (word) word++;
    }

    if ((count % 3) == 0 && (! word || *word == '\0')) { // check that phrase has correct number of words
        uint8_t buf[(count*11 + 7)/8];

        for (i = 0; i < (count*11 + 7)/8; i++) {
            x = idx[i*8/11];
            y = (i*8/11 + 1 < count) ? idx[i*8/11 + 1] : 0;
            b = ((x*BIP39_WORDLIST_COUNT + y) >> ((i*8/11 + 2)*11 - (i + 1)*8)) & 0xff;
            buf[i] = b;
        }
    
        ZNSHA256(hash, buf, count*4/3);

        if (b >> (8 - count/3) == (hash[0] >> (8 - count/3))) { // verify checksum
            r = count*4/3;
            if (data && r <= 32) memcpy(data, buf, r);
        }
        
        zn_mem_clean(buf, sizeof(buf));
    }

    zn_mem_clean(&b, sizeof(b));
    zn_mem_clean(&x, sizeof(x));
    zn_mem_clean(&y, sizeof(y));
    zn_mem_clean(idx, sizeof(idx));
    return r;
}

// verifies that all phrase words are contained in wordlist and checksum is valid
int ZNBIP39PhraseIsValid(const char *wordList[], const char *phrase)
{
    assert(phrase != NULL);
    return (ZNBIP39Decode(NULL, wordList, phrase) > 0);
}

// key must hold 64 bytes (512 bits), phrase and passphrase must be unicode NFKD normalized
// http://www.unicode.org/reports/tr15/#Norm_Forms
// BUG: does not currently support passphrases containing NULL characters
void ZNBIP39DeriveKey(uint8_t key[64], const char *phrase, const char *passphrase)
{
    char salt[strlen("mnemonic") + (passphrase ? strlen(passphrase) : 0) + 1];

    assert(key != NULL);
    assert(phrase != NULL);
    
    if (phrase) {
        strcpy(salt, "mnemonic");
        if (passphrase) strcpy(salt + strlen("mnemonic"), passphrase);
        ZNPBKDF2(key, 64, ZNSHA512, 512/8, (const uint8_t *)phrase, strlen(phrase), 
                 (const uint8_t *)salt, strlen(salt), 2048);
        zn_mem_clean(salt, sizeof(salt));
    }
}
