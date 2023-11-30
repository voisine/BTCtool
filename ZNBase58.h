//
//  ZNBase58.h
//  zinc
//
//  Created by Aaron Voisine on 9/15/15.
//

#ifndef ZNBase58_h
#define ZNBase58_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// base58 and base58check encoding: https://en.bitcoin.it/wiki/Base58Check_encoding

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t ZNBase58Encode(char *str, size_t strLen, const uint8_t *data, size_t dataLen);

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t ZNBase58Decode(uint8_t *data, size_t dataLen, const char *str);

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t ZNBase58CheckEncode(char *str, size_t strLen, const uint8_t *data, size_t dataLen);

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t ZNBase58CheckDecode(uint8_t *data, size_t dataLen, const char *str);

#ifdef __cplusplus
}
#endif

#endif // ZNBase58_h
