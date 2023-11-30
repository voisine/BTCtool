//
//  ZNBech32m.h
//  zinc
//
//  Created by Aaron Voisine on 1/20/18.
//

#ifndef ZNBech32m_h
#define ZNBech32m_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// bech32 address format: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
// bech32m format for v1+: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

// returns the number of bytes written to data (maximum of 42)
size_t ZNBech32mDecode(char hrp[84], uint8_t data[42], const char *addr);

// data must contain a valid BIP141 witness program
// returns the number of bytes written to addr (maximum of 91)
size_t ZNBech32mEncode(char addr[91], const char *hrp, const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif // ZNBech32_h
