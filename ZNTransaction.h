//
//  ZNTransaction.h
//  zinc
//
//  Created by Aaron Voisine on 8/31/15.
//

#ifndef ZNTransaction_h
#define ZNTransaction_h

#include "ZNKey.h"
#include "ZNAddress.h"
#include "ZNRefCount.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZN_FEE_PER_KB      1000LL     // standard tx fee per kb of tx size (bitcoind 0.12 default min-relay fee-rate)
#define ZN_OUTPUT_SIZE     34         // estimated size for a typical transaction output
#define ZN_INPUT_SIZE      148        // estimated size for a typical compact pubkey transaction input
#define ZN_MIN_OUTPUT_AMT  (ZN_FEE_PER_KB*3*(ZN_OUTPUT_SIZE + ZN_INPUT_SIZE)/1000) // txout less than this are dust
#define ZN_MAX_VSIZE       100000     // tx larger than this virtual size in bytes are non-standard
#define ZN_UNCONFIRMED     INT32_MAX  // block height indicating transaction is unconfirmed
#define ZN_MAX_LOCK_HEIGHT 500000000  // a lockTime below this value is a block height, otherwise a timestamp
#define ZN_TXIN_SEQUENCE   UINT32_MAX // sequence number for a finalized tx input

#define ZN_SATOSHIS        100000000LL
#define ZN_MAX_MONEY       (21000000LL*ZN_SATOSHIS)

typedef struct {
    uint8_t txHash[32];
    uint32_t index;
    uint64_t amount;
    uint8_t *scriptPubKey;
    size_t scriptPKLen;
    uint8_t *scriptSig;
    size_t sigLen;
    uint8_t *witness;
    size_t witLen;
    uint32_t sequence;
} ZNTxInput;

#define ZN_TX_INPUT_NONE (ZNTxInput){ ZN_HASH_ZERO, 0, 0, NULL, 0, NULL, 0, NULL, 0, 0 }

size_t ZNTxInputAddress(const ZNTxInput *input, char addr[75], ZNAddrParams params);
void ZNTxInputSetAddress(ZNTxInput *input, const char *addr, ZNAddrParams params);
void ZNTxInputSetScriptPubKey(ZNTxInput *input, const uint8_t *scriptPubKey, size_t scriptPKLen);
void ZNTxInputSetScriptSig(ZNTxInput *input, const uint8_t *scriptSig, size_t sigLen);
void ZNTxInputSetWitness(ZNTxInput *input, const uint8_t *witness, size_t witLen);

typedef struct {
    uint64_t amount;
    uint8_t *scriptPubKey;
    size_t scriptPKLen;
} ZNTxOutput;

#define ZN_TX_OUTPUT_NONE (ZNTxOutput){ 0, NULL, 0 }

// when creating a ZNTxOutput struct outside of a ZNTransaction, set address or script to NULL when done to free memory
size_t ZNTxOutputAddress(const ZNTxOutput *output, char addr[75], ZNAddrParams params);
void ZNTxOutputSetAddress(ZNTxOutput *output, const char *addr, ZNAddrParams params);
void ZNTxOutputSetScriptPubKey(ZNTxOutput *output, const uint8_t *scriptPubKey, size_t scriptPkLen);

typedef struct {
    uint8_t txHash[32];
    uint8_t wtxHash[32];
    uint32_t version;
    ZNTxInput *inputs;
    size_t inCount;
    ZNTxOutput *outputs;
    size_t outCount;
    uint32_t lockTime;
    uint32_t blockHeight;
    uint32_t timeStamp; // time interval since unix epoch
} ZNTransaction;

// returns a new refrence counted empty transaction that must be released by calling zn_ref_release()
ZNTransaction *ZNTransactionNew(void);

// buf must contain a serialized tx
// retruns a reference counted transaction that must be released by calling zn_ref_release()
ZNTransaction *ZNTransactionParse(const uint8_t *buf, size_t bufLen, size_t *off);

// returns number of bytes written to buf, or total bufLen needed if buf is NULL
// (tx->blockHeight and tx->timestamp are not serialized)
size_t ZNTransactionSerialize(const ZNTransaction *tx, uint8_t *buf, size_t bufLen);

// adds an input to tx
void ZNTransactionAddInput(ZNTransaction *tx, const uint8_t txHash[32], uint32_t index, uint64_t amount,
                           const uint8_t *scriptPubKey, size_t scriptPKLen, const uint8_t *scriptSig, size_t sigLen,
                           const uint8_t *witness, size_t witLen, uint32_t sequence);

// adds an output to tx
void ZNTransactionAddOutput(ZNTransaction *tx, uint64_t amount, const uint8_t *scriptPubKey, size_t scriptPKLen);

// shuffles order of tx outputs
void ZNTransactionShuffleOutputs(ZNTransaction *tx);

// size in bytes if signed, or estimated size assuming compact pubkey sigs
size_t ZNTransactionSize(const ZNTransaction *tx);

// virtual transaction size as defined by BIP141: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
size_t ZNTransactionVSize(const ZNTransaction *tx);

// checks if all signatures exist, but does not verify them
int ZNTransactionIsSigned(const ZNTransaction *tx);

// adds signatures to any inputs with NULL signatures that can be signed with any keys
// forkId is 0 for bitcoin, 0x40 for bch/bsv, 0x4f for btg
// returns true if tx is signed
int ZNTransactionSign(ZNTransaction *tx, uint8_t forkId, ZNKey keys[], size_t keysCount);

// returns a hash value for tx suitable for use in a hashtable
//static size_t ZNTransactionHash(const ZNTransaction *tx)
//{
//    return *(size_t *)tx->txHash;
//}

// true if tx and otherTx have equal txHash values
//static int ZNTransactionEq(const ZNTransaction *tx, const ZNTransaction *otherTx)
//{
//    return (tx == otherTx || memcmp(tx->txHash, otherTx->txHash, sizeof(tx->txHash)) == 0);
//}

#ifdef __cplusplus
}
#endif

#endif // ZNTransaction_h
