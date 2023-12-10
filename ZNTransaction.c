//
//  ZNTransaction.c
//  zinc
//
//  Created by Aaron Voisine on 8/31/15.
//

#include "ZNTransaction.h"
#include "ZNArray.h"
#include "ZNRefCount.h"
#include "ZNCrypto.h"
#include <stdlib.h>
#include <limits.h>

#define ZN_TX_VERSION           0x00000001
#define ZN_LOCKTIME             0x00000000
#define ZN_SIGHASH_ALL          0x01 // default, sign all inputs and outputs
#define ZN_SIGHASH_NONE         0x02 // sign none of the outputs, I don't care where the funds go
#define ZN_SIGHASH_SINGLE       0x03 // sign one output corresponding to each input, I don't care where other outputs go
#define ZN_SIGHASH_ANYONECANPAY 0x80 // let others add inputs, I don't care where the rest of the funds come from
#define ZN_SIGHASH_FORKID       0x40 // use BIP143 digest method (for bch/bsv/btg signatures)

size_t ZNTxInputAddress(const ZNTxInput *input, char addr[75], ZNAddrParams params)
{
    size_t r = ZNAddressFromScriptPubKey(addr, params, input->scriptPubKey, input->scriptPKLen);
    
    if (r == 0) r = ZNAddressFromScriptSig(addr, params, input->scriptSig, input->sigLen);
    if (r == 0) r = ZNAddressFromWitness(addr, params, input->witness, input->witLen);
    return r;
}

void ZNTxInputSetAddress(ZNTxInput *input, const char *addr, ZNAddrParams params)
{
    assert(input != NULL);
    assert(addr == NULL || ZNAddressIsValid(addr, params));
    if (input->scriptPubKey) zn_array_free(input->scriptPubKey);
    input->scriptPubKey = NULL;
    input->scriptPKLen = 0;

    if (addr) {
        input->scriptPubKey = zn_array_new(sizeof(*input->scriptPubKey), 42);
        input->scriptPKLen = ZNAddressScriptPubKey(input->scriptPubKey, addr, params);
        zn_array_set_count(input->scriptPubKey, input->scriptPKLen);
    }
}

void ZNTxInputSetScriptPubKey(ZNTxInput *input, const uint8_t *scriptPubKey, size_t scriptPKLen)
{
    assert(input != NULL);
    assert(scriptPubKey != NULL || scriptPKLen == 0);
    if (input->scriptPubKey) zn_array_free(input->scriptPubKey);
    input->scriptPubKey = NULL;
    input->scriptPKLen = 0;
    
    if (scriptPubKey) {
        input->scriptPKLen = scriptPKLen;
        input->scriptPubKey = zn_array_new(sizeof(*input->scriptPubKey), scriptPKLen);
        zn_array_add_array(input->scriptPubKey, scriptPubKey, scriptPKLen);
    }
}

void ZNTxInputSetScriptSig(ZNTxInput *input, const uint8_t *scriptSig, size_t sigLen)
{
    assert(input != NULL);
    assert(scriptSig != NULL || sigLen == 0);
    if (input->scriptSig) zn_array_free(input->scriptSig);
    input->scriptSig = NULL;
    input->sigLen = 0;
    
    if (scriptSig) {
        input->sigLen = sigLen;
        input->scriptSig = zn_array_new(sizeof(*input->scriptSig), sigLen);
        zn_array_add_array(input->scriptSig, scriptSig, sigLen);
    }
}

void ZNTxInputSetWitness(ZNTxInput *input, const uint8_t *witness, size_t witLen)
{
    assert(input != NULL);
    assert(witness != NULL || witLen == 0);
    if (input->witness) zn_array_free(input->witness);
    input->witness = NULL;
    input->witLen = 0;
    
    if (witness) {
        input->witLen = witLen;
        input->witness = zn_array_new(sizeof(*input->witness), witLen);
        zn_array_add_array(input->witness, witness, witLen);
    }
}

// serializes a tx input for a signature pre-image
// set input->amount to 0 to skip serializing the input amount in non-witness signatures
static void _ZNTxInputDataSet(uint8_t *data, size_t dataLen, const ZNTxInput *input, size_t *off)
{
    ZNDataSet(data, dataLen, input->txHash, sizeof(input->txHash), off); // previous out
    ZNUInt32Set(data, dataLen, input->index, off);
    ZNVarIntSet(data, dataLen, input->sigLen, off);
    ZNDataSet(data, dataLen, input->scriptSig, input->sigLen, off); // scriptSig
    if (input->amount != 0) ZNUInt64Set(data, dataLen, input->amount, off);
    ZNUInt32Set(data, dataLen, input->sequence, off);
}

size_t ZNTxOutputAddress(const ZNTxOutput *output, char addr[75], ZNAddrParams params)
{
    return ZNAddressFromScriptPubKey(addr, params, output->scriptPubKey, output->scriptPKLen);
}

void ZNTxOutputSetAddress(ZNTxOutput *output, const char *addr, ZNAddrParams params)
{
    assert(output != NULL);
    assert(addr == NULL || ZNAddressIsValid(addr, params));
    if (output->scriptPubKey) zn_array_free(output->scriptPubKey);
    output->scriptPubKey = NULL;
    output->scriptPKLen = 0;

    if (addr) {
        output->scriptPubKey = zn_array_new(sizeof(*output->scriptPubKey), 42);
        output->scriptPKLen = ZNAddressScriptPubKey(output->scriptPubKey, addr, params);
        zn_array_set_count(output->scriptPubKey, output->scriptPKLen);
    }
}

void ZNTxOutputSetScriptPubKey(ZNTxOutput *output, const uint8_t *scriptPubKey, size_t scriptPKLen)
{
    assert(output != NULL);
    if (output->scriptPubKey) zn_array_free(output->scriptPubKey);
    output->scriptPubKey = NULL;
    output->scriptPKLen = 0;

    if (scriptPubKey) {
        output->scriptPKLen = scriptPKLen;
        output->scriptPubKey = zn_array_new(sizeof(*output->scriptPubKey), scriptPKLen);
        zn_array_add_array(output->scriptPubKey, scriptPubKey, scriptPKLen);
    }
}

// serializes the tx output at index for a signature pre-image
// an index of SIZE_MAX will serialize all tx outputs for SIGHASH_ALL signatures
static void _ZNTxOutputDataSet(uint8_t *data, size_t dataLen, const ZNTransaction *tx, size_t index, size_t *off)
{
    size_t i;
    
    for (i = (index == SIZE_MAX ? 0 : index); i < tx->outCount && (index == SIZE_MAX || index == i); i++) {
        ZNUInt64Set(data, dataLen, tx->outputs[i].amount, off);
        ZNVarIntSet(data, dataLen, tx->outputs[i].scriptPKLen, off);
        ZNDataSet(data, dataLen, tx->outputs[i].scriptPubKey, tx->outputs[i].scriptPKLen, off);
    }
}

// writes the BIP143 witness program data that needs to be hashed and signed for the tx input at index
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
// returns number of bytes written, or total len needed if data is NULL
static size_t _ZNTxWitnessData(const ZNTransaction *tx, uint8_t *data, size_t dataLen, size_t index, uint32_t hashType)
{
    ZNTxInput input;
    uint32_t anyoneCanPay = (hashType & ZN_SIGHASH_ANYONECANPAY), sigHash = (hashType & 0x1f);
    size_t i, o, bufLen, off = 0;
    uint8_t *buf, _buf[0x1000], hash[32];
    uint8_t scriptCode[] = { ZN_OP_DUP, ZN_OP_HASH160, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             ZN_OP_EQUALVERIFY, ZN_OP_CHECKSIG };

    if (index >= tx->inCount) return 0;
    ZNUInt32Set(data, dataLen, tx->version, &off); // tx version
    
    if (! anyoneCanPay) {
        bufLen = (sizeof(tx->inputs->txHash) + sizeof(tx->inputs->index))*tx->inCount;
        buf = (bufLen <= sizeof(_buf)) ? _buf : malloc(bufLen);
        
        for (i = 0, o = 0; i < tx->inCount; i++) {
            ZNDataSet(buf, bufLen, tx->inputs[i].txHash, sizeof(tx->inputs->txHash), &o);
            ZNUInt32Set(buf, bufLen, tx->inputs[i].index, &o);
        }
        
        ZNSHA256_2(hash, buf, bufLen);
        if (buf != _buf) free(buf);
    }
    else memset(hash, 0, sizeof(hash)); // anyone-can-pay

    ZNDataSet(data, dataLen, hash, sizeof(hash), &off); // inputs hash
    
    if (! anyoneCanPay && sigHash != ZN_SIGHASH_SINGLE && sigHash != ZN_SIGHASH_NONE) {
        bufLen = sizeof(uint32_t)*tx->inCount;
        buf = (bufLen <= sizeof(_buf)) ? _buf : malloc(bufLen);
        
        for (i = 0, o = 0; i < tx->inCount; i++) {
            ZNUInt32Set(buf, bufLen, tx->inputs[i].sequence, &o);
        }
        
        ZNSHA256_2(hash, buf, bufLen);
        if (buf != _buf) free(buf);
    }
    else memset(hash, 0, sizeof(hash));

    ZNDataSet(data, dataLen, hash, sizeof(hash), &off); // sequence hash
    
    input = tx->inputs[index];
    input.scriptSig = input.scriptPubKey; // TODO: handle OP_CODESEPARATOR
    input.sigLen = input.scriptPKLen;

    if (input.scriptPKLen == 22 && input.scriptPubKey[0] == ZN_OP_0 && input.scriptPubKey[1] == 20) {//P2WPKH scriptCode
        memcpy(scriptCode + 3, input.scriptPubKey + 2, 20);
        input.scriptSig = scriptCode;
        input.sigLen = sizeof(scriptCode);
    }

    _ZNTxInputDataSet(data, dataLen, &input, &off);
    o = bufLen = 0;
    
    if (sigHash != ZN_SIGHASH_SINGLE && sigHash != ZN_SIGHASH_NONE) { // SIGHASH_ALL
        _ZNTxOutputDataSet(NULL, 0, tx, SIZE_MAX, &bufLen);
        buf = (bufLen <= sizeof(_buf)) ? _buf : malloc(bufLen);
        _ZNTxOutputDataSet(buf, bufLen, tx, SIZE_MAX, &o);
        ZNSHA256_2(hash, buf, bufLen);
        if (buf != _buf) free(buf);
    }
    else if (sigHash == ZN_SIGHASH_SINGLE && index < tx->outCount) { // SIGHASH_SINGLE
        _ZNTxOutputDataSet(NULL, 0, tx, index, &bufLen);
        buf = (bufLen <= sizeof(_buf)) ? _buf : malloc(bufLen);
        _ZNTxOutputDataSet(buf, bufLen, tx, index, &o);
        ZNSHA256_2(hash, buf, bufLen);
        if (buf != _buf) free(buf);
    }
    else memset(hash, 0, sizeof(hash)); // SIGHASH_NONE
    
    ZNDataSet(data, dataLen, hash, sizeof(hash), &off); // outputs hash
    
    ZNUInt32Set(data, dataLen, tx->lockTime, &off); // locktime
    ZNUInt32Set(data, dataLen, hashType, &off); // hash type
    return (! data || off <= dataLen) ? off : 0;
}

// writes the data that needs to be hashed and signed for the tx input at index
// an index of SIZE_MAX will write the entire signed transaction
// returns number of bytes written, or total dataLen needed if data is NULL
static size_t _ZNTxData(const ZNTransaction *tx, uint8_t *data, size_t dataLen, size_t index, uint32_t hashType)
{
    ZNTxInput input;
    uint32_t anyoneCanPay = (hashType & ZN_SIGHASH_ANYONECANPAY), sigHash = (hashType & 0x1f), witnessFlag = 0;
    size_t i, count, woff, off = 0;
    
    if (hashType & ZN_SIGHASH_FORKID) return _ZNTxWitnessData(tx, data, dataLen, index, hashType);
    if (anyoneCanPay && index >= tx->inCount) return 0;
    
    for (i = 0; index == SIZE_MAX && ! witnessFlag && i < tx->inCount; i++) {
        if (tx->inputs[i].witLen > 0) witnessFlag = 1;
    }
    
    ZNUInt32Set(data, dataLen, tx->version, &off); // tx version
    
    if (! anyoneCanPay) {
        if (witnessFlag) ZNUInt16Set(data, dataLen, (uint16_t)(witnessFlag << 8), &off);
        ZNVarIntSet(data, dataLen, tx->inCount, &off);
        
        for (i = 0; i < tx->inCount; i++) { // inputs
            input = tx->inputs[i];

            if (index == i || (index == SIZE_MAX && ! tx->inputs[i].scriptSig)) {
                input.scriptSig = input.scriptPubKey; // TODO: handle OP_CODESEPARATOR
                input.sigLen = input.scriptPKLen;
                if (index == i) input.amount = 0;
            }
            else if (index != SIZE_MAX) {
                input.sigLen = 0;
                if (sigHash == ZN_SIGHASH_NONE || sigHash == ZN_SIGHASH_SINGLE) input.sequence = 0;
                input.amount = 0;
            }
            else input.amount = 0;
            
            _ZNTxInputDataSet(data, dataLen, &input, &off);
        }
    }
    else {
        ZNVarIntSet(data, dataLen, 1, &off);
        input = tx->inputs[index];
        input.scriptSig = input.scriptPubKey; // TODO: handle OP_CODESEPARATOR
        input.sigLen = input.scriptPKLen;
        input.amount = 0;
        _ZNTxInputDataSet(data, dataLen, &input, &off);
    }
    
    if (sigHash != ZN_SIGHASH_SINGLE && sigHash != ZN_SIGHASH_NONE) { // SIGHASH_ALL outputs
        ZNVarIntSet(data, dataLen, tx->outCount, &off);
        _ZNTxOutputDataSet(data, dataLen, tx, SIZE_MAX, &off);
    }
    else if (sigHash == ZN_SIGHASH_SINGLE && index < tx->outCount) { // SIGHASH_SINGLE outputs
        ZNVarIntSet(data, dataLen, index + 1, &off);

        for (i = 0; i < index; i++) {
            ZNUInt64Set(data, dataLen, (uint32_t)-1L, &off);
            ZNVarIntSet(data, dataLen, 0, &off);
        }
        
        _ZNTxOutputDataSet(data, dataLen, tx, index, &off);
    }
    else ZNVarIntSet(data, dataLen, 0, &off); // SIGHASH_NONE outputs
    
    for (i = 0; witnessFlag && i < tx->inCount; i++) { // witness data
        for (count = 0, woff = 0; woff < tx->inputs[i].witLen; count++) {
            woff += (size_t)ZNVarInt(tx->inputs[i].witness, tx->inputs[i].witLen, &woff);
        }

        ZNVarIntSet(data, dataLen, count, &off);
        ZNDataSet(data, dataLen, tx->inputs[i].witness, tx->inputs[i].witLen, &off);
    }
    
    ZNUInt32Set(data, dataLen, tx->lockTime, &off); // locktime
    if (index != SIZE_MAX) ZNUInt32Set(data, dataLen, hashType, &off); // hash type
    return (! data || off <= dataLen) ? off : 0;
}

// frees memory allocated for tx
static void _ZNTransactionFree(void *ptr)
{
    ZNTransaction *tx = ptr;
    size_t i;
    
    assert(tx != NULL);
    
    if (tx) {
        for (i = 0; i < tx->inCount; i++) {
            ZNTxInputSetScriptPubKey(tx->inputs + i, NULL, 0);
            ZNTxInputSetScriptSig(tx->inputs + i, NULL, 0);
            ZNTxInputSetWitness(tx->inputs + i, NULL, 0);
        }

        for (i = 0; i < tx->outCount; i++) {
            ZNTxOutputSetScriptPubKey(tx->outputs + i, NULL, 0);
        }

        zn_array_free(tx->outputs);
        zn_array_free(tx->inputs);
        zn_ref_free(tx);
    }
}

// returns a new reference counted empty transaction that must be released by calling zn_ref_release()
ZNTransaction *ZNTransactionNew(void)
{
    ZNTransaction *tx = zn_ref_new(sizeof(*tx), _ZNTransactionFree);

    tx->version = ZN_TX_VERSION;
    tx->inputs = zn_array_new(sizeof(*tx->inputs), 1);
    tx->outputs = zn_array_new(sizeof(*tx->outputs), 1);
    tx->lockTime = ZN_LOCKTIME;
    tx->blockHeight = ZN_UNCONFIRMED;
    return tx;
}

// buf must contain a serialized tx
// retruns a reference counted transaction that must be released by calling zn_ref_release()
ZNTransaction *ZNTransactionParse(const uint8_t *buf, size_t bufLen, size_t *off)
{
    int isSigned = 1, witnessFlag = 0;
    uint8_t _txBuf[0x1000], *txBuf;
    size_t i, j, count, len, txLen, txOff = 0, o = off ? *off : 0;
    ZNTransaction *tx = ZNTransactionNew();
 
    assert(buf != NULL || bufLen == 0);
    tx->version = ZNUInt32(buf, bufLen, &o);
    tx->inCount = (size_t)ZNVarInt(buf, bufLen, &o);
    if (tx->inCount == 0) witnessFlag = ZNUInt8(buf, bufLen, &o);
    if (witnessFlag) tx->inCount = (size_t)ZNVarInt(buf, bufLen, &o);
    if (o + tx->inCount*(sizeof(tx->inputs->txHash) + sizeof(uint32_t)*2 + 1) > bufLen) tx->inCount = 0;
    zn_array_set_count(tx->inputs, tx->inCount);
    
    for (i = 0; o <= bufLen && i < tx->inCount; i++) {
        ZNData(tx->inputs[i].txHash, sizeof(tx->inputs[i].txHash), buf, bufLen, &o);
        tx->inputs[i].index = ZNUInt32(buf, bufLen, &o);
        len = (size_t)ZNVarInt(buf, bufLen, &o);
        
        if (o + len <= bufLen && ZNScriptPubKeyIsValid(buf + o, len)) {
            ZNTxInputSetScriptPubKey(tx->inputs + i, ZNData(NULL, len, buf, bufLen, &o), len);
            tx->inputs[i].amount = ZNUInt64(buf, bufLen, &o);
            isSigned = 0;
        }
        else ZNTxInputSetScriptSig(tx->inputs + i, ZNData(NULL, len, buf, bufLen, &o), len);
        
        if (! witnessFlag) ZNTxInputSetWitness(tx->inputs + i, buf + o, 0); // set witness to empty byte array
        tx->inputs[i].sequence = ZNUInt32(buf, bufLen, &o);
    }
    
    tx->outCount = (size_t)ZNVarInt(buf, bufLen, &o);
    if (o + tx->outCount*(sizeof(tx->outputs->amount) + 1) > bufLen) tx->outCount = 0;
    zn_array_set_count(tx->outputs, tx->outCount);
    
    for (i = 0; o <= bufLen && i < tx->outCount; i++) {
        tx->outputs[i].amount = ZNUInt64(buf, bufLen, &o);
        len = (size_t)ZNVarInt(buf, bufLen, &o);
        ZNTxOutputSetScriptPubKey(tx->outputs + i, ZNData(NULL, len, buf, bufLen, &o), len);
    }
    
    txLen = (o - 2) + sizeof(uint32_t); // tx length without witness data
    
    for (i = 0; witnessFlag && o <= bufLen && i < tx->inCount; i++) {
        count = (size_t)ZNVarInt(buf, bufLen, &o);

        for (j = 0, len = 0; j < count && o + len <= bufLen; j++) {
            len += (size_t)ZNVarInt(buf + o, bufLen - o, &len);
        }

        ZNTxInputSetWitness(tx->inputs + i, ZNData(NULL, len, buf, bufLen, &o), len);
    }
    
    tx->lockTime = ZNUInt32(buf, bufLen, &o);
    
    if (tx->inCount == 0 || tx->outCount == 0 || o > bufLen) {
        zn_ref_release(tx);
        tx = NULL;
    }
    else if (isSigned && witnessFlag) {
        ZNSHA256_2(tx->wtxHash, buf, o);
        txBuf = (txLen <= sizeof(_txBuf)) ? _txBuf : malloc(txLen);
        ZNUInt32Set(txBuf, txLen, tx->version, &txOff);
        ZNDataSet(txBuf, txLen, buf + txOff + 2, txLen - txOff, &txOff);
        ZNUInt32Set(txBuf, txLen, tx->lockTime, &txOff);
        ZNSHA256_2(tx->txHash, txBuf, txLen);
        if (txBuf != _txBuf) free(txBuf);
    }
    else if (isSigned) {
        ZNSHA256_2(tx->txHash, buf, o);
        memcpy(tx->wtxHash, tx->txHash, sizeof(tx->txHash));
    }
    
    if (off) *off = o;
    return tx;
}

// returns number of bytes written to buf, or total bufLen needed if buf is NULL
// (tx->blockHeight and tx->timestamp are not serialized)
size_t ZNTransactionSerialize(const ZNTransaction *tx, uint8_t *buf, size_t bufLen)
{
    assert(tx != NULL);
    return (tx) ? _ZNTxData(tx, buf, bufLen, SIZE_MAX, ZN_SIGHASH_ALL) : 0;
}

// adds an input to tx
void ZNTransactionAddInput(ZNTransaction *tx, const uint8_t txHash[32], uint32_t index, uint64_t amount,
                           const uint8_t *scriptPubKey, size_t scriptPKLen, const uint8_t *scriptSig, size_t sigLen,
                           const uint8_t *witness, size_t witLen, uint32_t sequence)
{
    ZNTxInput input = { zn_hash_const(txHash), index, amount, NULL, 0, NULL, 0, NULL, 0, sequence };

    assert(tx != NULL);
    assert(txHash != NULL);
    assert(scriptPubKey != NULL || scriptPKLen == 0);
    assert(scriptSig != NULL || sigLen == 0);
    assert(witness != NULL || witLen == 0);
    
    if (tx && txHash) {
        if (scriptPubKey) ZNTxInputSetScriptPubKey(&input, scriptPubKey, scriptPKLen);
        if (scriptSig) ZNTxInputSetScriptSig(&input, scriptSig, sigLen);
        if (witness) ZNTxInputSetWitness(&input, witness, witLen);
        zn_array_add(tx->inputs, input);
        tx->inCount = zn_array_count(tx->inputs);
    }
}

// adds an output to tx
void ZNTransactionAddOutput(ZNTransaction *tx, uint64_t amount, const uint8_t *scriptPubKey, size_t scriptPKLen)
{
    ZNTxOutput output = ZN_TX_OUTPUT_NONE;
    
    assert(tx != NULL);
    assert(scriptPubKey != NULL || scriptPKLen == 0);
    
    if (tx) {
        output.amount = amount;
        ZNTxOutputSetScriptPubKey(&output, scriptPubKey, scriptPKLen);
        zn_array_add(tx->outputs, output);
        tx->outCount = zn_array_count(tx->outputs);
    }
}

// shuffles order of tx outputs
void ZNTransactionShuffleOutputs(ZNTransaction *tx)
{
    ZNTxOutput t;
    size_t i, j;
    
    assert(tx != NULL);
    
    for (i = 0; tx && i + 1 < tx->outCount; i++) { // fischer-yates shuffle
        j = i + (size_t)ZNRand(tx->outCount - i);
        
        if (j != i) {
            t = tx->outputs[i];
            tx->outputs[i] = tx->outputs[j];
            tx->outputs[j] = t;
        }
    }
}

// size in bytes if signed, or estimated size assuming compact pubkey sigs, using non-segwit encoding
static size_t _ZNTxSize(const ZNTransaction *tx, size_t *witSize)
{
    static const size_t inSize = sizeof(tx->txHash) + sizeof(tx->inputs->index) + sizeof(tx->inputs->sequence);
    size_t i, size;

    assert(tx != NULL);
    size = (tx) ? 8 + ZNVarIntSize(tx->inCount) + ZNVarIntSize(tx->outCount) : 0;
    *witSize = 0;
    
    for (i = 0; tx && i < tx->inCount; i++) {
        if (tx->inputs[i].scriptSig && tx->inputs[i].witness) {
            size += ZNVarIntSize(tx->inputs[i].sigLen) + tx->inputs[i].sigLen + inSize;
            *witSize += tx->inputs[i].witLen;
        }
        else if (tx->inputs[i].scriptPubKey && tx->inputs[i].scriptPKLen > 0 &&
                 tx->inputs[i].scriptPubKey[0] == ZN_OP_0) { // estimated P2WPKH input size
            size += ZNVarIntSize(0) + inSize;
            *witSize += ZN_INPUT_SIZE - (ZNVarIntSize(0) + inSize);
        }
        else size += ZN_INPUT_SIZE; // estimated P2PKH input size
    }
    
    for (i = 0; tx && i < tx->outCount; i++) {
        size += sizeof(tx->outputs->amount) + ZNVarIntSize(tx->outputs[i].scriptPKLen) + tx->outputs[i].scriptPKLen;
    }
    
    if (tx && *witSize > 0) *witSize += 2 + tx->inCount;
    return size;
}


// size in bytes if signed, or estimated size assuming compact pubkey sigs
size_t ZNTransactionSize(const ZNTransaction *tx)
{
    size_t witSize, size = _ZNTxSize(tx, &witSize);

    return size + witSize;
}

// virtual transaction size as defined by BIP141: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
size_t ZNTransactionVSize(const ZNTransaction *tx)
{
    size_t witSize, size = _ZNTxSize(tx, &witSize);

    return (size*4 + witSize + 3)/4;
}

// checks if all signatures exist, but does not verify them
int ZNTransactionIsSigned(const ZNTransaction *tx)
{
    size_t i;
    
    assert(tx != NULL);
    
    for (i = 0; tx && i < tx->inCount; i++) {
        if (! tx->inputs[i].scriptSig || ! tx->inputs[i].witness) return 0;
    }

    return (tx) ? 1 : 0;
}

// adds signatures to any inputs with NULL signatures that can be signed with any keys
// forkId is 0 for bitcoin, 0x40 for bch/bsv, 0x4f for btg
// returns true if tx is signed
int ZNTransactionSign(ZNTransaction *tx, uint8_t forkId, ZNKey keys[], size_t keysCount)
{
    ZNTransaction *t;
    uint8_t _data[0x1000], *data, pubKey[65], sig[73], script[1 + 73 + 1 + 65], md[32], pkh[keysCount][20];
    const uint8_t *hash, *_elems[0x100], **elems = _elems;
    size_t i, j, dataLen, sigLen, scriptLen, pkLen, elemsCount;
    
    assert(tx != NULL);
    assert(keys != NULL || keysCount == 0);
    
    for (i = 0; tx && i < keysCount; i++) {
        ZNKeyHash160(keys + i, pkh[i]);
    }
    
    for (i = 0; tx && i < tx->inCount; i++) {
        hash = ZNScriptPubKeyPKH(tx->inputs[i].scriptPubKey, tx->inputs[i].scriptPKLen);
        j = 0;
        while (j < keysCount && (! hash || memcmp(pkh[j], hash, sizeof(*pkh)) != 0)) j++;
        if (j >= keysCount) continue;
        pkLen = ZNKeyPubKey(keys + j, pubKey);
        elemsCount = ZNScriptElements(elems, 0x100, tx->inputs[i].scriptPubKey, tx->inputs[i].scriptPKLen);

        if (elemsCount > 0x100) {
            elems = malloc(elemsCount*sizeof(*elems));
            ZNScriptElements(elems, elemsCount, tx->inputs[i].scriptPubKey, tx->inputs[i].scriptPKLen);
        }
        
        if (elemsCount == 2 && *elems[0] == ZN_OP_0 && *elems[1] == 20) { // pay-to-witness-pubkey-hash
            dataLen = _ZNTxWitnessData(tx, NULL, 0, i, forkId | ZN_SIGHASH_ALL);
            data = (dataLen <= sizeof(_data)) ? _data : malloc(dataLen);
            dataLen = _ZNTxWitnessData(tx, data, dataLen, i, forkId | ZN_SIGHASH_ALL);
            ZNSHA256_2(md, data, dataLen);
            sigLen = ZNKeySign(keys + j, sig, md);
            sig[sigLen++] = forkId | ZN_SIGHASH_ALL;
            scriptLen = ZNScriptPushData(script, sizeof(script), sig, sigLen);
            scriptLen += ZNScriptPushData(script + scriptLen, sizeof(script) - scriptLen, pubKey, pkLen);
            ZNTxInputSetScriptSig(tx->inputs + i, script, 0);
            ZNTxInputSetWitness(tx->inputs + i, script, scriptLen);
        }
        else if (elemsCount >= 2 && *elems[elemsCount - 2] == ZN_OP_EQUALVERIFY) { // pay-to-pubkey-hash
            dataLen = _ZNTxData(tx, NULL, 0, i, forkId | ZN_SIGHASH_ALL);
            data = (dataLen <= sizeof(_data)) ? _data : malloc(dataLen);
            dataLen = _ZNTxData(tx, data, dataLen, i, forkId | ZN_SIGHASH_ALL);
            ZNSHA256_2(md, data, dataLen);
            sigLen = ZNKeySign(keys + j, sig, md);
            sig[sigLen++] = forkId | ZN_SIGHASH_ALL;
            scriptLen = ZNScriptPushData(script, sizeof(script), sig, sigLen);
            scriptLen += ZNScriptPushData(script + scriptLen, sizeof(script) - scriptLen, pubKey, pkLen);
            ZNTxInputSetScriptSig(tx->inputs + i, script, scriptLen);
            ZNTxInputSetWitness(tx->inputs + i, script, 0);
        }
        else { // pay-to-pubkey
            dataLen = _ZNTxData(tx, NULL, 0, i, forkId | ZN_SIGHASH_ALL);
            data = (dataLen <= sizeof(_data)) ? _data : malloc(dataLen);
            dataLen = _ZNTxData(tx, data, dataLen, i, forkId | ZN_SIGHASH_ALL);
            ZNSHA256_2(md, data, dataLen);
            sigLen = ZNKeySign(keys + j, sig, md);
            sig[sigLen++] = forkId | ZN_SIGHASH_ALL;
            scriptLen = ZNScriptPushData(script, sizeof(script), sig, sigLen);
            ZNTxInputSetScriptSig(tx->inputs + i, script, scriptLen);
            ZNTxInputSetWitness(tx->inputs + i, script, 0);
        }
        
        if (elems != _elems) free(elems);
        if (data != _data) free(data);
    }
    
    if (tx && ZNTransactionIsSigned(tx)) {
        dataLen = ZNTransactionSerialize(tx, NULL, 0);
        data = (dataLen <= sizeof(_data)) ? _data : malloc(dataLen);
        dataLen = ZNTransactionSerialize(tx, data, dataLen);
        t = ZNTransactionParse(data, dataLen, NULL);
        if (data != _data) free(data);
        
        if (t) {
            memcpy(tx->txHash, t->txHash, sizeof(tx->txHash));
            memcpy(tx->wtxHash, t->wtxHash, sizeof(tx->wtxHash));
            zn_ref_release(t);
        }

        return 1;
    }
    else return 0;
}

// outputs below this amount are uneconomical due to fees (ZN_MIN_OUTPUT_AMT is the minimum relayable output amount)
uint64_t ZNMinOutputAmount(uint64_t feePerKb)
{
    uint64_t amount = ZNFeeForTxVSize(feePerKb, (ZN_OUTPUT_SIZE + ZN_INPUT_SIZE)*2);
    
    return (amount > ZN_MIN_OUTPUT_AMT) ? amount : ZN_MIN_OUTPUT_AMT;
}

// fee added for a transaction of the given virtual size
uint64_t ZNFeeForTxVSize(uint64_t feePerKb, size_t vsize)
{
    uint64_t standardFee = vsize*ZN_FEE_PER_KB/1000,                 // standard fee based on tx vsize
             fee = ((((uint64_t)vsize*feePerKb/1000) + 99)/100)*100; // fee using feePerKb, rounded up to nearest 100sat
    
    return (fee > standardFee) ? fee : standardFee;
}
