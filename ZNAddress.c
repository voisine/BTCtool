//
//  ZNAddress.c
//  zinc
//
//  Created by Aaron Voisine on 9/18/15.
//

#include "ZNAddress.h"
#include "ZNBase58.h"
#include "ZNBech32m.h"
#include "ZNCrypto.h"
#include <inttypes.h>
#include <assert.h>

#define ZN_VAR_INT16 0xfd
#define ZN_VAR_INT32 0xfe
#define ZN_VAR_INT64 0xff
#define ZN_MAX_SCRIPT_LEN 520 // scripts over this size will not be parsed for an address

// reads a uint8_t from buf at offset off and stores the new offset in off
uint8_t ZNUInt8(const uint8_t *buf, size_t bufLen, size_t *off)
{
    uint8_t r = (buf && *off + sizeof(r) <= bufLen) ? buf[*off] : 0;
    
    *off += sizeof(r);
    return r;
}

// writes a uint8_t to buf at offset off and stores the new offset in off
void ZNUInt8Set(uint8_t *buf, size_t bufLen, uint8_t u, size_t *off)
{
    if (buf && *off + sizeof(u) <= bufLen) buf[*off] = u;
    *off += sizeof(u);
}

// reads a uint16_t from buf at offset off and stores the new buf offset in off
uint16_t ZNUInt16(const uint8_t *buf, size_t bufLen, size_t *off)
{
    uint16_t r = (buf && *off + sizeof(r) <= bufLen) ? zn_le16(buf + *off) : 0;
    
    *off += sizeof(r);
    return r;
}

// writes a uint16_t to buf at offset off and stores the new offset in off
void ZNUInt16Set(uint8_t *buf, size_t bufLen, uint16_t u, size_t *off)
{
    if (buf && *off + sizeof(u) <= bufLen) zn_le16set(buf + *off, u);
    *off += sizeof(u);
}

// reads a uint32_t from buf at offset off and stores the new buf offset in off
uint32_t ZNUInt32(const uint8_t *buf, size_t bufLen, size_t *off)
{
    uint32_t r = (buf && *off + sizeof(r) <= bufLen) ? zn_le32(buf + *off) : 0;
    
    *off += sizeof(r);
    return r;
}

// writes a uint32_t to buf at offset off and stores the new offset in off
void ZNUInt32Set(uint8_t *buf, size_t bufLen, uint32_t u, size_t *off)
{
    if (buf && *off + sizeof(u) <= bufLen) zn_le32set(buf + *off, u);
    *off += sizeof(u);
}

// reads a uint64_t from buf at offset off and stores the new buf offset in off
uint64_t ZNUInt64(const uint8_t *buf, size_t bufLen, size_t *off)
{
    uint64_t r = (buf && *off + sizeof(r) <= bufLen) ? zn_le64(buf + *off) : 0;
    
    *off += sizeof(r);
    return r;
}

// writes a uint64_t to buf at offset off and stores the new offset in off
void ZNUInt64Set(uint8_t *buf, size_t bufLen, uint64_t u, size_t *off)
{
    if (buf && *off + sizeof(u) <= bufLen) zn_le64set(buf + *off, u);
    *off += sizeof(u);
}

// reads a varint from buf at offset off and stores the new offset in off
uint64_t ZNVarInt(const uint8_t *buf, size_t bufLen, size_t *off)
{
    uint64_t r = 0;
    uint8_t h = ZNUInt8(buf, bufLen, off);
    
    switch (h) {
        case ZN_VAR_INT16: r = ZNUInt16(buf, bufLen, off); break;
        case ZN_VAR_INT32: r = ZNUInt32(buf, bufLen, off); break;
        case ZN_VAR_INT64: r = ZNUInt64(buf, bufLen, off); break;
        default: r = h; break;
    }
    
    return r;
}

// writes i to buf as a varint at offset off and stores the new offset in off
void ZNVarIntSet(uint8_t *buf, size_t bufLen, uint64_t i, size_t *off)
{
    if (i < ZN_VAR_INT16) {
        ZNUInt8Set(buf, bufLen, (uint8_t)i, off);
    }
    else if (i <= UINT16_MAX) {
        ZNUInt8Set(buf, bufLen, ZN_VAR_INT16, off);
        ZNUInt16Set(buf, bufLen, (uint16_t)i, off);
    }
    else if (i <= UINT32_MAX) {
        ZNUInt8Set(buf, bufLen, ZN_VAR_INT32, off);
        ZNUInt32Set(buf, bufLen, (uint32_t)i, off);
    }
    else {
        ZNUInt8Set(buf, bufLen, ZN_VAR_INT64, off);
        ZNUInt64Set(buf, bufLen, i, off);
    }
}

// returns the number of bytes needed to encode i as a varint
size_t ZNVarIntSize(uint64_t i)
{
    size_t off = 0;
    
    ZNVarIntSet(NULL, 0, i, &off);
    return off;
}

// reads dataLen bytes from buf at offset off and writes them to data unless data is NULL
// stores the new offset in off and returns a pointer to the bytes read from buf
const uint8_t *ZNData(uint8_t *data, size_t dataLen, const uint8_t *buf, size_t bufLen, size_t *off)
{
    const uint8_t *r = (buf && *off + dataLen <= bufLen) ? buf + *off : NULL;
    
    if (data && r) memcpy(data, r, dataLen);
    *off += dataLen;
    return r;
}

// writes dataLen bytes from data to buf at offset off and stores the new offset in off
void ZNDataSet(uint8_t *buf, size_t bufLen, const uint8_t *data, size_t dataLen, size_t *off)
{
    if (buf && *off + dataLen <= bufLen && data) memcpy(buf + *off, data, dataLen);
    *off += dataLen;
}

// parses script and writes an array of pointers to the script elements (opcodes and data pushes) to elems
// returns the total number of elements contained in script
size_t ZNScriptElements(const uint8_t *elems[], size_t elemsCount, const uint8_t *script, size_t scriptLen)
{
    size_t off = 0, i = 0, len = 0;
    
    assert(script != NULL || scriptLen == 0);
    
    while (script && off < scriptLen) {
        if (elems && i < elemsCount) elems[i] = script + off;
        len = ZNUInt8(script, scriptLen, &off);
        
        switch (len) {
            case ZN_OP_PUSHDATA1: len = ZNUInt8(script, scriptLen, &off); break;
            case ZN_OP_PUSHDATA2: len = ZNUInt16(script, scriptLen, &off); break;
            case ZN_OP_PUSHDATA4: len = ZNUInt32(script, scriptLen, &off); break;
            default: if (len > ZN_OP_PUSHDATA4) len = 0; break;
        }
        
        off += len;
        i++;
    }
        
    return i;
}

// given a data push script element, returns a pointer to the start of the data and writes its length to dataLen
const uint8_t *ZNScriptData(const uint8_t *elem, size_t *dataLen)
{
    assert(elem != NULL);
    assert(dataLen != NULL);
    if (! elem || ! dataLen) return NULL;
    
    switch (*elem) {
        case ZN_OP_PUSHDATA1:
            elem++;
            *dataLen = *elem;
            elem += sizeof(uint8_t);
            break;
            
        case ZN_OP_PUSHDATA2:
            elem++;
            *dataLen = zn_le16(elem);
            elem += sizeof(uint16_t);
            break;
            
        case ZN_OP_PUSHDATA4:
            elem++;
            *dataLen = zn_le32(elem);
            elem += sizeof(uint32_t);
            break;
            
        default:
            *dataLen = (*elem > ZN_OP_PUSHDATA4) ? 0 : *elem;
            elem++;
            break;
    }
    
    return (*dataLen > 0) ? elem : NULL;
}

// writes a data push script element to script
// returns the number of bytes written, or scriptLen needed if script is NULL
size_t ZNScriptPushData(uint8_t *script, size_t scriptLen, const uint8_t *data, size_t dataLen)
{
    size_t len = dataLen;

    assert(data != NULL || dataLen == 0);
    if (data == NULL && dataLen != 0) return 0;
    
    if (dataLen < ZN_OP_PUSHDATA1) {
        len += 1;
        if (script && len <= scriptLen) script[0] = dataLen & 0xff;
    }
    else if (dataLen < UINT8_MAX) {
        len += 1 + sizeof(uint8_t);
        
        if (script && len <= scriptLen) {
            script[0] = ZN_OP_PUSHDATA1;
            script[1] = dataLen & 0xff;
        }
    }
    else if (dataLen < UINT16_MAX) {
        len += 1 + sizeof(uint16_t);
        
        if (script && len <= scriptLen) {
            script[0] = ZN_OP_PUSHDATA2;
            zn_le16set(script + 1, dataLen);
        }
    }
    else {
        len += 1 + sizeof(uint32_t);
        
        if (script && len <= scriptLen) {
            script[0] = ZN_OP_PUSHDATA4;
            zn_le32set(script + 1, (uint32_t)dataLen);
        }
    }
    
    if (script && len <= scriptLen) memcpy(script + len - dataLen, data, dataLen);
    return (! script || len <= scriptLen) ? len : 0;
}

// returns true if script contains a known valid scriptPubKey
int ZNScriptPubKeyIsValid(const uint8_t *script, size_t scriptLen)
{
    const uint8_t *elems[ZN_MAX_SCRIPT_LEN];
    size_t count;
    int r = 0;

    assert(script != NULL || scriptLen == 0);
    if (! script || scriptLen == 0 || scriptLen > ZN_MAX_SCRIPT_LEN) return 0;
    count = ZNScriptElements(elems, sizeof(elems)/sizeof(*elems), script, scriptLen);
    
    if (count == 5 && *elems[0] == ZN_OP_DUP && *elems[1] == ZN_OP_HASH160 && *elems[2] == 20 &&
        *elems[3] == ZN_OP_EQUALVERIFY && *elems[4] == ZN_OP_CHECKSIG) {
        r = 1; // pay-to-pubkey-hash scriptPubKey
    }
    else if (count == 3 && *elems[0] == ZN_OP_HASH160 && *elems[1] == 20 && *elems[2] == ZN_OP_EQUAL) {
        r = 1; // pay-to-script-hash scriptPubKey
    }
    else if (count == 2 && (*elems[0] == 65 || *elems[0] == 33) && *elems[1] == ZN_OP_CHECKSIG) {
        r = 1; // pay-to-pubkey scriptPubKey
    }
    else if (count == 2 && ((*elems[0] == ZN_OP_0 && (*elems[1] == 20 || *elems[1] == 32)) ||
                            (*elems[0] >= ZN_OP_1 && *elems[0] <= ZN_OP_16 && *elems[1] >= 2 && *elems[1] <= 40))) {
        r = 1; // pay-to-witness scriptPubKey
    }
    
    return r;
}

// returns a pointer to the 20byte pubkey-hash, or NULL if none
const uint8_t *ZNScriptPubKeyPKH(const uint8_t *scriptPubKey, size_t scriptLen)
{
    const uint8_t *elems[ZN_MAX_SCRIPT_LEN], *r = NULL;
    size_t l, count;

    assert(scriptPubKey != NULL || scriptLen == 0);
    if (! scriptPubKey || scriptLen == 0 || scriptLen > ZN_MAX_SCRIPT_LEN) return NULL;
    count = ZNScriptElements(elems, sizeof(elems)/sizeof(*elems), scriptPubKey, scriptLen);
    
    if (count == 5 && *elems[0] == ZN_OP_DUP && *elems[1] == ZN_OP_HASH160 && *elems[2] == 20 &&
        *elems[3] == ZN_OP_EQUALVERIFY && *elems[4] == ZN_OP_CHECKSIG) {
        r = ZNScriptData(elems[2], &l); // pay-to-pubkey-hash
    }
    else if (count == 3 && *elems[0] == ZN_OP_HASH160 && *elems[1] == 20 && *elems[2] == ZN_OP_EQUAL) {
        r = ZNScriptData(elems[1], &l); // pay-to-script-hash
    }
    else if (count == 2 && (*elems[0] == ZN_OP_0 || (*elems[0] >= ZN_OP_1 && *elems[0] <= ZN_OP_16)) &&
             *elems[1] == 20) {
        r = ZNScriptData(elems[1], &l); // pay-to-witness
    }
    
    return r;
}

// writes the 20 byte pubkey hash from signature to pkh and returns the number of bytes written
size_t ZNScriptSigPKH(uint8_t pkh[20], const uint8_t *scriptSig, size_t sigLen)
{
    const uint8_t *d = NULL, *elems[ZN_MAX_SCRIPT_LEN];
    size_t count, r = 0, l = 0;

    assert(pkh != NULL);
    assert(scriptSig != NULL || sigLen == 0);
    if (! scriptSig || sigLen == 0 || sigLen > ZN_MAX_SCRIPT_LEN) return 0;
    count = ZNScriptElements(elems, sizeof(elems)/sizeof(*elems), scriptSig, sigLen);
    
    if (count == 2 && *elems[0] <= ZN_OP_PUSHDATA4 && (*elems[1] == 65 || *elems[1] == 33)) {
        // pay-to-pubkey-hash scriptSig
        d = ZNScriptData(elems[1], &l);
        if (l != 65 && l != 33) d = NULL;
        if (d) { ZNHash160(pkh, d, l); r = 20; }
    }
    else if (count >= 1 && *elems[count - 1] <= ZN_OP_PUSHDATA4 && *elems[count - 1] > 0 &&
             (count >= 2 || ((d = ZNScriptData(elems[0], &l)) &&
                             (d[0] == ZN_OP_0 || (d[0] >= ZN_OP_1 && d[0] <= ZN_OP_16))))) {
        // pay-to-script-hash scriptSig
        d = ZNScriptData(elems[count - 1], &l);
        if (d) { ZNHash160(pkh, d, l); r = 20; }
    }
    
    return r;
}

// writes the 20 byte pubkey hash from witness to pkh and returns the number of bytes written
size_t ZNWitnessPKH(uint8_t pkh[20], const uint8_t *witness, size_t witLen)
{
    const uint8_t *d = NULL, *elems[ZN_MAX_SCRIPT_LEN];
    size_t count, r = 0, l = 0;

    assert(pkh != NULL);
    assert(witness != NULL || witLen == 0);
    if (! witness || witLen == 0 || witLen > ZN_MAX_SCRIPT_LEN) return 0;
    count = ZNScriptElements(elems, sizeof(elems)/sizeof(*elems), witness, witLen);
    
    if (count == 2 && *elems[0] <= ZN_OP_PUSHDATA4 && *elems[0] > 0 && (*elems[1] == 65 || *elems[1] == 33)) {
        // pay-to-witness-pubkey-hash
        d = ZNScriptData(elems[count - 1], &l);
        if (l != 65 && l != 33) d = NULL;
        if (d) { ZNHash160(pkh, d, l); r = 20; }
    }
    
    return r;
}

// writes the bitcoin address for a scriptPubKey to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromScriptPubKey(char addr[75], ZNAddrParams params, const uint8_t *script, size_t scriptLen)
{
    uint8_t data[21];
    const uint8_t *elems[ZN_MAX_SCRIPT_LEN];
    size_t count, r = 0, l = 0;

    assert(addr != NULL);
    assert(script != NULL || scriptLen == 0);
    if (! script || scriptLen == 0 || scriptLen > ZN_MAX_SCRIPT_LEN) return 0;
    count = ZNScriptElements(elems, sizeof(elems)/sizeof(*elems), script, scriptLen);
    
    if (count == 5 && *elems[0] == ZN_OP_DUP && *elems[1] == ZN_OP_HASH160 && *elems[2] == 20 &&
        *elems[3] == ZN_OP_EQUALVERIFY && *elems[4] == ZN_OP_CHECKSIG) {
        // pay-to-pubkey-hash scriptPubKey
        data[0] = params.pubKeyPrefix;
        memcpy(data + 1, ZNScriptData(elems[2], &l), 20);
        r = ZNBase58CheckEncode(addr, 75, data, 21);
    }
    else if (count == 3 && *elems[0] == ZN_OP_HASH160 && *elems[1] == 20 && *elems[2] == ZN_OP_EQUAL) {
        // pay-to-script-hash scriptPubKey
        data[0] = params.scriptPrefix;
        memcpy(data + 1, ZNScriptData(elems[1], &l), 20);
        r = ZNBase58CheckEncode(addr, 75, data, 21);
    }
//    else if (count == 2 && (*elems[0] == 65 || *elems[0] == 33) && *elems[1] == OP_CHECKSIG) {
//        // pay-to-pubkey scriptPubKey
//    }
    else if (count == 2 && ((*elems[0] == ZN_OP_0 && (*elems[1] == 20 || *elems[1] == 32)) ||
                            (*elems[0] >= ZN_OP_1 && *elems[0] <= ZN_OP_16 && *elems[1] >= 2 && *elems[1] <= 40)) &&
             params.bech32Prefix && strlen(params.bech32Prefix) == 2) {
        // pay-to-witness scriptPubKey
        r = ZNBech32mEncode(addr, params.bech32Prefix, script);
    }
    
    return r;
}

// writes the bitcoin address for a scriptSig to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromScriptSig(char addr[75], ZNAddrParams params, const uint8_t *script, size_t scriptLen)
{
    uint8_t data[21];
    const uint8_t *d = NULL, *elems[ZN_MAX_SCRIPT_LEN];
    size_t count, l = 0;

    assert(addr != NULL);
    assert(script != NULL || scriptLen == 0);
    if (! script || scriptLen == 0 || scriptLen > ZN_MAX_SCRIPT_LEN) return 0;
    count = ZNScriptElements(elems, sizeof(elems)/sizeof(*elems), script, scriptLen);
    
    if (count == 2 && *elems[0] <= ZN_OP_PUSHDATA4 && (*elems[1] == 65 || *elems[1] == 33)) {
        // pay-to-pubkey-hash scriptSig
        data[0] = params.pubKeyPrefix;
        d = ZNScriptData(elems[1], &l);
        if (l != 65 && l != 33) d = NULL;
        if (d) ZNHash160(data + 1, d, l);
    }
    else if (count >= 1 && *elems[count - 1] <= ZN_OP_PUSHDATA4 && *elems[count - 1] > 0 &&
             (count >= 2 || ((d = ZNScriptData(elems[0], &l)) &&
                             (d[0] == ZN_OP_0 || (d[0] >= ZN_OP_1 && d[0] <= ZN_OP_16))))) {
        // pay-to-script-hash scriptSig
        data[0] = params.scriptPrefix;
        d = ZNScriptData(elems[count - 1], &l);
        if (d) ZNHash160(data + 1, d, l);
    }
//    else if (count == 1 && *elems[0] <= OP_PUSHDATA4 && *elems[0] > 0) { // pay-to-pubkey scriptSig
//    }
    // pay-to-witness scriptSig's are empty
    
    return (d) ? ZNBase58CheckEncode(addr, 75, data, 21) : 0;
}

// writes the bitcoin address for a witness to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromWitness(char addr[75], ZNAddrParams params, const uint8_t *witness, size_t witLen)
{
    uint8_t data[34];
    const uint8_t *d = NULL, *elems[ZN_MAX_SCRIPT_LEN];
    size_t count, l = 0;

    assert(addr != NULL);
    assert(witness != NULL || witLen == 0);
    if (! witness || witLen == 0 || witLen > ZN_MAX_SCRIPT_LEN) return 0;
    count = ZNScriptElements(elems, sizeof(elems)/sizeof(*elems), witness, witLen);
    
    if (count == 2 && *elems[0] <= ZN_OP_PUSHDATA4 && *elems[0] > 0 && (*elems[1] == 65 || *elems[1] == 33)) {
        // pay-to-witness-pubkey-hash
        data[0] = 0;
        data[1] = 20;
        d = ZNScriptData(elems[count - 1], &l);
        if (l != 65 && l != 33) d = NULL;
        if (d) ZNHash160(data + 2, d, l);
    }
    else if (count >= 2 && (*elems[0] == ZN_OP_0 || (*elems[0] >= ZN_OP_1 && *elems[0] <= ZN_OP_16)) &&
             *elems[count - 1] <= ZN_OP_PUSHDATA4 && *elems[count - 1] > 0) {
        // pay-to-witness-script-hash
        data[0] = *elems[0];
        data[1] = 32;
        d = ZNScriptData(elems[count - 1], &l);
        if (d) ZNSHA256(data + 2, d, l);
    }

    if (! params.bech32Prefix && strlen(params.bech32Prefix) != 2) d = NULL;
    return (d) ? ZNBech32mEncode(addr, params.bech32Prefix, data) : 0;
}

// writes the bech32 pay-to-witness-pubkey-hash address for a 20 byte pubkey hash to addr
// returns the number of bytes written, maximum is 75 bytes
size_t ZNAddressFromPKH(char addr[75], ZNAddrParams params, const uint8_t pkh[20])
{
    uint8_t data[22] = { 0, 20 };
    size_t r;
    
    assert(addr != NULL);
    assert(pkh != NULL);
    
    if (params.bech32Prefix && strlen(params.bech32Prefix) == 2) {
        memcpy(data + 2, pkh, 20);
        r = ZNBech32mEncode(addr, params.bech32Prefix, data);
    }
    else {
        data[0] = params.pubKeyPrefix;
        memcpy(data + 1, pkh, 20);
        r = ZNBase58CheckEncode(addr, 75, data, 21);
    }
    
    return r;
}

// writes the scriptPubKey for addr to script
// returns the number of bytes written, or scriptLen needed if script is NULL
size_t ZNAddressScriptPubKey(uint8_t script[42], const char *addr, ZNAddrParams params)
{
    uint8_t data[42];
    char hrp[84];
    size_t dataLen, r = 0;
    
    assert(addr != NULL);
    assert(script != NULL);
    
    if (ZNBase58CheckDecode(data, sizeof(data), addr) == 21) {
        if (data[0] == params.pubKeyPrefix) {
            script[0] = ZN_OP_DUP;
            script[1] = ZN_OP_HASH160;
            script[2] = 20;
            memcpy(script + 3, data + 1, 20);
            script[23] = ZN_OP_EQUALVERIFY;
            script[24] = ZN_OP_CHECKSIG;
            r = 25;
        }
        else if (data[0] == params.scriptPrefix) {
            script[0] = ZN_OP_HASH160;
            script[1] = 20;
            memcpy(script + 2, data + 1, 20);
            script[22] = ZN_OP_EQUAL;
            r = 23;
        }
    }
    else {
        dataLen = ZNBech32mDecode(hrp, data, addr);
        
        if (dataLen > 2 && dataLen <= 42 && params.bech32Prefix && strcmp(hrp, params.bech32Prefix) == 0 &&
            (data[0] != ZN_OP_0 || data[1] == 20 || data[1] == 32)) {
            memcpy(script, data, dataLen);
            r = dataLen;
        }
    }

    return r;
}

// writes the 20 byte pubkey hash of addr to pkh and returns the number of bytes written
size_t ZNAddressPKH(uint8_t pkh[20], const char *addr, ZNAddrParams params)
{
    char hrp[84];
    uint8_t data[42];
    size_t r = 0;
    
    assert(pkh != NULL);
    assert(addr != NULL);
    
    if (ZNBase58CheckDecode(data + 1, sizeof(data) - 1, addr) == 21) {
        if (data[1] == params.pubKeyPrefix || data[1] == params.scriptPrefix) r = 20;
    }
    else if (ZNBech32mDecode(hrp, data, addr) == 22) {
        if (params.bech32Prefix && strcmp(hrp, params.bech32Prefix) == 0 && data[1] == 20) r = 20;
    }
    
    if (pkh) memcpy(pkh, data + 2, r);
    return r;
}

// returns true if addr is a valid bitcoin address
int ZNAddressIsValid(const char *addr, ZNAddrParams params)
{
    uint8_t data[42];
    char hrp[84];
    int r = 0;
    
    assert(addr != NULL);
    
    if (ZNBase58CheckDecode(data, sizeof(data), addr) == 21) {
        r = (data[0] == params.pubKeyPrefix || data[0] == params.scriptPrefix);
    }
    else if (ZNBech32mDecode(hrp, data, addr) > 2) {
        r = (params.bech32Prefix && strcmp(hrp, params.bech32Prefix) == 0 &&
             (data[0] != ZN_OP_0 || data[1] == 20 || data[1] == 32));
    }
    
    return r;
}
