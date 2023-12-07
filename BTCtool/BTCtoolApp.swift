//
//  BTCtoolApp.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI

func bip38privKey(entropy: String, passphrase: String) -> (address: String?, bip38Key: String?) {
    var secret = [Int8](repeating: 0, count: 32)
    var bip38Key = [CChar](repeating: 0, count: 61)
    var address = [CChar](repeating: 0, count: 36)
    var key = ZNKey()
    ZNKeyClean(&key)
    key.compressed = 1

    if (SecRandomCopyBytes(kSecRandomDefault, 32, &secret) == errSecSuccess) {
        ZNPBKDF2(&key.secret, 32, ZNSHA256, 256/8, secret, 32, entropy, entropy.count, 1)
        memset(&secret, 0, 32)
        
        if (ZNKeyLegacyAddr(&key, &address, ZNMainNetParams) > 0 &&
            ZNKeyBIP38Key(&key, &bip38Key, passphrase, ZNMainNetParams) > 0) {
            ZNKeyClean(&key)
            return (String(validatingUTF8:address), String(validatingUTF8:bip38Key))
        }
    }

    return (nil, nil)
}

func signTx(privKey: UnsafeMutablePointer<ZNKey>!, tx: UnsafeMutablePointer<ZNTransaction>?) -> [Int8]? {
    var buf = [Int8](repeating: 0, count: 0x1000)

    ZNTransactionSign(tx, 0, privKey, 1)
    return [Int8](buf.prefix(ZNTransactionSerialize(tx, &buf, buf.count)))
}

@main
struct BTCtoolApp: App {
    //private var test = ZNRunTests()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
