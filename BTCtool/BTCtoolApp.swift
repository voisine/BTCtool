//
//  BTCtoolApp.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI

func base58Encode(str: String) -> String? {
    var buf = [Int8](repeating: 0, count: 2048)
    return str.withCString { cString in
        return (ZNBase58Encode(&buf, buf.count, cString, str.count) > 0) ? String(validatingUTF8:buf) : nil
    }
}

func bip38privKey(passphrase: String) -> (address:String?, bip38Key:String?) {
    var bip38Key = [CChar](repeating: 0, count: 61)
    var address = [CChar](repeating: 0, count: 36)
    var key = ZNKey()
    ZNKeyClean(&key)
    key.compressed = 1

    if (SecRandomCopyBytes(kSecRandomDefault, 32, &key.secret) == errSecSuccess &&
        ZNKeyLegacyAddr(&key, &address, ZNMainNetParams) > 0 &&
        ZNKeyBIP38Key(&key, &bip38Key, passphrase, ZNMainNetParams) > 0) {
        ZNKeyClean(&key)
        return (String(validatingUTF8:address), String(validatingUTF8:bip38Key))
    }

    return (nil, nil)
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
