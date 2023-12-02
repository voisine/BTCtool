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
        ZNBase58Encode(&buf, buf.count, cString, str.count)
        return String(validatingUTF8:buf)
    }
}

func bip38privKey(passphrase: String) -> String? {
    var key = ZNKey()
    var secret = [Int8](repeating: 0, count: 32)
    var bip38Key = [Int8](repeating: 0, count: 61)

    if (SecRandomCopyBytes(kSecRandomDefault, secret.count, &secret) == errSecSuccess) {
        ZNKeySetSecret(&key, &secret, 1)
        _ = SecRandomCopyBytes(kSecRandomDefault, secret.count, &secret) // wipe secret
        
        ZNKeyBIP38Key(&key, &bip38Key, passphrase, ZNMainNetParams)
    }

    return String(validatingUTF8:bip38Key)
}

@main
struct BTCtoolApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
