//
//  BTCtoolApp.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI

func base58Encode(str: String) -> String? {
    var buf = Array<Int8>(repeating: 0, count: 2048)
    return str.withCString { cString in
        ZNBase58Encode(&buf, buf.count, cString, str.count)
        return String(validatingUTF8:buf)
    }
}

@main
struct BTCtoolApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
