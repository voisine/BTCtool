//
//  ContentView.swift
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

struct ContentView: View {
    var str = base58Encode(str:"Hello, world!")!
    var body: some View {
        VStack {
            //Image(systemName: "globe")
            //    .imageScale(.large)
            //    .foregroundStyle(.tint)
            Image(uiImage: UIImage.qrCode(data: str.data(using: .utf8)!)!.resize(CGSize(width: 300, height: 300))!)
            //Text("Hello, world!")
            Text(str)
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
