//
//  ContentView.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI

struct ContentView: View {
    @State private var isPresentingScanner = false
    @State private var scannedCode: String? = base58Encode(str:"Hello, world!")!
    var body: some View {
        VStack {
            //Image(systemName: "globe")
            //    .imageScale(.large)
            //    .foregroundStyle(.tint)
            Image(uiImage: UIImage.qrCode(data: (scannedCode ?? "").data(using: .utf8)!)!
                .resize(CGSize(width: 300, height: 300))!)
            //Text("Hello, world!")
            Text(scannedCode ?? "[]")
            Button("Scan QR") { isPresentingScanner = true }
            .padding()
        }
        .buttonStyle(.bordered)
        .padding()
        .sheet(isPresented: $isPresentingScanner) {
            CodeScannerView(codeTypes: [.qr], showViewfinder: true, simulatedData: "Hello, world!") { response in
                if case let .success(result) = response {
                    scannedCode = result.string
                    isPresentingScanner = false
                }
            }
        }
    }
}

#Preview {
    ContentView()
}
