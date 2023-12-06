//
//  ContentView.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI

struct ContentView: View {
    @State private var isPresentingScanner = false
    @State private var isEnteringPassword = false
    @State private var password = ""
    @State private var qr1Data: String? = nil
    @State private var qr2Data: String? = base58Encode(str:"Hello, world!")!
    var body: some View {
        VStack {
            Image(uiImage: UIImage.qrCode(data: (qr1Data ?? "").data(using: .utf8)!)!
            .resize(CGSize(width: 150, height: 150))!)
            Text(qr1Data ?? "[]").font(.system(.body, design: .monospaced))
            Image(uiImage: UIImage.qrCode(data: (qr2Data ?? "").data(using: .utf8)!)!
            .resize(CGSize(width: 300, height: 300))!)
            Text(qr2Data ?? "[]").font(.system(.body, design: .monospaced))
            Button("Scan QR") { isPresentingScanner = true }
            .padding()
            Button("Paper Key") { isEnteringPassword = true }
        }
        .buttonStyle(.bordered)
        .padding()
        .sheet(isPresented: $isPresentingScanner) {
            CodeScannerView(codeTypes: [.qr], showViewfinder: true, simulatedData: "Hello, world!") { response in
                if case let .success(result) = response {
                    qr2Data = result.string
                    isPresentingScanner = false
                }
            }
        }
        .alert("Select Password", isPresented: $isEnteringPassword) {
            SecureField("Password", text: $password)
            Button("OK", action: { (qr1Data, qr2Data) = bip38privKey(passphrase: password); password = "" })
            Button("Cancel", role: .cancel) { password = "" }
        }
    }
}

#Preview {
    ContentView()
}
