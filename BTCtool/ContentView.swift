//
//  ContentView.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI

struct ContentView: View {
    @State private var isPresentingScanner = false
    @State private var isEnteringEntropy = false
    @State private var entropy = ""
    @State private var isEnteringPassword = false
    @State private var passwordMismatch = false
    @State private var password = ""
    @State private var password2 = ""
    @State private var qr1Data: String? = nil
    @State private var qr2Data: String? = nil
    
    //"a\xc3\xb1\xc3\x28\xa0\xa1\xe2\x82\xa1\xe2\x28\xa1\xe2\x82\x28\xf0\x90\x8c\xbc\xf0\x28\x8c\xbc\xf0\x90\x28\xbc\xf0\x28\x8c\x28\xf8\xa1\xa1\xa1\xa1\xfc\xa1\xa1\xa1\xa1\xa1"

    @State private var tx: UnsafeMutablePointer<ZNTransaction>?
    var body: some View {
        VStack {
            if (qr1Data != nil) {
                Image(uiImage: UIImage.qrCode(data: qr1Data!.data(using: .utf8)!)!
                .resize(CGSize(width: 200, height: 200))!)
                Text(qr1Data!).font(.system(.body, design: .monospaced))
            }
            if (qr2Data != nil) {
                Image(uiImage: UIImage.qrCode(data: qr2Data!.data(using: .utf8)!)!
                .resize(CGSize(width: 300, height: 300))!)
                Text(qr2Data!).font(.system(.body, design: .monospaced))
            }
            Button("Sign Transaction") { isPresentingScanner = true }
            .padding()
            Button("Create Paper Key") { isEnteringEntropy = true }
        }
        .buttonStyle(.bordered)
        .padding()
        .sheet(isPresented: $isPresentingScanner) {
            CodeScannerView(codeTypes: [.qr], showViewfinder: true, simulatedData: "Hello, world!") { response in
                if case let .success(result) = response {
                    if (tx == nil) { tx = ZNTransactionParse([UInt8](result.data!), result.data!.count, nil) }
                    qr1Data = nil
                    qr2Data = result.string
                    isPresentingScanner = false
                }
            }
        }
        .alert("Enter 50 dice rolls", isPresented: $isEnteringEntropy) {
            SecureField("dice results", text: $entropy)
            Button("OK", action: { isEnteringPassword = true })
            Button("Cancel", role: .cancel) { entropy = "" }
        }
        .alert((passwordMismatch) ? "Password Mismatch" : "Select Password", isPresented: $isEnteringPassword) {
            SecureField("Password", text: $password)
            SecureField("Re-enter Password", text: $password2)
            Button("OK", action: { createKey() })
            Button("Cancel", role: .cancel) { entropy = ""; password = ""; password2 = ""; passwordMismatch = false }
        }
        .alert("Password Mismatch", isPresented: $passwordMismatch) {
            SecureField("Password", text: $password)
            SecureField("Re-enter Password", text: $password2)
            Button("OK", action: { createKey(); if (passwordMismatch) { isEnteringPassword = true } })
            Button("Cancel", role: .cancel) { entropy = ""; password = ""; password2 = ""; passwordMismatch = false }
        }
    }
    
    func createKey() {
        if (password == password2) {
            (qr1Data, qr2Data) = bip38privKey(entropy: entropy, passphrase: password)
            entropy = ""
            passwordMismatch = false
        }
        else { passwordMismatch = true; }

        password = ""
        password2 = ""
    }
}

#Preview {
    ContentView()
}
