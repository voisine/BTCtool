//
//  ContentView.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI

struct ContentView: View {
    @State private var presentScanner = false
    @State private var enterEntropy = false
    @State private var entropy = ""
    @State private var selectPassword = false
    @State private var passwordMismatch = false
    @State private var password = ""
    @State private var password2 = ""
    @State private var bip38Key = ""
    @State private var enterPassword = false
    @State private var incorrectPassword = false
    @State private var qr1Data: Data? = nil
    @State private var qr2Data: Data? = nil
    @State private var qr2Label = ""
    
    //"a\xc3\xb1\xc3\x28\xa0\xa1\xe2\x82\xa1\xe2\x28\xa1\xe2\x82\x28\xf0\x90\x8c\xbc\xf0\x28\x8c\xbc\xf0\x90\x28\xbc\xf0\x28\x8c\x28\xf8\xa1\xa1\xa1\xa1\xfc\xa1\xa1\xa1\xa1\xa1"

    @State private var tx: UnsafeMutablePointer<ZNTransaction>?
    var body: some View {
        VStack {
            if (qr1Data != nil) {
                Image(uiImage: UIImage.qrCode(data: qr1Data!)!.resize(CGSize(width: 150, height: 150))!)
                Text(String(data: qr1Data!, encoding: .utf8) ?? "[binary]").font(.system(.caption, design: .monospaced))
            }
            if (qr2Data != nil) {
                Image(uiImage: UIImage.qrCode(data: qr2Data!)!.resize(CGSize(width: 375, height: 375))!)
                Text(String(data: qr2Data!, encoding: .utf8) ?? qr2Label).font(.system(.caption, design: .monospaced))
            }
            Button((tx == nil) ? "Scan Unsigned Tx" : "Scan private key") { presentScanner = true }
            .padding()
            Button("Create Paper Key") { enterEntropy = true }
        }
        .buttonStyle(.bordered)
        .sheet(isPresented: $presentScanner) {
            CodeScannerView(codeTypes: [.qr], showViewfinder: true, simulatedData: "Hello, world!") { response in
                if case let .success(result) = response {
                    if (tx != nil) {
                        if (ZNBIP38KeyIsValid(result.string) != 0) {
                            bip38Key = result.string
                            enterPassword = true
                        }
                        else if (ZNPrivKeyIsValid(result.string, ZNMainNetParams) != 0) {
                            var key = ZNKey()
                            var buf = [UInt8](repeating: 0, count: 0x1000)
                            
                            ZNKeySetPrivKey(&key, result.string, ZNMainNetParams)
                            ZNTransactionSign(tx, 0, &key, 1)
                            ZNKeyClean(&key)
                            qr2Data = Data(buf.prefix(ZNTransactionSerialize(tx, &buf, buf.count)))
                            ZNKeyClean(&key)
                        }
                    }
                    else { 
                        tx = ZNTransactionParse([UInt8](result.data!), result.data!.count, nil)

                        if (tx != nil) {
                            qr2Label = ""
                            
                            for i in 0..<tx!.pointee.inCount {
                                let amount = Double(tx!.pointee.inputs[i].amount/1000)/Double(ZN_SATOSHIS/1000)
                                qr2Label += ((qr2Label == "") ? "" : ", ") + "\(amount)"
                            }

                            qr2Label += "\n->"
                            
                            for i in 0..<tx!.pointee.outCount {
                                var addr = [CChar](repeating: 0, count: 75)
                                let amount = Double(tx!.pointee.outputs[i].amount/1000)/Double(ZN_SATOSHIS/1000)
                                ZNTxOutputAddress(&(tx!.pointee.outputs[i]), &addr, ZNMainNetParams)
                                qr2Label += "\n\(amount) " + (String(validatingUTF8: addr) ?? "[?]")
                            }
                        }
                    }
                    
                    qr1Data = nil
                    qr2Data = result.data
                    presentScanner = false
                }
            }
        }
        .alert("Enter 50 dice rolls", isPresented: $enterEntropy) {
            SecureField("dice results", text: $entropy)
            Button("OK", action: { selectPassword = true })
            Button("Cancel", role: .cancel) { entropy = "" }
        }
        .alert((passwordMismatch) ? "Password Mismatch" : "Select Password", isPresented: $selectPassword) {
            SecureField("Password", text: $password)
            SecureField("Re-enter Password", text: $password2)
            Button("OK", action: { createKey() })
            Button("Cancel", role: .cancel) { entropy = ""; password = ""; password2 = ""; passwordMismatch = false }
        }
        .alert("Password Mismatch", isPresented: $passwordMismatch) {
            SecureField("Password", text: $password)
            SecureField("Re-enter Password", text: $password2)
            Button("OK", action: { createKey(); if (passwordMismatch) { selectPassword = true } })
            Button("Cancel", role: .cancel) { entropy = ""; password = ""; password2 = ""; }
        }
        .alert((incorrectPassword) ? "Incorrect Password" : "Enter Password", isPresented: $enterPassword) {
            SecureField("Password", text: $password)
            Button("OK", action: { signTx() })
            Button("Cancel", role: .cancel) { password = ""; incorrectPassword = false }
        }
        .alert("Incorrect Password", isPresented: $incorrectPassword) {
            SecureField("Password", text: $password)
            Button("OK", action: { signTx(); if (incorrectPassword) { enterPassword = true } })
            Button("Cancel", role: .cancel) { password = ""; }
        }
    }
    
    func createKey() {
        if (password == password2) {
            var address: String?, bip38Key: String?
            (address, bip38Key) = bip38privKey(entropy: entropy, passphrase: password)
            qr1Data = address?.data(using: .utf8)
            qr2Data = bip38Key?.data(using: .utf8)
            entropy = ""
            passwordMismatch = false
        }
        else { passwordMismatch = true; }

        password = ""
        password2 = ""
    }
    
    func signTx() {
        var key = ZNKey()
        var buf = [UInt8](repeating: 0, count: 0x1000)
        
        if (ZNKeySetBIP38Key(&key, bip38Key, password, ZNMainNetParams) != 0) {
            ZNTransactionSign(tx, 0, &key, 1)
            ZNKeyClean(&key)
            password = ""
            qr2Data = Data(buf.prefix(ZNTransactionSerialize(tx, &buf, buf.count)))
        }
        else { incorrectPassword = true; }
    }
}

#Preview {
    ContentView()
}
