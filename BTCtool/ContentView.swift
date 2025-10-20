//
//  ContentView.swift
//  BTCtool
//
//  Created by ajv on 11/29/23.
//

import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @State private var presentScanner = false
    @State private var enterEntropy = false
    @State private var entropy = ""
    @State private var phrase = ""
    @State private var selectPassword = false
    @State private var passwordMismatch = false
    @State private var password = ""
    @State private var password2 = ""
    @State private var bip38Key = ""
    @State private var seed: [UInt8] = []
    @State private var enterPassword = false
    @State private var incorrectPassword = false
    @State private var enterTxInfo = false
    @State private var enterPhrase = false
    @State private var fromAddress = ""
    @State private var toAddress = ""
    @State private var amount = ""
    @State private var changeAddress = ""
    @State private var qr1Data: Data? = nil
    @State private var qr2Data: Data? = nil
    @State private var qr2Label = ""
    @State private var utxos: [UTXO] = []
    @State private var feeRate: feeRates? = nil
    @State private var showError = false
    @State private var error = ""
    @State private var tx: UnsafeMutablePointer<ZNTransaction>?
    @State private var isScanningChain = false
    @State private var scanIdx = UInt32(0)
    @State private var scanChange = UInt32(0)
    @State private var scanGap = Int(20)
    
    var body: some View {
        VStack {
            if (qr1Data != nil) {
                Image(uiImage: UIImage.qrCode(data: qr1Data!)!.resize(CGSize(width: 150, height: 150))!)
                Text(String(data: qr1Data!, encoding: .utf8) ?? "[?]").font(.system(.caption, design: .monospaced))
            }
            
            if (qr2Data != nil) {
                Image(uiImage: UIImage.qrCode(data: qr2Data!)!.resize(CGSize(width: 375, height: 375))!)
                Text((qr2Label.count > 0) ? qr2Label : String(data: qr2Data!, encoding: .utf8) ?? "")
                .font(.system(.caption, design: .monospaced))
            }
            else if (qr2Label.count > 0) { Text(qr2Label).font(.system(.caption, design: .monospaced)) }
            
            Button((phrase == "") ? "Scan backup phrase" : "Continue phrase scan") {
                if (!isScanningChain) {
                    if (phrase == "") { enterPhrase = true }
                    else { scanChain(idx: scanIdx + 1, change: scanChange, legacy: true, gap: scanGap) }
                }
            }.padding()
            
            Button((tx == nil || ZNTransactionIsSigned(tx) != 0) ? "Scan Unsigned Tx" : "Scan private key") {
                if (qr2Data == nil) { scanResult(result: UIPasteboard.general.string ?? "") }
                presentScanner = true
            }

            if (qr2Data == nil) { 
                Button("Create Paper Key") { enterEntropy = true }.padding()
                Button("Create Transaction") { utxos = []; enterTxInfo = true; }
            }
        }
        .buttonStyle(.bordered)
        .sheet(isPresented: $presentScanner, onDismiss: { if (bip38Key != "") { enterPassword = true } }) {
            CodeScannerView(codeTypes: [.qr], showViewfinder: true,
                            simulatedData: UIPasteboard.general.string ?? "Hello, world!") { response in
                if case let .success(result) = response { scanResult(result: result.string) }
            }
        }
        .alert("Enter 12 word phrase", isPresented: $enterPhrase) {
            TextField("12 word phrase", text: $phrase)
            Button("OK", action: {            
                seed = [UInt8](repeating:0, count:64)
                ZNBIP39DeriveKey(&seed, phrase, nil)
                scanChain(idx: 0, change: 0, legacy: true, gap: 20)
            })
            Button("Cancel", role: .cancel) { phrase = "" }
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
        .alert("Enter Transaction Info", isPresented: $enterTxInfo) {
            TextField("From Address", text: $fromAddress)
            TextField("To Address", text: $toAddress)
            TextField("Amount", text: $amount)
            TextField("Change Address", text: $changeAddress)
            Button("OK", action: { createTx() })
            Button("Cancel", role: .cancel) { }
        }
        //.alert(error, isPresented: $showError)
    }

    func scanResult(result: String) {
        if (ZNBIP38KeyIsValid(result) != 0) { bip38Key = result }

        if (ZNBIP39PhraseIsValid(nil, result) != 0 && !isScanningChain) {
            seed = [UInt8](repeating:0, count:64)
            ZNBIP39DeriveKey(&seed, result, nil)
            scanChain(idx: 0, change: 0, legacy: true, gap: 20)
        }

        if (tx != nil) {
            qr1Data = nil
            
            if (ZNPrivKeyIsValid(result, ZNMainNetParams) != 0) {
                var key = ZNKey()
                var buf = [UInt8](repeating: 0, count: 0x1000)
                var addr = [CChar](repeating: 0, count: 75)
                ZNKeySetPrivKey(&key, result, ZNMainNetParams)
                ZNKeyAddress(&key, &addr, ZNMainNetParams)
                print("got privkey for: %s\n", String(validatingUTF8: addr) ?? "[?]")
                ZNTransactionSign(tx, 0, &key, 1)
                ZNKeyClean(&key)
                let bufLen = ZNTransactionSerialize(tx, &buf, buf.count)
                qr2Data = buf.prefix(bufLen).reduce("") { $0 + String(format: "%02hhx", $1) }.data(using: .utf8)
                labelTx()
                UIPasteboard.general.string = String(data: qr2Data!, encoding: .utf8)
            }
        }
        else {
            qr1Data = nil
            qr2Data = result.data(using: .utf8)
            qr2Label = ""
            var buf = [UInt8](repeating:0, count:result.count/2)
            ZNHexDecode(&buf, buf.count, result)
            tx = ZNTransactionParse(buf, buf.count, nil)
            if (tx != nil) { labelTx() }
            UIPasteboard.general.string = result
        }
        

        presentScanner = false
    }
    
    func createKey() {
        if (password == password2) {
            var address: String?, bip38Key: String?
            (address, bip38Key) = bip38privKey(entropy: entropy, passphrase: password)
            qr1Data = address?.data(using: .utf8)
            qr2Data = bip38Key?.data(using: .utf8)
            qr2Label = ""
            entropy = ""
            passwordMismatch = false
        }
        else { passwordMismatch = true; }

        password = ""
        password2 = ""
    }
    
    func signTx() {
        var key = ZNKey()

        if (ZNKeySetBIP38Key(&key, bip38Key, password, ZNMainNetParams) != 0) {
            if (tx != nil) {
                ZNTransactionSign(tx, 0, &key, 1)
                ZNKeyClean(&key)
                password = ""
                bip38Key = ""
                var buf = [UInt8](repeating: 0, count: 0x1000)
                let bufLen = ZNTransactionSerialize(tx, &buf, buf.count)
                qr2Data = buf.prefix(bufLen).reduce("") { $0 + String(format: "%02hhx", $1) }.data(using: .utf8)
                labelTx()
            }
            else {
                var privKey = [CChar](repeating: 0, count: 53)
                ZNKeyPrivKey(&key, &privKey, ZNMainNetParams)
                ZNKeyClean(&key)
                password = ""
                bip38Key = ""
                qr2Label = String(validatingUTF8: privKey) ?? "[?]"
                qr2Data = qr2Label.data(using: .utf8)
            }
            
            incorrectPassword = false
            UIPasteboard.general.string = String(data: qr2Data!, encoding: .utf8)
        }
        else { incorrectPassword = true }
    }
        
    func createTx() {
        var total = UInt64(0)
        if (utxos.count == 0) { fetchUTXOs(address: fromAddress); return }
        tx = ZNTransactionNew()
        
        for o in utxos {
            var hash = [UInt8](repeating: 0, count: 32)
            var script = [UInt8](repeating: 0, count: o.script.count/2)

            if (o.value < ZNMinOutputAmount(UInt64(Int64(feeRate!.priority*1000)))) { continue }
            total += UInt64(o.value)
            ZNTransactionAddInput(tx, ZNHexDecode(&hash, 32, o.tx_hash), UInt32(o.tx_output_n), UInt64(o.value),
                                  ZNHexDecode(&script, o.script.count/2, o.script), o.script.count/2, nil, 0, nil, 0,
                                  ZN_TXIN_SEQUENCE)
        }
        
        let outAmount = UInt64((Double(amount) ?? 0)*Double(ZN_SATOSHIS) + 0.5)
        var scriptPK = [UInt8](repeating:0, count:42)
        var scriptPKLen = ZNAddressScriptPubKey(&scriptPK, toAddress, ZNMainNetParams)
        ZNTransactionAddOutput(tx, outAmount, &scriptPK, scriptPKLen)
        let fee = ZNFeeForTxVSize(UInt64(feeRate!.priority*1000), ZNTransactionVSize(tx) + Int(ZN_OUTPUT_SIZE))
        scriptPKLen = ZNAddressScriptPubKey(&scriptPK, changeAddress, ZNMainNetParams)

        if (scriptPKLen > 0 && total > outAmount + fee) {
            ZNTransactionAddOutput(tx, (total - outAmount) - fee, &scriptPK, scriptPKLen) 
        }

        labelTx()
        var buf = [UInt8](repeating: 0, count: 0x1000)
        let bufLen = ZNTransactionSerialize(tx, &buf, buf.count)
        qr2Data = buf.prefix(bufLen).reduce("") { $0 + String(format: "%02hhx", $1) }.data(using: .utf8)
        UIPasteboard.general.string = String(data: qr2Data!, encoding: .utf8)
    }
    
    func labelTx() {
        var fee = Int64(0)
        qr2Label = ""
        
        for i in 0..<tx!.pointee.inCount {
            let inAmount = Double(tx!.pointee.inputs[i].amount/100)/Double(ZN_SATOSHIS/100)
            let isSigned = (tx!.pointee.inputs[i].scriptSig != nil && tx!.pointee.inputs[i].witness != nil)
            fee += Int64(tx!.pointee.inputs[i].amount)
            qr2Label += ((qr2Label == "") ? "" : ", ") + "\(inAmount)" + (isSigned ? "\u{2705}" : "")
        }

        qr2Label += " ->"
        
        for i in 0..<tx!.pointee.outCount {
            var addr = [CChar](repeating: 0, count: 75)
            let outAmount = Double(tx!.pointee.outputs[i].amount/100)/Double(ZN_SATOSHIS/100)
            ZNTxOutputAddress(&(tx!.pointee.outputs[i]), &addr, ZNMainNetParams)
            fee -= Int64(tx!.pointee.outputs[i].amount)
            qr2Label += "\n\(outAmount) " + (String(validatingUTF8: addr) ?? "[?]")
        }
        
        qr2Label += "\n\(Double(fee/100)/Double(ZN_SATOSHIS/100)) fee"
    }
    
    func fetchFeeRate() {
        guard let url = URL(string: "https://api.blockchain.info/mempool/fees") else { return }

        URLSession.shared.dataTask(with: url) { data, response, error in
            guard let data = data else { return }
            do {
                let feeRate = try JSONDecoder().decode(feeRates.self, from: data)
                DispatchQueue.main.async {
                    self.feeRate = feeRate
                    if (utxos.count > 0) { createTx() }
                }
            }
            catch { print(error.localizedDescription) }
        }.resume()
    }

    func fetchUTXOs(address: String) {
        for addr in address.split(separator: ",") {
            let input = addr.split(separator: ":")
            
            if (input.count == 4) {
                self.utxos.append(UTXO(tx_hash: String(input[1]), tx_output_n: Int(String(input[2])) ?? 0,
                                       script: String(input[0]), value: Int(String(input[3])) ?? 0))
            }
            else {
                guard let url = URL(string: "https://blockchain.info/unspent?active=" + address) else { return }

                URLSession.shared.dataTask(with: url) { data, response, error in
                    guard let data = data else { return }
                    do {
                        let utxos = try JSONDecoder().decode(UTXOs.self, from: data)
                        DispatchQueue.main.async {
                            self.utxos = utxos.unspent_outputs
                            fetchFeeRate()
                        }
                    }
                    catch { print(error.localizedDescription) }
                }.resume()
            }
        }
        
        if (self.utxos.count > 0) { fetchFeeRate() }
    }

    func scanChain(idx: UInt32, change: UInt32, legacy: Bool, gap: Int) {
        isScanningChain = true
        var key = ZNKey()
        var addr = [CChar](repeating:0, count:75)
        ZNBIP32PrivKeyPath(&key, seed, seed.count, 3, [ZN_BIP32_HARD, change, idx])
        if (legacy) { ZNKeyLegacyAddr(&key, &addr, ZNMainNetParams) }
        else { ZNKeyAddress(&key, &addr, ZNMainNetParams) }
        guard let url = URL(string: "https://blockstream.info/api/address/" + String(validatingUTF8: addr)!) 
        else { return }
        qr2Label = "m/0h/\(change)/\(idx)" + (legacy ? " legacy" : " segwit")
        print("https://blockstream.info/api/address/" + String(validatingUTF8: addr)! + "\n" + qr2Label)
        
        URLSession.shared.dataTask(with: url) { data, response, error in
            guard let data = data else { return }
            do {
                let res = try JSONDecoder().decode(address_result.self, from: data)
                DispatchQueue.main.async {
                    print("tx_count:\(res.chain_stats.tx_count) " +
                          "balance:\(res.chain_stats.funded_txo_sum - res.chain_stats.spent_txo_sum)\n")

                    if (res.chain_stats.tx_count == 0) {
                        if (legacy) { scanChain(idx: idx, change: change, legacy: false, gap: gap) }
                        else if (gap > 0) {
                            scanIdx = idx
                            scanChange = change
                            scanGap = gap
                            scanChain(idx: idx + 1, change: change, legacy: true, gap: gap - 1)
                        }
                        else if (change == 0) { scanChain(idx: 0, change: 1, legacy: true, gap: 20) }
                        else { phrase = ""; isScanningChain = false }
                    }
                    else if (res.chain_stats.funded_txo_sum == res.chain_stats.spent_txo_sum) {
                        if (legacy) { scanChain(idx: idx, change: change, legacy: false, gap: 20) }
                        else {
                            scanIdx = idx
                            scanChange = change
                            scanGap = 20
                            scanChain(idx: idx + 1, change: change, legacy: true, gap: 20)
                        }
                    }
                    else {
                        qr1Data = String(validatingUTF8: addr)!.data(using: .utf8)
                        var privKey = [CChar](repeating: 0, count: 53)
                        //key.compressed = (legacy) ? 0x01 : 0x11
                        ZNKeyPrivKey(&key, &privKey, ZNMainNetParams)
                        qr2Label = String(validatingUTF8: privKey) ?? "[?]"
                        qr2Data = qr2Label.data(using: .utf8)
                        qr2Label += " [\(res.chain_stats.funded_txo_sum - res.chain_stats.spent_txo_sum)]"
                        isScanningChain = false
                        scanIdx = idx
                        scanChange = change
                        scanGap = 20
                    }
                }
            }
            catch {
                isScanningChain = false
                qr2Label = error.localizedDescription
                print(error.localizedDescription)
            }
        }.resume()
    }
    
    struct UTXOs: Codable {
        let unspent_outputs: [UTXO]
    }
    
    struct UTXO: Codable {
        let tx_hash: String
        let tx_output_n: Int
        let script: String
        let value: Int
    }
    
    struct feeRates: Codable {
        let limits: limits
        let regular: Int
        let priority: Int
    }
    
    struct limits: Codable {
        let min: Int
        let max: Int
    }
    
    struct address_result: Codable {
        let address: String
        let chain_stats: chain_stats
        let mempool_stats: mempool_stats
    }
    
    struct chain_stats: Codable {
        let funded_txo_count: Int
        let funded_txo_sum: Int
        let spent_txo_count: Int
        let spent_txo_sum: Int
        let tx_count: Int
    }
    
    struct mempool_stats: Codable {
        let funded_txo_count: Int
        let funded_txo_sum: Int
        let spent_txo_count: Int
        let spent_txo_sum: Int
        let tx_count: Int
    }
}

#Preview {
    ContentView()
}
