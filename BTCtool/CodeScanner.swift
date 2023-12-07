//
//  CodeScanner.swift
//  https://github.com/twostraws/CodeScanner
//
//  Created by Paul Hudson on 14/12/2021.
//  Copyright © 2021 Paul Hudson. All rights reserved.
//

import AVFoundation
import SwiftUI

/// An enum describing the ways CodeScannerView can hit scanning problems.
public enum ScanError: Error {
    /// The camera could not be accessed.
    case badInput

    /// The camera was not capable of scanning the requested codes.
    case badOutput

    /// Initialization failed.
    case initError(_ error: Error)
  
    /// The camera permission is denied 
    case permissionDenied
}

/// The result from a successful scan: the string that was scanned, and also the type of data that was found.
/// The type is useful for times when you've asked to scan several different code types at the same time, because
/// it will report the exact code type that was found.
@available(macCatalyst 14.0, *)
public struct ScanResult {
    /// The contents of the code.
    public let string: String
    
    /// Raw data of code after stripping error correction
    public let data: Data?

    /// The type of code that was matched.
    public let type: AVMetadataObject.ObjectType
    
    /// The image of the code that was matched
    public let image: UIImage?
  
    /// The corner coordinates of the scanned code.
    public let corners: [CGPoint]
}

/// The operating mode for CodeScannerView.
public enum ScanMode {
    /// Scan exactly one code, then stop.
    case once

    /// Scan each code no more than once.
    case oncePerCode

    /// Keep scanning all codes until dismissed.
    case continuous

    /// Scan only when capture button is tapped.
    case manual
}

/// A SwiftUI view that is able to scan barcodes, QR codes, and more, and send back what was found.
/// To use, set `codeTypes` to be an array of things to scan for, e.g. `[.qr]`, and set `completion` to
/// a closure that will be called when scanning has finished. This will be sent the string that was detected or a `ScanError`.
/// For testing inside the simulator, set the `simulatedData` property to some test data you want to send back.
@available(macCatalyst 14.0, *)
public struct CodeScannerView: UIViewControllerRepresentable {
    
    public let codeTypes: [AVMetadataObject.ObjectType]
    public let scanMode: ScanMode
    public let manualSelect: Bool
    public let scanInterval: Double
    public let showViewfinder: Bool
    public var simulatedData = ""
    public var shouldVibrateOnSuccess: Bool
    public var isTorchOn: Bool
    public var isGalleryPresented: Binding<Bool>
    public var videoCaptureDevice: AVCaptureDevice?
    public var completion: (Result<ScanResult, ScanError>) -> Void

    public init(
        codeTypes: [AVMetadataObject.ObjectType],
        scanMode: ScanMode = .once,
        manualSelect: Bool = false,
        scanInterval: Double = 2.0,
        showViewfinder: Bool = false,
        simulatedData: String = "",
        shouldVibrateOnSuccess: Bool = true,
        isTorchOn: Bool = false,
        isGalleryPresented: Binding<Bool> = .constant(false),
        videoCaptureDevice: AVCaptureDevice? = AVCaptureDevice.bestForVideo,
        completion: @escaping (Result<ScanResult, ScanError>) -> Void
    ) {
        self.codeTypes = codeTypes
        self.scanMode = scanMode
        self.manualSelect = manualSelect
        self.showViewfinder = showViewfinder
        self.scanInterval = scanInterval
        self.simulatedData = simulatedData
        self.shouldVibrateOnSuccess = shouldVibrateOnSuccess
        self.isTorchOn = isTorchOn
        self.isGalleryPresented = isGalleryPresented
        self.videoCaptureDevice = videoCaptureDevice
        self.completion = completion
    }

    public func makeUIViewController(context: Context) -> ScannerViewController {
        return ScannerViewController(showViewfinder: showViewfinder, parentView: self)
    }

    public func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {
        uiViewController.parentView = self
        uiViewController.updateViewController(
            isTorchOn: isTorchOn,
            isGalleryPresented: isGalleryPresented.wrappedValue,
            isManualCapture: scanMode == .manual,
            isManualSelect: manualSelect
        )
    }
    
}

@available(macCatalyst 14.0, *)
struct CodeScannerView_Previews: PreviewProvider {
    static var previews: some View {
        CodeScannerView(codeTypes: [.qr]) { result in
            // do nothing
        }
    }
}

extension CIQRCodeDescriptor
{
    var payload: Data?
    {
        var halves = errorCorrectedPayload.halfBytes()
        var batch = takeBatch(&halves)
        var output = batch
        while !batch.isEmpty
        {
            batch = takeBatch(&halves)
            output.append(contentsOf: batch)
        }
        return Data(output)
    }
    
    private func takeBatch(_ input: inout [HalfByte]) -> [UInt8]
    {
        let version = symbolVersion
        let characterCountLength = version > 9 ? 16 : 8
        let mode = input.remove(at: 0)
        var output = [UInt8]()
        switch (mode.value)
        {
                // TODO If there is not only binary in the QRCode, then cases should be added here.
            case 0x04: // Binary
                let charactersCount: UInt16
                if characterCountLength == 8
                {
                    charactersCount = UInt16(input.takeUInt8())
                }
                else
                {
                    charactersCount = UInt16(input.takeUInt16())
                }
                for _ in 0..<charactersCount
                {
                    output.append(input.takeUInt8())
                }
                return output
            case 0x00: // End of data
                return []
            default:
                return []
        }
    }
}

fileprivate struct HalfByte
{
    let value: UInt8
}

fileprivate extension [HalfByte]
{
    mutating func takeUInt8() -> UInt8
    {
        let left = self.remove(at: 0)
        let right = self.remove(at: 0)
        return UInt8(left, right)
    }

    mutating func takeUInt16() -> UInt16
    {
        let first = self.remove(at: 0)
        let second = self.remove(at: 0)
        let third = self.remove(at: 0)
        let fourth = self.remove(at: 0)
        return UInt16(first, second, third, fourth)
    }
}

fileprivate extension Data
{
    func halfBytes() -> [HalfByte]
    {
        var result = [HalfByte]()
        self.forEach
            { (byte: UInt8) in result.append(contentsOf: byte.halfBytes()) }
        return result
    }

    init(_ halves: [HalfByte])
    {
        var halves = halves
        var result = [UInt8]()
        while halves.count > 1
        {
            result.append(halves.takeUInt8())
        }
        self.init(result)
    }
}

fileprivate extension UInt8
{
    func halfBytes() -> [HalfByte]
    {
        [HalfByte(value: self >> 4), HalfByte(value: self & 0x0F)]
    }

    init(_ left: HalfByte, _ right: HalfByte)
    {
        self.init((left.value << 4) + (right.value & 0x0F))
    }
}

fileprivate extension UInt16
{
    init(_ first: HalfByte, _ second: HalfByte, _ third: HalfByte, _ fourth: HalfByte)
    {
        let first = UInt16(first.value) << 12
        let second = UInt16(second.value) << 8
        let third = UInt16(third.value) << 4
        let fourth = UInt16(fourth.value) & 0x0F
        let result = first + second + third + fourth
        self.init(result)
    }
}
