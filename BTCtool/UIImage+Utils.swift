//
//  UIImage+Utils.swift
//  BTCtool
//
//  Created by ajv on 11/30/23.
//

import UIKit
import CoreGraphics

private let inputImageKey = "inputImage"

extension UIImage {
    static func qrCode(data: Data,
                       color: CIColor = .black,
                       backgroundColor: CIColor = .white) -> UIImage? {
        guard let qrFilter = CIFilter(name: "CIQRCodeGenerator"),
            let colorFilter = CIFilter(name: "CIFalseColor") else { return nil }

        qrFilter.setDefaults()
        qrFilter.setValue(data, forKey: "inputMessage")
        qrFilter.setValue("L", forKey: "inputCorrectionLevel")

        colorFilter.setDefaults()
        colorFilter.setValue(qrFilter.outputImage, forKey: "inputImage")
        colorFilter.setValue(color, forKey: "inputColor0")
        colorFilter.setValue(backgroundColor, forKey: "inputColor1")

        guard let outputImage = colorFilter.outputImage else { return nil }
        guard let cgImage = CIContext().createCGImage(outputImage, from: outputImage.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }

    func resize(_ size: CGSize, inset: CGFloat = 6.0) -> UIImage? {
        UIGraphicsBeginImageContext(size)
        defer { UIGraphicsEndImageContext() }
        guard let context = UIGraphicsGetCurrentContext() else { assert(false, "No image context"); return nil }
        guard let cgImage = self.cgImage else { assert(false, "No cgImage property"); return nil }

        context.interpolationQuality = .none
        context.rotate(by: Double.pi) // flip
        context.scaleBy(x: -1.0, y: 1.0) // mirror
        context.draw(cgImage, in: context.boundingBoxOfClipPath.insetBy(dx: inset, dy: inset))
        return UIGraphicsGetImageFromCurrentImageContext()
    }
    
    func image(withInsets insets: UIEdgeInsets) -> UIImage? {
        let width = self.size.width + insets.left + insets.right
        let height = self.size.height + insets.top + insets.bottom
        UIGraphicsBeginImageContextWithOptions(CGSize(width: width, height: height), false, self.scale)
        let origin = CGPoint(x: insets.left, y: insets.top)
        self.draw(at: origin)
        let imageWithInsets = UIGraphicsGetImageFromCurrentImageContext()
        UIGraphicsEndImageContext()
        return imageWithInsets?.withRenderingMode(renderingMode)
    }
    
    convenience init?(optionalData data: Data?) {
        guard let data = data else { return nil }
        self.init(data: data)
    }
}