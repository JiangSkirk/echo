// JS Agent — deterministic app-icon renderer (CoreText/CoreGraphics).
// Renders the iconset PNGs + 1024 master from the same layout as icon.svg:
// warm ivory rounded square, pine-green "JS", one small cinnabar dot.
// Usage: swift render_icons.swift <output_dir>
// No third-party dependencies; runs on stock macOS Swift.

import AppKit
import CoreText
import Foundation

let ivory = NSColor(calibratedRed: 0xFC / 255.0, green: 0xFB / 255.0, blue: 0xF7 / 255.0, alpha: 1.0)
let border = NSColor(calibratedRed: 0xE3 / 255.0, green: 0xDE / 255.0, blue: 0xD0 / 255.0, alpha: 1.0)
let pine = NSColor(calibratedRed: 0x35 / 255.0, green: 0x5D / 255.0, blue: 0x4C / 255.0, alpha: 1.0)
let cinnabar = NSColor(calibratedRed: 0xB8 / 255.0, green: 0x4F / 255.0, blue: 0x3B / 255.0, alpha: 1.0)

func brandFont(size: CGFloat) -> CTFont {
    // Deterministic font source: macOS system fonts only, explicit fallbacks.
    let candidates = ["SongtiSC-Bold", "STSongti-SC-Bold", "Songti SC", "PingFangSC-Semibold"]
    for name in candidates {
        if let font = CTFontCreateWithName(name as CFString, size, nil) as CTFont? {
            return font
        }
    }
    return CTFontCreateWithName("HelveticaNeue-Bold" as CFString, size, nil)
}

func renderIcon(pixel size: Int, to url: URL) throws {
    let s = CGFloat(size)
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(
        data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
        space: colorSpace,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else {
        throw NSError(domain: "render_icons", code: 1)
    }
    // Transparent background; the rounded square carries the icon.
    ctx.clear(CGRect(x: 0, y: 0, width: s, height: s))

    let inset = s * 0.105
    let rect = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let radius = s * 0.176
    let path = CGPath(
        roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil
    )
    ctx.setFillColor(ivory.cgColor)
    ctx.addPath(path)
    ctx.fillPath()
    ctx.setStrokeColor(border.cgColor)
    ctx.setLineWidth(max(1.0, s / 512.0))
    ctx.addPath(path)
    ctx.strokePath()

    // "JS" wordmark, optically centered.
    let font = brandFont(size: s * 0.42)
    let attributes: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: pine,
    ]
    let text = NSAttributedString(string: "JS", attributes: attributes)
    let line = CTLineCreateWithAttributedString(text)
    let bounds = CTLineGetBoundsWithOptions(line, .useOpticalBounds)
    let tx = rect.midX - bounds.midX
    let ty = rect.midY - bounds.midY - s * 0.012
    ctx.textPosition = CGPoint(x: tx, y: ty)
    CTLineDraw(line, ctx)

    // One small cinnabar dot, lower-right of the wordmark.
    let dotD = s * 0.047
    let dotX = tx + bounds.width + s * 0.028
    let dotY = ty + s * 0.012
    ctx.setFillColor(cinnabar.cgColor)
    ctx.fillEllipse(in: CGRect(x: dotX, y: dotY, width: dotD, height: dotD))

    guard let image = ctx.makeImage() else {
        throw NSError(domain: "render_icons", code: 2)
    }
    guard let dest = CGImageDestinationCreateWithURL(
        url as CFURL, "public.png" as CFString, 1, nil
    ) else {
        throw NSError(domain: "render_icons", code: 3)
    }
    CGImageDestinationAddImage(dest, image, nil)
    if !CGImageDestinationFinalize(dest) {
        throw NSError(domain: "render_icons", code: 4)
    }
}

// macOS iconset slots: (filename, pixel size)
let slots: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]

let args = CommandLine.arguments
guard args.count == 2 else {
    FileHandle.standardError.write("usage: swift render_icons.swift <output_dir>\n".data(using: .utf8)!)
    exit(64)
}
let outDir = URL(fileURLWithPath: args[1], isDirectory: true)
try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
for (name, pixels) in slots {
    try renderIcon(pixel: pixels, to: outDir.appendingPathComponent(name))
}
try renderIcon(pixel: 1024, to: outDir.appendingPathComponent("icon-master-1024.png"))
print("rendered \(slots.count + 1) pngs into \(outDir.path)")
