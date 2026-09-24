// Draws the app icon, the DLPrevent emblem (output/branding/dlprevent-emblem.svg)
// on the macOS icon grid, and writes an .icns.
// Call: swift icon/make-icon.swift <target.icns>
import AppKit

let out = CommandLine.arguments.dropFirst().first ?? "AppIcon.icns"
let tmp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("deelpe-\(getpid()).iconset")
try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)

func render(_ px: Int) -> Data {
    let s = CGFloat(px)
    let img = NSImage(size: NSSize(width: s, height: s))
    img.lockFocus()
    guard let ctx = NSGraphicsContext.current?.cgContext else { fatalError("kein Kontext") }
    ctx.clear(CGRect(x: 0, y: 0, width: s, height: s))

    // macOS grid: tile ~82 % of the area, corner radius ~22 % of the tile.
    let inset = s * 0.09
    let tile = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let radius = tile.width * 0.225
    let path = NSBezierPath(roundedRect: tile, xRadius: radius, yRadius: radius)

    // Shadow under the tile
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.012), blur: s * 0.03, color: NSColor.black.withAlphaComponent(0.35).cgColor)
    NSColor(calibratedRed: 0.13, green: 0.32, blue: 0.62, alpha: 1).setFill()
    path.fill()
    ctx.restoreGState()

    // The emblem's own tile colour.
    path.addClip()
    NSColor(srgbRed: 0xfa / 255, green: 0xf8 / 255, blue: 0xf4 / 255, alpha: 1).setFill()
    tile.fill()

    // The SVG's paths, in its 128 × 128 viewBox (y down), with its
    // `translate(12 10) scale(.9)`.
    ctx.translateBy(x: tile.minX, y: tile.maxY)
    ctx.scaleBy(x: tile.width / 128, y: -tile.height / 128)
    ctx.translateBy(x: 12, y: 10)
    ctx.scaleBy(x: 0.9, y: 0.9)
    let d = CGMutablePath()
    d.move(to: CGPoint(x: 8, y: 8))
    d.addLine(to: CGPoint(x: 55, y: 8))
    d.addCurve(to: CGPoint(x: 108, y: 60), control1: CGPoint(x: 87, y: 8), control2: CGPoint(x: 108, y: 29))
    d.addCurve(to: CGPoint(x: 55, y: 112), control1: CGPoint(x: 108, y: 91), control2: CGPoint(x: 87, y: 112))
    d.addLine(to: CGPoint(x: 8, y: 112))
    d.addLine(to: CGPoint(x: 8, y: 90))
    d.addLine(to: CGPoint(x: 54, y: 90))
    d.addCurve(to: CGPoint(x: 84, y: 60), control1: CGPoint(x: 73, y: 90), control2: CGPoint(x: 84, y: 79))
    d.addCurve(to: CGPoint(x: 54, y: 30), control1: CGPoint(x: 84, y: 41), control2: CGPoint(x: 73, y: 30))
    d.addLine(to: CGPoint(x: 8, y: 30))
    d.closeSubpath()
    ctx.addPath(d)
    ctx.setFillColor(CGColor(srgbRed: 0x17 / 255, green: 0x18 / 255, blue: 0x1a / 255, alpha: 1))
    ctx.fillPath()
    ctx.setFillColor(CGColor(srgbRed: 0x9e / 255, green: 0x47 / 255, blue: 0x08 / 255, alpha: 1))
    ctx.fill(CGRect(x: 16, y: 43, width: 34, height: 34))
    img.unlockFocus()

    let rep = NSBitmapImageRep(cgImage: img.cgImage(forProposedRect: nil, context: nil, hints: nil)!)
    rep.size = NSSize(width: s, height: s)
    return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
    try render(base).write(to: tmp.appendingPathComponent("icon_\(base)x\(base).png"))
    try render(base * 2).write(to: tmp.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", tmp.path, "-o", out]
try p.run(); p.waitUntilExit()
try? FileManager.default.removeItem(at: tmp)
guard p.terminationStatus == 0 else { exit(1) }
