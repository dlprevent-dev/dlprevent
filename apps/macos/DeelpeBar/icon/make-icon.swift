// Draws the app icon (rounded square, blue gradient, white lock shield) and
// writes an .icns. Call: swift icon/make-icon.swift <ziel.icns>
// Deliberately plain, the same symbol as in the menu bar (lock.shield.fill).
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

    // Gradient: light blue at the top, dark navy at the bottom
    path.addClip()
    let g = NSGradient(colors: [NSColor(calibratedRed: 0.27, green: 0.56, blue: 0.93, alpha: 1),
                                NSColor(calibratedRed: 0.09, green: 0.22, blue: 0.48, alpha: 1)])!
    g.draw(in: tile, angle: -90)

    // White lock shield
    let cfg = NSImage.SymbolConfiguration(pointSize: tile.width * 0.56, weight: .medium)
    guard let sym = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil)?.withSymbolConfiguration(cfg) else {
        fatalError("Symbol fehlt")
    }
    let white = NSImage(size: sym.size, flipped: false) { r in
        sym.draw(in: r)
        NSColor.white.set()
        r.fill(using: .sourceAtop)
        return true
    }
    let sz = white.size
    let origin = CGPoint(x: tile.midX - sz.width / 2, y: tile.midY - sz.height / 2 + tile.height * 0.01)
    white.draw(in: CGRect(origin: origin, size: sz))
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
