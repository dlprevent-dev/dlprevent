import Foundation

/// Export of the alerts as CSV or JSON, for the app's save dialog. The same
/// CSV columns as `deelpe export` (Rust); JSON has the fields of the wire
/// format. Values such as the identity description follow the app's language
/// (English), timestamps carry milliseconds.
///
/// Until 2026-09-08 the IP reputation lived here as the `abuse_score` column.
/// It now comes from the central server and is exported there, no longer per
/// Mac.
public enum AlertExport {
    public static let csvHeader = "id,time,process,identity,pid,destination,port,bytes_out,files,via,verdict,reason"

    public static func csv(_ alerts: [Alert]) -> String {
        var out = csvHeader + "\n"
        for a in alerts {
            let fields: [String] = [
                String(a.id),
                isoFractional.string(from: a.at),
                a.identity.short,
                a.identity.description,
                String(a.pid),
                a.remote ?? "",
                a.remotePort.map(String.init) ?? "",
                String(a.bytesOut),
                a.files.joined(separator: "; "),
                a.via ?? "",
                a.verdict,
                a.reason ?? "",
            ]
            out += fields.map(csvField).joined(separator: ",") + "\n"
        }
        return out
    }

    /// RFC 4180: fields containing a comma, a quote or a line break go in
    /// quotes, inner quotes are doubled. A `;` or TAB is quoted too.
    ///
    /// Quoting does not stop a spreadsheet from evaluating a cell that starts
    /// with `=`, `+`, `-`, `@`, TAB or CR, and file names are attacker input.
    /// Such a cell gets a leading `'`, which every spreadsheet reads as
    /// "text"; a BOM, zero-width character or space in front does not hide
    /// the trigger. The same after every `;`, TAB and line break inside the
    /// value: a spreadsheet in a `;` locale splits there and honours a quote
    /// only at the start of a field. Same rule as `csv_field` in Rust.
    /// Checked per scalar, since "\r\n" or "=" plus a combining mark is a
    /// single `Character`.
    static func csvField(_ s: String) -> String {
        var out: [Unicode.Scalar] = []
        var mark: Int? = 0
        for c in s.unicodeScalars {
            if let m = mark, !"\u{FEFF}\u{200B}\u{200C}\u{200D} ".unicodeScalars.contains(c) {
                if "=+-@\t\r".unicodeScalars.contains(c) { out.insert("'", at: m) }
                mark = nil
            }
            out.append(c)
            if ";\t\n\r".unicodeScalars.contains(c) { mark = out.count }
        }
        var view = String.UnicodeScalarView()
        view.append(contentsOf: out)
        let s = String(view)
        guard s.unicodeScalars.contains(where: { ",\"\n\r;\t".unicodeScalars.contains($0) }) else { return s }
        return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    public static func json(_ alerts: [Alert]) throws -> Data {
        let rows: [[String: Any]] = alerts.map { a in
            var d: [String: Any] = [
                "id": a.id,
                "at": isoFractional.string(from: a.at),
                "pid": a.pid,
                "identity": a.identity.json,
                "files": a.files,
                "remote": a.remote ?? NSNull(),
                "remote_port": a.remotePort ?? NSNull(),
                "bytes_out": a.bytesOut,
            ]
            if let v = a.via { d["via"] = v }
            d["verdict"] = a.verdict
            if let r = a.reason { d["reason"] = r }
            return d
        }
        return try JSONSerialization.data(withJSONObject: rows, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }
}

extension ProcessIdentity {
    /// Externally tagged form as in the wire format (`{"Signed":{...}}`).
    var json: [String: [String: String]] {
        switch self {
        case .signed(let team, let id): return ["Signed": ["team_id": team, "signing_id": id]]
        case .hashed(let path, let sha): return ["Hashed": ["path": path, "sha256": sha]]
        case .unknown(let path): return ["Unknown": ["path": path]]
        }
    }
}
