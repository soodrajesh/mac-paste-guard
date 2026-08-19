import Foundation

/// Append-only local log of decisions.
///
/// The single hard rule of this file: **the pasted text never enters it.**
/// Not the match, not a hash of the match, not a preview. Only what kind of
/// thing was found, how many, where it was headed, and what the user chose.
/// That constraint is the product's entire claim — a team dashboard built on
/// this log can be shared with a security team without ever handing them the
/// contents of anyone's clipboard.
enum AuditLog {
    struct Entry: Codable {
        let timestamp: String
        let destinationApp: String
        let destinationDetail: String?
        let findings: [String: Int]     // kind -> count
        let highestSeverity: String
        let decision: String
        let charactersScanned: Int      // size only, never content
    }

    private static let directory: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("PasteGuard", isDirectory: true)
    }()

    static var fileURL: URL { directory.appendingPathComponent("audit.jsonl") }

    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func record(destination: Destination,
                       findings: [Finding],
                       decision: String,
                       charactersScanned: Int) {
        var counts: [String: Int] = [:]
        for finding in findings { counts[finding.kind, default: 0] += 1 }

        let entry = Entry(
            timestamp: formatter.string(from: Date()),
            destinationApp: destination.appName,
            destinationDetail: destination.detail,
            findings: counts,
            highestSeverity: (findings.map(\.severity).max() ?? .medium).label,
            decision: decision,
            charactersScanned: charactersScanned
        )

        guard let data = try? JSONEncoder().encode(entry) else { return }
        var line = data
        line.append(0x0A)

        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: fileURL.path) {
                let handle = try FileHandle(forWritingTo: fileURL)
                defer { try? handle.close() }
                try handle.seekToEnd()
                try handle.write(contentsOf: line)
            } else {
                try line.write(to: fileURL, options: .atomic)
            }
        } catch {
            // A failure to log must never block or alter a paste decision the
            // user has already made.
            NSLog("PasteGuard: could not write audit entry: \(error.localizedDescription)")
        }
    }

    /// Menu bytes to read from the tail of the file, not the whole thing.
    /// `menuNeedsUpdate` calls this on the main thread every time the
    /// menubar icon is clicked, and the log has no rotation — over months of
    /// daily use it would otherwise mean parsing an ever-growing file on
    /// every click. Each line is well under 300 bytes, so this comfortably
    /// covers hundreds of entries regardless of how large the file has grown.
    private static let tailReadBytes = 64 * 1024

    static func recentEntries(limit: Int = 20) -> [Entry] {
        guard let handle = try? FileHandle(forReadingFrom: fileURL) else { return [] }
        defer { try? handle.close() }

        guard let fileSize = try? handle.seekToEnd() else { return [] }
        let readSize = min(fileSize, UInt64(tailReadBytes))
        guard readSize > 0 else { return [] }

        do {
            try handle.seek(toOffset: fileSize - readSize)
        } catch {
            return []
        }
        guard let chunk = try? handle.readToEnd(), let contents = String(data: chunk, encoding: .utf8) else {
            return []
        }

        // The read may start mid-line if it didn't happen to land on a file
        // boundary; drop that leading partial line rather than fail to parse
        // a truncated entry.
        var lines = contents.split(separator: "\n", omittingEmptySubsequences: true)
        if readSize < fileSize, !lines.isEmpty { lines.removeFirst() }

        let decoder = JSONDecoder()
        return lines
            .suffix(limit)
            .compactMap { try? decoder.decode(Entry.self, from: Data($0.utf8)) }
            .reversed()
    }
}
