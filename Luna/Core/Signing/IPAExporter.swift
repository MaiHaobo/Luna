//
//  IPAExporter.swift
//  Luna
//
//  Repackages a signed bundle as an installable `.ipa`.
//
//  WHY NOT `ZIPWriter`
//  -------------------
//  `ZIPWriter.build(entries:)` takes an array of in-memory `Data` and returns
//  one in-memory `Data`. That is the right shape for the small archives it was
//  written for. It is the wrong shape here: a signed guest can be several
//  gigabytes, and materialising that twice — once as entries, once as output —
//  is an out-of-memory crash on a phone, not a slow success. So this file
//  writes *streaming*, in the same stored-only format, using the same
//  little-endian primitives and the same CRC-32.
//
//  Stored (uncompressed) is again the deliberate choice: the payload is
//  already mostly incompressible binaries and media, deflating multi-gigabyte
//  bundles on device costs minutes for a few percent, and the consumers —
//  AltStore, SideStore, `ideviceinstaller` — do not look at the ratio.
//
//  WHAT AN IPA ACTUALLY IS
//  -----------------------
//  A ZIP with exactly one top-level directory, `Payload/`, containing exactly
//  one `.app`. Anything else is rejected by every installer, so the layout
//  here is not a convention to be relaxed:
//
//      Payload/
//      Payload/Example.app/
//      Payload/Example.app/Info.plist
//      …
//
//  Installation note, surfaced in the UI rather than buried here: an IPA
//  signed with a development profile only installs on devices whose UDID is
//  in that profile. Exporting does not change that — it just produces the
//  file. An enterprise profile has no such limit.
//

import Foundation

/// What an export produced.
struct IPAExportReport {
    /// The `.ipa` on disk.
    var url: URL
    /// Size of the finished archive.
    var byteCount: Int64
    /// Files written into the archive.
    var fileCount: Int

    var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: byteCount, countStyle: .file)
    }
}

enum IPAExporter {

    /// Packages `bundleURL` into `destination`.
    ///
    /// The bundle must already be signed, and — when a certificate was used —
    /// must already carry its `embedded.mobileprovision`. Nothing here signs
    /// or patches anything; this is purely repackaging, deliberately, so that
    /// the file it writes is a byte-for-byte record of what was signed.
    ///
    /// - Parameters:
    ///   - bundleURL: the signed `.app` directory.
    ///   - destination: where to write the `.ipa`.
    ///   - progress: called with a short stage label and a 0…1 fraction.
    static func export(
        bundleURL: URL,
        to destination: URL,
        progress: ((String, Double) -> Void)? = nil
    ) throws -> IPAExportReport {

        let fm = FileManager.default

        guard fm.fileExists(atPath: bundleURL.path) else {
            throw CodeSignError.signingFailed(
                "找不到已签名的 bundle：\(bundleURL.lastPathComponent)")
        }

        // Collect and sort first: the walk has to be complete before the first
        // entry is written, because the ZIP's central directory is only
        // assemblable at the end either way, and a deterministic order makes
        // two exports of the same bundle byte-identical.
        progress?("扫描 bundle…", 0)
        let files = try collectFiles(in: bundleURL)
        guard !files.isEmpty else {
            throw CodeSignError.signingFailed("bundle 是空的")
        }
        guard files.count <= 0xFFFF else {
            throw ZIPWriterError.tooManyEntries(files.count)
        }

        // Write to a temporary file beside the destination and move it into
        // place at the end. A half-written IPA that a user shares because it
        // exists is worse than no file at all.
        let temporary = destination
            .deletingLastPathComponent()
            .appendingPathComponent(".\(UUID().uuidString).ipa.partial")
        fm.createFile(atPath: temporary.path, contents: nil)
        guard let handle = FileHandle(forWritingAtPath: temporary.path) else {
            throw CodeSignError.signingFailed("无法创建导出文件：\(temporary.lastPathComponent)")
        }
        defer { try? handle.close() }

        var offset: Int64 = 0
        var records: [ExportCentralRecord] = []
        records.reserveCapacity(files.count)

        let (dosTime, dosDate) = DosTimestamp.make(Date())

        do {
            for (index, file) in files.enumerated() {
                let pathBytes = Data(file.archivePath.utf8)
                let data = try Data(contentsOf: file.url, options: .mappedIfSafe)
                let crc = CRC32.checksum(data)

                var local = Data()
                local.appendLE(0x0403_4B50)          // local file header
                local.appendLE16(20)                 // version needed: 2.0
                local.appendLE16(0x0800)             // UTF-8 names
                local.appendLE16(0)                  // stored
                local.appendLE16(dosTime)
                local.appendLE16(dosDate)
                local.appendLE(crc)
                local.appendLE(UInt32(data.count))
                local.appendLE(UInt32(data.count))
                local.appendLE16(UInt16(pathBytes.count))
                local.appendLE16(0)                  // no extra field
                local.append(pathBytes)

                try handle.write(contentsOf: local)
                try handle.write(contentsOf: data)

                records.append(ExportCentralRecord(
                    pathBytes: pathBytes,
                    crc: crc,
                    size: data.count,
                    localOffset: offset))
                offset += Int64(local.count) + Int64(data.count)

                guard offset <= Int64(UInt32.max) else {
                    throw ZIPWriterError.archiveTooLarge(Int(offset))
                }

                if index % 32 == 0 || index == files.count - 1 {
                    progress?("打包 IPA…", Double(index + 1) / Double(files.count))
                }
            }

            // ── Central directory ───────────────────────────────────────────
            let centralStart = offset
            var central = Data()
            for record in records {
                central.appendLE(0x0201_4B50)        // central file header
                central.appendLE16(20)               // version made by
                central.appendLE16(20)               // version needed
                central.appendLE16(0x0800)           // UTF-8 names
                central.appendLE16(0)                // stored
                central.appendLE16(dosTime)
                central.appendLE16(dosDate)
                central.appendLE(record.crc)
                central.appendLE(UInt32(record.size))
                central.appendLE(UInt32(record.size))
                central.appendLE16(UInt16(record.pathBytes.count))
                central.appendLE16(0)                // extra
                central.appendLE16(0)                // comment
                central.appendLE16(0)                // disk start
                central.appendLE16(0)                // internal attrs
                // External attributes: 0o100644 in the high 16 bits, which is
                // the Unix mode some installers read to tell a file from a
                // directory. The low byte stays zero (MS-DOS attribute).
                central.appendLE(UInt32(0o100644) << 16)
                central.appendLE(UInt32(record.localOffset))
                central.append(record.pathBytes)
            }
            try handle.write(contentsOf: central)

            // ── End of central directory ────────────────────────────────────
            var eocd = Data()
            eocd.appendLE(0x0605_4B50)
            eocd.appendLE16(0)                       // this disk
            eocd.appendLE16(0)                       // disk with central dir
            eocd.appendLE16(UInt16(records.count))
            eocd.appendLE16(UInt16(records.count))
            eocd.appendLE(UInt32(central.count))
            eocd.appendLE(UInt32(centralStart))
            eocd.appendLE16(0)                       // comment length
            try handle.write(contentsOf: eocd)

            offset = centralStart + Int64(central.count) + Int64(eocd.count)
            try handle.close()
        } catch {
            try? handle.close()
            try? fm.removeItem(at: temporary)
            throw error
        }

        // Move into place.
        try? fm.removeItem(at: destination)
        do {
            try fm.moveItem(at: temporary, to: destination)
        } catch {
            try? fm.removeItem(at: temporary)
            throw CodeSignError.signingFailed(
                "无法写入导出文件：\(error.localizedDescription)")
        }

        progress?("导出完成", 1)

        return IPAExportReport(
            url: destination,
            byteCount: offset,
            fileCount: files.count)
    }

    // MARK: - Internals

    private struct ExportCentralRecord {
        let pathBytes: Data
        let crc: UInt32
        let size: Int
        let localOffset: Int64
    }

    private struct FileEntry {
        let url: URL
        /// Path inside the archive, e.g. `Payload/Example.app/Info.plist`.
        let archivePath: String
    }

    /// Every regular file in the bundle, with its archive-relative path.
    ///
    /// The top-level directory is named after the bundle itself, so the
    /// archive is `Payload/<whatever>.app/…` — the name is preserved rather
    /// than normalised because `Info.plist` and the profile's application
    /// identifier do not care, but a user extracting the IPA by hand
    /// certainly does.
    private static func collectFiles(in bundleURL: URL) throws -> [FileEntry] {
        let bundleName = bundleURL.lastPathComponent
        let root = bundleURL.standardizedFileURL.path

        guard let enumerator = FileManager.default.enumerator(
            at: bundleURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: []
        ) else {
            throw CodeSignError.signingFailed(
                "无法遍历 bundle：\(bundleName)")
        }

        var files: [FileEntry] = []

        for case let url as URL in enumerator {
            let values = try? url.resourceValues(
                forKeys: [.isRegularFileKey, .isDirectoryKey])
            guard values?.isRegularFile == true else { continue }

            // AppleDouble sidecars and `.DS_Store` are filesystem noise. An
            // installer does not care, but they are a few hundred bytes each
            // in an archive the user may be squeezing onto a device, and they
            // serve no purpose in the file.
            let name = url.lastPathComponent
            if name.hasPrefix("._") || name == ".DS_Store" { continue }

            let full = url.standardizedFileURL.path
            guard full.hasPrefix(root) else { continue }
            var relative = String(full.dropFirst(root.count))
            while relative.hasPrefix("/") { relative.removeFirst() }
            guard !relative.isEmpty else { continue }

            files.append(FileEntry(
                url: url,
                archivePath: "Payload/\(bundleName)/\(relative)"))
        }

        files.sort { $0.archivePath < $1.archivePath }
        return files
    }
}

/// MS-DOS packed date/time, as ZIP headers carry it.
///
/// Duplicated from `ZIPWriter` rather than shared: the two writers are
/// otherwise independent, and reaching into one to borrow a private helper
/// would couple the small in-memory writer to this streaming one for the sake
/// of six lines.
private enum DosTimestamp {
    static func make(_ date: Date) -> (time: UInt16, date: UInt16) {
        let calendar = Calendar(identifier: .gregorian)
        let parts = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: date)
        let year = max(0, (parts.year ?? 1980) - 1980)
        let time = UInt16(((parts.hour ?? 0) << 11)
            | ((parts.minute ?? 0) << 5)
            | ((parts.second ?? 0) / 2))
        let day = UInt16((year << 9) | ((parts.month ?? 1) << 5) | (parts.day ?? 1))
        return (time, day)
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    mutating func appendLE16(_ value: UInt16) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}
