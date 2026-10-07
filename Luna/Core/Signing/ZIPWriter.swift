//
//  ZIPWriter.swift
//  Luna
//
//  A minimal ZIP writer — the counterpart to `IPAArchive`.
//
//  Re-signing rewrites files inside an IPA, so the archive has to be rebuilt.
//  We emit `stored` (uncompressed) entries only, which sounds wasteful and is
//  actually the right call here:
//
//    • An IPA is already mostly incompressible binaries and media; re-deflating
//      a multi-gigabyte bundle costs minutes of CPU on a phone for a few
//      percent.
//    • The output is a signed artifact that will be consumed by AltStore,
//      SideStore, or a manual `installd` — none of which care about the
//      compression ratio.
//    • It keeps this file free of a compressor, so the code that writes user
//      archives cannot itself corrupt them.
//
//  Scope matches `IPAArchive`: no ZIP64. An archive beyond 4 GB or 65535
//  entries is reported as unsupported rather than silently truncated — that
//  limit is well past any App Store IPA, and silently producing a corrupt
//  archive is far worse than a clear error.
//

import Foundation

enum ZIPWriterError: LocalizedError {
    case tooManyEntries(Int)
    case archiveTooLarge(Int)
    case unsupportedCompression(UInt16)

    var errorDescription: String? {
        switch self {
        case .tooManyEntries(let count):
            return "条目过多（\(count) 个），超出 ZIP 格式上限（65535）"
        case .archiveTooLarge(let size):
            return "归档过大（\(size) 字节），需要 ZIP64 支持"
        case .unsupportedCompression(let method):
            return "不支持的压缩方式（method=\(method)）"
        }
    }
}

/// One file to write into the archive.
struct ZIPWriteEntry {
    /// Path inside the archive, with `/` separators and no leading slash.
    let path: String
    /// Uncompressed contents.
    let data: Data
}

enum ZIPWriter {

    private static let localHeaderSignature: UInt32 = 0x0403_4B50
    private static let centralHeaderSignature: UInt32 = 0x0201_4B50
    private static let endOfCentralDirectorySignature: UInt32 = 0x0605_4B50

    /// Builds a stored-only ZIP archive from `entries`.
    ///
    /// Directory entries are implied by the file paths, matching what
    /// `IPAArchive.extract` expects on the way back in.
    static func build(entries: [ZIPWriteEntry]) throws -> Data {
        guard entries.count <= 0xFFFF else {
            throw ZIPWriterError.tooManyEntries(entries.count)
        }

        var output = Data()
        var centralDirectory = Data()

        // Records what the central directory needs for each entry.
        struct CentralRecord {
            let pathBytes: Data
            let crc: UInt32
            let size: Int
            let localOffset: Int
        }
        var records: [CentralRecord] = []
        records.reserveCapacity(entries.count)

        let (dosTime, dosDate) = dosTimestamp(Date())

        for entry in entries {
            guard output.count <= Int(UInt32.max) else {
                throw ZIPWriterError.archiveTooLarge(output.count)
            }
            let localOffset = output.count

            let pathBytes = Data(entry.path.utf8)
            let crc = CRC32.checksum(entry.data)
            let size = entry.data.count

            // ── Local file header (30 bytes + name) ─────────────────────────
            //   0  signature          4
            //   4  version needed     2   (20 = 2.0, no compression features)
            //   6  flags              2   (bit 11 set: names are UTF-8)
            //   8  compression method 2   (0 = stored)
            //  10  mod time           2
            //  12  mod date           2
            //  14  crc32              4
            //  18  compressed size    4
            //  22  uncompressed size  4
            //  26  filename length    2
            //  28  extra length       2
            //  30  filename           n
            var header = Data()
            header.appendLE(localHeaderSignature)
            header.appendLE16(20)
            header.appendLE16(0x0800)
            header.appendLE16(0)            // stored
            header.appendLE16(dosTime)
            header.appendLE16(dosDate)
            header.appendLE(crc)
            header.appendLE(UInt32(size))
            header.appendLE(UInt32(size))
            header.appendLE16(UInt16(pathBytes.count))
            header.appendLE16(0)            // no extra field
            header.append(pathBytes)

            output.append(header)
            output.append(entry.data)

            records.append(CentralRecord(
                pathBytes: pathBytes, crc: crc, size: size, localOffset: localOffset))
        }

        // ── Central directory ───────────────────────────────────────────────
        let centralStart = output.count
        for record in records {
            //  0  signature            4
            //  4  version made by      2
            //  6  version needed       2
            //  8  flags                2
            // 10  compression method   2
            // 12  mod time             2
            // 14  mod date             2
            // 16  crc32                4
            // 20  compressed size      4
            // 24  uncompressed size    4
            // 28  filename length      2
            // 30  extra length         2
            // 32  comment length       2
            // 34  disk number start    2
            // 36  internal attrs       2
            // 38  external attrs       4
            // 42  local header offset  4
            // 46  filename             n
            var entry = Data()
            entry.appendLE(centralHeaderSignature)
            entry.appendLE16(20)            // version made by
            entry.appendLE16(20)            // version needed
            entry.appendLE16(0x0800)        // UTF-8 names
            entry.appendLE16(0)             // stored
            entry.appendLE16(dosTime)
            entry.appendLE16(dosDate)
            entry.appendLE(record.crc)
            entry.appendLE(UInt32(record.size))
            entry.appendLE(UInt32(record.size))
            entry.appendLE16(UInt16(record.pathBytes.count))
            entry.appendLE16(0)             // extra
            entry.appendLE16(0)             // comment
            entry.appendLE16(0)             // disk start
            entry.appendLE16(0)             // internal attrs
            entry.appendLE(UInt32(0))       // external attrs
            entry.appendLE(UInt32(record.localOffset))
            entry.append(record.pathBytes)
            centralDirectory.append(entry)
        }

        output.append(centralDirectory)
        let centralSize = centralDirectory.count

        // ── End of central directory ────────────────────────────────────────
        var eocd = Data()
        eocd.appendLE(endOfCentralDirectorySignature)
        eocd.appendLE16(0)                                  // this disk
        eocd.appendLE16(0)                                  // disk with CD
        eocd.appendLE16(UInt16(records.count))              // entries on disk
        eocd.appendLE16(UInt16(records.count))              // total entries
        eocd.appendLE(UInt32(centralSize))
        eocd.appendLE(UInt32(centralStart))
        eocd.appendLE16(0)                                  // comment length
        output.append(eocd)

        return output
    }

    /// MS-DOS packed date/time, which is what ZIP headers carry.
    ///
    /// Field layout is unusually dense: bits 0-4 seconds/2, 5-10 minutes,
    /// 11-15 hours; date year is an offset from 1980.
    private static func dosTimestamp(_ date: Date) -> (time: UInt16, date: UInt16) {
        let calendar = Calendar(identifier: .gregorian)
        let parts = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: date)
        let year = max(0, (parts.year ?? 1980) - 1980)
        let month = parts.month ?? 1
        let day = parts.day ?? 1
        let hour = parts.hour ?? 0
        let minute = parts.minute ?? 0
        let second = (parts.second ?? 0) / 2

        let time = UInt16((hour << 11) | (minute << 5) | second)
        let date = UInt16((year << 9) | (month << 5) | day)
        return (time, date)
    }
}

/// CRC-32 (IEEE 802.3), the checksum every ZIP entry carries.
enum CRC32 {

    private static let table: [UInt32] = {
        var table = [UInt32](repeating: 0, count: 256)
        for index in 0..<256 {
            var value = UInt32(index)
            for _ in 0..<8 {
                value = (value & 1) != 0
                    ? 0xEDB8_8320 ^ (value >> 1)
                    : value >> 1
            }
            table[index] = value
        }
        return table
    }()

    static func checksum(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            let index = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = table[index] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
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
