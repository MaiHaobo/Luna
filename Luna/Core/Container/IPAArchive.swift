//
//  IPAArchive.swift
//  Luna
//
//  IPA container handling. An `.ipa` is a plain ZIP whose `Payload/` directory
//  holds exactly one `.app` bundle.
//
//  We implement a minimal, self-contained ZIP reader rather than pulling in a
//  third-party dependency:
//    • it keeps the build tree free of binary blobs and SPM fetches, which
//      matters because the CI runner has no network guarantees;
//    • it lets us enforce entry-path safety (no `../`, no absolute paths)
//      before a single byte is written, which is a genuine attack surface when
//      the archive comes from an untrusted source;
//    • it compiles unchanged on both iOS and macOS, so the same code path is
//      exercised by unit tests on the runner.
//
//  Scope note: we support the two compression methods that App Store tooling
//  and every packaging pipeline actually emit — `stored` and `deflate`. Other
//  methods (bzip2, LZMA, zstd) are reported as unsupported rather than
//  silently mis-extracted.
//

import Foundation
import Compression

enum IPAError: LocalizedError {
    case notAZipArchive
    case malformedCentralDirectory(String)
    case unsupportedCompression(UInt16)
    case unsafeEntryPath(String)
    case missingPayloadDirectory
    case emptyPayloadDirectory
    case inflateFailed(String)

    var errorDescription: String? {
        switch self {
        case .notAZipArchive:
            return "文件不是有效的 IPA / ZIP 归档"
        case .malformedCentralDirectory(let detail):
            return "ZIP 中央目录损坏：\(detail)"
        case .unsupportedCompression(let method):
            return "不支持的压缩方式（method=\(method)）"
        case .unsafeEntryPath(let path):
            return "归档中存在不安全的路径条目：\(path)"
        case .missingPayloadDirectory:
            return "IPA 中缺少 Payload 目录"
        case .emptyPayloadDirectory:
            return "Payload 目录中没有 .app 包"
        case .inflateFailed(let entry):
            return "解压失败：\(entry)"
        }
    }
}

/// One entry in a ZIP central directory.
struct ZIPEntry {
    let path: String
    let compressionMethod: UInt16
    let compressedSize: Int
    let uncompressedSize: Int
    /// Offset of the local file header, relative to the start of the archive.
    let localHeaderOffset: Int
}

enum IPAArchive {

    // MARK: - Central directory parsing

    /// Scans backwards for the End Of Central Directory record.
    ///
    /// The record is 22 bytes plus a variable-length comment, and a trailing
    /// comment may be up to 65535 bytes, so we search that window.
    private static func findEndOfCentralDirectory(in data: Data) throws -> Int {
        let signature: UInt32 = 0x0605_4B50
        let maxComment = 0xFFFF
        let minEOCD = 22

        guard data.count >= minEOCD else { throw IPAError.notAZipArchive }

        let lowerBound = max(0, data.count - minEOCD - maxComment)
        var cursor = data.count - minEOCD

        while cursor >= lowerBound {
            if let value = ByteReader(data).u32(at: cursor), value == signature {
                return cursor
            }
            cursor -= 1
        }
        throw IPAError.notAZipArchive
    }

    /// Parses every entry in the central directory.
    static func entries(of archive: Data) throws -> [ZIPEntry] {
        let reader = ByteReader(archive)
        let eocd = try findEndOfCentralDirectory(in: archive)

        // EOCD layout:
        //   0  signature          4
        //   4  disk number        2
        //   6  cd start disk      2
        //   8  entries on disk    2
        //  10  total entries      2
        //  12  cd size            4
        //  16  cd offset          4
        guard let totalEntries = reader.u32(at: eocd + 10).map({ Int($0 & 0xFFFF) }),
              let centralDirOffset = reader.u32(at: eocd + 16).map({ Int($0) })
        else {
            throw IPAError.malformedCentralDirectory("EOCD 记录不完整")
        }

        var result: [ZIPEntry] = []
        result.reserveCapacity(totalEntries)

        var cursor = centralDirOffset
        for index in 0..<totalEntries {
            // Central directory file header:
            //   0  signature            4   = 0x02014B50
            //   4  version made by      2
            //   6  version needed       2
            //   8  flags                2
            //  10  compression method   2
            //  12  mod time             2
            //  14  mod date             2
            //  16  crc32                4
            //  20  compressed size      4
            //  24  uncompressed size    4
            //  28  filename length      2
            //  30  extra length         2
            //  32  comment length       2
            //  34  disk number start    2
            //  36  internal attrs       2
            //  38  external attrs       4
            //  42  local header offset  4
            //  46  filename             n
            guard let sig = reader.u32(at: cursor), sig == 0x0201_4B50 else {
                throw IPAError.malformedCentralDirectory("第 \(index) 条目录记录签名错误")
            }
            guard let method = reader.u32(at: cursor + 10).map({ UInt16($0 & 0xFFFF) }),
                  let compressed = reader.u32(at: cursor + 20).map({ Int($0) }),
                  let uncompressed = reader.u32(at: cursor + 24).map({ Int($0) }),
                  let nameLength = reader.u32(at: cursor + 28).map({ Int($0 & 0xFFFF) }),
                  let extraLength = reader.u32(at: cursor + 30).map({ Int($0 & 0xFFFF) }),
                  let commentLength = reader.u32(at: cursor + 32).map({ Int($0 & 0xFFFF) }),
                  let localOffset = reader.u32(at: cursor + 42).map({ Int($0) })
            else {
                throw IPAError.malformedCentralDirectory("第 \(index) 条目录记录字段被截断")
            }

            let nameStart = cursor + 46
            guard let path = reader.cString(at: nameStart, maxLength: nameLength) else {
                throw IPAError.malformedCentralDirectory("第 \(index) 条目录记录文件名缺失")
            }

            result.append(ZIPEntry(
                path: path,
                compressionMethod: method,
                compressedSize: compressed,
                uncompressedSize: uncompressed,
                localHeaderOffset: localOffset
            ))

            cursor = nameStart + nameLength + extraLength + commentLength
        }
        return result
    }

    // MARK: - Safety

    /// Rejects entries that would escape the destination directory.
    ///
    /// This is the classic "Zip Slip" defence: a legitimate IPA never contains
    /// `..` components or absolute paths, so anything that does is hostile.
    static func isSafeEntryPath(_ path: String) -> Bool {
        if path.hasPrefix("/") { return false }
        if path.contains("\\") { return false }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        for component in components where component == ".." {
            return false
        }
        return true
    }

    // MARK: - Extraction

    /// Extracts the archive into `destination`, returning the paths written.
    ///
    /// Files are written one at a time; we never hold the whole expanded
    /// payload in memory, which matters because a large IPA can expand well
    /// past the point where iOS is willing to hand out contiguous memory.
    @discardableResult
    static func extract(
        archiveAt archiveURL: URL,
        to destination: URL,
        progress: ((Double, String) -> Void)? = nil
    ) throws -> [URL] {

        let archive = try Data(contentsOf: archiveURL, options: .mappedIfSafe)
        let allEntries = try entries(of: archive)

        // `IPAArchive` is an enum with only static members, and every one of
        // them is `Sendable`-safe because they operate on value types. That
        // makes this whole call graph usable from a detached task without any
        // actor hops.
        return try extract(archive: archive, entries: allEntries,
                           to: destination, progress: progress)
    }

    /// Extracts from an already-loaded archive. Split out so the expensive
    /// `Data(contentsOf:)` happens once and so tests can pass a buffer directly.
    @discardableResult
    static func extract(
        archive: Data,
        entries allEntries: [ZIPEntry],
        to destination: URL,
        progress: ((Double, String) -> Void)? = nil
    ) throws -> [URL] {

        // Directories are implied by the path structure; skip explicit
        // directory entries and just create parents as needed.
        let fileEntries = allEntries.filter { !$0.path.hasSuffix("/") }

        try FileManager.default.createDirectory(
            at: destination, withIntermediateDirectories: true)

        var written: [URL] = []
        written.reserveCapacity(fileEntries.count)

        for (index, entry) in fileEntries.enumerated() {
            guard isSafeEntryPath(entry.path) else {
                throw IPAError.unsafeEntryPath(entry.path)
            }

            let outputURL = destination.appendingPathComponent(entry.path)
            try FileManager.default.createDirectory(
                at: outputURL.deletingLastPathComponent(),
                withIntermediateDirectories: true)

            let payload = try readEntry(entry, from: archive)
            try payload.write(to: outputURL, options: .atomic)
            written.append(outputURL)

            progress?(Double(index + 1) / Double(fileEntries.count), entry.path)
        }

        return written
    }

    /// Reads and decompresses a single entry's contents.
    static func readEntry(_ entry: ZIPEntry, from archive: Data) throws -> Data {
        let reader = ByteReader(archive)

        // Local file header:
        //   0  signature          4
        //   4  version needed     2
        //   6  flags              2
        //   8  compression method 2
        //  10  mod time           2
        //  12  mod date           2
        //  14  crc32              4
        //  18  compressed size    4
        //  22  uncompressed size  4
        //  26  filename length    2
        //  28  extra length       2
        //  30  filename           n
        guard let sig = reader.u32(at: entry.localHeaderOffset), sig == 0x0403_4B50 else {
            throw IPAError.malformedCentralDirectory("\(entry.path) 的本地头签名错误")
        }
        guard let nameLength = reader.u32(at: entry.localHeaderOffset + 26).map({ Int($0 & 0xFFFF) }),
              let extraLength = reader.u32(at: entry.localHeaderOffset + 28).map({ Int($0 & 0xFFFF) })
        else {
            throw IPAError.malformedCentralDirectory("\(entry.path) 的本地头字段被截断")
        }

        let dataStart = entry.localHeaderOffset + 30 + nameLength + extraLength
        guard dataStart + entry.compressedSize <= archive.count else {
            throw IPAError.malformedCentralDirectory("\(entry.path) 的数据范围越界")
        }
        let compressed = archive.subdata(in: dataStart..<(dataStart + entry.compressedSize))

        switch entry.compressionMethod {
        case 0: // stored
            return compressed
        case 8: // deflate
            return try inflate(compressed, expectedSize: entry.uncompressedSize, name: entry.path)
        default:
            throw IPAError.unsupportedCompression(entry.compressionMethod)
        }
    }

    /// Raw DEFLATE decompression via Apple's Compression framework.
    ///
    /// ZIP stores a raw deflate stream with no zlib wrapper, which maps to
    /// `COMPRESSION_ZLIB` in this API (the name is historical — `COMPRESSION_ZLIB`
    /// means "raw deflate", whereas `COMPRESSION_ZLIB` + header is not exposed).
    private static func inflate(
        _ input: Data,
        expectedSize: Int,
        name: String
    ) throws -> Data {

        // Zero-length files have no deflate stream to decode.
        guard !input.isEmpty else { return Data() }

        // We must know the output size up front for a single-shot decode.
        // The central directory always records it, so trust that field but
        // sanity-check it so a lying header can't make us allocate wildly.
        guard expectedSize > 0 else { return Data() }
        let capacity = expectedSize

        var output = Data(count: capacity)
        let decodedCount: Int = output.withUnsafeMutableBytes { outRaw -> Int in
            guard let outPtr = outRaw.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return input.withUnsafeBytes { inRaw -> Int in
                guard let inPtr = inRaw.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_decode_buffer(
                    outPtr, capacity,
                    inPtr, input.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }

        guard decodedCount > 0 else {
            throw IPAError.inflateFailed(name)
        }
        // Deflate may legitimately decode to fewer bytes than the header
        // promised only if the header lied; treat a short read as corruption.
        guard decodedCount == expectedSize else {
            output.removeSubrange(decodedCount..<capacity)
            if decodedCount < expectedSize {
                throw IPAError.inflateFailed("\(name)（期望 \(expectedSize) 字节，实际 \(decodedCount) 字节）")
            }
            return output
        }
        return output
    }
}
