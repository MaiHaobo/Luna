//
//  MachOPatcher.swift
//  Luna
//
//  The binary rewriting engine. This is the part of Luna that makes an app
//  bundle loadable as a dynamic library instead of as a process.
//
//  Every transformation below is written against the documented Mach-O format.
//  No private symbols, no runtime hooking — just byte-level surgery on a file
//  that lives inside Luna's own sandbox.
//
//  The three edits are the same ones any in-app launcher must perform:
//
//   1. `LC_LOAD_DYLIB` injection — add a load command pointing at our loader
//      shim, so dyld runs our setup code as the guest image is mapped in.
//   2. `__PAGEZERO` relocation — the guest's reserved zero page would collide
//      with Luna's own address space once the image is mapped inside Luna.
//      Shrinking it to a 16 KB guard page moves it out of the way.
//   3. `filetype` rewrite — `MH_EXECUTE` → `MH_DYLIB`. `dlopen()` categorically
//      refuses `MH_EXECUTE` images; `MH_DYLIB` is accepted.
//
//  IMPORTANT: this engine only produces a *patched copy*. It never touches the
//  original IPA, and it never writes outside Luna's container directory.
//

import Foundation

/// A summary of what a patch pass changed.
struct MachOPatchReport {
    var sourcePath: String
    var outputPath: String
    var wasFat: Bool
    var originalFileType: String
    var pageZeroOriginal: (vmAddress: UInt64, vmSize: UInt64)?
    var pageZeroPatched: (vmAddress: UInt64, vmSize: UInt64)?
    var injectedDylibPath: String?
    var warnings: [String]

    var humanReadable: String {
        var lines: [String] = []
        lines.append("源文件：\(sourcePath)")
        lines.append("输出：\(outputPath)")
        lines.append("架构：\(wasFat ? "通用二进制（fat）" : "单架构（thin）")")
        lines.append("文件类型：\(originalFileType) → MH_DYLIB")
        if let before = pageZeroOriginal, let after = pageZeroPatched {
            lines.append(String(
                format: "__PAGEZERO：0x%llX / 0x%llX → 0x%llX / 0x%llX",
                before.vmAddress, before.vmSize, after.vmAddress, after.vmSize))
        } else {
            lines.append("__PAGEZERO：不存在（可能已修补过）")
        }
        if let dylib = injectedDylibPath {
            lines.append("注入 LC_LOAD_DYLIB：\(dylib)")
        }
        for warning in warnings {
            lines.append("⚠️ \(warning)")
        }
        return lines.joined(separator: "\n")
    }
}

enum MachOPatcher {

    /// Values a patched `__PAGEZERO` must carry.
    ///
    /// The guest image is mapped into Luna's address space, so its reserved
    /// zero page has to vacate the region Luna is already using. We shrink it
    /// to a single 16 KB guard page parked at the very top of the 4 GB window.
    static let patchedPageZeroVMAddress: UInt64 = 0xFFFF_C000
    static let patchedPageZeroVMSize: UInt64 = 0x4000

    // MARK: - Public API

    /// Produces a patched copy of `sourceURL` at `outputURL`.
    ///
    /// The original file is never modified. If `outputURL` already exists it is
    /// replaced.
    ///
    /// - Parameters:
    ///   - sourceURL: the guest's main executable (inside Luna's container).
    ///   - outputURL: where to write the patched binary.
    ///   - loaderPath: `LC_LOAD_DYLIB` path to inject. Pass `nil` to skip
    ///     injection — useful when only inspecting, or when the loader shim
    ///     isn't shipped in the build.
    @discardableResult
    static func patch(
        sourceURL: URL,
        outputURL: URL,
        loaderPath: String? = nil
    ) throws -> MachOPatchReport {

        let image = try MachOImage(contentsOf: sourceURL)
        var buffer = image.data
        var warnings: [String] = []

        // ── Edit 3 (done first, in-place): filetype MH_EXECUTE → MH_DYLIB ────
        let originalFileType = image.fileTypeDescription
        buffer = try rewriteFileType(in: buffer, image: image)

        // ── Edit 2: relocate __PAGEZERO ─────────────────────────────────────
        let originalPageZero = image.pageZeroSegment()
        if originalPageZero != nil {
            buffer = try relocatePageZero(in: buffer, image: image)
        } else {
            warnings.append("未找到 __PAGEZERO 段，跳过该步修补")
        }

        // ── Edit 1: inject LC_LOAD_DYLIB ────────────────────────────────────
        var injectedPath: String?
        if let loaderPath {
            // The injection must be applied to a freshly parsed copy, because
            // the previous edit changed the load-command count.
            let refreshed = try MachOImage(data: buffer)
            buffer = try injectLoadDylib(
                into: buffer, image: refreshed, path: loaderPath)
            injectedPath = loaderPath
        }

        try buffer.write(to: outputURL, options: .atomic)

        return MachOPatchReport(
            sourcePath: sourceURL.path,
            outputPath: outputURL.path,
            wasFat: image.isFat,
            originalFileType: originalFileType,
            pageZeroOriginal: originalPageZero.map { ($0.vmAddress, $0.vmSize) },
            pageZeroPatched: originalPageZero == nil
                ? nil
                : (patchedPageZeroVMAddress, patchedPageZeroVMSize),
            injectedDylibPath: injectedPath,
            warnings: warnings
        )
    }

    // MARK: - Edit 3: file type

    /// Overwrites the `filetype` field at header offset 12.
    private static func rewriteFileType(in buffer: Data, image: MachOImage) throws -> Data {
        guard !image.isAlreadyDylib else { return buffer }
        var out = buffer
        let fieldOffset = image.sliceOffset + 12
        guard fieldOffset + 4 <= out.count else { throw MachOError.truncatedHeader }
        writeUInt32LE(MachOFileType.dylib, into: &out, at: fieldOffset)
        return out
    }

    // MARK: - Edit 2: __PAGEZERO

    /// Rewrites `vmaddr` and `vmsize` of the `__PAGEZERO` segment.
    private static func relocatePageZero(in buffer: Data, image: MachOImage) throws -> Data {
        guard let pageZero = image.pageZeroSegment() else { return buffer }
        var out = buffer
        let base = pageZero.commandOffset
        // vmaddr sits at +24, vmsize at +32 within segment_command_64.
        writeUInt64LE(patchedPageZeroVMAddress, into: &out, at: base + 24)
        writeUInt64LE(patchedPageZeroVMSize, into: &out, at: base + 32)
        return out
    }

    // MARK: - Edit 1: LC_LOAD_DYLIB injection

    /// Appends an `LC_LOAD_DYLIB` command in the zero padding that follows the
    /// last load command, then bumps `ncmds` and `sizeofcmds`.
    ///
    /// Linkers round the load-command region up to a page or segment boundary,
    /// which leaves usable slack. We verify the slack is genuinely zeroed and
    /// large enough before writing, so a malformed binary fails loudly instead
    /// of corrupting the first section.
    private static func injectLoadDylib(
        into buffer: Data,
        image: MachOImage,
        path: String
    ) throws -> Data {

        let command = try makeLoadDylibCommand(path: path)
        let headerSize = 32 // sizeof(mach_header_64)

        // Region the loader believes is occupied by load commands.
        let commandsEnd = image.sliceOffset + headerSize + Int(image.sizeofcmds)

        // Find how much contiguous zero padding is available after it. We cap
        // the search so a broken binary can't make us scan the whole file.
        let maxLookahead = 64 * 1024
        let searchLimit = min(buffer.count, commandsEnd + maxLookahead)
        var available = 0
        while commandsEnd + available < searchLimit,
              buffer[buffer.startIndex + commandsEnd + available] == 0 {
            available += 1
        }

        guard available >= command.count else {
            throw MachOError.noRoomForLoadCommand
        }

        var out = buffer
        out.replaceSubrange(commandsEnd..<(commandsEnd + command.count), with: command)

        // Bump ncmds (+1) and sizeofcmds (+command length) in the header.
        writeUInt32LE(image.ncmds + 1, into: &out, at: image.sliceOffset + 16)
        writeUInt32LE(image.sizeofcmds + UInt32(command.count), into: &out, at: image.sliceOffset + 20)

        return out
    }

    /// Builds a `dylib_command` for `LC_LOAD_DYLIB`.
    ///
    /// Layout:
    ///   0  cmd                    4   = LC_LOAD_DYLIB
    ///   4  cmdsize                4   = total, 8-byte aligned
    ///   8  dylib.name.offset      4   = 24 (string starts right after struct)
    ///  12  dylib.timestamp        4   = 0
    ///  16  dylib.current_version  4   = 0
    ///  20  dylib.compat_version   4   = 0
    ///  24  name string (NUL-terminated), padded to 8-byte alignment
    static func makeLoadDylibCommand(path: String) throws -> Data {
        let nameBytes = Array(path.utf8) + [0]
        let structSize = 24
        var total = structSize + nameBytes.count
        // cmdsize must be a multiple of 8.
        let padding = (8 - (total % 8)) % 8
        total += padding

        // Apple encodes dylib versions as packed X.Y.Z but both current and
        // compatibility version are irrelevant for our shim, so zero is fine.
        var out = Data()
        out.appendLE(UInt32(MachOLoadCommand.loadDylib))
        out.appendLE(UInt32(total))
        out.appendLE(UInt32(structSize)) // name offset
        out.appendLE(UInt32(0))          // timestamp
        out.appendLE(UInt32(0))          // current_version
        out.appendLE(UInt32(0))          // compatibility_version
        out.append(contentsOf: nameBytes)
        out.append(contentsOf: [UInt8](repeating: 0, count: padding))
        return out
    }

    // MARK: - Little-endian writes

    private static func writeUInt32LE(_ value: UInt32, into data: inout Data, at offset: Int) {
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { raw in
            data.replaceSubrange(offset..<(offset + 4), with: raw)
        }
    }

    private static func writeUInt64LE(_ value: UInt64, into data: inout Data, at offset: Int) {
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { raw in
            data.replaceSubrange(offset..<(offset + 8), with: raw)
        }
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        // `Swift.` is required: inside a Data extension, the bare name
        // resolves to Data.withUnsafeBytes(_:) (an instance method) rather
        // than the global withUnsafeBytes(of:_:), and the instance method
        // does not accept an `of:` label.
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}
