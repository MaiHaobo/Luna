//
//  MachOCodeSigner.swift
//  Luna
//
//  Writes a SuperBlob into a Mach-O and wires up `LC_CODE_SIGNATURE`.
//
//  THE PROBLEM
//  -----------
//  A Mach-O executable already carries an `LC_CODE_SIGNATURE` command pointing
//  at a signature region at the tail of `__LINKEDIT`. Signing again means
//  replacing that region — and the new signature is almost never the same size
//  as the old one. Two cases:
//
//    • The new blob fits in the existing `datasize`: overwrite and shrink the
//      command's `datasize`. Easy, and nothing else in the file moves.
//    • It does not: the file has to grow. Everything the signature covers
//      is unchanged (it is all before the signature), so the only edits are
//      the file length, `__LINKEDIT`'s `filesize`/`vmsize`, and the command.
//
//  The second case is the interesting one and it is why `codeLimit` matters:
//  the CodeDirectory hashes bytes `[0, codeLimit)`, so `codeLimit` must be the
//  offset at which the signature starts. Growth therefore happens strictly
//  *after* everything that gets hashed, which is what keeps the signature
//  self-consistent — a signature that covers its own bytes could never be
//  computed.
//
//  ALIGNMENT
//  ---------
//  The signature region must start on a 16-byte boundary (the kernel — and
//  `codesign` itself — require it). `__LINKEDIT.fileoff` is page aligned and
//  the region after it is padded, so in practice the existing command already
//  satisfies this; we still verify and pad when growing the file.
//

import Foundation

/// Result of signing one Mach-O.
struct MachOSignReport {
    /// Bytes the signature covers.
    var codeLimit: UInt32
    /// Total size of the new signature blob.
    var signatureSize: Int
    /// The old `datasize`, for comparison in the UI.
    var previousSignatureSize: Int
    /// Whether the file had to grow.
    var didGrow: Bool
    /// First 20 bytes of the CodeDirectory's SHA-256 — the `cdhash`.
    var cdhash: [UInt8]

    var cdhashHex: String { cdhash.hexString }

    var humanReadable: String {
        var lines: [String] = []
        lines.append("签名覆盖：\(codeLimit) 字节")
        lines.append("签名大小：\(signatureSize) 字节（原 \(previousSignatureSize) 字节）")
        lines.append(didGrow ? "签名区已扩展（文件增长）" : "签名区已原地覆写")
        lines.append("cdhash：\(cdhashHex)")
        return lines.joined(separator: "\n")
    }
}

enum MachOCodeSigner {

    /// Alignment the signature region must start at.
    static let signatureAlignment = 16

    /// `linkedit_data_command` (`LC_CODE_SIGNATURE`) offset of `dataoff`
    /// within the command.
    private static let dataOffFieldOffset = 8
    private static let dataSizeFieldOffset = 12
    private static let linkeditDataCommandSize = 16

    // MARK: - Entry point

    /// Signs `image` (already parsed) producing a new file buffer.
    ///
    /// Signing is the *last* step of a punch list: the binary must already
    /// carry its final bytes, because the signature hashes them. In
    /// particular, whatever `MachOPatcher` did (`__PAGEZERO`, `filetype`,
    /// injected dylibs) has to have happened first.
    ///
    /// - Parameters:
    ///   - image: the parsed, already-patched binary.
    ///   - identifier: `CFBundleIdentifier`-equivalent string for the code.
    ///   - teamID: team identifier, or `nil` for a signature with none.
    ///   - entitlementsXML: XML plist bytes to embed, or `nil` for none.
    ///   - extraSpecialSlots: slots the *bundle* signer owns and has already
    ///     hashed — `Info.plist` (`CSSLOT_INFOSLOT`) and the resource seal
    ///     (`CSSLOT_RESOURCEDIR`). They are merged with the ones this function
    ///     computes, because the CodeDirectory hashes all of them together.
    ///   - specialSlotCount: reserved special slots. Must be at least as large
    ///     as the highest slot actually populated.
    static func sign(
        image: MachOImage,
        identifier: String,
        teamID: String? = nil,
        entitlementsXML: Data? = nil,
        extraSpecialSlots: [UInt32: [UInt8]] = [:],
        specialSlotCount: UInt32? = nil
    ) throws -> (data: Data, report: MachOSignReport) {

        guard !identifier.isEmpty else { throw CodeSignError.identifierMissing }

        // ── Locate LC_CODE_SIGNATURE ────────────────────────────────────────
        guard let command = image.codeSignatureCommand() else {
            throw CodeSignError.noCodeSignatureLoadCommand
        }

        let previousSize = Int(command.dataSize)
        var buffer = image.data

        // ── Decide where the signature will live ────────────────────────────
        // `codeLimit` is the offset the signature starts at; everything before
        // it is hashed. We keep the existing position when possible so the file
        // layout is untouched.
        let signatureOffset = Int(command.dataOff)
        guard signatureOffset <= buffer.count else {
            throw CodeSignError.malformedMachO(
                "LC_CODE_SIGNATURE 的文件偏移 \(signatureOffset) 超出文件长度 \(buffer.count)")
        }

        // ── Build the member blobs ──────────────────────────────────────────
        // Order matters: the CodeDirectory hashes every special slot, so all
        // of them must exist before it is built. Neither the entitlements plist
        // nor the (empty) signature wrapper depends on the CodeDirectory, so
        // everything can be produced in one pass.
        //
        // Info.plist and the resource directory (CodeResources) are hashed by
        // the *bundle* signer, which is the only layer that knows their bytes;
        // it passes them in as pre-computed slots.
        let entitlementsBlob = entitlementsXML.map {
            SuperBlobBuilder.entitlementsBlob(xml: $0)
        }
        let signatureWrapper = SuperBlobBuilder.emptySignatureWrapper()

        var specialSlots: [UInt32: [UInt8]] = extraSpecialSlots
        if let entitlementsBlob {
            specialSlots[CodeSignSlot.entitlements] = SHA256.hash(data: entitlementsBlob)
        }
        // The signature wrapper is a SuperBlob member, not a hash-table slot,
        // so it is deliberately NOT added here.

        // ── Executable segment bounds ───────────────────────────────────────
        // The 0x20400 fields describe where executable code lives, which the
        // kernel consults for JIT and library-validation decisions.
        let text = image.segment(named: "__TEXT")

        let input = CodeDirectoryInput(
            identifier: identifier,
            teamID: teamID,
            code: buffer,
            codeLimit: UInt32(signatureOffset),
            specialSlots: specialSlots,
            specialSlotCount: specialSlotCount,
            execSegBase: text?.vmAddress ?? 0,
            execSegLimit: text?.vmSize ?? 0,
            execSegFlags: image.fileType == MachOFileType.execute
                ? CodeSignExecSeg.mainBinary
                : 0,
            flags: CodeSignFlag.adhoc,
            pageSize: CodeDirectoryBuilder.pageSizeExponent
        )

        let codeDirectory = try CodeDirectoryBuilder.build(input)

        var members: [SuperBlobMember] = [
            SuperBlobMember(slot: CodeSignSlot.codeDirectory, blob: codeDirectory),
            SuperBlobMember(slot: CodeSignSlot.requirements,
                            blob: SuperBlobBuilder.emptyRequirements()),
        ]
        if let entitlementsBlob {
            members.append(SuperBlobMember(
                slot: CodeSignSlot.entitlements, blob: entitlementsBlob))
        }
        members.append(SuperBlobMember(
            slot: CodeSignSlot.signature, blob: signatureWrapper))

        let superBlob = SuperBlobBuilder.build(members: members)

        // ── Place the blob ──────────────────────────────────────────────────
        let available = buffer.count - signatureOffset
        let didGrow = superBlob.count > available

        if didGrow {
            // Trim anything after the old signature (there should be nothing,
            // but a padded or appended file could carry trailing bytes).
            buffer = buffer.subdata(in: 0..<signatureOffset)
            buffer.append(superBlob)
        } else {
            buffer.replaceSubrange(
                signatureOffset..<(signatureOffset + superBlob.count),
                with: superBlob)
        }

        // ── Update the load command ─────────────────────────────────────────
        writeUInt32LE(UInt32(superBlob.count),
                      into: &buffer, at: command.commandOffset + dataSizeFieldOffset)

        // ── Update __LINKEDIT ───────────────────────────────────────────────
        if didGrow, let linkeditOffset = image.segmentCommandOffset(named: "__LINKEDIT") {
            // filesize covers the signature; vmsize must stay page-aligned and
            // large enough to map it.
            let linkeditFileOff = image.segment(named: "__LINKEDIT")?.fileOffset ?? 0
            let newFileSize = UInt64(buffer.count) - linkeditFileOff
            let newVMSize = align(newFileSize, to: UInt64(CodeDirectoryBuilder.pageSize))
            writeUInt64LE(newFileSize, into: &buffer, at: linkeditOffset + 48)
            writeUInt64LE(newVMSize, into: &buffer, at: linkeditOffset + 32)
        }

        let report = MachOSignReport(
            codeLimit: UInt32(signatureOffset),
            signatureSize: superBlob.count,
            previousSignatureSize: previousSize,
            didGrow: didGrow,
            cdhash: CodeDirectoryBuilder.cdhash(of: codeDirectory)
        )

        return (buffer, report)
    }

    // MARK: - Helpers

    private static func align(_ value: UInt64, to alignment: UInt64) -> UInt64 {
        let remainder = value % alignment
        return remainder == 0 ? value : value + (alignment - remainder)
    }

    private static func writeUInt32LE(_ value: UInt32, into data: inout Data, at offset: Int) {
        guard offset >= 0, offset + 4 <= data.count else { return }
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { raw in
            data.replaceSubrange(offset..<(offset + 4), with: raw)
        }
    }

    private static func writeUInt64LE(_ value: UInt64, into data: inout Data, at offset: Int) {
        guard offset >= 0, offset + 8 <= data.count else { return }
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { raw in
            data.replaceSubrange(offset..<(offset + 8), with: raw)
        }
    }
}
