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
    /// Whether an `LC_CODE_SIGNATURE` command had to be added — true for a
    /// binary that was never signed before.
    var didInjectCommand: Bool
    /// First 20 bytes of the CodeDirectory's SHA-256 — the `cdhash`.
    var cdhash: [UInt8]

    var cdhashHex: String { cdhash.hexString }

    var humanReadable: String {
        var lines: [String] = []
        lines.append("签名覆盖：\(codeLimit) 字节")
        if didInjectCommand {
            lines.append("已注入 LC_CODE_SIGNATURE 命令（原二进制未签名）")
        }
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
    ///   - credential: the certificate to sign with, or `nil` for an ad-hoc
    ///     signature. Ad-hoc is not a degraded mode here — it is what a guest
    ///     with no imported certificate gets, and it is a complete, valid
    ///     signature for a binary that is never going to be installed by iOS.
    ///   - entitlementsXML: XML plist bytes to embed, or `nil` for none. The
    ///     credential carries its own copy for the main bundle; this parameter
    ///     exists for the nested-code case, where entitlements are
    ///     deliberately withheld.
    ///   - extraSpecialSlots: slots the *bundle* signer owns and has already
    ///     hashed — `Info.plist` (`CSSLOT_INFOSLOT`) and the resource seal
    ///     (`CSSLOT_RESDIR`). They are merged with the ones this function
    ///     computes, because the CodeDirectory hashes all of them together.
    ///   - specialSlotCount: reserved special slots. Must be at least as large
    ///     as the highest slot actually populated.
    static func sign(
        image: MachOImage,
        identifier: String,
        credential: SigningCredential? = nil,
        entitlementsXML: Data? = nil,
        extraSpecialSlots: [UInt32: [UInt8]] = [:],
        specialSlotCount: UInt32? = nil
    ) throws -> (data: Data, report: MachOSignReport) {

        guard !identifier.isEmpty else { throw CodeSignError.identifierMissing }

        // A certificate-backed signature has to name its team: the
        // CodeDirectory's `teamID` field is part of what the verifier checks
        // against the certificate. Refuse rather than emit one that will be
        // rejected on the device.
        if let credential, credential.teamID.isEmpty {
            throw CodeSignError.signingFailed("证书签名的 teamID 不能为空")
        }

        let effectiveTeamID = credential?.teamID

        var buffer = image.data

        // ── Locate or create LC_CODE_SIGNATURE ──────────────────────────────
        // A binary that was never signed — a self-built app, a stripped dump —
        // has no such command at all. Rather than refuse it, we place an
        // empty one in the load-command padding and treat the region after
        // the current load commands as the signing area. `MachOPatcher` uses
        // the same trick for its dylib injection, so the code is proven.
        let command: MachOImage.CodeSignatureCommand
        var previousSize = 0
        var didInjectCommand = false

        if let existing = image.codeSignatureCommand() {
            command = existing
            previousSize = Int(existing.dataSize)
        } else {
            let placement = try injectEmptyCodeSignatureCommand(into: &buffer, image: image)
            command = placement.command
            didInjectCommand = true
        }

        // ── Decide where the signature will live ────────────────────────────
        // `codeLimit` is the offset the signature starts at; everything before
        // it is hashed. We keep the existing position when possible so the file
        // layout is untouched.
        let signatureOffset = Int(command.dataOff)
        guard signatureOffset <= buffer.count else {
            throw CodeSignError.malformedMachO(
                "LC_CODE_SIGNATURE 的文件偏移 \(signatureOffset) 超出文件长度 \(buffer.count)")
        }

        // ── Plan the signature ──────────────────────────────────────────────
        // A CodeDirectory's length depends only on its *shape* — the page
        // count, the special-slot count, and the identifier's length — never
        // on the hash values themselves. So the SuperBlob's final size is
        // known before its contents are final, which is what lets this run in
        // a clean three-step order:
        //
        //   1. build once, to learn the size
        //   2. write every field that lives before the signature region
        //   3. rebuild over the final bytes, and place the blob
        //
        // Step 2 has to come before step 3 because the CodeDirectory hashes
        // `[0, codeLimit)` — a region that includes the `LC_CODE_SIGNATURE`
        // command (and its `dataSize` field) and every segment header. Writing
        // those after hashing produces a signature describing a file that no
        // longer exists, which verifies as invalid with no obvious cause.
        //
        // Info.plist and the resource directory (CodeResources) are hashed by
        // the *bundle* signer, which is the only layer that knows their bytes;
        // it passes them in as pre-computed slots.
        let entitlementsBlob = entitlementsXML.map {
            SuperBlobBuilder.entitlementsBlob(xml: $0)
        }

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

        /// The parts of a CodeDirectory that do not depend on the file bytes.
        func makeInput(code: Data) -> CodeDirectoryInput {
            CodeDirectoryInput(
                identifier: identifier,
                teamID: effectiveTeamID,
                code: code,
                codeLimit: UInt32(signatureOffset),
                specialSlots: specialSlots,
                specialSlotCount: specialSlotCount,
                execSegBase: text?.vmAddress ?? 0,
                execSegLimit: text?.vmSize ?? 0,
                execSegFlags: image.fileType == MachOFileType.execute
                    ? CodeSignExecSeg.mainBinary
                    : 0,
                // `CodeSignFlag.adhoc` is a *claim* that this signature has no
                // certificate behind it. Left set on a certificate-backed
                // signature it contradicts the CMS blob sitting in the same
                // SuperBlob, and a verifier that believes the flag skips the
                // certificate check entirely.
                flags: credential == nil ? CodeSignFlag.adhoc : 0,
                pageSize: CodeDirectoryBuilder.pageSizeExponent)
        }

        /// Builds the signature slot for a given CodeDirectory.
        ///
        /// A closure rather than a value because the CMS blob signs the
        /// CodeDirectory, and the final CodeDirectory is not known until step
        /// 3. Its *length*, however, is known the moment we have any
        /// CodeDirectory of the right shape — see the comment on step 1.
        func makeSignatureWrapper(codeDirectory: Data) throws -> Data {
            guard let credential else {
                // Ad-hoc: an empty `CSMAGIC_BLOBWRAPPER`, which is what
                // `codesign -s -` writes.
                return SuperBlobBuilder.emptySignatureWrapper()
            }
            return SuperBlobBuilder.genericBlob(
                magic: CodeSignMagic.blobWrapper,
                payload: try CMSSigner.signedData(
                    codeDirectory: codeDirectory,
                    certificate: credential.leafCertificate,
                    key: credential.privateKey,
                    algorithm: credential.algorithm))
        }

        func assemble(codeDirectory: Data) throws -> Data {
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
                slot: CodeSignSlot.signature,
                blob: try makeSignatureWrapper(codeDirectory: codeDirectory)))
            return SuperBlobBuilder.build(members: members)
        }

        // Step 1: build once purely to learn the final length.
        //
        // This works for the certificate case too, and the reason is worth
        // spelling out. A CMS blob's size is driven by the certificate's DER
        // and the key's signature length; the CodeDirectory it signs is
        // *detached* (never carried) and there are no signed attributes, so
        // nothing about the blob's length depends on the CodeDirectory's
        // contents. A probe built over the pre-edit bytes is therefore exactly
        // as long as the final blob, which is what makes the rest of this
        // function sound.
        let plannedSuperBlob = try assemble(
            codeDirectory: try CodeDirectoryBuilder.build(makeInput(code: buffer)))
        let signatureSize = plannedSuperBlob.count

        // Step 2: write everything that lands before the signature region.
        //
        // Order matters and is subtle: the CodeDirectory hashes `[0, codeLimit)`
        // and *every* field written below lives inside that range —
        // `LC_CODE_SIGNATURE.dataSize` is a load command, and `__LINKEDIT`'s
        // `filesize`/`vmsize` are load-command payloads. All of them must be
        // final *before* step 3 hashes. Writing any of them afterwards produces
        // a signature describing a file that no longer exists on disk: it
        // verifies as invalid with no obvious cause.

        // 2a. `LC_CODE_SIGNATURE.dataSize`
        writeUInt32LE(UInt32(signatureSize),
                      into: &buffer, at: command.commandOffset + dataSizeFieldOffset)

        // 2b. Size the file so the signature region ends exactly where the blob
        //     wants it. The bytes after `signatureOffset` are the *old*
        //     signature — never covered by the hash — so they can be dropped
        //     freely, whether they are too few (grow) or too many (shrink).
        let available = buffer.count - signatureOffset
        let didGrow = signatureSize > available
        let didShrink = signatureSize < available

        if didGrow || didShrink {
            buffer = buffer.subdata(in: 0..<signatureOffset)
            buffer.append(plannedSuperBlob)
        }

        // 2c. `__LINKEDIT` must cover the final signature region.
        //
        // `segment_command_64` layout:
        //   32  vmsize
        //   48  filesize
        //
        // This deliberately runs for every case — not just growth — because the
        // fields are inside `[0, codeLimit)` and therefore hashed. Writing them
        // after step 3 would silently invalidate the signature.
        if let linkedit = image.segment(named: "__LINKEDIT") {
            let newFileSize = UInt64(buffer.count) - linkedit.fileOffset
            // `vmsize` only ever grows: shrinking a virtual size would ask the
            // kernel to unmap pages that are still present in the file.
            let newVMSize = max(
                linkedit.vmSize,
                align(newFileSize, to: UInt64(CodeDirectoryBuilder.pageSize)))
            writeUInt64LE(newFileSize, into: &buffer, at: linkedit.commandOffset + 48)
            writeUInt64LE(newVMSize, into: &buffer, at: linkedit.commandOffset + 32)
        }

        // Step 3: recompute over the final bytes and place the blob.
        //
        // This is where the CMS signature is actually produced — over the
        // authoritative bytes, after every pre-`codeLimit` field has settled.
        let finalCodeDirectory = try CodeDirectoryBuilder.build(makeInput(code: buffer))
        let finalSuperBlob = try assemble(codeDirectory: finalCodeDirectory)
        assert(finalSuperBlob.count == signatureSize,
               "CodeDirectory length must not depend on its contents")

        // The blob lands at `[signatureOffset, signatureOffset + size)`. Its own
        // bytes are never hashed — they start exactly at `codeLimit` — so writing
        // it last cannot invalidate what step 3 just computed.
        buffer.replaceSubrange(
            signatureOffset..<(signatureOffset + finalSuperBlob.count),
            with: finalSuperBlob)

        let report = MachOSignReport(
            codeLimit: UInt32(signatureOffset),
            signatureSize: finalSuperBlob.count,
            previousSignatureSize: previousSize,
            didGrow: didGrow,
            didInjectCommand: didInjectCommand,
            cdhash: CodeDirectoryBuilder.cdhash(of: finalCodeDirectory)
        )

        return (buffer, report)
    }

    // MARK: - Helpers

    /// Injects an empty `LC_CODE_SIGNATURE` and reports where the signature
    /// should go.
    ///
    /// Used for binaries that were never signed. The command is written into
    /// the zero padding that follows the last load command, and the signature
    /// region is defined as "everything from the current end of the file
    /// onward", 16-byte aligned.
    ///
    /// This mirrors `MachOPatcher.injectLoadDylib`, including the check that
    /// the padding is genuinely zeroed — a malformed binary should fail loudly
    /// rather than have its first section overwritten.
    private static func injectEmptyCodeSignatureCommand(
        into buffer: inout Data,
        image: MachOImage
    ) throws -> (command: MachOImage.CodeSignatureCommand, commandOffset: Int) {

        let headerSize = 32 // sizeof(mach_header_64)
        let commandSize = linkeditDataCommandSize

        // Region the loader believes is occupied by load commands.
        let commandsEnd = image.sliceOffset + headerSize + Int(image.sizeofcmds)

        let maxLookahead = 64 * 1024
        let searchLimit = min(buffer.count, commandsEnd + maxLookahead)
        var available = 0
        while commandsEnd + available < searchLimit,
              buffer[buffer.startIndex + commandsEnd + available] == 0 {
            available += 1
        }
        guard available >= commandSize else {
            throw CodeSignError.cannotExpandSignatureRegion(
                needed: commandSize, available: available)
        }

        // The signature starts at the end of the file, aligned up to 16 bytes.
        // Everything between the current end and that boundary is zero padding
        // that we own, so the alignment never touches real data.
        let currentEnd = buffer.count
        let alignedStart = (currentEnd + signatureAlignment - 1)
            / signatureAlignment * signatureAlignment
        if alignedStart > currentEnd {
            buffer.append(contentsOf: [UInt8](repeating: 0, count: alignedStart - currentEnd))
        }

        // ── Write the command ───────────────────────────────────────────────
        //   0  cmd        4   = LC_CODE_SIGNATURE
        //   4  cmdsize    4   = 16
        //   8  dataoff    4   file offset of the signature
        //  12  datasize   4   0 (nothing written yet)
        var command = Data()
        command.appendLE32(MachOLoadCommand.codeSignature)
        command.appendLE32(UInt32(commandSize))
        command.appendLE32(UInt32(alignedStart))
        command.appendLE32(0)

        buffer.replaceSubrange(commandsEnd..<(commandsEnd + commandSize), with: command)

        // Bump ncmds (+1) and sizeofcmds (+16) in the header.
        writeUInt32LE(image.ncmds + 1, into: &buffer, at: image.sliceOffset + 16)
        writeUInt32LE(
            image.sizeofcmds + UInt32(commandSize),
            into: &buffer, at: image.sliceOffset + 20)

        let injected = MachOImage.CodeSignatureCommand(
            commandOffset: commandsEnd,
            dataOff: UInt32(alignedStart),
            dataSize: 0)
        return (injected, commandsEnd)
    }

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

private extension Data {
    mutating func appendLE32(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}
