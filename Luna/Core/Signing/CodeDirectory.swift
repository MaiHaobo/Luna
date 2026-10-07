//
//  CodeDirectory.swift
//  Luna
//
//  The CodeDirectory — the heart of an iOS code signature.
//
//  A CodeDirectory is a flat table of SHA-256 hashes:
//
//    • one hash per 4 KB *page* of the signed region (the "code slots"),
//      so amfid can detect a single modified instruction;
//    • plus a handful of "special slots" that bind the surrounding metadata
//      — Info.plist, the resource seal, the entitlements — into the same
//      signature, so none of them can be swapped without invalidating it.
//
//  Everything above this file (the CMS signature, the SuperBlob container) is
//  packaging. This file is where the semantics live, so it is written to mirror
//  Apple's own `CS_CodeDirectory` layout field for field.
//
//  LAYOUT (all little-endian)
//  --------------------------
//    0   magic            4   CSMAGIC_CODEDIRECTORY (0xfade0c02)
//    4   length           4   total blob length
//    8   version          4   0x20400 (see CodeDirectoryVersion)
//   12   flags            4   CS_ADHOC for an unsigned build
//   16   hashOffset       4   offset of the *first code slot*
//   20   identOffset      4   offset of the identifier string
//   24   nSpecialSlots    4   count of special slots
//   28   nCodeSlots       4   count of code slots
//   32   codeLimit        4   signed byte count (must divide into pages)
//   36   hashSize         1   32 for SHA-256
//   37   hashType         1   CS_HASHTYPE_SHA256
//   38   platform         1   0
//   39   pageSize         1   log2(page bytes) = 12 for 4096
//   40   spare2           4   0
//
//  Version 0x20400 adds (after the base struct):
//   44   scatterOffset    4   0 (scatter is legacy)
//   48   teamOffset       4   offset of team ID string, 0 when absent
//   52   spare3           4   0
//   56   codeLimit64      8   same as codeLimit, widened
//   64   execSegBase      8   __TEXT vmaddr
//   72   execSegLimit     8   __TEXT vmsize
//   80   execSegFlags     8   CS_EXECSEG_MAIN_BINARY for a main binary
//
//  BODY ORDER — this is the part that is easy to get wrong
//  ------------------------------------------------------
//  After the 88-byte header the blob continues:
//
//      [ identifier string (NUL-terminated) ]
//      [ team id string     (NUL-terminated, omitted when empty) ]
//      [ special slots      (descending: highest slot first) ]
//      [ code slots         (one per page, ascending) ]
//
//  The strings come *first*, before the hash tables, which is what makes
//  `hashOffset` larger than the header. zsign's `SlotBuildCodeDirectory`
//  computes it exactly this way:
//
//      hashOffset = headerLength + bundleIDLength + teamIDLength + specialSlotsLength
//
//  THE SPECIAL-SLOT GOTCHA
//  -----------------------
//  Special slots are stored *immediately before* the code slots and are
//  addressed with **negative indices**: slot 1 (`CSSLOT_INFOSLOT`) lives at
//  `hashOffset - 1 * hashSize`, slot 2 at `hashOffset - 2 * hashSize`, and so
//  on. The table therefore runs from the highest special slot down to slot 1,
//  then jumps to the code slots at `hashOffset`. Getting this backwards
//  produces a signature that parses but never verifies, which is a miserable
//  thing to debug on a device — hence the explicit comments here.
//
//  The signature slot (`CSSLOT_SIGNATURESLOT = 0x10000`) is **not** part of
//  this table. Its value is far too large to be a slot index in the ordinary
//  sense; it names the *separate* SuperBlob member that holds the CMS blob,
//  and the CodeDirectory covers it by being the thing the CMS signs.
//

import Foundation

/// Code signing magic numbers and slot indices, taken from XNU's
/// `osfmk/kern/cs_blobs.h`.
///
/// Re-declared rather than imported for the same reason as `MachODefines`:
/// the C headers are not shippable to every build target, and keeping our own
/// copy means this code is testable off-device.
enum CodeSignMagic {
    /// Embedded signature container (our SuperBlob).
    static let embeddedSignature: UInt32 = 0xfade_0cc0
    /// A single CodeDirectory blob.
    static let codeDirectory: UInt32 = 0xfade_0c02
    /// Requirement set (`CSMAGIC_REQUIREMENTS`).
    static let requirements: UInt32 = 0xfade_0c01
    /// A single requirement (`CSMAGIC_REQUIREMENT`).
    static let requirement: UInt32 = 0xfade_0c00
    /// XML entitlements (`CSMAGIC_EMBEDDED_ENTITLEMENTS`).
    static let entitlements: UInt32 = 0xfade_7171
    /// DER entitlements (`CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`).
    static let derEntitlements: UInt32 = 0xfade_7172
    /// Opaque wrapper holding the CMS signature (`CSMAGIC_BLOBWRAPPER`).
    static let blobWrapper: UInt32 = 0xfade_0b01
}

/// `CSSLOT_*` — the type tag in each `CS_BlobIndex`.
enum CodeSignSlot {
    static let codeDirectory: UInt32 = 0
    static let info: UInt32 = 1
    static let requirements: UInt32 = 2
    static let resourceDirectory: UInt32 = 3
    static let entitlements: UInt32 = 5
    static let derEntitlements: UInt32 = 7
    /// First alternate CodeDirectory (SHA-1 sidecar on modern signatures).
    static let alternateCodeDirectories: UInt32 = 0x1000
    static let signature: UInt32 = 0x10000
}

/// `CS_HASHTYPE_*`.
enum CodeSignHashType {
    static let sha1: UInt8 = 1
    static let sha256: UInt8 = 2
}

/// `CS_*` flag bits we set ourselves.
enum CodeSignFlag {
    /// Ad-hoc signature: no CMS blob, no certificate.
    static let adhoc: UInt32 = 0x0000_0002
}

/// `CS_EXECSEG_*`.
enum CodeSignExecSeg {
    static let mainBinary: UInt64 = 0x1
    static let allowUnsigned: UInt64 = 0x10
}

/// CodeDirectory format versions. 0x20400 is the last one that matters for
/// iOS; it introduced the executable-segment fields (used for JIT / library
/// validation decisions on Apple silicon).
enum CodeDirectoryVersion {
    static let base: UInt32 = 0x20001
    static let scatter: UInt32 = 0x20100
    static let teamID: UInt32 = 0x20200
    static let codeLimit64: UInt32 = 0x20300
    static let execSeg: UInt32 = 0x20400
}

/// Bits that describe which optional regions a CodeDirectory carries.
///
/// Kept separate from the version constant because the offsets have to be
/// computed in the same order the kernel reads them.
enum CodeDirectoryLayout {
    /// Base struct: 44 bytes through `spare2`.
    static let baseSize = 44
    /// 0x20100 adds `scatterOffset`.
    static let scatterSize = 4
    /// 0x20200 adds `teamOffset`.
    static let teamIDSize = 4
    /// 0x20300 adds `spare3` + `codeLimit64`.
    static let codeLimit64Size = 12
    /// 0x20400 adds `execSegBase` + `execSegLimit` + `execSegFlags`.
    static let execSegSize = 24

    /// Total header size for version 0x20400.
    static let execSegVersionSize =
        baseSize + scatterSize + teamIDSize + codeLimit64Size + execSegSize
}

/// What a CodeDirectory needs from the caller.
struct CodeDirectoryInput {
    /// Identifier string — the code's `CFBundleIdentifier` for an app binary.
    var identifier: String
    /// Team identifier, written when non-empty.
    var teamID: String?
    /// The signed byte range: bytes `[0, codeLimit)` of the file.
    var code: Data
    /// Number of bytes the signature covers. Must be ≤ `code.count`.
    var codeLimit: UInt32
    /// Hash of each special slot, indexed by `CSSLOT_*`. `nil` slots are
    /// written as `hashSize` zero bytes — the kernel expects the slot to
    /// exist but treats an all-zero hash as "absent".
    var specialSlots: [UInt32: [UInt8]]
    /// Total number of special slots to reserve. Defaults to the highest
    /// populated slot; pass a larger value to reserve space for a slot that
    /// is filled in later.
    var specialSlotCount: UInt32?
    /// Executable segment bounds, for the 0x20400 fields. Zero when unknown.
    var execSegBase: UInt64
    var execSegLimit: UInt64
    /// `CS_EXECSEG_*` flags; `CS_EXECSEG_MAIN_BINARY` for an app's main binary.
    var execSegFlags: UInt64
    /// Signature flags — `CS_ADHOC` when there is no CMS blob.
    var flags: UInt32
    /// Page size exponent. 12 (4096 bytes) is what iOS uses.
    var pageSize: UInt8
}

enum CodeDirectoryBuilder {

    /// Page size used by every iOS code signature, in bytes.
    static let pageSize: Int = 4096
    /// `log2(4096)`, stored in the `pageSize` field.
    static let pageSizeExponent: UInt8 = 12

    /// Builds the complete CodeDirectory blob (magic + length prefix included).
    ///
    /// Structure of the returned bytes:
    ///
    ///     [ 88-byte header ][ identifier ][ team id ][ special slots ][ code slots ]
    ///
    /// The two hash tables are positioned by `hashOffset`, which sits after the
    /// strings. The code slots end the blob.
    static func build(_ input: CodeDirectoryInput) throws -> Data {

        // ── Hash the page table ─────────────────────────────────────────────
        let pageCount = (Int(input.codeLimit) + pageSize - 1) / pageSize
        var codeHashes = Data()
        codeHashes.reserveCapacity(pageCount * 32)

        for index in 0..<pageCount {
            let start = index * pageSize
            let end = min(start + pageSize, Int(input.codeLimit))
            let chunk = input.code.subdata(in: start..<end)
            codeHashes.append(contentsOf: SHA256.hash(data: chunk))
        }

        // ── Lay out the special slots ───────────────────────────────────────
        // Slot indices run 1...nSpecialSlots and are stored in DESCENDING
        // order, so the region begins with the highest slot and ends with
        // slot 1 (Info.plist) immediately before the code slots.
        //
        // The signature slot is deliberately excluded: its index 0x10000 is a
        // SuperBlob member name, not a position in this table. Including it
        // would inflate the table to 65536 entries — 2 MB of zeros — and
        // produce a CodeDirectory the kernel rejects.
        let highestSlot = Self.highestHashSlot(in: input.specialSlots)
        let nSpecialSlots = input.specialSlotCount.map { max($0, highestSlot) }
            ?? highestSlot
        guard nSpecialSlots >= highestSlot else {
            throw CodeSignError.specialSlotCountTooSmall(
                declared: nSpecialSlots, required: highestSlot)
        }

        var specialHashes = Data()
        specialHashes.reserveCapacity(Int(nSpecialSlots) * 32)
        if nSpecialSlots > 0 {
            for slot in stride(from: nSpecialSlots, through: 1, by: -1) {
                if let hash = input.specialSlots[slot] {
                    specialHashes.append(contentsOf: hash)
                } else {
                    specialHashes.append(contentsOf: [UInt8](repeating: 0, count: 32))
                }
            }
        }

        // ── Header ──────────────────────────────────────────────────────────
        let identifierBytes = Data(input.identifier.utf8) + Data([0])
        let teamBytes: Data = input.teamID.map { Data($0.utf8) + Data([0]) } ?? Data()

        // Strings come before the hash tables, so `hashOffset` sits past both.
        let identOffset = UInt32(CodeDirectoryLayout.execSegVersionSize)
        let teamOffset: UInt32 = teamBytes.isEmpty
            ? 0
            : identOffset + UInt32(identifierBytes.count)
        let hashOffset = identOffset
            + UInt32(identifierBytes.count)
            + UInt32(teamBytes.count)
            + UInt32(specialHashes.count)

        let totalLength = Int(hashOffset) + codeHashes.count

        var out = Data()
        out.reserveCapacity(totalLength)

        out.appendLE(CodeSignMagic.codeDirectory)
        out.appendLE(UInt32(totalLength))
        out.appendLE(CodeDirectoryVersion.execSeg)
        out.appendLE(input.flags)
        out.appendLE(hashOffset)
        out.appendLE(identOffset)
        out.appendLE(nSpecialSlots)
        out.appendLE(UInt32(pageCount))
        out.appendLE(input.codeLimit)
        out.append(32)                               // hashSize (SHA-256 = 32 bytes)
        out.append(CodeSignHashType.sha256)          // hashType
        out.append(0)                                // platform
        out.append(input.pageSize)                   // pageSize
        out.appendLE(UInt32(0))                      // spare2

        // ── Version 0x20100 onward ──────────────────────────────────────────
        out.appendLE(UInt32(0))                      // scatterOffset
        // ── Version 0x20200 ─────────────────────────────────────────────────
        out.appendLE(teamOffset)
        // ── Version 0x20300 ─────────────────────────────────────────────────
        out.appendLE(UInt32(0))                      // spare3
        out.appendLE(UInt64(input.codeLimit))        // codeLimit64
        // ── Version 0x20400 ─────────────────────────────────────────────────
        out.appendLE(input.execSegBase)
        out.appendLE(input.execSegLimit)
        out.appendLE(input.execSegFlags)

        // ── Body: strings, then hashes ──────────────────────────────────────
        out.append(identifierBytes)
        out.append(teamBytes)
        out.append(specialHashes)
        out.append(codeHashes)

        return out
    }

    /// The highest slot that belongs in the hash table.
    ///
    /// `CSSLOT_SIGNATURESLOT` and `CSSLOT_ALTERNATE_CODEDIRECTORIES` are
    /// SuperBlob member names, not table positions, so they are filtered out.
    /// `CSSLOT_DER_ENTITLEMENTS` (7) and below are real hash slots.
    static func highestHashSlot(in slots: [UInt32: [UInt8]]) -> UInt32 {
        slots.keys
            .filter { $0 < CodeSignSlot.alternateCodeDirectories }
            .max() ?? 0
    }

    /// The `cdhash` — the identifier amfid and dyld use to refer to a
    /// signature. For a SHA-256 CodeDirectory it is the first 20 bytes of the
    /// blob's SHA-256, per `CS_CDHASH_LEN`.
    static func cdhash(of codeDirectory: Data) -> [UInt8] {
        Array(SHA256.hash(data: codeDirectory).prefix(20))
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    mutating func appendLE(_ value: UInt64) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}
