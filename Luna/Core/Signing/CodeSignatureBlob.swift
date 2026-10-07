//
//  CodeSignatureBlob.swift
//  Luna
//
//  Assembles the SuperBlob — the single opaque structure the kernel reads out
//  of `LC_CODE_SIGNATURE`.
//
//  A SuperBlob is a directory followed by its members:
//
//    ┌──────────────────────────────────────────┐
//    │ magic    0xfade0cc0          4 bytes      │
//    │ length                      4 bytes      │
//    │ count      number of members 4 bytes      │
//    ├──────────────────────────────────────────┤
//    │ index[0]  { type, offset }   8 bytes      │
//    │ index[1]  { type, offset }   8 bytes      │
//    │ …                                        │
//    ├──────────────────────────────────────────┤
//    │ blob 0   (CodeDirectory)                 │
//    │ blob 1   (Requirements)                  │
//    │ blob 2   (Entitlements)                  │
//    │ blob 3   (CMS signature, or empty)       │
//    └──────────────────────────────────────────┘
//
//  Two details bite people here:
//
//    • Offsets are relative to the START OF THE SUPERBLOB, not to the end of
//      the index table.
//    • Every member blob must start 8-byte aligned, and the SuperBlob's own
//      length must be too. Padding goes *between* blobs, never inside one.
//
//  The ad-hoc case (no certificate to sign with) still builds a complete
//  SuperBlob; it simply carries an empty `CSMAGIC_BLOBWRAPPER` in the signature
//  slot and sets `CS_ADHOC` in the CodeDirectory flags. That is exactly what
//  `codesign -s -` produces, and it is what Luna emits in this stage — the CMS
//  signature is the one piece a certificate is required for.
//

import Foundation

enum CodeSignError: LocalizedError {
    case specialSlotCountTooSmall(declared: UInt32, required: UInt32)
    case noCodeSignatureLoadCommand
    case codeLimitExceedsFile
    case cannotExpandSignatureRegion(needed: Int, available: Int)
    case malformedMachO(String)
    case identifierMissing
    case unsupportedBinary(String)
    case signingFailed(String)

    var errorDescription: String? {
        switch self {
        case .specialSlotCountTooSmall(let declared, let required):
            return "签名槽位数量不足：声明 \(declared)，实际需要 \(required)"
        case .noCodeSignatureLoadCommand:
            return "二进制中没有 LC_CODE_SIGNATURE 命令，无法写入签名"
        case .codeLimitExceedsFile:
            return "签名覆盖范围超出文件长度"
        case .cannotExpandSignatureRegion(let needed, let available):
            return "签名区空间不足：需要 \(needed) 字节，只有 \(available) 字节可用"
        case .malformedMachO(let detail):
            return "Mach-O 结构异常：\(detail)"
        case .identifierMissing:
            return "缺少签名标识符（CFBundleIdentifier）"
        case .unsupportedBinary(let detail):
            return "不支持该二进制：\(detail)"
        case .signingFailed(let detail):
            return "签名失败：\(detail)"
        }
    }
}

/// One member of a SuperBlob.
struct SuperBlobMember {
    /// `CSSLOT_*` slot index.
    let slot: UInt32
    /// A fully formed blob, including its own `magic` and `length` prefix.
    let blob: Data

    init(slot: UInt32, blob: Data) {
        self.slot = slot
        self.blob = blob
    }
}

enum SuperBlobBuilder {

    /// Packs members into a SuperBlob.
    ///
    /// Member order follows the order given, but the blob table is padded so
    /// each member begins on an 8-byte boundary. The index is written first
    /// and the offsets are patched in as the body is appended.
    static func build(members: [SuperBlobMember]) -> Data {

        let indexEntrySize = 8
        let headerSize = 12
        let indexSize = members.count * indexEntrySize
        let bodyStart = headerSize + indexSize

        // Lay out the body, recording an offset for each member as we go.
        var body = Data()
        var offsets: [UInt32] = []
        offsets.reserveCapacity(members.count)

        for member in members {
            // Pad up to the next 8-byte boundary. The first member sits at
            // `bodyStart`, which is already aligned because both the header
            // and the index entry are multiples of 8.
            let current = bodyStart + body.count
            let padding = (8 - (current % 8)) % 8
            if padding > 0 {
                body.append(contentsOf: [UInt8](repeating: 0, count: padding))
            }
            offsets.append(UInt32(bodyStart + body.count))
            body.append(member.blob)
        }

        let totalLength = bodyStart + body.count

        var out = Data()
        out.reserveCapacity(totalLength)
        out.appendLE(CodeSignMagic.embeddedSignature)
        out.appendLE(UInt32(totalLength))
        out.appendLE(UInt32(members.count))

        for (index, member) in members.enumerated() {
            out.appendLE(member.slot)
            out.appendLE(offsets[index])
        }
        out.append(body)

        return out
    }

    // MARK: - Member blobs

    /// A generic blob: `magic | length | payload`.
    ///
    /// Every member except the SuperBlob itself uses this shape, so one
    /// builder covers the CodeDirectory, both entitlements flavours, and the
    /// blob wrapper.
    static func genericBlob(magic: UInt32, payload: Data) -> Data {
        var out = Data()
        out.reserveCapacity(8 + payload.count)
        out.appendLE(magic)
        out.appendLE(UInt32(8 + payload.count))
        out.append(payload)
        return out
    }

    /// The Requirements slot.
    ///
    /// A real signature carries a compiled requirement expression here. Writing
    /// one by hand means emitting the requirement language's opcode form, which
    /// is a sizeable piece of work with no benefit for our case: an ad-hoc
    /// signature is explicitly outside any identity-based policy, and the
    /// kernel treats an empty requirement set as "no constraints". We therefore
    /// emit the canonical empty set — a `CSMAGIC_REQUIREMENTS` header with a
    /// zero count — which is exactly what `codesign -s -` writes.
    static func emptyRequirements() -> Data {
        var payload = Data()
        payload.appendLE(UInt32(0))                 // count = 0 requirements
        return genericBlob(magic: CodeSignMagic.requirements, payload: payload)
    }

    /// The entitlements slot, carrying an XML plist verbatim.
    ///
    /// The kernel only needs the bytes to hash consistently; it parses them
    /// when checking a process's entitlements. An empty dictionary plist is
    /// the honest value for a guest whose entitlements are not being claimed.
    static func entitlementsBlob(xml: Data) -> Data {
        genericBlob(magic: CodeSignMagic.entitlements, payload: xml)
    }

    /// An empty `CSMAGIC_BLOBWRAPPER`, used as the signature slot for an
    /// ad-hoc signature.
    ///
    /// The slot must exist and be describable by the CodeDirectory's special
    /// slots; leaving it empty (rather than omitting it) is what `codesign`
    /// does and what the kernel expects to find.
    static func emptySignatureWrapper() -> Data {
        genericBlob(magic: CodeSignMagic.blobWrapper, payload: Data())
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}
