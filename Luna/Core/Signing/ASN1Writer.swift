//
//  ASN1Writer.swift
//  Luna
//
//  Minimal DER (Distinguished Encoding Rules) encoder.
//
//  WHY THIS EXISTS
//  ---------------
//  An iOS code signature is a stack of ASN.1 structures: the Requirements blob
//  is DER, the entitlements are embedded as DER, and the CMS signature wrapping
//  the CodeDirectory is a full PKCS#7 SignedData. The established tools reach
//  for OpenSSL to build these (zsign and ldid both do), but a ~5 MB C
//  dependency is a poor fit for an iOS app that must build in a sandboxed CI
//  with no network guarantees.
//
//  The newer generation of signers has moved away from OpenSSL: `zsign-rs`
//  builds every structure by hand and pairs it with a pure-Rust crypto stack,
//  verifying the result with Apple's own `codesign --verify --deep --strict`
//  in CI. Luna follows that route, with one advantage — the cryptographic
//  primitive (RSA / ECDSA) comes from Security.framework via
//  `SecKeyCreateSignature`, so only the *encoding* has to be written here.
//
//  SCOPE
//  -----
//  Only the DER subset a code signature needs: definite lengths, primitive and
//  constructed tags, and context-specific tagging. No BER, no indefinite
//  lengths, no character sets beyond UTF8String and PrintableString.
//
//  The encoder is a value builder: each `append` returns a new instance, so
//  call sites read as nested expressions that mirror the structure they emit.
//

import Foundation

/// DER tag classes and the encoded-tag constants we actually use.
enum ASN1Tag {
    /// Universal, primitive.
    static let boolean: UInt8 = 0x01
    static let integer: UInt8 = 0x02
    static let bitString: UInt8 = 0x03
    static let octetString: UInt8 = 0x04
    static let null: UInt8 = 0x05
    static let objectIdentifier: UInt8 = 0x06
    static let utf8String: UInt8 = 0x0C
    static let printableString: UInt8 = 0x13
    static let utcTime: UInt8 = 0x17
    static let generalizedTime: UInt8 = 0x18

    /// Universal, constructed.
    static let sequence: UInt8 = 0x30
    static let set: UInt8 = 0x31

    /// Context-specific, constructed — tag `n` in `[n]`.
    ///
    /// CMS wraps several fields (`contentInfo.content`, `signerInfos`, …) in
    /// explicit context tags. DER encodes `[0] constructed` as `0xA0 | n`.
    static func contextConstructed(_ n: UInt8) -> UInt8 { 0xA0 | n }

    /// Context-specific, primitive — used for the DER entitlements' implicit
    /// tags and for `[0] IMPLICIT` fields inside CMS.
    static func contextPrimitive(_ n: UInt8) -> UInt8 { 0x80 | n }
}

/// Builds a DER-encoded byte string.
struct ASN1Writer {

    private(set) var bytes: Data

    init() { bytes = Data() }

    init(_ bytes: Data) { self.bytes = bytes }

    // MARK: - Length

    /// Encodes a DER length in the shortest form.
    ///
    /// `0..<128` is a single byte. Larger values use the long form: a leading
    /// byte with the high bit set, whose low 7 bits give the count of
    /// subsequent big-endian length bytes.
    static func encodeLength(_ length: Int) -> Data {
        precondition(length >= 0, "DER length cannot be negative")
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        var value = length
        var octets: [UInt8] = []
        while value > 0 {
            octets.append(UInt8(value & 0xFF))
            value >>= 8
        }
        octets.reverse()
        return Data([0x80 | UInt8(octets.count)] + octets)
    }

    // MARK: - Primitives

    /// A tag-length-value triple.
    static func tlv(tag: UInt8, content: Data) -> Data {
        var out = Data([tag])
        out.append(encodeLength(content.count))
        out.append(content)
        return out
    }

    /// Appends a pre-encoded child.
    mutating func append(_ child: Data) {
        bytes.append(child)
    }

    mutating func append(_ child: ASN1Writer) {
        bytes.append(child.bytes)
    }

    /// Wraps everything appended so far — and nothing else — in a new
    /// structure.
    ///
    /// The builder pattern is: start empty, append children, then `wrapped`.
    /// Returning a fresh writer rather than mutating in place keeps the
    /// nesting readable and makes each value independent.
    func wrapped(tag: UInt8) -> ASN1Writer {
        ASN1Writer(Self.tlv(tag: tag, content: bytes))
    }

    // MARK: - Universal types

    static func boolean(_ value: Bool) -> Data {
        tlv(tag: ASN1Tag.boolean, content: Data([value ? 0xFF : 0x00]))
    }

    static func null() -> Data {
        tlv(tag: ASN1Tag.null, content: Data())
    }

    /// A non-negative INTEGER, minimal two's-complement form.
    ///
    /// DER requires the shortest encoding, and requires a leading 0x00 when
    /// the top bit of the most significant byte is set (otherwise the value
    /// would read as negative). Code signatures only ever carry non-negative
    /// integers, so the negative path is not implemented.
    static func integer(_ value: Int) -> Data {
        precondition(value >= 0, "ASN.1 INTEGER here must be non-negative")
        if value == 0 {
            return tlv(tag: ASN1Tag.integer, content: Data([0x00]))
        }
        var octets: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            octets.append(UInt8(remaining & 0xFF))
            remaining >>= 8
        }
        octets.reverse()
        if octets[0] & 0x80 != 0 {
            octets.insert(0x00, at: 0)
        }
        return tlv(tag: ASN1Tag.integer, content: Data(octets))
    }

    /// A non-negative INTEGER from an unsigned 64-bit value.
    static func integer(_ value: UInt64) -> Data {
        if value == 0 {
            return tlv(tag: ASN1Tag.integer, content: Data([0x00]))
        }
        var octets: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            octets.append(UInt8(remaining & 0xFF))
            remaining >>= 8
        }
        octets.reverse()
        if octets[0] & 0x80 != 0 {
            octets.insert(0x00, at: 0)
        }
        return tlv(tag: ASN1Tag.integer, content: Data(octets))
    }

    /// An INTEGER from raw bytes, always encoded as positive.
    ///
    /// Used for cryptographic values (RSA moduli, ECDSA coordinates) that
    /// arrive as unsigned big-endian byte strings: DER still needs the leading
    /// 0x00 guard when the high bit is set.
    static func positiveInteger(_ raw: Data) -> Data {
        var content = Data(raw.drop { $0 == 0x00 })
        if content.isEmpty { content = Data([0x00]) }
        if content[content.startIndex] & 0x80 != 0 {
            content.insert(0x00, at: 0)
        }
        return tlv(tag: ASN1Tag.integer, content: content)
    }

    static func octetString(_ value: Data) -> Data {
        tlv(tag: ASN1Tag.octetString, content: value)
    }

    static func utf8String(_ value: String) -> Data {
        tlv(tag: ASN1Tag.utf8String, content: Data(value.utf8))
    }

    static func printableString(_ value: String) -> Data {
        tlv(tag: ASN1Tag.printableString, content: Data(value.utf8))
    }

    /// A BIT STRING with the given number of unused trailing bits.
    ///
    /// The first content byte is the count of unused bits in the final octet.
    /// Public keys and CMS signatures are both BIT STRINGs with zero unused
    /// bits.
    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        tlv(tag: ASN1Tag.bitString, content: Data([unusedBits]) + value)
    }

    /// An OBJECT IDENTIFIER from dotted-decimal notation.
    ///
    /// Encoding: the first two arcs are packed into one byte as `40*a + b`,
    /// and every subsequent arc is base-128 with continuation bits.
    static func objectIdentifier(_ dotted: String) -> Data {
        let arcs = dotted.split(separator: ".").compactMap { UInt64($0) }
        precondition(arcs.count >= 2, "OID needs at least two arcs: \(dotted)")

        var content = Data()
        content.append(UInt8(arcs[0] * 40 + arcs[1]))

        for arc in arcs.dropFirst(2) {
            var value = arc
            var stack: [UInt8] = [UInt8(value & 0x7F)]
            value >>= 7
            while value > 0 {
                stack.append(UInt8(value & 0x7F) | 0x80)
                value >>= 7
            }
            content.append(contentsOf: stack.reversed())
        }
        return tlv(tag: ASN1Tag.objectIdentifier, content: content)
    }

    // MARK: - Time

    /// `UTCTime`, used by X.509 certificates for dates before 2050.
    ///
    /// Format is `YYMMDDHHMMSSZ`, always UTC. DER forbids the missing-seconds
    /// and local-time variants.
    static func utcTime(_ date: Date) -> Data {
        tlv(tag: ASN1Tag.utcTime, content: timeData(date, format: "yyMMddHHmmss"))
    }

    /// `GeneralizedTime`, the encoding X.509 requires from 2050 onward.
    static func generalizedTime(_ date: Date) -> Data {
        tlv(tag: ASN1Tag.generalizedTime, content: timeData(date, format: "yyyyMMddHHmmss"))
    }

    private static func timeData(_ date: Date, format: String) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = format
        return Data((formatter.string(from: date) + "Z").utf8)
    }

    // MARK: - Context-specific

    /// `[n]` constructed (explicit tagging), wrapping `content`.
    static func context(_ n: UInt8, _ content: Data) -> Data {
        tlv(tag: ASN1Tag.contextConstructed(n), content: content)
    }

    /// `[n]` primitive (implicit tagging), carrying `content` directly.
    static func contextImplicit(_ n: UInt8, _ content: Data) -> Data {
        tlv(tag: ASN1Tag.contextPrimitive(n), content: content)
    }

    // MARK: - Sequences and sets

    /// A SEQUENCE built from already-encoded children.
    static func sequence(_ children: [Data]) -> Data {
        var body = Data()
        for child in children { body.append(child) }
        return tlv(tag: ASN1Tag.sequence, content: body)
    }

    /// A SET built from already-encoded children.
    ///
    /// DER requires SET members to be sorted by their encodings; callers that
    /// emit CMS signed attributes are responsible for the sort, because the
    /// ordering is part of what gets hashed.
    static func set(_ children: [Data], sort: Bool = true) -> Data {
        var ordered = children
        if sort {
            ordered.sort { lhs, rhs in
                lhs.lexicographicallyPrecedes(rhs)
            }
        }
        var body = Data()
        for child in ordered { body.append(child) }
        return tlv(tag: ASN1Tag.set, content: body)
    }
}
