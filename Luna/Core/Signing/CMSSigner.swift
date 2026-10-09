//
//  CMSSigner.swift
//  Luna
//
//  Builds the PKCS#7 signature that goes in a SuperBlob's signature slot.
//
//  This is the piece that turns "Luna wrote a signature" into "Luna wrote a
//  signature Apple will accept". It is also, by a wide margin, the most
//  delicate code in the project: every field here is one that a plausible
//  implementation gets subtly wrong, and the failure mode is not an exception
//  but a signature that a device silently refuses to honour.
//
//  THE SHAPE, AND WHY
//  ------------------
//  Apple's signature slot holds a DER `ContentInfo` wrapping `SignedData`.
//  The variant is *detached*, and Apple's verifier takes that literally:
//
//    → `eContent` is **omitted entirely**. Not an empty OCTET STRING — the
//      field is absent. The content being signed is the CodeDirectory, which
//      the verifier already has by virtue of reading this very SuperBlob;
//      repeating it would be circular, since the signature is part of the
//      blob the CodeDirectory's length covers.
//
//    → `signedAttrs` is **omitted entirely**. This is the single most common
//      way to get this wrong. In ordinary CMS, signed attributes are the
//      normal case and the signature covers a re-encoding of them rather than
//      the content. Apple's verifier does not do that: it expects the
//      signature to be over the CodeDirectory bytes directly. Emit a
//      `signedAttrs` field — even an empty one — and the verifier will hash
//      something Luna did not sign, and reject the result without saying why.
//
//    → `sid` uses `issuerAndSerialNumber`, not the SubjectKeyIdentifier.
//      Apple's verifier identifies the signer from the issuer name and serial
//      that also appear in the certificate, and re-encoding the issuer from
//      parsed fields (CN, O, …) does not reliably reproduce the original
//      bytes. `SecCertificateCopyNormalizedIssuerSequence` hands back the
//      original DER, which is what has to go in.
//
//    → `certificates` is `[0] IMPLICIT`, so the `A0` tag is followed
//      *directly* by the certificate's own SEQUENCE. Wrapping them in another
//      SEQUENCE — which is what the explicit-tagging reflex produces — makes
//      the whole block unparseable.
//
//    → `signature` is an OCTET STRING. Not a BIT STRING; that is X.509's
//      convention for certificate signatures, not CMS's for SignerInfo.
//
//  Everything about the structure is fixed except the two things that vary:
//  the signer's identity and the signature bytes. That is what lets
//  `MachOCodeSigner` use this as a *length-stable* replacement for the empty
//  ad-hoc wrapper: the CMS blob's length depends only on the certificate's
//  size and the key's signature size, never on the CodeDirectory's contents.
//  The three-step signing pass depends on that property; see
//  `MachOCodeSigner.sign` for why.
//
//  Note this class does no I/O and reads no clock. Given the same inputs it
//  produces the same bytes, which is what makes it testable against openssl.
//

import Foundation
import Security

/// The signing algorithms Luna supports, and the details that differ between
/// them.
enum KeyAlgorithm {

    case rsa
    case ecdsa

    /// The `signatureAlgorithm` OID to write into `SignerInfo`.
    ///
    /// The `parameters` field differs between the two and the difference is
    /// not optional: `sha256WithRSAEncryption` is defined with a NULL
    /// parameter and RSA implementations expect it present, while
    /// `ecdsa-with-SHA256` is defined with *no* parameters — RFC 5758 says so
    /// explicitly, and a NULL there produces a verification failure on some
    /// verifiers.
    var signatureAlgorithmOID: Data {
        switch self {
        case .rsa:
            // 1.2.840.113549.1.1.11 sha256WithRSAEncryption
            return ASN1Writer.sequence([
                ASN1Writer.objectIdentifier("1.2.840.113549.1.1.11"),
                ASN1Writer.null(),
            ])
        case .ecdsa:
            // 1.2.840.10045.4.3.2 ecdsa-with-SHA256
            return ASN1Writer.sequence([
                ASN1Writer.objectIdentifier("1.2.840.10045.4.3.2"),
            ])
        }
    }

    /// Maps a `SecKey` to one of the supported algorithms.
    ///
    /// Everything else — and there is plenty, from Ed25519 to an
    /// odd-sized EC key — is refused here rather than producing a signature
    /// with an algorithm identifier nothing matches.
    static func of(_ key: SecKey) throws -> KeyAlgorithm {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attributes[kSecAttrKeyType] as? String
        else {
            throw CertificateImportError.unsupportedKeyAlgorithm("未知")
        }

        if type == (kSecAttrKeyTypeRSA as String) {
            let bits = (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0
            // Apple's verifier is documented against 2048; 1024 is below what
            // the platform will even accept for a signing certificate, and
            // larger sizes are fine.
            guard bits >= 2048, bits % 8 == 0 else {
                throw CertificateImportError.unsupportedKeyAlgorithm("RSA-\(bits)")
            }
            return .rsa
        }

        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            let bits = (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0
            guard bits == 256 else {
                throw CertificateImportError.unsupportedKeyAlgorithm("EC-\(bits)")
            }
            return .ecdsa
        }

        throw CertificateImportError.unsupportedKeyAlgorithm(type)
    }

    /// The `SecKeyAlgorithm` passed to `SecKeyCreateSignature`.
    ///
    /// The `…Message…` variants are the ones that take the raw message and
    /// hash it internally. The alternative — `…Digest…` variants — take an
    /// already-computed digest, and using one by mistake here would produce a
    /// signature over a hash of a hash: structurally valid, and rejected by
    /// every verifier.
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .rsa: return .rsaSignatureMessagePKCS1v15SHA256
        case .ecdsa: return .ecdsaSignatureMessageX962SHA256
        }
    }
}

enum CMSSigner {

    /// The digest algorithm identifier, `sha256`, with parameters omitted.
    ///
    /// RFC 5754 requires the parameters to be *absent* for the SHA-2 family.
    /// Writing a NULL here is a common mistake — it is right for the RSA
    /// signature identifier next to it, but wrong for the digest identifier
    /// itself.
    private static var sha256AlgorithmIdentifier: Data {
        ASN1Writer.sequence([
            ASN1Writer.objectIdentifier("2.16.840.1.101.3.4.2.1"),
        ])
    }

    /// Builds the CMS `SignedData` payload for a CodeDirectory.
    ///
    /// The result is what `SuperBlobBuilder.genericBlob(magic: .blobWrapper)`
    /// wraps — that is, the raw DER, without the blob magic and length. The
    /// caller owns that wrapper because the same bytes also have to be
    /// assembled during the length-probing pass.
    ///
    /// - Parameters:
    ///   - codeDirectory: the blob whose bytes are signed, exactly as they
    ///     will appear in the finished SuperBlob.
    ///   - identity: the signer.
    ///   - key: the private key. Passed in rather than read from the identity
    ///     because a retried import may hold a key the identity no longer
    ///     references, and the caller is the one that knows which is current.
    ///   - algorithm: how to sign.
    ///   - additionalCertificates: intermediates to carry alongside the leaf.
    ///     Apple's chain for a developer certificate is short enough that the
    ///     leaf alone usually suffices, but an enterprise chain may not be.
    static func signedData(
        codeDirectory: Data,
        certificate: SecCertificate,
        key: SecKey,
        algorithm: KeyAlgorithm,
        additionalCertificates: [SecCertificate] = []
    ) throws -> Data {

        // MARK: Sign

        // Sign the CodeDirectory *bytes*. The `…Message…` algorithm hashes
        // them internally, so what goes in is the blob, not its digest.
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, algorithm.secKeyAlgorithm,
            codeDirectory as CFData, &error) as Data?
        else {
            let detail = error?.takeRetainedValue().localizedDescription
                ?? "未知错误"
            throw CodeSignError.signingFailed("证书签名运算失败：\(detail)")
        }

        // MARK: SignerInfo

        let signerInfo = ASN1Writer.sequence([
            // version — 1 for issuerAndSerialNumber.
            ASN1Writer.integer(1),
            try signerIdentifier(certificate),
            sha256AlgorithmIdentifier,
            algorithm.signatureAlgorithmOID,
            // signerInfo.signature is an OCTET STRING. The public key is a
            // BIT STRING, which is a different thing, and the two are easy to
            // confuse because both wrap opaque bytes.
            ASN1Writer.octetString(signature),
        ])

        // MARK: SignedData

        // certificates [0] IMPLICIT. The `A0` tag goes straight onto the
        // concatenation of certificate SEQUENCEs — `contextImplicit` produces
        // exactly that, whereas `context` would wrap them in another
        // SEQUENCE and make the block unparseable.
        var certificatesContent = SecCertificateCopyData(certificate) as Data
        for extra in additionalCertificates {
            certificatesContent.append(SecCertificateCopyData(extra) as Data)
        }
        let certificates = ASN1Writer.contextImplicit(0, certificatesContent)

        let signedData = ASN1Writer.sequence([
            // version — 1. (3 would indicate the optional
            // EncapsulatedContentInfo fields, none of which are present.)
            ASN1Writer.integer(1),

            // digestAlgorithms — a SET of the digest identifier. The SET's
            // implicit sort is the DER requirement and, with one member, a
            // no-op.
            ASN1Writer.set([sha256AlgorithmIdentifier]),

            // encapContentInfo — eContentType only. The absence of eContent
            // is the detached form; see the file header.
            ASN1Writer.sequence([
                ASN1Writer.objectIdentifier("1.2.840.113549.1.7.1"),
            ]),

            certificates,

            // signerInfos — a SET of one SignerInfo. Note: no `signedAttrs`
            // anywhere inside it. That omission is deliberate and load
            // bearing.
            ASN1Writer.set([signerInfo]),
        ])

        // MARK: ContentInfo

        return ASN1Writer.sequence([
            ASN1Writer.objectIdentifier("1.2.840.113549.1.7.2"),   // signedData
            ASN1Writer.context(0, signedData),                     // [0] EXPLICIT
        ])
    }

    // MARK: - Pieces

    /// Builds `SignerIdentifier`, the `sid` field.
    ///
    /// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`
    ///
    /// The issuer is taken as the certificate's *original* DER bytes. Building
    /// a `Name` from parsed components would produce a plausible-looking
    /// sequence whose bytes differ from the certificate's — RDN ordering, the
    /// choice between PrintableString and UTF8String, and the treatment of
    /// multi-valued RDNs all vary — and a verifier that looks the serial up
    /// under that name would find nothing.
    private static func signerIdentifier(
        _ certificate: SecCertificate
    ) throws -> Data {
        guard let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate)
            as Data?,
              let serial = SecCertificateCopySerialNumberData(certificate, nil)
            as Data?
        else {
            throw CodeSignError.signingFailed("无法读取证书的颁发者或序列号")
        }

        // `CopyNormalizedIssuerSequence` returns the DER *content* of the
        // Name — an un-tagged concatenation of RDN SETs — not a complete TLV.
        // The explicit sequence tag has to be put back before it can serve as
        // the `issuer` field.
        let issuerName: Data
        if issuer.first == ASN1Tag.sequence {
            issuerName = issuer
        } else {
            issuerName = ASN1Writer.tlv(tag: ASN1Tag.sequence, content: issuer)
        }

        // Ditto for the serial: the API already returns a complete INTEGER
        // TLV, so `positiveInteger` would double-wrap it. Only normalise the
        // case where raw content bytes came back instead.
        let serialNumber: Data
        if serial.first == ASN1Tag.integer {
            serialNumber = serial
        } else {
            serialNumber = ASN1Writer.positiveInteger(serial)
        }

        return ASN1Writer.sequence([issuerName, serialNumber])
    }
}
