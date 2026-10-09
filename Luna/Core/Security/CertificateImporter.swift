//
//  CertificateImporter.swift
//  Luna
//
//  Turns a user-supplied `.p12` (+ optional `.mobileprovision`) into a
//  `SigningCertificate` and the keychain items behind it.
//
//  This is the only place in Luna that reads keychain material, and it is
//  written so that every check that could possibly fail *before* the keychain
//  is touched happens first. Importing is a two-file operation against an
//  external portal's naming conventions, and the failure modes are
//  user-facing: a password typed once, weeks ago, on a different machine.
//
//  THE TWO FILE FORMATS
//  --------------------
//  `.p12` — PKCS#12. `SecPKCS12Import` parses it and hands back an identity
//  when the password is right, an empty result when the password is wrong,
//  and an error when the file is not a PKCS#12 at all. The three cases need
//  three different messages, which is why the code below inspects the
//  `OSStatus` rather than treating every failure as "bad password".
//
//  `.mobileprovision` — a plist wrapped in a PKCS#7 signature. The plist is
//  plain XML in the middle of the file. `CMSDecoder` unwraps it properly;
//  scanning for `<?xml` is the fallback for the rare profile that some
//  certificate authority has re-wrapped in a way `CMSDecoder` rejects.
//

import Foundation
import Security

enum CertificateImporter {

    /// Everything an import produces that the caller has to persist.
    struct Result {
        var certificate: SigningCertificate
        /// The `.p12` bytes, to be written to the certificate's folder.
        var p12Data: Data
        /// The original profile bytes, to be embedded at signing time.
        var profileData: Data?
    }

    // MARK: - Entry point

    /// A complete, persisted import.
    struct Installed {
        var certificate: SigningCertificate
        /// True when this fingerprint was already known; the record was
        /// refreshed rather than added.
        var replacedExisting: Bool
    }

    /// Parses, stores, and registers a signing identity.
    ///
    /// The whole import in one call, because the three steps have to happen
    /// in this order and with this much cleanup between them: validate
    /// everything first (so a bad profile leaves no trace), then write the
    /// keychain items and the `.p12` (so `CertificateStore.reconcile()` will
    /// keep the record), then hand the record to the store.
    static func install(
        p12: Data,
        password: String,
        profile profileData: Data?,
        into store: CertificateStore
    ) throws -> Installed {

        let parsed = try parse(p12: p12, password: password, profile: profileData)

        // Re-importing an existing certificate reuses its ID, so the old
        // files have to be cleared before the new ones are written —
        // otherwise the folder keeps a `.p12` from a previous, possibly
        // different, export.
        let known = store.certificates.first { $0.sha256 == parsed.certificate.sha256 }
        let id = known?.id ?? parsed.certificate.id

        let folder = LunaPaths.certificatesDirectory
            .appendingPathComponent(id.uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: folder, withIntermediateDirectories: true)
        } catch {
            throw CertificateImportError.storageFailure(error.localizedDescription)
        }

        // 0600 plus file-level protection: the `.p12` is already encrypted by
        // its export password, but there is no reason to also let it be read
        // from a backup image before the user has unlocked the device once.
        let p12URL = folder.appendingPathComponent("identity.p12")
        do {
            try parsed.p12Data.write(to: p12URL, options: [.atomic, .completeFileProtection])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: p12URL.path)
        } catch {
            throw CertificateImportError.storageFailure(error.localizedDescription)
        }
        excludeFromBackup(folder)
        excludeFromBackup(p12URL)

        // The profile goes next to the `.p12`, under a fixed name. It has to
        // be kept: the manifest's `ProvisioningProfileSummary` is lossy, and
        // signing needs the *entitlements dictionary* out of the original
        // plist. See `GuestStore.rawEntitlements`.
        if let profileData {
            let profileURL = folder.appendingPathComponent("profile.mobileprovision")
            do {
                try profileData.write(to: profileURL, options: [.atomic, .completeFileProtection])
            } catch {
                throw CertificateImportError.storageFailure(error.localizedDescription)
            }
            excludeFromBackup(profileURL)
        }

        // Keychain last among the writes: `reconcile()` treats a missing
        // keychain item as "this certificate is gone", so writing it before
        // the `.p12` would briefly describe a broken identity.
        try SigningKeychain.storePassword(password, for: id)

        // Re-import the identity from the bytes we just wrote rather than
        // persisting the one from `parse()`: this exercises the same path a
        // later signing run will take, so a `.p12` that cannot be re-read
        // fails here instead of at signing time.
        let reloaded = try importIdentity(from: parsed.p12Data, password: password)
        let key = try privateKey(of: reloaded)
        _ = try SigningKeychain.storePrivateKey(key, for: id)

        let certificate = SigningCertificate(
            id: id,
            displayName: known?.displayName ?? parsed.certificate.displayName,
            commonName: parsed.certificate.commonName,
            teamID: parsed.certificate.teamID,
            organization: parsed.certificate.organization,
            serialNumber: parsed.certificate.serialNumber,
            notBefore: parsed.certificate.notBefore,
            notAfter: parsed.certificate.notAfter,
            sha256: parsed.certificate.sha256,
            keyAlgorithm: parsed.certificate.keyAlgorithm,
            p12FileName: "identity.p12",
            importedAt: known?.importedAt ?? Date(),
            profile: parsed.certificate.profile ?? known?.profile)

        store.insert(certificate)

        return Installed(certificate: certificate, replacedExisting: known != nil)
    }

    /// Marks a URL as excluded from iCloud and iTunes backup.
    ///
    /// Best-effort: the attribute is a nicety, and failing to set it is not
    /// a reason to fail an import that has otherwise succeeded.
    private static func excludeFromBackup(_ url: URL) {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    /// Parses a `.p12`, optionally matching it against a `.mobileprovision`.
    ///
    /// Does no filesystem or keychain writes — the caller does that once
    /// these validations have all passed. That split matters: an import that
    /// fails on the profile should not leave a stray keychain item behind.
    static func parse(
        p12: Data,
        password: String,
        profile profileData: Data?
    ) throws -> Result {

        let identity = try importIdentity(from: p12, password: password)
        let certificateRef = try certificate(of: identity)
        let privateKey = try privateKey(of: identity)

        let summary = try summarize(certificateRef)
        let keyAlgorithm = describe(privateKey)

        try validateValidity(summary)

        var profileSummary: ProvisioningProfileSummary?
        if let profileData {
            let parsed = try parseProfile(profileData)
            try validate(profile: parsed, against: summary)
            profileSummary = parsed
        }

        guard let firstCertificate = summary.certificates.first else {
            throw CertificateImportError.noIdentity
        }

        let certificate = SigningCertificate(
            id: UUID(),
            displayName: summary.displayName,
            commonName: firstCertificate.commonName,
            teamID: firstCertificate.teamID,
            organization: firstCertificate.organization,
            serialNumber: firstCertificate.serialNumber,
            notBefore: firstCertificate.notBefore,
            notAfter: firstCertificate.notAfter,
            sha256: firstCertificate.sha256,
            keyAlgorithm: keyAlgorithm,
            p12FileName: "identity.p12",
            importedAt: Date(),
            profile: profileSummary)

        return Result(
            certificate: certificate,
            p12Data: p12,
            profileData: profileData)
    }

    // MARK: - Identity

    /// Runs `SecPKCS12Import` and pulls the identity out of the result.
    ///
    /// `SecPKCS12Import` does not distinguish "wrong password" from "not a
    /// p12" by status code — both surface as `errSecAuthFailed` on some iOS
    /// versions and `errSecDecode` on others. The check that actually
    /// disambiguates is whether the input even looks like DER: a PKCS#12 file
    /// always starts with a SEQUENCE tag and is long enough to hold one.
    static func importIdentity(from data: Data, password: String) throws -> SecIdentity {
        guard data.count > 32, data.first == ASN1Tag.sequence else {
            throw CertificateImportError.wrongFileType(
                name: "所选文件", expected: ".p12")
        }

        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: password]
        let status = SecPKCS12Import(
            data as CFData, options as CFDictionary, &items)

        switch status {
        case errSecSuccess:
            break
        case errSecAuthFailed, errSecPkcs12VerifyFailure:
            throw CertificateImportError.badPassword
        case errSecDecode:
            throw CertificateImportError.wrongFileType(
                name: "所选文件", expected: ".p12")
        default:
            throw CertificateImportError.badPassword
        }

        guard let entries = items as? [[String: Any]], !entries.isEmpty else {
            throw CertificateImportError.noIdentity
        }

        // A `.p12` can hold several identities; a signing certificate is the
        // first one that has both halves. Taking the first *identity* rather
        // than the first *certificate* is what makes an export that included
        // an intermediate CA work.
        for entry in entries {
            if let identity = entry[kSecImportItemIdentity as String] {
                return (identity as! SecIdentity)
            }
        }

        throw CertificateImportError.missingPrivateKey
    }

    private static func certificate(of identity: SecIdentity) throws -> SecCertificate {
        var certificate: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &certificate)
        guard status == errSecSuccess, let certificate else {
            throw CertificateImportError.noIdentity
        }
        return certificate
    }

    private static func privateKey(of identity: SecIdentity) throws -> SecKey {
        var key: SecKey?
        let status = SecIdentityCopyPrivateKey(identity, &key)
        guard status == errSecSuccess, let key else {
            throw CertificateImportError.missingPrivateKey
        }
        return key
    }

    // MARK: - Certificate fields

    /// The subset of a certificate's fields Luna needs, extracted via
    /// `SecCertificateCopyValues`.
    struct CertificateSummary {
        struct Entry {
            var commonName: String
            var teamID: String
            var organization: String
            var serialNumber: String
            var notBefore: Date
            var notAfter: Date
            var sha256: String
        }

        var displayName: String
        var certificates: [Entry]
    }

    /// Reads subject, validity, and fingerprint from a certificate.
    ///
    /// `SecCertificateCopyValues` is the sanctioned way to get at these
    /// fields — it is the only API that hands back the *typed* values Apple
    /// extracted, so `kSecOIDOrganizationalUnitName` really is the OU and not
    /// something that merely looks like it after a guess at the DER layout.
    static func summarize(_ certificate: SecCertificate) throws -> CertificateSummary {
        let der = SecCertificateCopyData(certificate) as Data
        let fingerprint = SHA256.hash(data: der).hexString

        guard let raw = SecCertificateCopyValues(
            certificate, nil, nil) as? [CFString: Any]
        else {
            throw CertificateImportError.noIdentity
        }

        var commonName = ""
        var teamID = ""
        var organization = ""

        if let subject = raw[kSecOIDX509V1SubjectName] as? [[CFString: Any]] {
            for entry in subject {
                let label = entry[kSecOIDX509V1SubjectNameLabel] as? String
                let value = entry[kSecOIDX509V1SubjectNameValue] as? String
                guard let value else { continue }
                switch label {
                case kSecOIDCommonName as String:
                    // A certificate can carry more than one CN; the first is
                    // the one Apple's tooling treats as primary.
                    if commonName.isEmpty { commonName = value }
                case kSecOIDOrganizationalUnitName as String:
                    // Apple puts the ten-character team ID in the OU. It is
                    // *also* where an unrelated organizational unit would go,
                    // so it is validated below rather than trusted blindly.
                    if teamID.isEmpty { teamID = value }
                case kSecOIDOrganizationName as String:
                    if organization.isEmpty { organization = value }
                default:
                    break
                }
            }
        }

        let notBefore = date(from: raw[kSecOIDX509V1ValidityNotBefore]) ?? .distantPast
        let notAfter = date(from: raw[kSecOIDX509V1ValidityNotAfter]) ?? .distantPast

        let serial = (raw[kSecOIDX509V1SerialNumber] as? String) ?? ""

        // Apple's developer certificates always carry a 10-character
        // alphanumeric OU. Anything else is either not a developer
        // certificate or has been hand-assembled, and either way cannot be
        // matched against a profile.
        guard teamID.count == 10,
              teamID.allSatisfy({ $0.isLetter || $0.isNumber })
        else {
            throw CertificateImportError.missingTeamIdentifier(
                "CN=\(commonName) OU=\(teamID.isEmpty ? "（空）" : teamID)")
        }

        let entry = Entry(
            commonName: commonName.isEmpty ? "未命名证书" : commonName,
            teamID: teamID,
            organization: organization,
            serialNumber: serial,
            notBefore: notBefore,
            notAfter: notAfter,
            sha256: fingerprint)

        return CertificateSummary(
            displayName: entry.commonName,
            certificates: [entry])
    }

    /// `SecCertificateCopyValues` dates come back wrapped in a dictionary.
    private static func date(from value: Any?) -> Date? {
        guard let dictionary = value as? [CFString: Any] else { return nil }
        return dictionary[kSecPropertyKeyValue] as? Date
    }

    private static func validateValidity(_ summary: CertificateSummary) throws {
        guard let entry = summary.certificates.first else { return }
        let now = Date()
        if entry.notAfter < now {
            throw CertificateImportError.certificateExpired(until: entry.notAfter)
        }
        if entry.notBefore > now {
            // A small tolerance: clocks drift, and a certificate that became
            // valid an hour ago in Cupertino can still look future-dated on a
            // device in a different time zone.
            if entry.notBefore.timeIntervalSince(now) > 3600 {
                throw CertificateImportError.certificateNotYetValid(from: entry.notBefore)
            }
        }
    }

    /// Human-readable key type, derived from the key itself.
    ///
    /// Derived rather than declared so that a stored `keyAlgorithm` can never
    /// disagree with the key it describes.
    static func describe(_ key: SecKey) -> String {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any]
        else { return "未知" }

        let type = attributes[kSecAttrKeyType] as? String ?? ""
        let size = (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0

        if type == (kSecAttrKeyTypeRSA as String) {
            return "RSA-\(size)"
        }
        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            switch size {
            case 256: return "EC-P256"
            case 384: return "EC-P384"
            case 521: return "EC-P521"
            default: return "EC-\(size)"
            }
        }
        return "\(type)-\(size)"
    }

    // MARK: - Provisioning profile

    /// Unwraps a `.mobileprovision` and reads the keys that matter.
    static func parseProfile(_ data: Data) throws -> ProvisioningProfileSummary {
        let plistData = unwrapProfile(data) ?? data

        let plist: [String: Any]
        do {
            guard let parsed = try PropertyListSerialization.propertyList(
                from: plistData, options: [], format: nil) as? [String: Any]
            else {
                throw CertificateImportError.profileUnreadable("内容不是属性列表")
            }
            plist = parsed
        } catch let error as CertificateImportError {
            throw error
        } catch {
            throw CertificateImportError.profileUnreadable(error.localizedDescription)
        }

        guard let name = plist["Name"] as? String,
              let uuid = plist["UUID"] as? String
        else {
            throw CertificateImportError.profileUnreadable("缺少 Name 或 UUID 字段")
        }

        guard let teams = plist["TeamIdentifier"] as? [String],
              let teamID = teams.first
        else {
            throw CertificateImportError.profileUnreadable("缺少 TeamIdentifier")
        }

        let entitlements = plist["Entitlements"] as? [String: Any] ?? [:]
        guard let applicationIdentifier =
                entitlements["application-identifier"] as? String
        else {
            throw CertificateImportError.profileUnreadable(
                "缺少 application-identifier，可能不是应用描述文件")
        }

        guard let expiration = plist["ExpirationDate"] as? Date else {
            throw CertificateImportError.profileUnreadable("缺少 ExpirationDate")
        }

        // `DeveloperCertificates` is an array of `Data`, each holding a full
        // DER certificate. The profile lists *certificate* fingerprints, so
        // the comparison at signing time is against the leaf certificate, not
        // against the p12.
        let certificateFingerprints = (plist["DeveloperCertificates"] as? [Data] ?? [])
            .map { SHA256.hash(data: $0).hexString }

        let devices = plist["ProvisionedDevices"] as? [String] ?? []

        return ProvisioningProfileSummary(
            name: name,
            profileUUID: uuid,
            teamID: teamID,
            applicationIdentifier: applicationIdentifier,
            expirationDate: expiration,
            provisionedDeviceCount: devices.count,
            developerCertificateShas: certificateFingerprints)
    }

    /// Strips the PKCS#7 wrapper, returning the plist bytes inside.
    ///
    /// `CMSDecoder` is the correct tool and handles every profile Apple
    /// actually issues. The byte scan is a fallback for profiles that some
    /// third-party tool has re-wrapped in a way `CMSDecoder` declines; it
    /// finds the XML by its declaration and the first `</plist>` after it.
    static func unwrapProfile(_ data: Data) -> Data? {
        var decoder: CMSDecoder?
        guard CMSDecoderCreate(&decoder) == errSecSuccess, let decoder else {
            return scanForPlist(in: data)
        }

        let updateStatus = data.withUnsafeBytes { buffer -> OSStatus in
            guard let base = buffer.baseAddress else { return errSecParam }
            return CMSDecoderUpdateMessage(decoder, base, data.count)
        }
        guard updateStatus == errSecSuccess,
              CMSDecoderFinalizeMessage(decoder) == errSecSuccess
        else {
            return scanForPlist(in: data)
        }

        var content: CFData?
        guard CMSDecoderCopyContent(decoder, &content) == errSecSuccess,
              let content, (content as Data).count > 0
        else {
            return scanForPlist(in: data)
        }
        return content as Data
    }

    /// Byte-scans for `<?xml` … `</plist>`.
    private static func scanForPlist(in data: Data) -> Data? {
        let startMarker = Data("<?xml".utf8)
        let endMarker = Data("</plist>".utf8)

        guard let start = data.range(of: startMarker),
              let end = data.range(of: endMarker, in: start.lowerBound..<data.endIndex)
        else { return nil }

        return data.subdata(in: start.lowerBound..<end.upperBound)
    }

    /// Checks that the profile will actually accept this certificate.
    ///
    /// Two independent checks, because they fail for different reasons and
    /// the user's fix differs:
    ///
    /// - **Team**: a profile and a certificate from different accounts never
    ///   work together, and the mismatch is obvious from the two IDs.
    /// - **Certificate list**: the profile enumerates the certificates it
    ///   will sign with. A certificate that is valid but not in the list
    ///   produces `0xe8008015` on install — an error that says nothing about
    ///   which half is wrong.
    static func validate(
        profile: ProvisioningProfileSummary,
        against summary: CertificateSummary
    ) throws {
        guard let entry = summary.certificates.first else { return }

        if !profile.teamID.isEmpty, profile.teamID != entry.teamID {
            throw CertificateImportError.teamMismatch(
                certificateTeam: entry.teamID, profileTeam: profile.teamID)
        }

        // A profile's `application-identifier` starts with the team ID, which
        // is a second, independent statement of the same fact. Disagreement
        // here means the profile is malformed rather than merely mismatched.
        let prefix = profile.applicationIdentifierTeamPrefix
        if !prefix.isEmpty, prefix != entry.teamID {
            throw CertificateImportError.teamMismatch(
                certificateTeam: entry.teamID, profileTeam: prefix)
        }

        guard profile.expirationDate > Date() else {
            throw CertificateImportError.profileExpired(on: profile.expirationDate)
        }

        // Enterprise and App Store profiles carry no `DeveloperCertificates`
        // list. In that case the team check above is the only gate available,
        // and it has already passed.
        if !profile.developerCertificateShas.isEmpty,
           !profile.developerCertificateShas.contains(entry.sha256) {
            throw CertificateImportError.profileCertificateMismatch(
                profileName: profile.name, certificateName: entry.commonName)
        }
    }

    // MARK: - Wildcard substitution

    /// Rewrites a wildcard profile's application identifier for a guest.
    ///
    /// `TEAMID.*` becomes `TEAMID.<guest bundle id>`, which is what the
    /// signature has to declare for the entitlements to match the bundle
    /// being signed. Without this, a wildcard profile produces an entitlement
    /// containing a literal `*` and iOS rejects the app on launch.
    ///
    /// Non-wildcard profiles pass through unchanged: the guest then has to
    /// have exactly the bundle ID the profile was made for, and if it does
    /// not, the mismatch is caught by iOS rather than silently papered over
    /// here.
    static func resolveApplicationIdentifier(
        _ identifier: String,
        bundleIdentifier: String
    ) -> String {
        guard identifier.hasSuffix("*") else { return identifier }
        let prefix = identifier.dropLast()
        // Strip the guest's own team prefix if the profile's has already been
        // folded in — bundle IDs in a signed bundle do not carry one.
        return prefix + bundleIdentifier
    }
}
