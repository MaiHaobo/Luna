//
//  SigningContext.swift
//  Luna
//
//  The identity a signing pass runs under.
//
//  Every layer of the pipeline — Mach-O signer, bundle signer, resigner —
//  needs the same four things: a key, the certificate that goes with it, the
//  entitlements to declare, and a team ID to record in the CodeDirectory.
//  Bundling them means the difference between "sign with a certificate" and
//  "sign ad-hoc" is a single optional value threaded through, rather than
//  four parameters that can disagree with one another.
//
//  WHY THIS IS NOT `Codable`
//  -------------------------
//  It holds a `SecKey` and a `SecIdentity`, neither of which is codable, and
//  that is the point: an instance exists only for the duration of one signing
//  pass. The durable half — the `SigningCertificate` — is what the store
//  persists.
//
//  THREADING
//  ---------
//  `SecKey` and `SecIdentity` are `CFTypeRef`s and are safe to hold across a
//  thread hop, but they are *not* `Sendable`, and marking a struct holding
//  them `Sendable` would be a lie the compiler is entitled to act on. So this
//  type stays non-`Sendable` and lives entirely inside the detached task that
//  builds it. `GuestResigner` resolves the credential *inside* the work item
//  rather than passing one across the boundary — see the note there.
//

import Foundation
import Security

/// Everything one signing pass needs to produce a certificate-backed
/// signature.
struct SigningCredential {

    /// The durable record, for display names and reporting.
    let certificate: SigningCertificate

    /// The signer. Held so the CMS builder can read the issuer and serial.
    let identity: SecIdentity

    /// The leaf certificate.
    let leafCertificate: SecCertificate

    /// The private key, already resolved from the keychain.
    let privateKey: SecKey

    /// How the key signs.
    let algorithm: KeyAlgorithm

    /// Entitlements to declare, as XML plist bytes.
    ///
    /// Applied to the **main bundle only**. Nested code — frameworks, app
    /// extensions, plain dylibs — is signed with the same key but without
    /// entitlements: an `application-identifier` naming the host app on a
    /// framework inside it is a mismatch iOS refuses, and a framework has no
    /// business claiming an application identifier at all.
    let entitlementsXML: Data

    /// Team ID recorded in the CodeDirectory.
    ///
    /// Must be present for a certificate-backed signature — the CodeDirectory
    /// has a dedicated `teamID` field and a signature that claims a
    /// certificate while leaving it blank is one Apple's verifier rejects. The
    /// initialiser enforces this for the certificate case rather than leaving
    /// it to a caller who might forget.
    let teamID: String

    init(
        certificate: SigningCertificate,
        identity: SecIdentity,
        leafCertificate: SecCertificate,
        privateKey: SecKey,
        algorithm: KeyAlgorithm,
        entitlementsXML: Data,
        teamID: String
    ) {
        self.certificate = certificate
        self.identity = identity
        self.leafCertificate = leafCertificate
        self.privateKey = privateKey
        self.algorithm = algorithm
        self.entitlementsXML = entitlementsXML
        self.teamID = teamID
    }
}

/// An entitlements plist built for a specific guest under a specific profile.
enum EntitlementsBuilder {

    /// Produces the XML bytes to embed, given a profile's entitlement
    /// dictionary and the guest's bundle identifier.
    ///
    /// The profile's `Entitlements` dictionary is what iOS will check against
    /// at launch, but two of its keys name the *host* profile rather than the
    /// guest and have to be rewritten:
    ///
    /// - `application-identifier` — a wildcard profile carries `TEAMID.*`,
    ///   which has to become the guest's real bundle ID.
    /// - `keychain-access-groups` — the same wildcard substitution, since the
    ///   group strings are prefixed with the application identifier.
    ///
    /// Everything else is copied through untouched. Inventing entitlements a
    /// profile did not grant is the fastest way to a rejected install, so the
    /// builder adds nothing.
    static func make(
        profile: ProvisioningProfileSummary,
        rawEntitlements: [String: Any],
        bundleIdentifier: String
    ) -> Data {

        var entitlements = rawEntitlements

        let resolved = CertificateImporter.resolveApplicationIdentifier(
            profile.applicationIdentifier, bundleIdentifier: bundleIdentifier)
        entitlements["application-identifier"] = resolved

        // `com.apple.developer.team-identifier` is the other key that names
        // the team; it comes straight from the profile and needs no rewriting.
        //
        // Keychain groups follow the same wildcard convention as the
        // application identifier — `TEAMID.*` for a wildcard profile — so the
        // substitution is the same one: everything before the `*`, then the
        // guest's bundle ID. A group without a `*` is a literal group the
        // profile explicitly granted and is left alone.
        if let groups = entitlements["keychain-access-groups"] as? [String] {
            entitlements["keychain-access-groups"] = groups.map { group in
                guard let star = group.lastIndex(of: "*") else { return group }
                return String(group[group.startIndex..<star]) + bundleIdentifier
            }
        }

        return (try? PropertyListSerialization.data(
            fromPropertyList: entitlements,
            format: .xml,
            options: 0)) ?? Data()
    }
}
