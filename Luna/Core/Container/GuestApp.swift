//
//  GuestApp.swift
//  Luna
//
//  The persistent record of a guest application installed inside Luna.
//
//  A guest is *not* installed on the system. It lives entirely inside Luna's
//  Documents directory, which means uninstalling Luna removes every guest —
//  and, importantly, that Luna is the only thing on the device that knows the
//  guest exists.
//

import Foundation

/// Where a guest sits in its lifecycle.
enum GuestState: String, Codable {
    /// Bundle imported and inspected; not yet patched.
    case imported
    /// Binary patched; ready to be handed to the loader.
    case ready
    /// Patched and signed; ready to load without a JIT entitlement.
    case signed
    /// A launch is in flight.
    case launching
    /// Last launch succeeded at least once.
    case launched
    /// Import or patch failed; `lastError` explains why.
    case failed

    var label: String {
        switch self {
        case .imported: return "已导入"
        case .ready: return "待启动"
        case .signed: return "已签名"
        case .launching: return "启动中"
        case .launched: return "已运行过"
        case .failed: return "失败"
        }
    }
}

/// A record of the signature Luna wrote over a guest's bundle.
///
/// Stored rather than recomputed because producing it means hashing every
/// resource in the bundle — expensive enough that the detail screen should not
/// pay for it on every redraw.
struct SignatureSummary: Codable, Hashable {
    /// True when the signature carries no certificate (`CS_ADHOC`).
    var isAdHoc: Bool
    /// Number of Mach-O files that were signed.
    var binaryCount: Int
    /// Number of resource files hashed into the seal.
    var resourceCount: Int
    /// When the signature was produced.
    var signedAt: Date
    /// `cdhash` of the main binary's CodeDirectory, hex encoded.
    var mainCdhash: String?

    /// Display name of the certificate that signed, when one was used.
    ///
    /// `nil` for ad-hoc, and also for signatures produced before this field
    /// existed — Swift's synthesized `Codable` treats a missing key as `nil`,
    /// so old manifests keep decoding. Both cases render the same way.
    var certificateName: String?

    /// Team ID recorded in the signature.
    var teamID: String?

    /// Set when the user asked for a certificate and Luna fell back to ad-hoc.
    ///
    /// Kept so the failure is visible on the detail screen rather than only in
    /// the moment's alert: a guest signed ad-hoc against the user's intent
    /// will likely fail to install, and "why" needs to be answerable later.
    var fellBackReason: String?

    var label: String {
        if isAdHoc {
            return fellBackReason == nil ? "adhoc（无证书）" : "adhoc（回退）"
        }
        return certificateName.map { "证书：\($0)" } ?? "证书签名"
    }
}

/// A guest application stored inside Luna's container.
struct GuestApp: Identifiable, Codable, Hashable {

    let id: UUID
    var bundleIdentifier: String
    var displayName: String
    var version: String
    var buildNumber: String
    var minimumOSVersion: String
    var executableName: String

    /// Opaque identifier for this guest's storage, used to build every path
    /// below. Deliberately a bare UUID with no structure: it is identity, not
    /// a description.
    ///
    /// Stored as a relative name rather than an absolute path so the record
    /// stays valid when the app container moves — which happens on every
    /// reinstall and every iOS update.
    var storageID: String

    /// The `.app` bundle's folder name inside the storage folder
    /// (e.g. `Example.app`). Recorded separately from `storageID` because a
    /// derived path is easier to debug than one glued together on the fly.
    var bundleFolderName: String

    /// Directory name inside `GuestData/` holding this guest's writable data.
    var dataFolderName: String

    var state: GuestState
    var importedAt: Date
    var lastLaunchedAt: Date?

    /// Result of the patch pass, if one has run.
    var patchSummary: String?

    /// Set when `state == .failed`.
    var lastError: String?

    /// Warnings captured at import time (encryption, entitlements, min OS…).
    var warnings: [String]

    /// FairPlay state of the main binary, captured at import time.
    ///
    /// `nil` for guests imported before this field existed — Swift's
    /// synthesized `Codable` treats a missing key as `nil`, so old manifests
    /// keep decoding. The detail screen's re-inspection fills it in.
    var encryption: EncryptionSummary?

    /// The signature Luna wrote over the guest's bundle, if any.
    ///
    /// `nil` means either "never signed" or "signed by a build that predates
    /// this field" — the two are indistinguishable in the manifest, and both
    /// are fixed the same way: press re-sign.
    var signature: SignatureSummary?

    /// Keychain access group index assigned to this guest for semi-isolation.
    var keychainGroupIndex: Int

    /// Raw bytes of the bundle on disk, for display.
    var bundleSize: Int64

    /// SHA-256 of the main executable, used to detect a tampered container.
    var executableDigest: String?

    /// Whether the user has explicitly acknowledged the trust warning for this
    /// guest. Luna refuses to launch a guest that has not been acknowledged.
    var trustAcknowledged: Bool

    var iconFileName: String?

    // MARK: - Derived

    /// The guest's storage folder, e.g. `GuestData/<uuid>/`.
    var storageURL: URL {
        LunaPaths.guestDataDirectory
            .appendingPathComponent(storageID, isDirectory: true)
    }

    /// `GuestData/<uuid>/<Name>.app` — the extracted, read-only bundle.
    var bundleURL: URL {
        storageURL.appendingPathComponent(bundleFolderName, isDirectory: true)
    }

    /// `GuestData/data-<uuid>/` — the guest's writable root.
    ///
    /// Kept as a sibling of the storage folder rather than a child so that a
    /// user deleting the app's code does not also delete its data.
    var dataURL: URL {
        LunaPaths.guestDataDirectory
            .appendingPathComponent(dataFolderName, isDirectory: true)
    }

    /// `Patched/<uuid>/` — where the rewritten binary is written.
    var patchedDirectoryURL: URL {
        LunaPaths.patchedDirectory
            .appendingPathComponent(storageID, isDirectory: true)
    }

    var patchedExecutableURL: URL {
        patchedDirectoryURL.appendingPathComponent(executableName)
    }

    /// A short label for diagnostics and the guest detail screen.
    var storageDescription: String {
        "\(storageID)/\(bundleFolderName)"
    }

    var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: bundleSize, countStyle: .file)
    }

    /// True only when the binary is *actually* FairPlay-encrypted, based on
    /// the recorded `cryptid`/`cryptsize` — never on warning strings, which
    /// change between releases and once misflagged every Xcode-linked binary.
    var hasBlockingWarning: Bool {
        encryption?.isEncrypted == true
    }

    /// Whether a signature has been written for this guest.
    var isSigned: Bool { signature != nil }

    /// The signed bundle produced by the last patch-and-sign pass, if present.
    var signedBundleURL: URL {
        patchedDirectoryURL.appendingPathComponent(bundleFolderName, isDirectory: true)
    }

    /// `Patched/<uuid>/<Name>.app/<exe>` — the patched *and* signed main
    /// executable. Callers must check existence: this URL is derived, and a
    /// guest that has never been signed has no file behind it.
    var signedExecutableURL: URL {
        signedBundleURL.appendingPathComponent(executableName)
    }
}

// MARK: - Filesystem layout

/// Central definition of Luna's on-disk layout.
///
/// Everything Luna creates lives under `Documents/Luna/`, with two exceptions.
/// The patched binaries go under `Library/Application Support/Luna/` — derived
/// data, kept out of Documents so it is excluded from iTunes and iCloud backup,
/// which is correct: a patched binary can always be regenerated, whereas guest
/// *data* cannot. And `Documents/Import/` sits at the top of Documents on
/// purpose: that is the directory `UIFileSharingEnabled` exposes to the Files
/// app, so it is where users drop IPA files from other file managers.
enum LunaPaths {

    /// Root of everything Luna owns.
    static var root: URL {
        documentsDirectory.appendingPathComponent("Luna", isDirectory: true)
    }

    static var documentsDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    /// Imported but not-yet-extracted IPAs are staged here.
    static var stagingDirectory: URL {
        root.appendingPathComponent("Staging", isDirectory: true)
    }

    /// Guest bundles *and* guest data both live here, side by side.
    static var guestDataDirectory: URL {
        root.appendingPathComponent("GuestData", isDirectory: true)
    }

    /// Patched binaries. Derived data — excluded from backup.
    static var patchedDirectory: URL {
        applicationSupportDirectory
            .appendingPathComponent("Luna/Patched", isDirectory: true)
    }

    /// The JSON manifest of all guests.
    static var manifestURL: URL {
        root.appendingPathComponent("guests.json")
    }

    /// Log files written by the container session.
    static var logsDirectory: URL {
        root.appendingPathComponent("Logs", isDirectory: true)
    }

    /// Imported signing identities, one folder per certificate.
    ///
    /// Each folder holds exactly one file — the `.p12` the user supplied —
    /// and is named after the certificate's UUID so the manifest can find it
    /// without storing an absolute path. The `.p12` stays encrypted by its
    /// export password (kept in the keychain); Luna deliberately does not
    /// wrap it in a second layer of its own encryption, because a home-grown
    /// envelope is one more thing that can be got wrong and one more thing
    /// that has to be unwrapped before `SecPKCS12Import` will look at it.
    static var certificatesDirectory: URL {
        root.appendingPathComponent("Certificates", isDirectory: true)
    }

    /// The JSON manifest of imported signing certificates.
    ///
    /// Separate from `guests.json` on purpose: certificates are global
    /// resources that outlive any particular guest, and a corrupt or
    /// hand-edited guest manifest should never be able to take the signing
    /// identities down with it.
    static var certificateManifestURL: URL {
        root.appendingPathComponent("certificates.json")
    }

    /// The drop folder for certificate material, reached through the Files
    /// app.
    ///
    /// A sibling of `Import/` rather than a child, and at the top of
    /// Documents for the same reason: `UIFileSharingEnabled` exposes the
    /// Documents directory, so users can see both drop folders side by side
    /// and tell at a glance which one takes IPAs and which one takes `.p12`
    /// and `.mobileprovision` files.
    static var certificateInboxDirectory: URL {
        documentsDirectory.appendingPathComponent("CertImport", isDirectory: true)
    }

    /// The drop folder users reach through the Files app or a desktop Finder.
    ///
    /// Deliberately at the top of Documents rather than under `root/`:
    /// `UIFileSharingEnabled` exposes the Documents directory itself, so this
    /// is what appears directly under On My iPhone → Luna. Files land here
    /// from any file manager and are picked up by
    /// `GuestStore.scanImportInbox()` at launch, on foreground, and on
    /// pull-to-refresh.
    static var importInboxDirectory: URL {
        documentsDirectory.appendingPathComponent("Import", isDirectory: true)
    }

    /// Where successfully imported inbox files are archived.
    ///
    /// Created on demand by `ImportInboxScan.archive(_:)`, not in
    /// `bootstrap()` — an empty "Imported" folder on first launch would just
    /// invite the question of what put it there.
    static var importInboxArchiveDirectory: URL {
        importInboxDirectory.appendingPathComponent("Imported", isDirectory: true)
    }

    static var applicationSupportDirectory: URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base
    }

    /// Creates every directory Luna expects. Safe to call repeatedly.
    ///
    /// The import inbox is in the list because it must exist *before* the user
    /// has anything to import — the whole point is that a file manager can
    /// browse to it right after first launch. It is deliberately NOT passed to
    /// `excludeFromBackup`: inbox files are the user's own, and users expect
    /// copies they placed there to survive a restore.
    ///
    /// The certificate *store* is excluded from backup, since it can be
    /// re-imported from the original `.p12`; the certificate *inbox* is not,
    /// for the same reason as the IPA inbox.
    static func bootstrap() throws {
        for directory in [
            root,
            stagingDirectory,
            guestDataDirectory,
            patchedDirectory,
            logsDirectory,
            importInboxDirectory,
            certificatesDirectory,
            certificateInboxDirectory,
        ] {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true)
        }
        excludeFromBackup(patchedDirectory)
        excludeFromBackup(certificatesDirectory)
    }

    /// Marks a directory as excluded from iCloud/iTunes backup.
    private static func excludeFromBackup(_ url: URL) {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
}
