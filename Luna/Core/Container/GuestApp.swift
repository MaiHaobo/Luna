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
        case .launching: return "启动中"
        case .launched: return "已运行过"
        case .failed: return "失败"
        }
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

    var hasBlockingWarning: Bool {
        warnings.contains { $0.contains("加密") }
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
    static func bootstrap() throws {
        for directory in [
            root,
            stagingDirectory,
            guestDataDirectory,
            patchedDirectory,
            logsDirectory,
            importInboxDirectory,
        ] {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true)
        }
        excludeFromBackup(patchedDirectory)
    }

    /// Marks a directory as excluded from iCloud/iTunes backup.
    private static func excludeFromBackup(_ url: URL) {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
}
