//
//  GuestStore.swift
//  Luna
//
//  Owns the guest manifest and the import pipeline.
//
//  All filesystem mutation funnels through this type. Views never touch the
//  container directly, which keeps the "where does a guest live" question
//  answered in exactly one place.
//

import Foundation
import Combine

/// Stages an import goes through, for progress reporting.
enum ImportStage: Equatable {
    case staging
    case extracting(progress: Double, entry: String)
    case inspecting
    case registering
    case finished(GuestApp)
    case failed(String)

    var label: String {
        switch self {
        case .staging: return "准备中…"
        case .extracting(let progress, _):
            return "解压中 \(Int(progress * 100))%"
        case .inspecting: return "检查 bundle…"
        case .registering: return "写入清单…"
        case .finished: return "完成"
        case .failed(let message): return "失败：\(message)"
        }
    }
}

@MainActor
final class GuestStore: ObservableObject {

    /// All known guests, newest first.
    @Published private(set) var guests: [GuestApp] = []

    /// Live import progress, `nil` when idle.
    @Published private(set) var importStage: ImportStage?

    /// True while an import (manual or inbox scan) is running. One at a
    /// time: the extraction pipeline is heavy, and two concurrent imports
    /// would fight over the manifest bookkeeping and the progress banner.
    @Published private(set) var isImporting = false

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init() {
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    // MARK: - Lifecycle

    /// Creates Luna's directory tree and loads the manifest.
    func bootstrap() {
        do {
            try LunaPaths.bootstrap()
            try load()
            reconcile()
        } catch {
            NSLog("[Luna] bootstrap failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Manifest

    private func load() throws {
        guard FileManager.default.fileExists(atPath: LunaPaths.manifestURL.path) else {
            guests = []
            return
        }
        let raw = try Data(contentsOf: LunaPaths.manifestURL)
        guests = try decoder.decode([GuestApp].self, from: raw)
        guests.sort { $0.importedAt > $1.importedAt }
    }

    private func persist() throws {
        let raw = try encoder.encode(guests)
        try raw.write(to: LunaPaths.manifestURL, options: .atomic)
    }

    /// Drops records whose backing directories vanished.
    ///
    /// This happens in practice: iOS reclaims files when storage runs low, and
    /// a user can delete the Luna folder through the Files app. A manifest
    /// pointing at directories that no longer exist produces confusing UI, so
    /// we prune on every launch rather than surfacing ghosts.
    private func reconcile() {
        let survivors = guests.filter { guest in
            FileManager.default.fileExists(atPath: guest.bundleURL.path)
        }
        if survivors.count != guests.count {
            let removed = guests.count - survivors.count
            NSLog("[Luna] reconciled manifest, dropped \(removed) orphaned record(s)")
            guests = survivors
            try? persist()
        }
    }

    // MARK: - Import

    /// Imports an IPA from an arbitrary URL (Files, share sheet, AirDrop).
    ///
    /// Returns `false` immediately when another import is already running —
    /// no queueing. The picker path turns that into an alert; the inbox scan
    /// simply skips and catches the files on the next foreground. Marked
    /// `@discardableResult` so fire-and-forget call sites
    /// (`Task { await store.importIPA(from: url) }`) stay legal.
    @discardableResult
    func importIPA(from sourceURL: URL) async -> Bool {
        guard !isImporting else { return false }
        isImporting = true
        defer { isImporting = false }
        return await performImport(from: sourceURL)
    }

    /// The actual pipeline. Separate from `importIPA` because the inbox scan
    /// holds `isImporting` for a whole batch of files and must reach the
    /// per-file work without re-taking the flag between them.
    ///
    /// Runs entirely off the main actor except for the published-state updates,
    /// so a multi-gigabyte IPA does not freeze the UI.
    private func performImport(from sourceURL: URL) async -> Bool {
        importStage = .staging

        // Copy into our own staging area first. The incoming URL is usually a
        // security-scoped bookmark into another app's container and will stop
        // being readable as soon as this call returns.
        let stagingURL = LunaPaths.stagingDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("ipa")

        do {
            try LunaPaths.bootstrap()
            try copyIntoSandbox(from: sourceURL, to: stagingURL)

            importStage = .extracting(progress: 0, entry: "")

            // Each guest gets an opaque storage folder plus a sibling data
            // folder. The UUID is identity; the bundle's own name is kept
            // separately so the on-disk layout stays readable.
            let storageID = UUID().uuidString
            let dataFolder = "data-\(storageID)"

            let storageRoot = LunaPaths.guestDataDirectory
                .appendingPathComponent(storageID, isDirectory: true)

            // Extraction walks potentially tens of thousands of entries and
            // inflates a lot of bytes. Running it off the main actor keeps the
            // import banner animating on a large IPA.
            let written = try await Self.extractOffMainActor(
                archiveURL: stagingURL,
                destination: storageRoot
            )

            importStage = .inspecting

            // Locate `Payload/*.app`.
            let payloadURL = written.appendingPathComponent("Payload", isDirectory: true)
            guard FileManager.default.fileExists(atPath: payloadURL.path) else {
                throw IPAError.missingPayloadDirectory
            }
            let payloadContents = try FileManager.default.contentsOfDirectory(
                at: payloadURL, includingPropertiesForKeys: nil)
            let appBundles = payloadContents.filter { $0.pathExtension == "app" }
            guard !appBundles.isEmpty else { throw IPAError.emptyPayloadDirectory }

            // An IPA with more than one .app is unusual (it means the archive
            // carries an extension or a watch app at the top level). We take
            // the largest, which is reliably the main bundle.
            guard let mainBundle = appBundles.max(by: { lhs, rhs in
                directorySize(lhs) < directorySize(rhs)
            }) else {
                throw IPAError.emptyPayloadDirectory
            }

            // Inspect once against the pre-lift location purely as a validity
            // gate — a bundle whose Info.plist or executable is missing should
            // fail before anything is moved. The values recorded below come
            // from the re-inspection after the lift, so every path is correct.
            _ = try BundleInspector.inspect(bundleURL: mainBundle)

            // The bundle arrived at `<storage>/Payload/X.app`, but `bundleURL`
            // derives `<storage>/X.app`, so lift it one level and drop the
            // now-empty Payload directory.
            let bundleFolderName = mainBundle.lastPathComponent
            let liftedBundle = storageRoot
                .appendingPathComponent(bundleFolderName, isDirectory: true)
            if mainBundle.standardizedFileURL.path != liftedBundle.standardizedFileURL.path {
                try FileManager.default.moveItem(at: mainBundle, to: liftedBundle)
                // Remove Payload/ only if it is now empty. A sibling (an
                // extension, a watch app) keeps it in place — we just do not
                // want an empty directory left behind.
                if let remaining = try? FileManager.default.contentsOfDirectory(
                    at: payloadURL, includingPropertiesForKeys: nil),
                   remaining.isEmpty {
                    try? FileManager.default.removeItem(at: payloadURL)
                }
            }

            // Re-inspect against the lifted location so every recorded path is
            // correct. Inspection is cheap — it only reads Info.plist and the
            // Mach-O header.
            let finalInspection = try BundleInspector.inspect(bundleURL: liftedBundle)
            let digest = try? FileDigest.sha256(of: finalInspection.executableURL)

            importStage = .registering

            let guest = GuestApp(
                id: UUID(),
                bundleIdentifier: finalInspection.bundleIdentifier,
                displayName: finalInspection.displayName,
                version: finalInspection.version,
                buildNumber: finalInspection.buildNumber,
                minimumOSVersion: finalInspection.minimumOSVersion,
                executableName: finalInspection.executableName,
                storageID: storageID,
                bundleFolderName: bundleFolderName,
                dataFolderName: dataFolder,
                state: .imported,
                importedAt: Date(),
                lastLaunchedAt: nil,
                patchSummary: nil,
                lastError: nil,
                warnings: finalInspection.warnings,
                encryption: finalInspection.encryptionSummary,
                keychainGroupIndex: KeychainGroupAllocator.groupIndex(
                    forBundleID: finalInspection.bundleIdentifier),
                bundleSize: directorySize(liftedBundle),
                executableDigest: digest,
                trustAcknowledged: false,
                iconFileName: nil
            )

            // Re-importing an existing bundle ID replaces the old record and
            // reclaims its storage, so a user can refresh an app in place.
            if let existing = guests.first(where: {
                $0.bundleIdentifier == guest.bundleIdentifier
            }) {
                removeStorage(for: existing)
                guests.removeAll { $0.bundleIdentifier == guest.bundleIdentifier }
            }

            // Create the guest's writable data root before anything can try to
            // write into it.
            try FileManager.default.createDirectory(
                at: guest.dataURL, withIntermediateDirectories: true)

            guests.insert(guest, at: 0)
            try persist()
            try? FileManager.default.removeItem(at: stagingURL)

            importStage = .finished(guest)
            return true
        } catch {
            try? FileManager.default.removeItem(at: stagingURL)
            importStage = .failed(error.localizedDescription)
            NSLog("[Luna] import failed: \(error)")
            return false
        }
    }

    /// Clears a finished/failed import banner.
    func clearImportStage() { importStage = nil }

    // MARK: - Import inbox

    /// Imports every IPA waiting in `Documents/Import`.
    ///
    /// Runs at launch, on every foreground, and on pull-to-refresh — the
    /// moments at which a user could have just dropped files in from another
    /// file manager. The whole batch holds `isImporting` once, so a scan can
    /// never interleave with a picker import; if one is already running the
    /// scan is skipped outright and the next foreground catches the files.
    ///
    /// Per file: success moves it into `Import/Imported/`, failure leaves it
    /// in place — the banner carries the reason, and the user can fix the IPA
    /// and try again. The banner reflects each file in turn and ends on the
    /// last one's result.
    func scanImportInbox() async {
        guard !isImporting else { return }
        let pending = ImportInboxScan.pendingFiles()
        guard !pending.isEmpty else { return }
        isImporting = true
        defer { isImporting = false }
        for file in pending {
            if await performImport(from: file) {
                ImportInboxScan.archive(file)
            }
        }
    }

    // MARK: - Mutation

    func update(_ guest: GuestApp) {
        guard let index = guests.firstIndex(where: { $0.id == guest.id }) else { return }
        guests[index] = guest
        try? persist()
    }

    func delete(_ guest: GuestApp) {
        removeStorage(for: guest)
        guests.removeAll { $0.id == guest.id }
        try? persist()
    }

    func acknowledgeTrust(for guest: GuestApp) {
        var updated = guest
        updated.trustAcknowledged = true
        update(updated)
    }

    /// Re-imports by wiping the derived state and re-running the patch pass.
    func repatch(_ guest: GuestApp) {
        var updated = guest
        updated.state = .imported
        updated.patchSummary = nil
        updated.lastError = nil
        try? FileManager.default.removeItem(at: guest.patchedDirectoryURL)
        update(updated)
    }

    /// Re-runs bundle inspection and refreshes the derived fields.
    ///
    /// Exists because the checks themselves evolve: the first release flagged
    /// every binary that merely carried an `LC_ENCRYPTION_INFO` command as
    /// encrypted, which misflagged decrypted dumps and self-built IPAs. Guests
    /// imported by that build keep the stale warning in their manifest record;
    /// re-inspection recomputes it against the current logic without asking
    /// the user to delete and re-import a multi-gigabyte bundle.
    func reinspect(_ guest: GuestApp) {
        do {
            let inspection = try BundleInspector.inspect(bundleURL: guest.bundleURL)
            var updated = guest
            updated.warnings = inspection.warnings
            updated.encryption = inspection.encryptionSummary
            updated.bundleSize = directorySize(guest.bundleURL)
            updated.lastError = nil
            update(updated)
        } catch {
            var updated = guest
            updated.lastError = "重新检测失败：\(error.localizedDescription)"
            update(updated)
        }
    }

    // MARK: - Signing

    /// Live signing progress, `nil` when idle.
    @Published private(set) var signingStage: String?

    /// Patches and signs `guest`, recording the outcome on its manifest record.
    ///
    /// The heavy work runs off the main actor: signing hashes every page of
    /// every binary and every resource in the bundle, which on a large app is
    /// seconds of CPU. Only the published-state updates hop back.
    ///
    /// Returns `true` when a signature was written. Failure is recorded in
    /// `lastError` rather than thrown, because the caller is a button.
    @discardableResult
    func resign(_ guest: GuestApp) async -> Bool {
        signingStage = "准备签名…"
        defer { signingStage = nil }

        do {
            let report = try await Self.performResignOffMainActor(
                guest: guest,
                progress: { [weak self] line in
                    Task { @MainActor in self?.signingStage = line }
                })

            var updated = guest
            updated.state = .signed
            updated.signature = SignatureSummary(
                isAdHoc: report.isAdHoc,
                binaryCount: report.signature.signedBinaries.count,
                resourceCount: report.signature.resourceCount,
                signedAt: Date(),
                mainCdhash: nil)
            updated.lastError = nil
            update(updated)
            return true
        } catch {
            var updated = guest
            updated.lastError = "签名失败：\(error.localizedDescription)"
            update(updated)
            NSLog("[Luna] resign failed: \(error)")
            return false
        }
    }

    /// Runs `GuestResigner` on a background thread.
    ///
    /// `GuestResigner.resign` is a plain synchronous function over files and
    /// `Data`, so it is safe to hand to a detached task — but it must be
    /// `nonisolated` to be callable from one, hence the static helper rather
    /// than a method on this `@MainActor` class.
    nonisolated private static func performResignOffMainActor(
        guest: GuestApp,
        progress: @escaping (String) -> Void
    ) async throws -> ResignReport {
        try await Task.detached(priority: .userInitiated) {
            // `GuestApp` is a value type, so capturing it here copies; the
            // detached task therefore never touches main-actor state.
            try GuestResigner.resign(
                guest: guest,
                progress: { line in progress(line) })
        }.value
    }

    private func removeStorage(for guest: GuestApp) {
        try? FileManager.default.removeItem(at: guest.bundleURL)
        try? FileManager.default.removeItem(at: guest.patchedDirectoryURL)
        // Guest data is deliberately NOT deleted here — see `delete(_:purgeData:)`.
    }

    /// Uninstall, optionally destroying the guest's saved data.
    func delete(_ guest: GuestApp, purgeData: Bool) {
        if purgeData {
            try? FileManager.default.removeItem(at: guest.dataURL)
        }
        delete(guest)
    }

    // MARK: - Helpers

    /// Runs extraction on a background thread.
    ///
    /// `IPAArchive.extract` is a plain synchronous function over `Data`, so it
    /// is safe to hand to a detached task — but it must be `nonisolated` to be
    /// callable from one, which is why it lives on a separate type rather than
    /// being a method on this `@MainActor` class.
    private static func extractOffMainActor(
        archiveURL: URL,
        destination: URL
    ) async throws -> URL {
        try await Task.detached(priority: .userInitiated) {
            try IPAArchive.extract(archiveAt: archiveURL, to: destination)
            return destination
        }.value
    }

    private func copyIntoSandbox(from source: URL, to destination: URL) throws {
        // URLs handed to us by the document picker are security-scoped.
        let needsScope = source.startAccessingSecurityScopedResource()
        defer { if needsScope { source.stopAccessingSecurityScopedResource() } }

        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.createDirectory(
            at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: source, to: destination)
    }

    private func directorySize(_ url: URL) -> Int64 {
        guard let enumerator = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return 0 }

        var total: Int64 = 0
        for case let fileURL as URL in enumerator {
            let values = try? fileURL.resourceValues(
                forKeys: [.fileSizeKey, .isRegularFileKey])
            if values?.isRegularFile == true {
                total += Int64(values?.fileSize ?? 0)
            }
        }
        return total
    }
}

// MARK: - Small utilities

enum FileDigest {
    /// SHA-256 of a file, hex encoded.
    static func sha256(of url: URL) throws -> String {
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        return SHA256.hash(data: data).hexString
    }
}

// MARK: - Import inbox

/// Enumerates and archives the files users drop into `Documents/Import`.
///
/// A caseless enum beside `FileDigest` on purpose: pure helpers over
/// `FileManager`, no state, nothing that belongs on the store itself.
enum ImportInboxScan {

    /// IPA files ready to import, name-ordered for determinism.
    ///
    /// Dot-prefixed names are skipped: several file managers leave `._foo.ipa`
    /// AppleDouble sidecars next to the real file, and importing one just
    /// produces a confusing failure banner. Files modified within the last two
    /// seconds are skipped too — a copy may still be mid-flight, and a
    /// truncated zip would fail noisily; the next scan picks it up instead.
    static func pendingFiles() -> [URL] {
        let contents: [URL]
        do {
            contents = try FileManager.default.contentsOfDirectory(
                at: LunaPaths.importInboxDirectory,
                includingPropertiesForKeys: [
                    .isRegularFileKey, .contentModificationDateKey,
                ],
                options: [.skipsHiddenFiles])
        } catch {
            // An absent inbox is the normal state before first launch.
            return []
        }

        let cutoff = Date().addingTimeInterval(-2)
        return contents
            .filter { url in
                guard !url.lastPathComponent.hasPrefix("."),
                      url.pathExtension.lowercased() == "ipa",
                      let values = try? url.resourceValues(
                        forKeys: [.isRegularFileKey, .contentModificationDateKey]),
                      values.isRegularFile == true
                else { return false }
                return values.contentModificationDate.map { $0 < cutoff } ?? true
            }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    /// Moves a successfully imported file into `Import/Imported/`.
    ///
    /// Archive rather than delete: the file is the user's, and a visible copy
    /// answers "where did my IPA go" without a trip back to the source app.
    /// Name collisions get a timestamp suffix rather than being overwritten.
    static func archive(_ file: URL) {
        let fm = FileManager.default
        let archive = LunaPaths.importInboxArchiveDirectory
        do {
            try fm.createDirectory(at: archive, withIntermediateDirectories: true)
            var destination = archive.appendingPathComponent(file.lastPathComponent)
            if fm.fileExists(atPath: destination.path) {
                let stamp = DateFormatter()
                stamp.dateFormat = "-yyyyMMdd-HHmmss"
                let base = file.deletingPathExtension().lastPathComponent
                destination = archive.appendingPathComponent(
                    base + stamp.string(from: Date()))
                    .appendingPathExtension("ipa")
            }
            try fm.moveItem(at: file, to: destination)
        } catch {
            // Archiving is a courtesy, not part of the import. If it fails the
            // file stays in the inbox and would be imported again on the next
            // scan — which replaces the existing guest, so it is harmless.
            NSLog("[Luna] could not archive %@: %@",
                  file.lastPathComponent, error.localizedDescription)
        }
    }
}
