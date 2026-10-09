//
//  CertificateStore.swift
//  Luna
//
//  Owns the manifest of imported signing identities.
//
//  Shaped after `GuestStore` — `@MainActor`, an `ObservableObject`, a single
//  JSON manifest under `Documents/Luna/` — but deliberately its own store
//  rather than a section of the guest store. Certificates are global: one
//  identity signs any number of guests, survives every one of them being
//  deleted, and is not part of a guest's lifecycle in any way.
//
//  The asymmetry that matters: a guest record is *the* thing, and its files
//  are derived from it. A certificate record is only a *description* of
//  files that coexist with it — the `.p12` on disk and two keychain items.
//  `reconcile()` exists to keep that description honest.
//

import Foundation
import Combine
import Security

@MainActor
final class CertificateStore: ObservableObject {

    /// All imported certificates, newest first.
    @Published private(set) var certificates: [SigningCertificate] = []

    /// Set while an import is running, for the progress banner.
    ///
    /// Writable by the view layer: the import is a multi-step synchronous
    /// operation (read, parse, validate, keychain, disk) and the view is the
    /// only thing that knows which step it is on. Keeping the string here
    /// rather than in view state means the banner survives a redraw, and means
    /// there is exactly one place that has to be cleared.
    @Published var importStage: String?

    /// The certificate new signatures should use by default.
    ///
    /// Persisted as a UUID in `UserDefaults` rather than in the manifest:
    /// it is a UI preference, not a fact about the certificates, and a
    /// manifest that also carried "which one is selected" would need
    /// rewriting on a mere selection change.
    @Published private(set) var selectedID: UUID?

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private static let selectedKey = "luna.signing.selectedCertificate"

    init() {
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
        selectedID = UserDefaults.standard
            .string(forKey: Self.selectedKey)
            .flatMap(UUID.init(uuidString:))
    }

    // MARK: - Lifecycle

    /// Loads the manifest and prunes records whose backing material is gone.
    ///
    /// Directory creation is `LunaPaths.bootstrap()`'s job and is called from
    /// `GuestStore.bootstrap()`; this only reads.
    func bootstrap() {
        do {
            try load()
            reconcile()
        } catch {
            NSLog("[Luna] certificate bootstrap failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Manifest

    private func load() throws {
        guard FileManager.default.fileExists(
            atPath: LunaPaths.certificateManifestURL.path)
        else {
            certificates = []
            return
        }
        let raw = try Data(contentsOf: LunaPaths.certificateManifestURL)
        certificates = try decoder.decode([SigningCertificate].self, from: raw)
        certificates.sort { $0.importedAt > $1.importedAt }
    }

    private func persist() throws {
        let raw = try encoder.encode(certificates)
        try raw.write(to: LunaPaths.certificateManifestURL, options: .atomic)
    }

    /// Drops records whose `.p12` or private key no longer exists.
    ///
    /// The private key case is not hypothetical: the keychain item is stored
    /// `ThisDeviceOnly`, so restoring a backup onto a new device brings the
    /// manifest and the `.p12` along but not the key. The certificate would
    /// then list as usable and fail at signing time, deep inside the pipeline,
    /// with a message about a missing key. Better to drop it here and let the
    /// user re-import — the `.p12` is still in the inbox.
    private func reconcile() {
        let survivors = certificates.filter { certificate in
            let p12 = p12URL(for: certificate)
            guard FileManager.default.fileExists(atPath: p12.path) else {
                NSLog("[Luna] certificate %@ dropped: .p12 missing",
                      certificate.displayName)
                return false
            }
            guard SigningKeychain.privateKey(for: certificate.id) != nil else {
                NSLog("[Luna] certificate %@ dropped: keychain item missing",
                      certificate.displayName)
                return false
            }
            return true
        }

        if survivors.count != certificates.count {
            certificates = survivors
            try? persist()
            pruneSelection()
        }
    }

    /// Keeps `selectedID` pointing at a certificate that still exists.
    private func pruneSelection() {
        guard let selectedID else { return }
        if !certificates.contains(where: { $0.id == selectedID }) {
            select(certificates.first?.id)
        }
    }

    // MARK: - Mutation

    /// Adds or replaces a certificate, matched by fingerprint.
    ///
    /// Re-importing the same `.p12` is a normal thing to do — a user forgets
    /// whether they already did it, or wants to re-attach a profile. Keying
    /// on the fingerprint rather than a fresh UUID makes that idempotent
    /// instead of piling up duplicates that are indistinguishable in the UI.
    func insert(_ certificate: SigningCertificate) {
        let existingIndex = certificates.firstIndex {
            $0.sha256 == certificate.sha256
        }

        if let existingIndex {
            let replaced = certificates[existingIndex]
            // Keep the original identity: the `.p12` on disk and the keychain
            // items are filed under it, and re-importing rewrote those in
            // place. Only the descriptive fields are refreshed.
            let updated = SigningCertificate(
                id: replaced.id,
                displayName: replaced.displayName,
                commonName: certificate.commonName,
                teamID: certificate.teamID,
                organization: certificate.organization,
                serialNumber: certificate.serialNumber,
                notBefore: certificate.notBefore,
                notAfter: certificate.notAfter,
                sha256: certificate.sha256,
                keyAlgorithm: certificate.keyAlgorithm,
                p12FileName: certificate.p12FileName,
                importedAt: replaced.importedAt,
                profile: certificate.profile ?? replaced.profile)
            certificates[existingIndex] = updated
        } else {
            certificates.insert(certificate, at: 0)
        }

        try? persist()
        if selectedID == nil { select(certificates.first?.id) }
    }

    /// Removes a certificate along with its `.p12`, keychain items, and
    /// folder.
    ///
    /// The keychain items are deleted first so that a failure part-way
    /// through leaves a record that `reconcile()` will clean up, rather than
    /// an orphaned private key with nothing pointing at it.
    func remove(_ certificate: SigningCertificate) {
        SigningKeychain.removeAll(for: certificate.id)
        try? FileManager.default.removeItem(at: folderURL(for: certificate))
        certificates.removeAll { $0.id == certificate.id }
        try? persist()
        pruneSelection()
    }

    /// Renders a certificate unable to sign, without deleting its record.
    ///
    /// Used when a signing attempt finds the identity unusable, so the UI can
    /// say why instead of the certificate silently disappearing.
    func update(_ certificate: SigningCertificate) {
        guard let index = certificates.firstIndex(where: { $0.id == certificate.id })
        else { return }
        certificates[index] = certificate
        try? persist()
    }

    /// Records which certificate future signatures use by default.
    func select(_ id: UUID?) {
        selectedID = id
        if let id {
            UserDefaults.standard.set(id.uuidString, forKey: Self.selectedKey)
        } else {
            UserDefaults.standard.removeObject(forKey: Self.selectedKey)
        }
    }

    /// Clears the import-progress banner.
    func clearImportStage() {
        importStage = nil
    }

    // MARK: - Lookup

    var selected: SigningCertificate? {
        guard let selectedID else { return nil }
        return certificates.first { $0.id == selectedID }
    }

    func certificate(id: UUID) -> SigningCertificate? {
        certificates.first { $0.id == id }
    }

    /// Certificates that are actually usable for signing, in list order.
    var usable: [SigningCertificate] {
        certificates.filter(\.isUsable)
    }

    // MARK: - Paths

    /// `Certificates/<uuid>/` — this certificate's folder.
    func folderURL(for certificate: SigningCertificate) -> URL {
        LunaPaths.certificatesDirectory
            .appendingPathComponent(certificate.id.uuidString, isDirectory: true)
    }

    /// `Certificates/<uuid>/<p12FileName>`.
    func p12URL(for certificate: SigningCertificate) -> URL {
        folderURL(for: certificate).appendingPathComponent(certificate.p12FileName)
    }
}

// MARK: - Import inbox

/// Finds certificate material the user dropped into `Documents/CertImport`.
///
/// Mirrors `ImportInboxScan`, with one addition: a `.p12` and a
/// `.mobileprovision` dropped together are paired by base name when possible,
/// but every `.p12` is imported regardless — a profile alone is useless, and
/// a `.p12` alone is still worth listing so the user can see it and attach a
/// profile later.
enum CertificateInboxScan {

    /// A `.p12` waiting to be imported, with the profile that appears to
    /// belong to it.
    struct Pending {
        var p12: URL
        var profile: URL?
    }

    /// Pairs up pending files, name-ordered for determinism.
    ///
    /// The two-second modification cutoff matches `ImportInboxScan`: a copy
    /// from a file manager may still be in flight, and importing a truncated
    /// `.p12` produces an alarming "file is corrupt" message for what is
    /// really just a race.
    static func pendingFiles() -> [Pending] {
        let contents: [URL]
        do {
            contents = try FileManager.default.contentsOfDirectory(
                at: LunaPaths.certificateInboxDirectory,
                includingPropertiesForKeys: [
                    .isRegularFileKey, .contentModificationDateKey,
                ],
                options: [.skipsHiddenFiles])
        } catch {
            return []
        }

        let cutoff = Date().addingTimeInterval(-2)
        let ready = contents.filter { url in
            guard !url.lastPathComponent.hasPrefix("."),
                  let values = try? url.resourceValues(
                    forKeys: [.isRegularFileKey, .contentModificationDateKey]),
                  values.isRegularFile == true
            else { return false }
            return values.contentModificationDate.map { $0 < cutoff } ?? true
        }

        let profiles = ready.filter {
            $0.pathExtension.lowercased() == "mobileprovision"
        }

        return ready
            .filter { $0.pathExtension.lowercased() == "p12" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { p12 in
                let base = p12.deletingPathExtension().lastPathComponent
                    .lowercased()
                // Exact base-name match first; otherwise take the only
                // profile present, which is the overwhelmingly common case
                // of a user dropping one certificate and one profile.
                let match = profiles.first {
                    $0.deletingPathExtension().lastPathComponent
                        .lowercased() == base
                } ?? (profiles.count == 1 ? profiles[0] : nil)
                return Pending(p12: p12, profile: match)
            }
    }

    /// Moves imported files into `CertImport/Imported/`.
    ///
    /// Same reasoning as the IPA inbox: the files are the user's, and a
    /// visible archive answers "did Luna take it" without a second import.
    static func archive(_ file: URL) {
        let fm = FileManager.default
        let archive = LunaPaths.certificateInboxDirectory
            .appendingPathComponent("Imported", isDirectory: true)
        do {
            try fm.createDirectory(at: archive, withIntermediateDirectories: true)
            var destination = archive.appendingPathComponent(file.lastPathComponent)
            if fm.fileExists(atPath: destination.path) {
                let stamp = DateFormatter()
                stamp.dateFormat = "-yyyyMMdd-HHmmss"
                let base = file.deletingPathExtension().lastPathComponent
                destination = archive.appendingPathComponent(
                    base + stamp.string(from: Date()))
                    .appendingPathExtension(file.pathExtension)
            }
            try fm.moveItem(at: file, to: destination)
        } catch {
            NSLog("[Luna] could not archive certificate file %@: %@",
                  file.lastPathComponent, error.localizedDescription)
        }
    }
}
