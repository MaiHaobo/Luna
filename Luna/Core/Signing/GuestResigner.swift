//
//  GuestResigner.swift
//  Luna
//
//  The composition step: patch a guest's binary, then sign the result.
//
//  WHY THE ORDER IS NOT NEGOTIABLE
//  -------------------------------
//  A code signature hashes the final bytes of the code it covers. Patching —
//  rewriting `filetype`, relocating `__PAGEZERO`, injecting `LC_LOAD_DYLIB` —
//  changes those bytes. So the pipeline is strictly:
//
//      1. patch      (MachOPatcher: filetype / __PAGEZERO / dylib injection)
//      2. sign       (BundleSigner: CodeDirectory + resource seal)
//
//  Doing it the other way produces a signature over the pre-patch bytes, which
//  the kernel rejects the moment anything validates the image.
//
//  WHAT GETS SIGNED
//  ----------------
//  Signing works on a *copy*. The imported bundle under `GuestData/` stays
//  pristine — it is the user's original, and re-importing is expensive — while
//  the patched-and-signed tree lives under `Patched/<uuid>/`. That directory
//  is already excluded from backup, which is correct for derived data.
//
//  This stage produces an **ad-hoc** signature: no certificate, no CMS blob,
//  and `CS_ADHOC` set in the CodeDirectory flags. That is the same signature
//  `codesign -s -` writes, and it is enough to load a guest on a build that
//  has JIT permission. Adding a certificate later means filling the signature
//  slot with a real CMS blob — the rest of this pipeline does not change.
//

import Foundation

/// Outcome of a patch-and-sign pass.
struct ResignReport {
    /// Where the signed bundle lives.
    var signedBundleURL: URL
    /// The patch summary, when a patch ran.
    var patch: MachOPatchReport?
    /// The bundle signing summary.
    var signature: BundleSignReport
    /// True when this is an ad-hoc signature (no certificate).
    var isAdHoc: Bool

    var humanReadable: String {
        var lines: [String] = []
        lines.append(isAdHoc ? "签名类型：adhoc（无证书）" : "签名类型：证书")
        if let patch {
            lines.append("")
            lines.append("── 二进制修补 ──")
            lines.append(patch.humanReadable)
        }
        lines.append("")
        lines.append("── 签名 ──")
        lines.append(signature.humanReadable)
        return lines.joined(separator: "\n")
    }
}

enum GuestResigner {

    /// Patches and signs `guest`, writing the result under `Patched/<uuid>/`.
    ///
    /// - Parameters:
    ///   - guest: the imported guest. Its `bundleURL` is read, never written.
    ///   - entitlementsXML: entitlements to embed. `nil` for a plain ad-hoc
    ///     signature with an empty entitlements set.
    ///   - progress: called with a short stage label.
    static func resign(
        guest: GuestApp,
        entitlementsXML: Data? = nil,
        progress: ((String) -> Void)? = nil
    ) throws -> ResignReport {

        let fm = FileManager.default

        // ── 1. Stage a working copy ─────────────────────────────────────────
        progress?("准备签名工作区…")
        let signedRoot = guest.patchedDirectoryURL
        if fm.fileExists(atPath: signedRoot.path) {
            try fm.removeItem(at: signedRoot)
        }
        try fm.createDirectory(at: signedRoot, withIntermediateDirectories: true)

        // Copy *into* the staged root, so the result matches
        // `GuestApp.signedBundleURL`: `Patched/<uuid>/<Name>.app`.
        //
        // `copyItem` makes the destination the copy itself, not a container to
        // copy into — aiming it at `signedRoot` would leave the app's own
        // contents (Info.plist, the executable, Frameworks/) directly inside
        // `<uuid>/`, and the staged bundle would then be looked up one level
        // too deep. That was a real bug: the copy succeeded, and the guard
        // below failed with "复制后的 bundle 不存在" for any guest whose bundle
        // was staged under a fresh UUID directory.
        let stagedBundle = signedRoot
            .appendingPathComponent(guest.bundleFolderName, isDirectory: true)

        progress?("复制 bundle…")
        do {
            try stageCopy(from: guest.bundleURL, to: stagedBundle,
                          bundleSize: guest.bundleSize)
        } catch {
            throw CodeSignError.signingFailed(describeCopyFailure(
                error,
                source: guest.bundleURL,
                destination: stagedBundle,
                bundleSize: guest.bundleSize))
        }

        guard fm.fileExists(atPath: stagedBundle.path) else {
            throw CodeSignError.signingFailed(
                "复制后的 bundle 不存在：\(stagedBundle.lastPathComponent)")
        }

        // ── 2. Patch the main binary ────────────────────────────────────────
        // Only the main executable needs the loader shim; frameworks and
        // dylibs are already loadable.
        progress?("修补主二进制…")
        let stagedExecutable = stagedBundle.appendingPathComponent(guest.executableName)
        var patchReport: MachOPatchReport?

        do {
            patchReport = try MachOPatcher.patch(
                sourceURL: stagedExecutable,
                outputURL: stagedExecutable,
                loaderPath: LunaEnvironment.effectiveLoaderPath)
        } catch {
            // A patch failure is reported but does not abort: signing a
            // partially-patched bundle still produces a loadable inspection
            // artefact, and the user sees exactly which step failed.
            NSLog("[Luna] patch during resign failed: \(error.localizedDescription)")
            throw CodeSignError.signingFailed(
                "二进制修补失败：\(error.localizedDescription)")
        }

        // ── 3. Sign the bundle ──────────────────────────────────────────────
        progress?("签名 bundle…")
        let signature = try BundleSigner.sign(
            bundleURL: stagedBundle,
            executableName: guest.executableName,
            identifier: guest.bundleIdentifier,
            entitlementsXML: entitlementsXML)

        progress?("签名完成")

        return ResignReport(
            signedBundleURL: stagedBundle,
            patch: patchReport,
            signature: signature,
            isAdHoc: true
        )
    }

    // MARK: - Staging

    /// `clonefile(2)` — APFS copy-on-write tree clone. Not in the Swift Darwin
    /// overlay, so it is bound directly; it has existed on iOS since the
    /// switch to APFS.
    @_silgen_name("clonefile")
    private static func systemClonefile(
        _ source: UnsafePointer<CChar>,
        _ destination: UnsafePointer<CChar>,
        _ flags: Int32
    ) -> Int32

    /// Stages `source` at `destination`.
    ///
    /// An APFS clone is tried first: it is instant and copy-on-write, so a
    /// multi-gigabyte guest (UTM unpacked runs to several GB) costs no real
    /// space until a file is actually modified by the patch or signature pass.
    /// A plain `copyItem` would duplicate every byte, which is how devices
    /// with a few GB free ended up failing mid-copy with a bare Cocoa error.
    ///
    /// When the clone is refused (non-APFS volume, cross-device, OS policy),
    /// the fallback checks that a deep copy would actually fit *before*
    /// starting one, and fails with a readable diagnosis if it would not.
    private static func stageCopy(from source: URL, to destination: URL,
                                  bundleSize: Int64) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: destination.path) {
            try fm.removeItem(at: destination)
        }

        if cloneTree(from: source, to: destination) { return }

        if availableCapacity(near: destination) != nil,
           !hasRoomForCopy(bundleSize: bundleSize, destination: destination) {
            throw CodeSignError.signingFailed(spaceShortageMessage(bundleSize: bundleSize))
        }
        try fm.copyItem(at: source, to: destination)
    }

    private static func cloneTree(from source: URL, to destination: URL) -> Bool {
        source.withUnsafeFileSystemRepresentation { src in
            destination.withUnsafeFileSystemRepresentation { dst in
                guard let src, let dst else { return false }
                return systemClonefile(src, dst, 0) == 0
            }
        }
    }

    /// Free space on the volume holding `url`, in bytes. `nil` when the
    /// system does not say — checks are skipped rather than guessed.
    private static func availableCapacity(near url: URL) -> Int64? {
        let values = try? url.resourceValues(
            forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        let bytes = values?.volumeAvailableCapacityForImportantUsage ?? 0
        return bytes > 0 ? bytes : nil
    }

    private static func hasRoomForCopy(bundleSize: Int64, destination: URL) -> Bool {
        // Headroom covers the patched binary rewrite, every signature blob,
        // and CodeResources — a few hundred MB over the largest code file.
        let headroom: Int64 = 512 * 1024 * 1024
        guard let available = availableCapacity(near: destination) else { return true }
        return available >= bundleSize + headroom
    }

    private static func spaceShortageMessage(bundleSize: Int64) -> String {
        String(
            format: "磁盘空间不足：这个应用约占 %.1f GB，签名需要再占用同等空间。请删除一些应用或视频后重试。",
            Double(bundleSize) / 1_000_000_000)
    }

    /// Turns a failed staging copy into a sentence that names the cause.
    ///
    /// The raw Cocoa message ("The file … couldn't be saved …") hides the
    /// errno that matters — space, permissions, I/O — and reads as a system
    /// quirk rather than something the user can act on.
    private static func describeCopyFailure(_ error: Error, source: URL,
                                            destination: URL,
                                            bundleSize: Int64) -> String {
        let ns = error as NSError
        let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError
        let code: Int? = underlying?.domain == NSPOSIXErrorDomain
            ? underlying?.code
            : (ns.domain == NSCocoaErrorDomain ? ns.code : nil)

        switch code {
        case 28, 640:   // ENOSPC / NSFileWriteOutOfSpaceError
            return spaceShortageMessage(bundleSize: bundleSize)
        case 1, 13, 513: // EPERM / EACCES / NSFileWriteNoPermissionError
            return "没有写入权限：\(destination.path)"
        case 516:       // NSFileWriteFileExistsError
            return "目标已存在：\(destination.path)"
        default:
            let detail = underlying?.localizedDescription ?? error.localizedDescription
            return "复制 \(source.lastPathComponent) 失败：\(detail)"
        }
    }
}
