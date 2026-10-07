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
        try fm.createDirectory(
            at: signedRoot.deletingLastPathComponent(), withIntermediateDirectories: true)

        progress?("复制 bundle…")
        try fm.copyItem(at: guest.bundleURL, to: signedRoot)

        let stagedBundle = signedRoot
            .appendingPathComponent(guest.bundleFolderName, isDirectory: true)
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
}
