//
//  BundleSigner.swift
//  Luna
//
//  Signs a whole `.app` bundle: every Mach-O inside it, and the resource seal
//  that binds them together.
//
//  ORDER OF OPERATIONS
//  -------------------
//  A bundle signature is not a single blob. It is a web of hashes:
//
//      CodeResources  ──hash of──▶  every resource file
//            │
//            ├──hashed into──▶  main binary's CodeDirectory special slot
//            │
//      Info.plist ─────hashed into──▶  main binary's CodeDirectory special slot
//            │
//            └──hashed into──▶  CodeResources itself (a special entry)
//
//  So the sequence has to run bottom-up: resources first, then Info.plist,
//  then the main binary (which hashes both), then the outer .app directory
//  seal if the bundle is nested. Getting this backwards yields a signature
//  that looks complete and fails every verification.
//
//  NESTED BUNDLES
//  --------------
//  Frameworks, app extensions, and watch apps are all separate code objects
//  with their own signatures, and they must be signed *before* the bundle that
//  contains them — a container hashes its children. We therefore walk
//  depth-first: `Frameworks/*.framework` and `PlugIns/*.appex` first, then the
//  main executable, then the top-level `_CodeSignature`.
//
//  THE TEMPORARY EXECUTABLE TRICK
//  ------------------------------
//  LiveContainer's JIT-less mode does something subtle and clever, and we copy
//  it: to sign a guest with the *host's* entitlements (which is where Luna's
//  128 keychain access groups live), it temporarily points the bundle's
//  `CFBundleExecutable` at a copy of the host's own binary, signs that, then
//  restores the original `Info.plist`. The guest's real executable keeps a
//  valid signature; the guest never has to be granted entitlements it did not
//  ask for. This stage does not need the trick — ad-hoc signatures claim no
//  entitlements — but the hook is kept so the certificate stage can use it
//  without restructuring.
//

import Foundation

/// What a bundle signing pass did.
struct BundleSignReport {
    /// Mach-O files that were re-signed, in the order they were processed.
    var signedBinaries: [String]
    /// Nested bundles signed before the main one.
    var nestedBundles: [String]
    /// Whether `_CodeSignature/CodeResources` was written.
    var wroteCodeResources: Bool
    /// Number of resource files hashed into the seal.
    var resourceCount: Int
    /// Files the walker skipped, with the reason.
    var skipped: [String]

    var humanReadable: String {
        var lines: [String] = []
        lines.append("签名二进制：\(signedBinaries.count) 个")
        for path in signedBinaries { lines.append("  · \(path)") }
        if !nestedBundles.isEmpty {
            lines.append("嵌套 bundle：\(nestedBundles.count) 个")
            for path in nestedBundles { lines.append("  · \(path)") }
        }
        lines.append(wroteCodeResources
            ? "已写入 _CodeSignature/CodeResources（\(resourceCount) 个资源文件）"
            : "未生成 CodeResources")
        if !skipped.isEmpty {
            lines.append("跳过：\(skipped.count) 项")
            for entry in skipped { lines.append("  · \(entry)") }
        }
        return lines.joined(separator: "\n")
    }
}

enum BundleSigner {

    /// Files and directories excluded from the resource seal.
    ///
    /// `_CodeSignature` is the seal itself — including it would be circular.
    /// `embedded.mobileprovision` is covered by a different mechanism (the
    /// profile's own hash is checked against the certificate, not the seal).
    /// `Info.plist` gets its own dedicated slot in the CodeDirectory and is
    /// deliberately kept out of the resource list.
    private static let excludedFromSeal: Set<String> = [
        "_CodeSignature",
        "embedded.mobileprovision",
    ]

    /// Directories whose contents are separate code objects, signed first.
    private static let nestedBundleDirectories = [
        "Frameworks", "PlugIns", "Extensions", "Watch",
    ]

    /// Signs the bundle at `bundleURL` in place.
    ///
    /// - Parameters:
    ///   - bundleURL: the `.app` directory.
    ///   - executableName: `CFBundleExecutable`; the main binary's file name.
    ///   - identifier: identifier for the main binary's CodeDirectory.
    ///   - entitlementsXML: entitlements to embed, or `nil`.
    static func sign(
        bundleURL: URL,
        executableName: String,
        identifier: String,
        entitlementsXML: Data? = nil
    ) throws -> BundleSignReport {

        let fm = FileManager.default
        var report = BundleSignReport(
            signedBinaries: [], nestedBundles: [],
            wroteCodeResources: false, resourceCount: 0, skipped: [])

        // ── 1. Nested code first ────────────────────────────────────────────
        // A container hashes its children, so children must be final.
        for directory in nestedBundleDirectories {
            let root = bundleURL.appendingPathComponent(directory, isDirectory: true)
            guard fm.fileExists(atPath: root.path) else { continue }
            let children = (try? fm.contentsOfDirectory(
                at: root, includingPropertiesForKeys: nil)) ?? []
            for child in children where child.pathExtension != "dylib" {
                // Only a directory that actually carries an Info.plist is a
                // nested code bundle. Ships like UTM also carry plain files in
                // `Extensions/` (e.g. `UTM.appexpt`, a placeholder not backed
                // by any bundle) — recursing into those would try to build a
                // `_CodeSignature` inside a file and abort the whole signing
                // pass. Anything else here is hashed as a resource instead.
                var isDirectory: ObjCBool = false
                guard fm.fileExists(atPath: child.path, isDirectory: &isDirectory),
                      isDirectory.boolValue,
                      (try? infoPlist(of: child)) ?? nil != nil
                else {
                    report.skipped.append(
                        "\(directory)/\(child.lastPathComponent)（非嵌套 bundle）")
                    continue
                }
                // Each nested bundle signs with its own Info.plist identity.
                let nestedName = try nestedExecutableName(of: child) ?? child
                    .lastPathComponent
                let nestedID = try bundleIdentifier(of: child)
                    ?? "\(identifier).\(child.deletingPathExtension().lastPathComponent)"
                let nested = try sign(
                    bundleURL: child,
                    executableName: nestedName,
                    identifier: nestedID,
                    entitlementsXML: nil)
                report.nestedBundles.append(child.lastPathComponent)
                report.signedBinaries.append(contentsOf: nested.signedBinaries)
            }
            // Bare dylibs in Frameworks/ are code objects with no bundle.
            for child in children where child.pathExtension == "dylib" {
                try signStandaloneMachO(
                    at: child, identifier: identifier, entitlementsXML: nil)
                report.signedBinaries.append(
                    "\(directory)/\(child.lastPathComponent)")
            }
        }

        // ── 2. Resource seal ────────────────────────────────────────────────
        // Computed before the main binary because the binary's CodeDirectory
        // hashes the seal file.
        let seal = try buildCodeResources(bundleURL: bundleURL)
        let codeSignatureDirectory = bundleURL
            .appendingPathComponent("_CodeSignature", isDirectory: true)
        try fm.createDirectory(at: codeSignatureDirectory,
                               withIntermediateDirectories: true)
        let sealURL = codeSignatureDirectory.appendingPathComponent("CodeResources")
        try seal.data.write(to: sealURL, options: .atomic)
        report.wroteCodeResources = true
        report.resourceCount = seal.resourceCount

        // ── 3. Main binary ──────────────────────────────────────────────────
        // Its special slots bind Info.plist and the seal into the signature.
        let executableURL = bundleURL.appendingPathComponent(executableName)
        guard fm.fileExists(atPath: executableURL.path) else {
            throw BundleInspectionError.executableNotFound(executableURL)
        }

        let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
        let infoPlistData = (try? Data(contentsOf: infoPlistURL)) ?? Data()

        try signMachO(
            at: executableURL,
            identifier: identifier,
            entitlementsXML: entitlementsXML,
            infoPlist: infoPlistData,
            codeResources: seal.data)
        report.signedBinaries.append(executableName)

        return report
    }

    // MARK: - Mach-O signing

    /// Signs a Mach-O file, supplying the bundle-level special slots.
    private static func signMachO(
        at url: URL,
        identifier: String,
        entitlementsXML: Data?,
        infoPlist: Data,
        codeResources: Data
    ) throws {
        let image = try MachOImage(contentsOf: url)

        // The bundle signer owns Info.plist and the resource seal, so it
        // pre-computes those two slots and hands them to the binary signer.
        // The entitlements slot is *not* pre-computed here — `MachOCodeSigner`
        // derives it from `entitlementsXML` itself, and hashing it twice would
        // just be two paths to the same value.
        let specialSlots: [UInt32: [UInt8]] = [
            CodeSignSlot.info: SHA256.hash(data: infoPlist),
            CodeSignSlot.resourceDirectory: SHA256.hash(data: codeResources),
        ]

        let (signed, _) = try MachOCodeSigner.sign(
            image: image,
            identifier: identifier,
            entitlementsXML: entitlementsXML,
            extraSpecialSlots: specialSlots,
            specialSlotCount: maximumSpecialSlot(
                in: specialSlots, includingEntitlements: entitlementsXML != nil))

        // Replace atomically so a failure mid-write cannot leave a bundle
        // whose binary is half old and half new.
        try signed.write(to: url, options: .atomic)
    }

    /// Signs a Mach-O that is not part of a bundle (a bare dylib).
    private static func signStandaloneMachO(
        at url: URL,
        identifier: String,
        entitlementsXML: Data?
    ) throws {
        let image = try MachOImage(contentsOf: url)
        let (signed, _) = try MachOCodeSigner.sign(
            image: image,
            identifier: identifier,
            entitlementsXML: entitlementsXML)
        try signed.write(to: url, options: .atomic)
    }

    // MARK: - Resource seal

    /// The pieces of a `_CodeSignature/CodeResources` file.
    struct ResourceSeal {
        var data: Data
        var resourceCount: Int
    }

    /// Builds the resource seal.
    ///
    /// `CodeResources` is a plist with two parallel maps:
    ///
    ///   • `files`  — SHA-1 hashes, for OS versions that still verify SHA-1
    ///   • `files2` — the richer form: a dictionary with `hash` (SHA-1) and
    ///                `hash2` (SHA-256), plus an optional `optional` flag
    ///
    /// A nested bundle or directory appears as a single entry whose value is
    /// `{ cdhash }` / `{ cdhash2, requirement }` rather than a file hash, so
    /// the kernel verifies its own signature instead of its bytes.
    ///
    /// We emit both maps with SHA-1 and SHA-256 so the seal is valid on every
    /// iOS version that can run Luna. (SHA-1 is computed here only because the
    /// format demands it — it is not used for any security decision.)
    private static func buildCodeResources(bundleURL: URL) throws -> ResourceSeal {
        var files: [String: Any] = [:]
        var files2: [String: Any] = [:]
        var count = 0

        guard let enumerator = FileManager.default.enumerator(
            at: bundleURL,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
            options: []
        ) else {
            throw CodeSignError.signingFailed("无法遍历 bundle：\(bundleURL.lastPathComponent)")
        }

        let rootPath = bundleURL.standardizedFileURL.path

        for case let itemURL as URL in enumerator {
            let relative = relativePath(of: itemURL, from: rootPath)
            guard !relative.isEmpty else { continue }

            // Skip the seal itself and the profile.
            let firstComponent = relative.split(separator: "/").first.map(String.init) ?? ""
            if excludedFromSeal.contains(firstComponent) { continue }
            if relative == "Info.plist" { continue }
            // AppleDouble sidecars are filesystem noise, not resources.
            if relative.split(separator: "/").contains(where: { $0.hasPrefix("._") }) {
                continue
            }

            let values = try? itemURL.resourceValues(
                forKeys: [.isDirectoryKey, .isRegularFileKey])

            if values?.isDirectory == true {
                // A nested code object is sealed by its cdhash, not its bytes.
                if let cdhash = try? mainCdhash(ofBundle: itemURL) {
                    files[relative] = cdhash.sha1
                    files2[relative] = [
                        "cdhash": cdhash.sha256,
                        "requirement": "cdhash \(cdhash.sha256)",
                    ]
                    count += 1
                }
                continue
            }

            guard values?.isRegularFile == true else { continue }
            // A single unreadable file (odd permissions, a dangling symlink
            // inside an extension directory) must not abort the whole pass;
            // it is skipped and the seal simply does not cover it.
            guard let data = try? Data(contentsOf: itemURL, options: .mappedIfSafe)
            else { continue }
            files[relative] = SHA1.hash(data: data).hexString
            files2[relative] = [
                "hash": SHA1.hash(data: data).hexString,
                "hash2": SHA256.hash(data: data).hexString,
            ]
            count += 1
        }

        let plist: [String: Any] = [
            "files": files,
            "files2": files2,
        ]

        let data = try PropertyListSerialization.data(
            fromPropertyList: plist, format: .xml, options: 0)
        return ResourceSeal(data: data, resourceCount: count)
    }

    // MARK: - Bundle helpers

    /// The `CFBundleIdentifier` in a nested bundle's Info.plist.
    private static func bundleIdentifier(of bundleURL: URL) throws -> String? {
        guard let plist = try infoPlist(of: bundleURL) else { return nil }
        return plist["CFBundleIdentifier"] as? String
    }

    /// The `CFBundleExecutable` in a nested bundle's Info.plist.
    private static func nestedExecutableName(of bundleURL: URL) throws -> String? {
        guard bundleURL.pathExtension == "app"
                || bundleURL.pathExtension == "appex"
                || bundleURL.pathExtension == "framework"
        else { return nil }
        guard let plist = try infoPlist(of: bundleURL) else { return nil }
        return plist["CFBundleExecutable"] as? String
    }

    private static func infoPlist(of bundleURL: URL) throws -> [String: Any]? {
        let url = bundleURL.appendingPathComponent("Info.plist")
        guard let raw = try? Data(contentsOf: url) else { return nil }
        return try? PropertyListSerialization.propertyList(
            from: raw, options: [], format: nil) as? [String: Any]
    }

    /// Reads a bundle's main binary and returns its cdhash pair.
    ///
    /// Used when sealing a nested bundle: the parent references the child by
    /// cdhash, which means the child's own signature is what gets verified.
    private static func mainCdhash(ofBundle bundleURL: URL) throws
        -> (sha1: String, sha256: String)? {
        guard let plist = try infoPlist(of: bundleURL),
              let executable = plist["CFBundleExecutable"] as? String
        else { return nil }
        let executableURL = bundleURL.appendingPathComponent(executable)
        guard FileManager.default.fileExists(atPath: executableURL.path) else { return nil }
        guard let image = try? MachOImage(contentsOf: executableURL),
              let command = image.codeSignatureCommand(),
              Int(command.dataOff) + Int(command.dataSize) <= image.data.count
        else { return nil }

        let blob = image.data.subdata(
            in: Int(command.dataOff)..<(Int(command.dataOff) + Int(command.dataSize)))

        // The cdhash is taken over the CodeDirectory member, which is the
        // first blob the SuperBlob's index points at.
        guard let codeDirectory = firstCodeDirectory(in: blob) else { return nil }
        let full = SHA256.hash(data: codeDirectory)
        let truncated = Array(full.prefix(20))
        return (truncated.hexString, full.hexString)
    }

    /// Pulls the CodeDirectory blob out of a SuperBlob.
    ///
    /// SuperBlob layout: `magic | length | count | count × {type, offset} | …`,
    /// with offsets relative to the start of the SuperBlob.
    private static func firstCodeDirectory(in superBlob: Data) -> Data? {
        let reader = ByteReader(superBlob)
        guard let magic = reader.u32(at: 0),
              magic == CodeSignMagic.embeddedSignature,
              let count = reader.u32(at: 8)
        else { return nil }

        for index in 0..<Int(count) {
            let entryOffset = 12 + index * 8
            guard let type = reader.u32(at: entryOffset),
                  let blobOffset = reader.u32(at: entryOffset + 4),
                  type == CodeSignSlot.codeDirectory
            else { continue }
            guard let length = reader.u32(at: Int(blobOffset) + 4),
                  Int(blobOffset) + Int(length) <= superBlob.count
            else { return nil }
            return superBlob.subdata(in: Int(blobOffset)..<(Int(blobOffset) + Int(length)))
        }
        return nil
    }

    /// Path of `url` relative to `root`, `/`-separated.
    private static func relativePath(of url: URL, from root: String) -> String {
        let full = url.standardizedFileURL.path
        guard full.hasPrefix(root) else { return "" }
        var relative = String(full.dropFirst(root.count))
        while relative.hasPrefix("/") { relative.removeFirst() }
        return relative
    }

    /// The highest populated special slot, which sets the table size.
    ///
    /// Only slots that live in the hash table count — the signature slot
    /// (`0x10000`) is a SuperBlob member name and is filtered out by
    /// `CodeDirectoryBuilder.highestHashSlot`.
    private static func maximumSpecialSlot(
        in slots: [UInt32: [UInt8]],
        includingEntitlements: Bool = false
    ) -> UInt32 {
        var candidates = slots.keys.filter {
            $0 < CodeSignSlot.alternateCodeDirectories
        }
        if includingEntitlements {
            candidates.append(CodeSignSlot.entitlements)
        }
        return candidates.max() ?? 0
    }
}

/// SHA-1, required by the resource seal format.
///
/// Implemented locally for the same reason as `SHA256`: CryptoKit is not
/// available on every target Luna builds for, and a dependency-free version
/// keeps the CI runner's environment irrelevant. This is *not* used as a
/// security boundary — it exists because `CodeResources` stores a SHA-1 hash
/// alongside the SHA-256 one and older iOS versions read that field.
enum SHA1 {

    static func hash(data: Data) -> [UInt8] {
        var h0: UInt32 = 0x6745_2301
        var h1: UInt32 = 0xEFCD_AB89
        var h2: UInt32 = 0x98BA_DCFE
        var h3: UInt32 = 0x1032_5476
        var h4: UInt32 = 0xC3D2_E1F0

        var message = [UInt8](data)
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)
        while message.count % 64 != 56 { message.append(0) }
        for shift in stride(from: 56, through: 0, by: -8) {
            message.append(UInt8((bitLength >> UInt64(shift)) & 0xFF))
        }

        var w = [UInt32](repeating: 0, count: 80)

        for chunkStart in stride(from: 0, to: message.count, by: 64) {
            for i in 0..<16 {
                let base = chunkStart + i * 4
                w[i] = (UInt32(message[base]) << 24)
                    | (UInt32(message[base + 1]) << 16)
                    | (UInt32(message[base + 2]) << 8)
                    | UInt32(message[base + 3])
            }
            for i in 16..<80 {
                w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
            }

            var (a, b, c, d, e) = (h0, h1, h2, h3, h4)

            for i in 0..<80 {
                let f: UInt32
                let k: UInt32
                switch i {
                case 0..<20:
                    f = (b & c) | (~b & d); k = 0x5A82_7999
                case 20..<40:
                    f = b ^ c ^ d; k = 0x6ED9_EBA1
                case 40..<60:
                    f = (b & c) | (b & d) | (c & d); k = 0x8F1B_BCDC
                default:
                    f = b ^ c ^ d; k = 0xCA62_C1D6
                }
                let temp = rotl(a, 5) &+ f &+ e &+ k &+ w[i]
                e = d; d = c; c = rotl(b, 30); b = a; a = temp
            }

            h0 = h0 &+ a; h1 = h1 &+ b; h2 = h2 &+ c; h3 = h3 &+ d; h4 = h4 &+ e
        }

        var out: [UInt8] = []
        out.reserveCapacity(20)
        for value in [h0, h1, h2, h3, h4] {
            out.append(UInt8((value >> 24) & 0xFF))
            out.append(UInt8((value >> 16) & 0xFF))
            out.append(UInt8((value >> 8) & 0xFF))
            out.append(UInt8(value & 0xFF))
        }
        return out
    }

    private static func rotl(_ value: UInt32, _ amount: UInt32) -> UInt32 {
        (value << amount) | (value >> (32 - amount))
    }
}
