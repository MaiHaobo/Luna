//
//  BundleInspector.swift
//  Luna
//
//  Reads an extracted `.app` bundle and pulls out everything Luna needs to
//  present it, validate it, and warn the user about it.
//
//  The signature inspection here is *descriptive only*. Luna cannot and does
//  not verify Apple's code signature — that is the system's job and it happens
//  (or is deliberately bypassed) at load time. What we surface is metadata that
//  helps a user decide whether they trust an IPA, which is the honest thing to
//  show given that Luna has no way to make that judgement for them.
//

import Foundation

/// Everything Luna learns about a guest bundle before installing it.
struct BundleInspection {
    var bundleIdentifier: String
    var displayName: String
    var bundleName: String
    var version: String
    var buildNumber: String
    var minimumOSVersion: String
    var executableName: String
    var supportedPlatforms: [String]
    var requiredCapabilities: [String]
    var urlSchemes: [String]
    var documentTypes: [String]

    /// Path of the main executable inside the extracted bundle.
    var executableURL: URL
    /// Path of the bundle itself.
    var bundleURL: URL

    /// Bytes on disk for the whole bundle.
    var bundleSize: Int64

    /// Whether the main binary carries an `LC_ENCRYPTION_INFO` command, which
    /// means it was FairPlay-encrypted on download and *cannot* be loaded.
    /// This is the single most common reason a dumped-from-device IPA fails.
    var isEncrypted: Bool

    /// Whether the binary links against a dynamic loader / is a dylib already.
    var isAlreadyDylib: Bool

    /// Human-readable warnings assembled during inspection.
    var warnings: [String]

    var shortDescription: String {
        "\(displayName) \(version) (\(bundleIdentifier))"
    }
}

enum BundleInspectionError: LocalizedError {
    case missingInfoPlist(URL)
    case unreadableInfoPlist(String)
    case missingExecutable(String)
    case executableNotFound(URL)

    var errorDescription: String? {
        switch self {
        case .missingInfoPlist(let url):
            return "bundle 缺少 Info.plist：\(url.lastPathComponent)"
        case .unreadableInfoPlist(let detail):
            return "Info.plist 解析失败：\(detail)"
        case .missingExecutable(let name):
            return "Info.plist 中声明的可执行文件不存在：\(name)"
        case .executableNotFound(let url):
            return "在 bundle 中找不到可执行文件：\(url.path)"
        }
    }
}

enum BundleInspector {

    /// Inspects the `.app` bundle at `bundleURL`.
    static func inspect(bundleURL: URL) throws -> BundleInspection {
        let plistURL = bundleURL.appendingPathComponent("Info.plist")
        guard FileManager.default.fileExists(atPath: plistURL.path) else {
            throw BundleInspectionError.missingInfoPlist(bundleURL)
        }

        // Bundles built for iOS are binary plists, but a hand-edited or
        // re-signed bundle may carry XML. PropertyListSerialization handles both.
        let plist: [String: Any]
        do {
            let raw = try Data(contentsOf: plistURL)
            guard let parsed = try PropertyListSerialization.propertyList(
                from: raw, options: [], format: nil) as? [String: Any]
            else {
                throw BundleInspectionError.unreadableInfoPlist("根节点不是字典")
            }
            plist = parsed
        } catch let error as BundleInspectionError {
            throw error
        } catch {
            throw BundleInspectionError.unreadableInfoPlist(error.localizedDescription)
        }

        // CFBundleExecutable is mandatory; without it we cannot launch anything.
        let executableName = plist["CFBundleExecutable"] as? String ?? ""
        guard !executableName.isEmpty else {
            throw BundleInspectionError.missingExecutable("CFBundleExecutable 为空")
        }
        let executableURL = bundleURL.appendingPathComponent(executableName)
        guard FileManager.default.fileExists(atPath: executableURL.path) else {
            throw BundleInspectionError.executableNotFound(executableURL)
        }

        var warnings: [String] = []

        // ── Encryption check ────────────────────────────────────────────────
        // A FairPlay-encrypted binary's __TEXT is ciphertext until the kernel
        // decrypts it for the owning process. Loaded as a library there is no
        // such decryption step, so the first instruction fetch faults.
        var encrypted = false
        if let image = try? MachOImage(contentsOf: executableURL) {
            encrypted = image.loadCommands.contains { entry in
                // LC_ENCRYPTION_INFO (0x21) and LC_ENCRYPTION_INFO_64 (0x2C)
                entry.cmd == 0x21 || entry.cmd == 0x2C
            }
            if encrypted {
                warnings.append(
                    "该二进制的 __TEXT 段处于加密状态（App Store 下载的 IPA 通常如此）。"
                    + "在 Luna 中加载会失败 —— 请使用已解密的 IPA。")
            }
        } else {
            warnings.append("无法解析主可执行文件，可能不是有效的 Mach-O。")
        }

        let alreadyDylib = (try? MachOImage(contentsOf: executableURL))?.isAlreadyDylib ?? false

        // ── Platform check ──────────────────────────────────────────────────
        // An iOS device cannot load a macOS or tvOS slice.
        let platforms = plist["CFBundleSupportedPlatforms"] as? [String] ?? []
        if !platforms.isEmpty,
           !platforms.contains(where: { $0.lowercased().contains("iphone") || $0.lowercased().contains("ios") }) {
            warnings.append("该 bundle 声明支持的平台为 \(platforms.joined(separator: ", "))，可能不是 iOS 应用。")
        }

        let minOS = plist["MinimumOSVersion"] as? String ?? ""
        if !minOS.isEmpty {
            let current = ProcessInfo.processInfo.operatingSystemVersion
            let currentString = "\(current.majorVersion).\(current.minorVersion)"
            if compareVersions(minOS, currentString) > 0 {
                warnings.append("该应用要求 iOS \(minOS) 或更高版本，当前系统为 iOS \(currentString)。")
            }
        }

        // ── Capability check ────────────────────────────────────────────────
        // These are the reachable-but-broken surface. Entitlements belong to
        // the host process, so anything gated on an entitlement the guest
        // declares simply will not work inside Luna.
        var capabilities: [String] = []
        let entitlementNames = entitlementsDeclared(in: bundleURL)
        let knownFragile: [(String, String)] = [
            ("aps-environment", "推送通知"),
            ("com.apple.developer.healthkit", "HealthKit"),
            ("com.apple.developer.homekit", "HomeKit"),
            ("com.apple.developer.associated-domains", "通用链接"),
            ("com.apple.developer.networking.networkextension", "网络扩展"),
            ("com.apple.developer.usernotifications.filtering", "通知过滤"),
            ("get-task-allow", "调试权限"),
        ]
        for (key, label) in knownFragile where entitlementNames.contains(key) {
            capabilities.append(label)
        }
        if !capabilities.isEmpty {
            warnings.append(
                "该应用依赖以下能力：\(capabilities.joined(separator: "、"))。"
                + "由于 Luna 无法把 guest 的 Entitlements 传递给宿主，这些功能在容器内不可用。")
        }

        // ── Size ────────────────────────────────────────────────────────────
        // Note: `attributesOfItem` reports the *directory entry's* size, not
        // the recursive size. The caller computes the real total separately;
        // this value is only a quick sanity number for the inspection result.
        let size = bundleSizeOnDisk(bundleURL)

        return BundleInspection(
            bundleIdentifier: plist["CFBundleIdentifier"] as? String ?? "unknown.bundle.id",
            displayName: plist["CFBundleDisplayName"] as? String
                ?? plist["CFBundleName"] as? String
                ?? bundleURL.deletingPathExtension().lastPathComponent,
            bundleName: plist["CFBundleName"] as? String ?? "",
            version: plist["CFBundleShortVersionString"] as? String ?? "—",
            buildNumber: plist["CFBundleVersion"] as? String ?? "—",
            minimumOSVersion: minOS,
            executableName: executableName,
            supportedPlatforms: platforms,
            requiredCapabilities: capabilities,
            urlSchemes: urlSchemes(from: plist),
            documentTypes: documentTypes(from: plist),
            executableURL: executableURL,
            bundleURL: bundleURL,
            bundleSize: size,
            isEncrypted: encrypted,
            isAlreadyDylib: alreadyDylib,
            warnings: warnings
        )
    }

    // MARK: - Info.plist extraction helpers

    private static func urlSchemes(from plist: [String: Any]) -> [String] {
        guard let types = plist["CFBundleURLTypes"] as? [[String: Any]] else { return [] }
        return types.compactMap { $0["CFBundleURLSchemes"] as? [String] }.flatMap { $0 }
    }

    private static func documentTypes(from plist: [String: Any]) -> [String] {
        guard let types = plist["CFBundleDocumentTypes"] as? [[String: Any]] else { return [] }
        return types.compactMap { $0["CFBundleTypeName"] as? String }
    }

    /// Best-effort read of the entitlements embedded in the code signature.
    ///
    /// Full signature parsing means walking a CMS blob, which is out of scope
    /// for what is ultimately a UI hint. Instead we look for the XML plist that
    /// `codesign` embeds and extract key names from it, which is enough to tell
    /// a user *which* capabilities their app is asking for.
    private static func entitlementsDeclared(in bundleURL: URL) -> Set<String> {
        // Entitlements live either in `<bundle>/embedded.mobileprovision` or in
        // a `_CodeSignature/CodeResources`-adjacent DER blob. We scan the
        // provisioning profile, which is XML-wrapped and reliably greppable.
        let profileURL = bundleURL.appendingPathComponent("embedded.mobileprovision")
        guard var text = try? String(contentsOf: profileURL, encoding: .utf8) else {
            return []
        }
        // The profile wraps an XML plist inside a binary preamble.
        if let range = text.range(of: "<?xml") {
            text = String(text[range.lowerBound...])
        }
        var found: Set<String> = []
        for key in [
            "aps-environment",
            "com.apple.developer.healthkit",
            "com.apple.developer.homekit",
            "com.apple.developer.associated-domains",
            "com.apple.developer.networking.networkextension",
            "com.apple.developer.usernotifications.filtering",
            "get-task-allow",
            "com.apple.developer.in-app-payments",
            "com.apple.developer.siri",
        ] where text.contains("<key>\(key)</key>") {
            found.insert(key)
        }
        return found
    }

    /// Numeric dotted-version comparison. Returns >0 when `lhs` is newer.
    static func compareVersions(_ lhs: String, _ rhs: String) -> Int {
        let left = lhs.split(separator: ".").map { Int($0) ?? 0 }
        let right = rhs.split(separator: ".").map { Int($0) ?? 0 }
        for index in 0..<max(left.count, right.count) {
            let l = index < left.count ? left[index] : 0
            let r = index < right.count ? right[index] : 0
            if l != r { return l - r }
        }
        return 0
    }

    /// Recursively totals the size of a bundle directory.
    private static func bundleSizeOnDisk(_ url: URL) -> Int64 {
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
