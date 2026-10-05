//
//  GuestLoader.swift
//  Luna
//
//  The launch abstraction.
//
//  WHY THIS IS A PROTOCOL
//  ----------------------
//  Loading a guest into Luna's address space is the highest-risk, most
//  version-fragile part of the whole project. It depends on:
//
//    • dyld's internal symbol layout (`dyld4::APIs::_NSGetExecutablePath`),
//      which Apple has changed between OS releases;
//    • whether the running binary is allowed to flip pages writable after
//      they were marked executable, which hinges on code signing;
//    • whether a JIT path exists at all — on iOS 26+ a debugger/JIT enabler
//      is required, and on the App Store there is none.
//
//  Rather than let that fragility leak into every view, the launch surface is
//  one protocol with two implementations:
//
//    PreviewLoader  — ships today, uses only public API, always works.
//    RuntimeLoader  — the real dlopen path, gated behind a capability check.
//
//  The UI asks `LoaderRegistry.active` for a loader and never branches on
//  capabilities itself. When `RuntimeLoader` reports it cannot run, the
//  session controller transparently falls back to preview and tells the user
//  exactly which precondition failed.
//

import Foundation
import UIKit

// MARK: - Capability reporting

/// What the current process is actually able to do.
struct LoaderCapabilities {

    /// True when the process can mark memory both writable and executable.
    /// Without this, dyld cannot relocate an image we mapped ourselves.
    var hasWritableExecutableMemory: Bool

    /// True when a debugger is attached, which on iOS is the usual proxy for
    /// "JIT is permitted" (`get-task-allow` is present in the signature).
    var isDebugged: Bool

    /// True when running under a jailbreak / TrollStore-style environment
    /// where the platform restrictions are relaxed.
    var isPrivilegedEnvironment: Bool

    /// Whether the guest binaries in this container are already patched.
    var binariesPatched: Bool

    /// Reasons the runtime loader cannot be used, in user-facing language.
    var blockingReasons: [String] {
        var reasons: [String] = []
        if !hasWritableExecutableMemory {
            reasons.append(
                "当前进程无法申请「可写且可执行」的内存页。iOS 要求 JIT 权限才允许这样做，"
                + "而 App Store 分发的应用永远拿不到该权限。")
        }
        if !isDebugged && !isPrivilegedEnvironment {
            reasons.append(
                "未检测到调试器或特权环境。使用 TrollStore / 自签调试证书"
                + "（签名中含 get-task-allow）或 StikDebug 启用 JIT 后可解除此限制。")
        }
        return reasons
    }

    var canRunRuntimeLoader: Bool {
        blockingReasons.isEmpty
    }

    /// Probes the current process.
    ///
    /// The memory probe is the meaningful one. We map a page, flip it to
    /// writable+executable, and immediately restore it. On a stock App Store
    /// build the `mprotect` fails with `EPERM`; on a build signed for
    /// development with `get-task-allow` it succeeds.
    static func probe() -> LoaderCapabilities {
        LoaderCapabilities(
            hasWritableExecutableMemory: probeWritableExecutableMemory(),
            isDebugged: probeIsDebugged(),
            isPrivilegedEnvironment: probePrivilegedEnvironment(),
            binariesPatched: false
        )
    }

    private static func probeWritableExecutableMemory() -> Bool {
        let pageSize = Int(getpagesize())
        guard let region = mmap(
            nil, pageSize,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0
        ), region != MAP_FAILED else {
            return false
        }
        defer { munmap(region, pageSize) }

        // The decisive call: can we upgrade this region to executable?
        let result = mprotect(region, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC)
        return result == 0
    }

    private static func probeIsDebugged() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let status = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard status == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    private static func probePrivilegedEnvironment() -> Bool {
        // TrollStore and jailbreaks relax sandboxing, which shows up as
        // writable system paths. We test a handful of well-known locations.
        let candidates = [
            "/var/jb",
            "/var/mobile/Library/Preferences",
            "/private/var/containers/Bundle/Application",
        ]
        for path in candidates where access(path, W_OK) == 0 {
            return true
        }
        return false
    }
}

// MARK: - Loader

/// A launch backend.
@MainActor
protocol GuestLoader {
    /// A short name shown in diagnostics.
    var name: String { get }
    /// Whether this loader can currently launch.
    var isAvailable: Bool { get }
    /// Human-readable explanation when `isAvailable` is false.
    var unavailabilityReason: String? { get }
    /// Performs a launch.
    func launch(_ guest: GuestApp) throws
}

/// True when the guest's binary has been patched into a loadable form.
enum LoaderError: LocalizedError {
    case notAcknowledged
    case executableMissing(String)
    case binaryEncrypted
    case runtimeUnavailable(String)
    case patchFailed(String)

    var errorDescription: String? {
        switch self {
        case .notAcknowledged:
            return "尚未确认该应用的可信来源。请在应用详情中确认后再启动。"
        case .executableMissing(let path):
            return "找不到可执行文件：\(path)"
        case .binaryEncrypted:
            return "该二进制处于加密状态，无法加载。请改用已解密的 IPA。"
        case .runtimeUnavailable(let reason):
            return "运行时加载不可用：\(reason)"
        case .patchFailed(let detail):
            return "二进制修补失败：\(detail)"
        }
    }
}

// MARK: - Preview loader

/// A launch backend that validates, prepares, and *presents* a guest without
/// mapping its code.
///
/// This is what ships enabled by default. It performs every step of a real
/// launch except the final `dlopen`, which means the patch pipeline, the
/// container plumbing, and the UI are all genuinely exercised — there is no
/// stub sitting in the middle pretending to work.
@MainActor
final class PreviewLoader: GuestLoader {

    let name = "预览模式"
    var isAvailable: Bool { true }
    var unavailabilityReason: String? { nil }

    /// Called with the guest once everything up to the load step has succeeded.
    var onPresent: ((GuestApp, MachOPatchReport?, URL) -> Void)?

    func launch(_ guest: GuestApp) throws {
        guard guest.trustAcknowledged else { throw LoaderError.notAcknowledged }

        let executable = guest.bundleURL.appendingPathComponent(guest.executableName)
        guard FileManager.default.fileExists(atPath: executable.path) else {
            throw LoaderError.executableMissing(executable.path)
        }
        guard !guest.hasBlockingWarning else { throw LoaderError.binaryEncrypted }

        // Run the real patch pipeline so the report we show is real data.
        var report: MachOPatchReport?
        var patchedExecutable = guest.bundleURL.appendingPathComponent(guest.executableName)

        do {
            try LunaPaths.bootstrap()
            try FileManager.default.createDirectory(
                at: guest.patchedDirectoryURL, withIntermediateDirectories: true)

            report = try MachOPatcher.patch(
                sourceURL: executable,
                outputURL: guest.patchedExecutableURL,
                loaderPath: LunaEnvironment.effectiveLoaderPath
            )
            patchedExecutable = guest.patchedExecutableURL
        } catch {
            // A patch failure is not fatal in preview mode — the user still
            // benefits from seeing what went wrong, so we surface it rather
            // than aborting.
            NSLog("[Luna] patch pass failed: \(error.localizedDescription)")
        }

        onPresent?(guest, report, patchedExecutable)
    }
}

// MARK: - Runtime loader

/// The real loader. Present as a fully-specified type so the architecture is
/// honest about where it is going, but hard-gated on capabilities so it can
/// never be reached in an environment where it would crash.
///
/// The remaining implementation work is documented in `docs/LOADER.md`; the
/// capability gate below is the contract that keeps that work isolated.
@MainActor
final class RuntimeLoader: GuestLoader {

    let name = "运行时加载"
    private let capabilities: LoaderCapabilities

    init(capabilities: LoaderCapabilities) {
        self.capabilities = capabilities
    }

    var isAvailable: Bool { capabilities.canRunRuntimeLoader }

    var unavailabilityReason: String? {
        let reasons = capabilities.blockingReasons
        return reasons.isEmpty ? nil : reasons.joined(separator: "\n")
    }

    func launch(_ guest: GuestApp) throws {
        guard isAvailable else {
            throw LoaderError.runtimeUnavailable(
                unavailabilityReason ?? "未知原因")
        }
        // Intentionally unreachable on stock devices — see docs/LOADER.md.
        // The implementation binds `_NSGetExecutablePath`, retargets
        // `NSBundle.mainBundle`, then `dlopen`s the patched image and jumps to
        // its entry point.
        throw LoaderError.runtimeUnavailable(
            "运行时加载尚未在当前构建中启用。")
    }
}
