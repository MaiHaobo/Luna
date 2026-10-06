//
//  LoaderRegistry.swift
//  Luna
//
//  Chooses which launch backend the app uses, and is the only place that
//  decision is made.
//
//  Split into its own file (rather than living beside the loaders) because it
//  carries the one piece of state that must not be duplicated: the capability
//  probe result. Probing maps and unmaps a page of executable memory, so doing
//  it more than once per launch is wasteful and, on some OS builds, noisy in
//  the system log.
//

import Foundation

@MainActor
final class LoaderRegistry {

    /// Result of the one-time capability probe.
    let capabilities: LoaderCapabilities

    /// The preview backend. Always available, and the one the coordinator wires
    /// its presentation callback into.
    let preview: PreviewLoader

    /// The runtime backend. Gated on `capabilities`.
    let runtime: RuntimeLoader

    init() {
        let caps = LoaderCapabilities.probe()
        self.capabilities = caps
        self.preview = PreviewLoader()
        self.runtime = RuntimeLoader(capabilities: caps)
    }

    /// The loader the app should use right now.
    var active: GuestLoader {
        runtime.isAvailable ? runtime : preview
    }

    /// Whether the user is getting a degraded experience and should be told.
    var isRunningDegraded: Bool { !runtime.isAvailable }

    /// Why the runtime loader is off, in user-facing language. `nil` when it
    /// is available.
    var runtimeUnavailabilityReason: String? { runtime.unavailabilityReason }
}

/// Build-time environment values the loaders need.
enum LunaEnvironment {

    /// Path the injected `LC_LOAD_DYLIB` points at.
    ///
    /// `@executable_path` resolves against the *host* binary's directory, which
    /// is what we want: the shim ships inside `Luna.app/Frameworks` and the
    /// loader path inside the guest's rewritten load commands stays valid no
    /// matter where the guest's bundle sits.
    static let loaderShimPath = "@executable_path/Frameworks/LunaLoaderShim.dylib"

    /// Name of the shim binary.
    static let loaderShimName = "LunaLoaderShim.dylib"

    /// The shim's location inside the running bundle, if it was packaged.
    static var loaderShimURL: URL? {
        Bundle.main.privateFrameworksURL?
            .appendingPathComponent(loaderShimName)
    }

    /// Whether this build shipped the loader shim.
    ///
    /// When it is absent we still run the patch pass — the rewrite is
    /// observable and testable on its own — but we omit the injection step,
    /// because injecting a path to a file that does not exist would make dyld
    /// fail the whole load rather than degrade gracefully.
    static var hasLoaderShim: Bool {
        guard let url = loaderShimURL else { return false }
        return FileManager.default.fileExists(atPath: url.path)
    }

    /// The injection path to use, or `nil` when there is nothing to inject.
    static var effectiveLoaderPath: String? {
        hasLoaderShim ? loaderShimPath : nil
    }

    /// Marketing version, surfaced in Settings and Diagnostics.
    static var appVersion: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "0"
        let build = info?["CFBundleVersion"] as? String ?? "0"
        return "\(version) (\(build))"
    }
}
