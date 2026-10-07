//
//  DyldImageLoader.swift
//  Luna
//
//  The mechanism behind the runtime loader: map a guest's rewritten main
//  binary into Luna's own process, retarget the process identity so the guest
//  believes it is the main executable, and resolve its entry point.
//
//  WHY THIS IS ITS OWN FILE
//  ------------------------
//  Everything here is process-global and irreversible. Rewriting
//  `NSBundle.mainBundle` and altering the path the system reports for the
//  executable cannot be undone by calling a counterpart. Isolating the work
//  means `RuntimeLoader` can decide *whether* to run it, log *why* it refused,
//  and never leave a half-applied identity change in a path that was meant to
//  be read-only.
//
//  THE STEPS (in order, and the order matters)
//  -------------------------------------------
//  A guest `.app`'s main binary is an `MH_EXECUTE` written to believe it is
//  the process's main executable. `MachOPatcher` already made the two changes
//  that let us *load* it (filetype → `MH_DYLIB`, `__PAGEZERO` out of the way).
//  What remains is convincing it that it *is* the main executable:
//
//    1. Redirect the reported executable path (see `ExecutablePathRedirect`).
//    2. Replace `NSBundle.mainBundle` (see `MainBundleRedirect`).
//    3. Note whether library validation could be relaxed.
//    4. `dlopen` the patched binary.
//    5. Resolve its entry point (`LC_MAIN` → `entryoff`).
//
//  WHAT THIS DOES NOT DO
//  ---------------------
//  It does not decrypt FairPlay binaries — see SECURITY.md. It does not
//  sandbox the guest: the guest shares Luna's process, address space, and UID.
//  That is inherent to the design, not an implementation gap.
//

import Foundation
import Darwin
import MachO

// MARK: - Result reporting

/// Why a dyld load could not proceed. Each case maps to one step above, so a
/// session log can say precisely where it stopped.
enum DyldLoadError: LocalizedError {
    case executableMissing(String)
    case notPatchedForLoading
    case imageAlreadyLoaded(String)
    case pathRedirectionFailed(String)
    case dlopenFailed(String)
    case entryPointNotFound

    var errorDescription: String? {
        switch self {
        case .executableMissing(let path):
            return "找不到已修补的可执行文件：\(path)"
        case .notPatchedForLoading:
            return "该二进制尚未完成加载前修补（需要 MH_DYLIB 与重定位后的 __PAGEZERO）。"
        case .imageAlreadyLoaded(let path):
            return "该 guest 已在本进程中加载过：\(path)"
        case .pathRedirectionFailed(let detail):
            return "重定向可执行文件路径失败：\(detail)"
        case .dlopenFailed(let detail):
            return "dlopen 失败：\(detail)"
        case .entryPointNotFound:
            return "在已加载的镜像中未找到可执行入口点。"
        }
    }
}

/// What a load accomplished, for the session log and the canvas readout.
struct DyldLoadReport {
    var guestPath: String
    var redirectedExecutablePath: Bool
    var redirectedMainBundle: Bool
    var libraryValidationRelaxed: Bool
    var dlopenHandle: UnsafeMutableRawPointer?
    var entryPointAddress: UInt?
    var notes: [String]
}

// MARK: - Loader

/// Performs the dyld load. Not a `GuestLoader` — that protocol is the *policy*
/// (when to use this backend); this type is the *mechanism*.
enum DyldImageLoader {

    /// Images this process has already mapped, keyed by resolved path.
    ///
    /// `dlopen` on an already-mapped path returns the existing handle rather
    /// than re-mapping, so a second launch would silently jump into state the
    /// first session already mutated. Tracking paths lets us refuse with a
    /// clear message instead.
    ///
    /// Guarded by a lock because `dlopen` state is process-global and the load
    /// can be driven from a background task.
    private static let lock = NSLock()
    private static var loadedImages: Set<String> = []

    // MARK: Preconditions

    /// Confirms the binary actually carries the patch pass's changes.
    ///
    /// This is a real check, not a formality: `dlopen` on an `MH_EXECUTE`
    /// fails, and a `__PAGEZERO` still covering the low 4 GB collides with
    /// Luna's own mappings. Failing here produces a specific message instead of
    /// an opaque dyld error.
    static func validatePatched(_ executableURL: URL) throws {
        guard FileManager.default.fileExists(atPath: executableURL.path) else {
            throw DyldLoadError.executableMissing(executableURL.path)
        }
        let image: MachOImage
        do {
            image = try MachOImage(contentsOf: executableURL)
        } catch {
            throw DyldLoadError.notPatchedForLoading
        }
        guard image.isAlreadyDylib else { throw DyldLoadError.notPatchedForLoading }
        if let pageZero = image.pageZeroSegment() {
            // The patch pass shrinks this to a 16 KB guard page; anything
            // larger means this binary never went through it.
            guard pageZero.vmSize <= MachOPatcher.patchedPageZeroVMSize else {
                throw DyldLoadError.notPatchedForLoading
            }
        }
    }

    // MARK: The load

    /// Runs the steps. Throws at the first failure so the caller can report how
    /// far it got.
    ///
    /// - Parameters:
    ///   - executableURL: the patched binary inside `Patched/<uuid>/`.
    ///   - bundleURL: the extracted guest `.app`, which step 2 must make the
    ///     guest believe is `mainBundle`.
    ///   - log: receives one line per step, for the session log pane.
    static func load(
        executableURL: URL,
        bundleURL: URL,
        log: (String) -> Void
    ) throws -> DyldLoadReport {

        try validatePatched(executableURL)

        let resolvedPath = executableURL.resolvingSymlinksInPath().path

        lock.lock()
        let alreadyLoaded = loadedImages.contains(resolvedPath)
        lock.unlock()
        guard !alreadyLoaded else { throw DyldLoadError.imageAlreadyLoaded(resolvedPath) }

        var report = DyldLoadReport(
            guestPath: resolvedPath,
            redirectedExecutablePath: false,
            redirectedMainBundle: false,
            libraryValidationRelaxed: false,
            dlopenHandle: nil,
            entryPointAddress: nil,
            notes: []
        )

        // ── Step 1: reported executable path ───────────────────────────────
        do {
            let changed = try ExecutablePathRedirect.apply(guestExecutablePath: resolvedPath)
            report.redirectedExecutablePath = changed
            log(changed
                ? "① 已重定向可执行文件路径 → \(resolvedPath)"
                : "① 可执行文件路径无需重定向")
        } catch {
            throw DyldLoadError.pathRedirectionFailed(error.localizedDescription)
        }

        // ── Step 2: NSBundle.mainBundle ────────────────────────────────────
        let bundleChanged = MainBundleRedirect.apply(guestBundleURL: bundleURL)
        report.redirectedMainBundle = bundleChanged
        if bundleChanged {
            log("② 已重定向 NSBundle.mainBundle → \(bundleURL.lastPathComponent)")
        } else {
            report.notes.append("未能替换 NSBundle.mainBundle，guest 可能读到宿主的 bundle 信息。")
            log("② NSBundle.mainBundle 未替换")
        }

        // ── Step 3: library validation ─────────────────────────────────────
        let relaxed = LibraryValidationBypass.canRelax
        report.libraryValidationRelaxed = relaxed
        if relaxed {
            log("③ 本进程可放宽库校验")
        } else {
            report.notes.append(
                "未能放宽库校验：guest 必须以与宿主一致的签名身份加载，否则 dlopen 会失败。")
            log("③ 未放宽库校验（依赖签名一致性）")
        }

        // ── Step 4: dlopen ─────────────────────────────────────────────────
        // RTLD_NOW resolves everything up front, so a missing symbol surfaces
        // here with a name instead of at an arbitrary later instruction.
        log("④ dlopen \(executableURL.lastPathComponent)…")
        guard let handle = dlopen(resolvedPath, RTLD_NOW) else {
            throw DyldLoadError.dlopenFailed(lastDyldError())
        }
        report.dlopenHandle = handle
        log("④ dlopen 成功")

        // ── Step 5: entry point ────────────────────────────────────────────
        // `dlsym(handle, "main")` is not the same thing as the image entry, so
        // the `LC_MAIN` load command is read directly.
        let entry = entryPoint(of: executableURL)
        report.entryPointAddress = entry
        if let entry {
            log(String(format: "⑤ 入口点已解析：0x%llX", UInt64(entry)))
        } else {
            report.notes.append(
                "镜像已映射，但未解析出入口点：该二进制可能使用 LC_UNIXTHREAD 而非 LC_MAIN。")
            log("⑤ 未解析出入口点")
        }

        lock.lock()
        loadedImages.insert(resolvedPath)
        lock.unlock()
        return report
    }

    /// The most recent dyld error, as a string.
    private static func lastDyldError() -> String {
        guard let raw = dlerror() else { return "未知 dyld 错误" }
        return String(cString: raw)
    }

    /// Resolves the image's entry point: its runtime base address plus
    /// `LC_MAIN.entryoff`.
    ///
    /// `entryoff` is relative to the start of the loaded image, so the header's
    /// runtime address is required first. `dlopen` returns no pointer to it,
    /// so dyld's image list is consulted for a path match.
    private static func entryPoint(of executableURL: URL) -> UInt? {
        guard let header = imageHeaderAddress(
            forPath: executableURL.resolvingSymlinksInPath().path
        ) else { return nil }
        guard let image = try? MachOImage(contentsOf: executableURL),
              let entryoff = image.mainEntryOffset()
        else { return nil }
        return header + UInt(entryoff)
    }

    /// Finds an image's runtime load address by walking dyld's image list.
    ///
    /// `_dyld_image_count` / `_dyld_get_image_name` / `_dyld_get_image_header`
    /// are public dyld API — the same triple every instrumenting tool uses.
    /// Walking them is O(images) and runs once per launch.
    private static func imageHeaderAddress(forPath path: String) -> UInt? {
        let count = _dyld_image_count()
        guard count > 0 else { return nil }
        for index in 0..<count {
            guard let name = _dyld_get_image_name(index) else { continue }
            guard String(cString: name) == path else { continue }
            guard let header = _dyld_get_image_header(index) else { continue }
            return UInt(bitPattern: header)
        }
        return nil
    }
}
