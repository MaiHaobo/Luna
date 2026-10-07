//
//  ProcessRedirects.swift
//  Luna
//
//  The three process-global redirections a guest needs in order to believe it
//  is the main executable, plus the probe that reports whether the process is
//  even allowed to perform them.
//
//  No third-party hooking library is used. Every mechanism below is either a
//  documented C API (`task_vm_protect`, `object_setClass`, `_dyld_*`) or plain
//  memory surgery on a buffer whose address came from the system. The reason is
//  not purity: each of these is a place where a partially-applied change leaves
//  the process in a state no error handler can describe, so being able to read
//  the whole mechanism in one file is the point.
//

import Foundation
import Darwin
import ObjectiveC
import MachO

// MARK: - Writable memory

/// Whether this process may turn mapped memory writable.
///
/// The redirects below modify memory inside dyld's own `__DATA`, which iOS
/// maps read-only and protects against writes unless the process carries
/// `get-task-allow` (a debug- or JIT-entitling signature). Probing is therefore
/// the precondition for the entire runtime path, and its result is reported to
/// the user rather than papered over.
enum WritableExecutableMemory {

    /// True when a freshly mapped page can be upgraded to `RWX`.
    ///
    /// Evaluated once and cached: the probe maps and unmaps a page, so
    /// repeating it per launch is both wasteful and noisy in the system log on
    /// builds where it fails.
    static let isAvailable: Bool = {
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
        return mprotect(region, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) == 0
    }()

    /// Makes `count` bytes at `address` writable, leaving execution to the
    /// caller. Returns false rather than throwing because every call site
    /// treats failure as "fall back", not "abort".
    ///
    /// `mprotect` rather than `task_vm_protect`: the latter is not exported to
    /// app-land on iOS, whereas `mprotect` is the call the platform expects and
    /// the one whose failure mode (EPERM without a debugging entitlement) is
    /// exactly the signal we want.
    ///
    /// The pages belong to a mapped image, so the protection is applied to a
    /// page-aligned range — `mprotect` rejects a misaligned address outright.
    static func makeWritable(_ address: UnsafeMutableRawPointer, count: Int) -> Bool {
        guard isAvailable else { return false }
        let pageSize = Int(getpagesize())
        let start = UInt(bitPattern: address)
        let alignedStart = start & ~UInt(pageSize - 1)
        let end = start + UInt(count)
        let alignedEnd = (end + UInt(pageSize - 1)) & ~UInt(pageSize - 1)
        let length = Int(alignedEnd - alignedStart)

        guard let region = UnsafeMutableRawPointer(bitPattern: alignedStart) else {
            return false
        }
        return mprotect(region, length, PROT_READ | PROT_WRITE) == 0
    }
}

// MARK: - Step 1: _NSGetExecutablePath

/// Rewrites the buffer `_NSGetExecutablePath` reports.
///
/// dyld4 resolves the main executable's path once, keeps it in its own data,
/// and returns the same string on every call. Changing what that string
/// contains is what makes a guest's startup logic conclude it is the main
/// executable, rather than a library loaded into someone else's process.
enum ExecutablePathRedirect {

    /// Overwrites the reported executable path with `guestExecutablePath`.
    ///
    /// - Returns: true when the path actually changed.
    static func apply(guestExecutablePath: String) throws -> Bool {
        var size: UInt32 = 0

        // A nil buffer is the documented way to ask how much room the path
        // needs; dyld writes that capacity into `size`.
        _ = _NSGetExecutablePath(nil as UnsafeMutablePointer<CChar>?, &size)
        guard size > 0 else { throw RedirectError.noPathBuffer }

        var buffer = [CChar](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&buffer, &size) == 0 else {
            throw RedirectError.pathQueryFailed
        }
        let current = String(cString: buffer)
        if current == guestExecutablePath { return false }

        let replacement = Array(guestExecutablePath.utf8CString)
        guard replacement.count <= Int(size) else {
            // Overrunning the system buffer would corrupt dyld's heap, and the
            // resulting crash would point nowhere near this line.
            throw RedirectError.pathTooLong(
                needed: replacement.count, available: Int(size))
        }

        // Find the system's own copy of the string so the edit is visible to
        // every other caller, not just to us.
        guard let live = locateExecutablePathBuffer(pattern: current, capacity: Int(size)) else {
            throw RedirectError.pathQueryFailed
        }
        guard WritableExecutableMemory.makeWritable(live, count: Int(size)) else {
            throw RedirectError.notWritable
        }

        let destination = live.assumingMemoryBound(to: CChar.self)
        for (index, byte) in replacement.enumerated() { destination[index] = byte }
        if replacement.count < Int(size) {
            for index in replacement.count..<Int(size) { destination[index] = 0 }
        }
        return true
    }

    /// Finds the system's copy of the executable path by scanning the mapped
    /// regions dyld reports.
    ///
    /// `_dyld_get_image_header(0)` is the main image by convention, and the
    /// path string lives inside its `__DATA`. The search is bounded to each
    /// image's own declared segment span so it never touches unmapped memory,
    /// and it compares the full string including its terminating NUL so a
    /// chance match inside unrelated data cannot be mistaken for the path.
    private static func locateExecutablePathBuffer(
        pattern: String,
        capacity: Int
    ) -> UnsafeMutableRawPointer? {
        let bytes = Array(pattern.utf8) + [0]

        let count = _dyld_image_count()
        guard count > 0 else { return nil }
        for index in 0..<count {
            guard let rawHeader = _dyld_get_image_header(index) else { continue }
            let header = UnsafeRawPointer(rawHeader)
            guard let span = mappedSpan(ofImageAt: header) else { continue }
            if let found = find(bytes, in: header, span: span) {
                return UnsafeMutableRawPointer(mutating: found)
            }
        }
        return nil
    }

    /// The byte span of one image, derived from its `segment_command_64`
    /// entries. Returns nil when the header cannot be walked, so the caller
    /// skips that image instead of probing a guess.
    private static func mappedSpan(ofImageAt header: UnsafeRawPointer) -> Int? {
        // mach_header_64:
        //   magic(4) cputype(4) cpusubtype(4) filetype(4)
        //   ncmds(4) sizeofcmds(4) flags(4) reserved(4)  = 32
        let ncmds = header.load(fromByteOffset: 16, as: UInt32.self)
        let sizeofcmds = header.load(fromByteOffset: 20, as: UInt32.self)
        guard ncmds > 0, sizeofcmds > 0, ncmds < 4096 else { return nil }

        let base = UInt(bitPattern: header)
        var highest: UInt64 = 0
        var cursor = 32
        for _ in 0..<Int(ncmds) {
            let cmd = header.load(fromByteOffset: cursor, as: UInt32.self)
            let cmdsize = header.load(fromByteOffset: cursor + 4, as: UInt32.self)
            guard cmdsize >= 8 else { break }
            if cmd == MachOLoadCommand.segment64 {
                // segment_command_64: segname(16)@8, vmaddr(8)@24, vmsize(8)@32
                let vmaddr = header.load(fromByteOffset: cursor + 24, as: UInt64.self)
                let vmsize = header.load(fromByteOffset: cursor + 32, as: UInt64.self)
                highest = max(highest, vmaddr + vmsize)
            }
            cursor += Int(cmdsize)
        }
        guard highest > 0, UInt(highest) > base else { return nil }
        // Cap the span so a corrupt header cannot make us scan gigabytes.
        return min(Int(UInt(highest) - base), 256 * 1024 * 1024)
    }

    /// Byte search inside a mapped region.
    private static func find(
        _ needle: [UInt8],
        in base: UnsafeRawPointer,
        span: Int
    ) -> UnsafeRawPointer? {
        guard span > needle.count else { return nil }
        let haystack = base.assumingMemoryBound(to: UInt8.self)
        let limit = span - needle.count
        var index = 0
        while index <= limit {
            if memcmp(haystack + index, needle, needle.count) == 0 {
                return UnsafeRawPointer(haystack + index)
            }
            index += 1
        }
        return nil
    }

    enum RedirectError: LocalizedError {
        case noPathBuffer
        case pathQueryFailed
        case pathTooLong(needed: Int, available: Int)
        case notWritable

        var errorDescription: String? {
            switch self {
            case .noPathBuffer:
                return "系统未提供可执行文件路径缓冲区"
            case .pathQueryFailed:
                return "无法定位系统持有的可执行文件路径"
            case .pathTooLong(let needed, let available):
                return "guest 路径长度 \(needed) 超过系统缓冲区 \(available)"
            case .notWritable:
                return "无法将系统数据段改为可写（缺少 JIT 权限）"
            }
        }
    }
}

// MARK: - Step 2: NSBundle.mainBundle

/// Makes `NSBundle.mainBundle` report the guest's bundle.
///
/// `mainBundle` returns a cached `NSBundle` built at first access, wrapping the
/// host's path, and there is no setter. Swizzling the class method is used
/// rather than re-pointing the cached instance because it also covers callers
/// that captured the class, and because the real host bundle stays reachable
/// through the swizzled implementation's original call.
enum MainBundleRedirect {

    private static var applied = false
    /// The guest path, read back by the swizzled implementation.
    private(set) static var guestPath: String?

    /// Installs the override. Idempotent.
    /// - Returns: true when the override is in place.
    @discardableResult
    static func apply(guestBundleURL: URL) -> Bool {
        guestPath = guestBundleURL.path
        if applied { return true }

        guard let original = class_getClassMethod(Bundle.self, #selector(getter: Bundle.main)),
              let replacement = class_getClassMethod(Bundle.self, #selector(Bundle.luna_mainBundle))
        else {
            return false
        }
        method_exchangeImplementations(original, replacement)
        applied = true
        return true
    }
}

extension Bundle {

    /// The replacement implementation exchanged with `mainBundle` by
    /// `MainBundleRedirect`. The prefix keeps it from colliding with a real
    /// `Bundle` member.
    ///
    /// After the exchange, calling `luna_mainBundle` here actually invokes the
    /// *original* `mainBundle`, which is how the host bundle remains reachable
    /// as the fallback when no guest is installed.
    @objc class func luna_mainBundle() -> Bundle {
        if let path = MainBundleRedirect.guestPath,
           let guest = Bundle(path: path) {
            return guest
        }
        return luna_mainBundle()
    }
}

// MARK: - Step 3: library validation

/// Reports whether the process can relax dyld's library validation.
///
/// dyld only maps a dylib whose signature chains to the host's Team ID, so a
/// guest signed by a different identity — or not signed at all — trips this.
/// Relaxing it depends on the same writable-memory grant as the redirects
/// above, which is controlled by the JIT/debug entitlement.
///
/// This reports *capability*, not a completed change: the relaxation is a
/// consequence of mapping with that grant already in place. Keeping the two
/// apart means the session log stays truthful in the case where the guest was
/// signed compatibly and no bypass was necessary.
enum LibraryValidationBypass {

    static var canRelax: Bool { WritableExecutableMemory.isAvailable }
}
