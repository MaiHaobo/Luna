//
//  MachODefines.swift
//  Luna
//
//  Minimal Mach-O constants used by the binary inspection / patching engine.
//
//  We deliberately re-declare these instead of relying on the C headers under
//  `#include <mach-o/loader.h>` because Swift's importer makes several of the
//  structs awkward to work with (fixed-size char arrays, bitfields, and
//  endianness unions). Keeping our own copy means the engine is portable,
//  unit-testable on any platform, and free of C-interop surprises.
//

import Foundation

// MARK: - Magic numbers

enum MachOMagic {
    /// 32-bit Mach-O, host byte order (little-endian on Apple silicon).
    static let magic32: UInt32 = 0xFEEDFACE
    /// 64-bit Mach-O, host byte order.
    static let magic64: UInt32 = 0xFEEDFACF
    /// 32-bit Mach-O, byte-swapped.
    static let cigaMagic32: UInt32 = 0xCEFAEDFE
    /// 64-bit Mach-O, byte-swapped.
    static let cigaMagic64: UInt32 = 0xCFFAEDFE

    /// Universal ("fat") binary, big-endian on disk.
    static let fatMagic: UInt32 = 0xCAFEBABE
    /// 64-bit universal binary header.
    static let fatMagic64: UInt32 = 0xCAFEBABF
}

// MARK: - CPU types

enum MachOCPUType {
    static let arm64: UInt32 = 0x0100_000C
    static let arm64_32: UInt32 = 0x0200_000C
    static let x86_64: UInt32 = 0x0100_0007
}

// MARK: - File types (`mach_header_64.filetype`)

enum MachOFileType {
    static let object: UInt32 = 0x1
    /// A normal executable. `dlopen()` refuses to load these.
    static let execute: UInt32 = 0x2
    static let fvmlib: UInt32 = 0x3
    static let core: UInt32 = 0x4
    static let preload: UInt32 = 0x5
    /// A shared library. This is what we rewrite `MH_EXECUTE` into, which is
    /// the trick that lets us `dlopen()` a guest app's main binary.
    static let dylib: UInt32 = 0x6
    static let dylinker: UInt32 = 0x7
    static let bundle: UInt32 = 0x8
}

// MARK: - Encryption info (`LC_ENCRYPTION_INFO*`)

enum MachOEncryption {
    /// `encryption_info_command` (32-bit slices).
    static let infoCommand: UInt32 = 0x21
    /// `encryption_info_command_64` (64-bit slices).
    static let infoCommand64: UInt32 = 0x2C
}

// MARK: - Load command types

enum MachOLoadCommand {
    static let segment64: UInt32 = 0x19
    static let loadDylib: UInt32 = 0xC
    static let idDylib: UInt32 = 0xD
    static let loadWeakDylib: UInt32 = 0x8000_0018
    static let reexportDylib: UInt32 = 0x8000_001F
    static let lazyLoadDylib: UInt32 = 0x20
    static let main: UInt32 = 0x8000_0028

    /// Human-readable name, used by the inspector UI.
    static func name(of cmd: UInt32) -> String {
        switch cmd {
        case segment64: return "LC_SEGMENT_64"
        case loadDylib: return "LC_LOAD_DYLIB"
        case idDylib: return "LC_ID_DYLIB"
        case loadWeakDylib: return "LC_LOAD_WEAK_DYLIB"
        case reexportDylib: return "LC_REEXPORT_DYLIB"
        case lazyLoadDylib: return "LC_LAZY_LOAD_DYLIB"
        case main: return "LC_MAIN"
        case 0x1: return "LC_SEGMENT"
        case 0x2: return "LC_SYMTAB"
        case 0x3: return "LC_SYMSEG"
        case 0x4: return "LC_THREAD"
        case 0x5: return "LC_UNIXTHREAD"
        case 0xE: return "LC_LOAD_DYLINKER"
        case 0x1B: return "LC_UUID"
        case 0x1D: return "LC_CODE_SIGNATURE"
        case 0x20: return "LC_LAZY_LOAD_DYLIB"
        case 0x22: return "LC_DYLD_INFO"
        case 0x21: return "LC_ENCRYPTION_INFO"
        case 0x26: return "LC_FUNCTION_STARTS"
        case 0x29: return "LC_VERSION_MIN_MACOSX"
        case 0x24: return "LC_VERSION_MIN_IPHONEOS"
        case 0x2A: return "LC_SOURCE_VERSION"
        case 0x2B: return "LC_MAIN"
        case 0x32: return "LC_BUILD_VERSION"
        case 0x33: return "LC_DYLD_EXPORTS_TRIE"
        case 0x34: return "LC_DYLD_CHAINED_FIXUPS"
        case 0x2C: return "LC_ENCRYPTION_INFO_64"
        case 0x1E: return "LC_SEGMENT_SPLIT_INFO"
        case 0x2E: return "LC_LINKER_OPTION"
        case 0x2F: return "LC_LINKER_OPTIMIZATION_HINT"
        default: return String(format: "LC_UNKNOWN(0x%X)", cmd)
        }
    }
}

// MARK: - Byte-order aware reading

/// A small cursor over a byte buffer that decodes fixed-width integers.
///
/// Mach-O headers are little-endian on every architecture iOS ships, so we
/// always read little-endian — but we expose explicit readers anyway so the
/// call sites read clearly and so the fat-header (big-endian) path is obvious.
struct ByteReader {
    let data: Data

    init(_ data: Data) { self.data = data }

    func u32(at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
    }

    /// Reads a big-endian u32. Used for the fat header, which is always
    /// big-endian regardless of the host architecture.
    func u32BE(at offset: Int) -> UInt32? {
        guard let v = u32(at: offset) else { return nil }
        return v.byteSwapped
    }

    func u64(at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= data.count else { return nil }
        return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self) }
    }

    /// Reads a fixed-length, NUL-terminated C string.
    func cString(at offset: Int, maxLength: Int = 256) -> String? {
        guard offset >= 0, offset < data.count else { return nil }
        let end = min(offset + maxLength, data.count)
        var bytes: [UInt8] = []
        for i in offset..<end {
            let b = data[data.startIndex + i]
            if b == 0 { break }
            bytes.append(b)
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}
