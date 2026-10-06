//
//  MachOImage.swift
//  Luna
//
//  Read-only view over a Mach-O binary. Handles both thin (single-arch) and
//  fat / universal (multi-arch) containers, and exposes the load-command
//  stream as a simple, throwing iterator.
//

import Foundation

enum MachOError: LocalizedError {
    case unreadableFile(String)
    case notMachO
    case unsupportedMagic(UInt32)
    case noArm64Slice
    case truncatedHeader
    case malformedLoadCommands(String)
    case segmentNotFound(String)
    case noRoomForLoadCommand

    var errorDescription: String? {
        switch self {
        case .unreadableFile(let path):
            return "无法读取文件：\(path)"
        case .notMachO:
            return "目标不是有效的 Mach-O 二进制"
        case .unsupportedMagic(let magic):
            return String(format: "不支持的 Mach-O magic：0x%08X", magic)
        case .noArm64Slice:
            return "通用二进制中未找到 arm64 架构切片"
        case .truncatedHeader:
            return "Mach-O 头部不完整"
        case .malformedLoadCommands(let detail):
            return "加载命令区损坏：\(detail)"
        case .segmentNotFound(let name):
            return "未找到段：\(name)"
        case .noRoomForLoadCommand:
            return "加载命令区没有足够的零填充空间来注入新命令"
        }
    }
}

/// A single parsed load command together with its byte range inside the file.
struct MachOLoadCommandEntry {
    let cmd: UInt32
    /// Absolute byte range of this command inside the whole file buffer.
    let range: Range<Int>

    var name: String { MachOLoadCommand.name(of: cmd) }
}

/// The `__PAGEZERO` segment, if present.
struct PageZeroSegment {
    /// Absolute byte offset of the `segment_command_64` structure.
    let commandOffset: Int
    let vmAddress: UInt64
    let vmSize: UInt64
}

/// Read-only analysis of a Mach-O binary.
///
/// Usage:
/// ```swift
/// let image = try MachOImage(contentsOf: url)
/// print(image.fileTypeDescription, image.segments.map(\.name))
/// ```
struct MachOImage {

    /// The entire file contents. For fat binaries this includes every slice.
    let data: Data

    /// Byte offset of the arm64 slice within `data`. Zero for thin binaries.
    let sliceOffset: Int

    /// True when the file was a universal binary.
    let isFat: Bool

    /// File type of the arm64 slice (`MH_EXECUTE`, `MH_DYLIB`, …).
    let fileType: UInt32

    /// All load commands belonging to the arm64 slice.
    let loadCommands: [MachOLoadCommandEntry]

    /// Total byte size of the load-command region (the `sizeofcmds` field).
    let sizeofcmds: UInt32

    /// Number of load commands (the `ncmds` field).
    let ncmds: UInt32

    // MARK: - Construction

    init(contentsOf url: URL) throws {
        let raw: Data
        do {
            raw = try Data(contentsOf: url, options: .mappedIfSafe)
        } catch {
            throw MachOError.unreadableFile(url.path)
        }
        try self.init(data: raw)
    }

    init(data raw: Data) throws {
        guard raw.count >= 4 else { throw MachOError.truncatedHeader }

        let reader = ByteReader(raw)
        guard let magic = reader.u32(at: 0) else { throw MachOError.truncatedHeader }

        var offset = 0
        var fat = false

        switch magic {
        case MachOMagic.fatMagic, MachOMagic.fatMagic64:
            fat = true
            offset = try Self.locateArm64Slice(in: raw, is64: magic == MachOMagic.fatMagic64)
        case MachOMagic.magic64, MachOMagic.cigaMagic64:
            offset = 0
        case MachOMagic.magic32, MachOMagic.cigaMagic32:
            throw MachOError.unsupportedMagic(magic) // 32-bit guests are not supported
        default:
            throw MachOError.notMachO
        }

        // Parse the thin header at `offset`.
        // mach_header_64 layout:
        //   0  magic        4
        //   4  cputype      4
        //   8  cpusubtype   4
        //  12  filetype     4
        //  16  ncmds        4
        //  20  sizeofcmds   4
        //  24  flags        4
        //  28  reserved     4     (total 32)
        guard let hdrMagic = reader.u32(at: offset),
              hdrMagic == MachOMagic.magic64 || hdrMagic == MachOMagic.cigaMagic64
        else {
            throw MachOError.notMachO
        }
        guard let ftype = reader.u32(at: offset + 12),
              let cmdCount = reader.u32(at: offset + 16),
              let cmdBytes = reader.u32(at: offset + 20)
        else {
            throw MachOError.truncatedHeader
        }

        var entries: [MachOLoadCommandEntry] = []
        entries.reserveCapacity(Int(cmdCount))

        var cursor = offset + 32
        let regionEnd = cursor + Int(cmdBytes)

        guard regionEnd <= raw.count else {
            throw MachOError.malformedLoadCommands("sizeofcmds 超出文件长度")
        }

        for index in 0..<Int(cmdCount) {
            guard let cmd = reader.u32(at: cursor),
                  let size = reader.u32(at: cursor + 4)
            else {
                throw MachOError.malformedLoadCommands("第 \(index) 条命令头部被截断")
            }
            let cmdSize = Int(size)
            // Every load command must be 8-byte aligned and at least 8 bytes.
            guard cmdSize >= 8, cursor + cmdSize <= regionEnd else {
                throw MachOError.malformedLoadCommands(
                    "第 \(index) 条命令长度非法（\(cmdSize) 字节）")
            }
            entries.append(MachOLoadCommandEntry(cmd: cmd, range: cursor..<(cursor + cmdSize)))
            cursor += cmdSize
        }

        self.data = raw
        self.sliceOffset = offset
        self.isFat = fat
        self.fileType = ftype
        self.loadCommands = entries
        self.ncmds = cmdCount
        self.sizeofcmds = cmdBytes
    }

    // MARK: - Fat slice resolution

    /// Walks a universal binary's architecture table and returns the byte
    /// offset of the arm64 slice.
    ///
    /// `fat_header` is big-endian:
    ///   0  magic     4
    ///   4  nfat_arch 4
    /// then `nfat_arch` × `fat_arch` (20 bytes) or `fat_arch_64` (32 bytes):
    ///   0  cputype    4
    ///   4  cpusubtype 4
    ///   8  offset     4 (or 8 for fat_arch_64, 8-byte aligned)
    ///   ...
    private static func locateArm64Slice(in data: Data, is64: Bool) throws -> Int {
        let reader = ByteReader(data)
        guard let count = reader.u32BE(at: 4) else { throw MachOError.truncatedHeader }

        let archStride = is64 ? 32 : 20
        // fat_arch_64 inserts 4 bytes of padding after cpusubtype so that the
        // 64-bit offset field stays 8-byte aligned.
        let offsetField = is64 ? 16 : 8

        for index in 0..<Int(count) {
            let base = 8 + index * archStride
            guard let cpuType = reader.u32BE(at: base),
                  let sliceOffset = reader.u32BE(at: base + offsetField)
            else {
                throw MachOError.malformedLoadCommands("fat_arch 表被截断")
            }
            if cpuType == MachOCPUType.arm64 || cpuType == MachOCPUType.arm64_32 {
                guard Int(sliceOffset) < data.count else {
                    throw MachOError.malformedLoadCommands("arm64 切片偏移越界")
                }
                return Int(sliceOffset)
            }
        }
        throw MachOError.noArm64Slice
    }

    // MARK: - Queries

    var fileTypeDescription: String {
        switch fileType {
        case MachOFileType.execute: return "MH_EXECUTE（可执行文件）"
        case MachOFileType.dylib: return "MH_DYLIB（动态库）"
        case MachOFileType.bundle: return "MH_BUNDLE（插件包）"
        case MachOFileType.object: return "MH_OBJECT（目标文件）"
        case MachOFileType.core: return "MH_CORE（核心转储）"
        default: return String(format: "未知类型 0x%X", fileType)
        }
    }

    /// Locates the `__PAGEZERO` segment.
    ///
    /// `segment_command_64` layout:
    ///   0  cmd            4
    ///   4  cmdsize        4
    ///   8  segname       16
    ///  24  vmaddr         8
    ///  32  vmsize         8
    ///  40  fileoff        8
    ///  48  filesize       8
    func pageZeroSegment() -> PageZeroSegment? {
        let reader = ByteReader(data)
        for entry in loadCommands where entry.cmd == MachOLoadCommand.segment64 {
            let base = entry.range.lowerBound
            guard let name = reader.cString(at: base + 8, maxLength: 16) else { continue }
            guard name == "__PAGEZERO" else { continue }
            guard let vmaddr = reader.u64(at: base + 24),
                  let vmsize = reader.u64(at: base + 32)
            else { continue }
            return PageZeroSegment(commandOffset: base, vmAddress: vmaddr, vmSize: vmsize)
        }
        return nil
    }

    /// The names of every segment in the arm64 slice, in load-command order.
    func segmentNames() -> [String] {
        let reader = ByteReader(data)
        var names: [String] = []
        for entry in loadCommands where entry.cmd == MachOLoadCommand.segment64 {
            if let name = reader.cString(at: entry.range.lowerBound + 8, maxLength: 16) {
                names.append(name)
            }
        }
        return names
    }

    /// The file paths of every dylib this binary links against.
    func linkedDylibs() -> [String] {
        let reader = ByteReader(data)
        var paths: [String] = []
        let dylibCommands: Set<UInt32> = [
            MachOLoadCommand.loadDylib,
            MachOLoadCommand.loadWeakDylib,
            MachOLoadCommand.reexportDylib,
            MachOLoadCommand.lazyLoadDylib,
            MachOLoadCommand.idDylib,
        ]
        for entry in loadCommands where dylibCommands.contains(entry.cmd) {
            // dylib_command: cmd(4) cmdsize(4) name_offset(4) ...
            guard let nameOffset = reader.u32(at: entry.range.lowerBound + 8) else { continue }
            let stringStart = entry.range.lowerBound + Int(nameOffset)
            if let path = reader.cString(at: stringStart, maxLength: entry.range.count) {
                paths.append(path)
            }
        }
        return paths
    }

    /// True when the binary is already a dylib (i.e. already patched).
    var isAlreadyDylib: Bool { fileType == MachOFileType.dylib }
}
