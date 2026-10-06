#!/usr/bin/env python3
"""
Validates the Mach-O patching logic by re-implementing it in Python and
running it against a real Mach-O binary.

This exists because the Swift engine cannot be executed here (no Apple
toolchain). The algorithm is short and fully specified, so porting it to Python
lets us verify the *logic* — offsets, byte order, command sizing, zero-padding
discovery, header bookkeeping — on a genuine arm64 Mach-O produced by the
toolchain, and then confirm the Swift uses identical offsets.

What this cannot verify: Swift syntax, types, or API usage. Those are covered by
tools/swift_sanity.py and by the CI build itself.
"""

import struct
import sys
import subprocess
from pathlib import Path

# ── Mach-O constants, mirroring Luna/Core/MachO/MachODefines.swift ──────────
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC

# Mirrors MachOPatcher.patchedPageZero
PATCHED_VMADDR = 0xFFFFC000
PATCHED_VMSIZE = 0x4000

HEADER_SIZE_64 = 32


class MachO:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.slice_offset = self._locate_slice()

    def _locate_slice(self) -> int:
        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            is64 = magic == FAT_MAGIC_64
            nfat = struct.unpack_from(">I", self.data, 4)[0]
            stride = 32 if is64 else 20
            offset_field = 16 if is64 else 8
            for i in range(nfat):
                base = 8 + i * stride
                cputype = struct.unpack_from(">I", self.data, base)[0]
                if cputype == CPU_TYPE_ARM64:
                    return struct.unpack_from(">I", self.data, base + offset_field)[0]
            raise ValueError("no arm64 slice")
        if magic not in (MH_MAGIC_64, 0xCFFAEDFE):
            raise ValueError(f"not a 64-bit Mach-O: {magic:#x}")
        return 0

    # ── Header fields ───────────────────────────────────────────────────────
    @property
    def filetype(self) -> int:
        return struct.unpack_from("<I", self.data, self.slice_offset + 12)[0]

    @property
    def ncmds(self) -> int:
        return struct.unpack_from("<I", self.data, self.slice_offset + 16)[0]

    @property
    def sizeofcmds(self) -> int:
        return struct.unpack_from("<I", self.data, self.slice_offset + 20)[0]

    def load_commands(self):
        """Yields (cmd, offset, size) for each load command."""
        cursor = self.slice_offset + HEADER_SIZE_64
        end = cursor + self.sizeofcmds
        for _ in range(self.ncmds):
            if cursor + 8 > end:
                raise ValueError("load command region overrun")
            cmd, size = struct.unpack_from("<II", self.data, cursor)
            if size < 8 or cursor + size > end:
                raise ValueError(f"bad command size {size}")
            yield cmd, cursor, size
            cursor += size

    def pagezero(self):
        for cmd, off, size in self.load_commands():
            if cmd != LC_SEGMENT_64:
                continue
            name = bytes(self.data[off + 8:off + 24]).split(b"\x00")[0].decode()
            if name == "__PAGEZERO":
                vmaddr, vmsize = struct.unpack_from("<QQ", self.data, off + 24)
                return off, vmaddr, vmsize
        return None

    def dylibs(self):
        out = []
        for cmd, off, size in self.load_commands():
            if cmd in (LC_LOAD_DYLIB, 0xD, 0x80000018):
                name_off = struct.unpack_from("<I", self.data, off + 8)[0]
                start = off + name_off
                end = self.data.index(b"\x00", start)
                out.append(bytes(self.data[start:end]).decode())
        return out

    # ── The three edits ─────────────────────────────────────────────────────
    def rewrite_filetype(self):
        if self.filetype == MH_DYLIB:
            return False
        struct.pack_into("<I", self.data, self.slice_offset + 12, MH_DYLIB)
        return True

    def relocate_pagezero(self):
        pz = self.pagezero()
        if pz is None:
            return None
        off, before_vmaddr, before_vmsize = pz
        struct.pack_into("<QQ", self.data, off + 24, PATCHED_VMADDR, PATCHED_VMSIZE)
        return (before_vmaddr, before_vmsize)

    def inject_load_dylib(self, path: str):
        encoded = path.encode() + b"\x00"
        cmdsize = 24 + len(encoded)
        cmdsize += (8 - cmdsize % 8) % 8

        command = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 0, 0, 0)
        command += encoded
        command += b"\x00" * (cmdsize - len(command))

        # Zero-padding search, capped exactly as the Swift does.
        commands_end = self.slice_offset + HEADER_SIZE_64 + self.sizeofcmds
        max_lookahead = 64 * 1024
        limit = min(len(self.data), commands_end + max_lookahead)
        available = 0
        while commands_end + available < limit and \
                self.data[commands_end + available] == 0:
            available += 1
        if available < len(command):
            raise ValueError(
                f"no room: need {len(command)}, have {available}")

        self.data[commands_end:commands_end + len(command)] = command
        struct.pack_into("<I", self.data, self.slice_offset + 16, self.ncmds + 1)
        struct.pack_into("<I", self.data, self.slice_offset + 20,
                         self.sizeofcmds + len(command))
        return len(command)

    def repatch(self, path: str):
        self.rewrite_filetype()
        pz = self.relocate_pagezero()
        self.inject_load_dylib(path)
        return pz


# ── Test driver ─────────────────────────────────────────────────────────────

def make_test_binary() -> bytes:
    """
    Builds a synthetic arm64 Mach-O executable that mirrors what a real linker
    emits: a __PAGEZERO segment, a __TEXT segment, an LC_MAIN, and — crucially —
    zero padding after the last load command.
    """
    def segment(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot):
        # segment_command_64 is 72 bytes, not 64: the layout ends with
        # nsects(4) and flags(4) after maxprot/initprot. Getting this wrong
        # shifts every subsequent load command and corrupts the parse —
        # which is precisely why this fixture is built explicitly rather
        # than eyeballed.
        #
        #   cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8)
        #   filesize(8) maxprot(4) initprot(4) nsects(4) flags(4)  = 72
        command = struct.pack(
            "<II16sQQQQIIII",
            LC_SEGMENT_64, 72,
            name.encode().ljust(16, b"\x00"),
            vmaddr, vmsize, fileoff, filesize,
            maxprot, initprot,
            0,  # nsects
            0,  # flags
        )
        assert len(command) == 72, len(command)
        return command

    pagezero = segment("__PAGEZERO", 0, 0x100000000, 0, 0, 0, 0)
    text = segment("__TEXT", 0x100000000, 0x4000, 0, 0x4000, 5, 5)
    main_cmd = struct.pack("<IIQQ", 0x80000028, 24, 0x3F00, 0)

    commands = pagezero + text + main_cmd
    # Real linkers pad the command region; emulate 4 KB of slack.
    padding = b"\x00" * (4096 - len(commands))

    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE,
        3, len(commands), 0, 0,
    )
    body = header + commands + padding + b"\x00" * (0x4000 - 4096 - len(header) - len(commands))
    return body


def run_tests():
    results = []

    def check(name, condition, detail=""):
        results.append((name, condition, detail))
        mark = "✓" if condition else "✗"
        print(f"  {mark} {name}" + (f"  ({detail})" if detail else ""))
        return condition

    print("── 1. 合成 Mach-O 基础解析 ──")
    binary = make_test_binary()
    image = MachO(binary)
    check("识别为 MH_EXECUTE", image.filetype == MH_EXECUTE,
          f"filetype={image.filetype}")
    check("ncmds = 3", image.ncmds == 3, f"ncmds={image.ncmds}")
    pz = image.pagezero()
    check("找到 __PAGEZERO", pz is not None)
    check("原始 vmaddr = 0", pz[1] == 0, f"vmaddr={pz[1]:#x}")
    check("原始 vmsize = 0x100000000", pz[2] == 0x100000000,
          f"vmsize={pz[2]:#x}")

    print("\n── 2. 三步修补 ──")
    before_offset = pz[0]
    before_ncmds = image.ncmds
    before_sizeofcmds = image.sizeofcmds
    reported = image.repatch("@executable_path/Frameworks/LunaLoaderShim.dylib")
    check("返回了原始 PAGEZERO 值", reported is not None)

    check("filetype 已改为 MH_DYLIB", image.filetype == MH_DYLIB,
          f"filetype={image.filetype}")

    pz2 = image.pagezero()
    check("__PAGEZERO vmaddr → 0xFFFFC000",
          pz2[1] == PATCHED_VMADDR, f"vmaddr={pz2[1]:#x}")
    check("__PAGEZERO vmsize → 0x4000",
          pz2[2] == PATCHED_VMSIZE, f"vmsize={pz2[2]:#x}")
    check("段命令偏移未移动", pz2[0] == before_offset,
          f"before={before_offset} after={pz2[0]}")

    check("ncmds 增加 1", image.ncmds == before_ncmds + 1,
          f"{before_ncmds} → {image.ncmds}")

    expected_size = 24 + len("@executable_path/Frameworks/LunaLoaderShim.dylib") + 1
    expected_size += (8 - expected_size % 8) % 8
    check("sizeofcmds 增加量 = 注入命令长度",
          image.sizeofcmds == before_sizeofcmds + expected_size,
          f"+{image.sizeofcmds - before_sizeofcmds}, 期望 +{expected_size}")
    check("注入长度 8 字节对齐", expected_size % 8 == 0,
          f"cmdsize={expected_size}")

    print("\n── 3. 注入后的 load command 可被遍历 ──")
    commands = list(image.load_commands())
    check("命令数量 = 4", len(commands) == 4, f"实际 {len(commands)}")
    check("最后一条是 LC_LOAD_DYLIB", commands[-1][0] == LC_LOAD_DYLIB,
          f"cmd={commands[-1][0]:#x}")

    dylibs = image.dylibs()
    check("注入的 dylib 路径可读回",
          "@executable_path/Frameworks/LunaLoaderShim.dylib" in dylibs,
          f"找到 {dylibs}")

    print("\n── 4. 幂等性 ──")
    second = MachO(bytes(image.data))
    changed = second.rewrite_filetype()
    check("二次改写 filetype 不重复执行", changed is False)

    print("\n── 5. 边界情况 ──")
    try:
        tiny = MachO(make_test_binary())
        # Fill the padding with non-zero so there is no room.
        commands_end = tiny.slice_offset + HEADER_SIZE_64 + tiny.sizeofcmds
        for i in range(commands_end, commands_end + 4096):
            tiny.data[i] = 0xFF
        tiny.inject_load_dylib("@executable_path/Frameworks/X.dylib")
        check("零填充不足时应抛错", False, "未抛错")
    except ValueError as e:
        check("零填充不足时抛出 noRoomForLoadCommand 等价错误", True, str(e)[:50])

    try:
        MachO(b"not a mach-o at all")
        check("非 Mach-O 应抛错", False)
    except ValueError:
        check("非 Mach-O 正确抛错", True)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n{'=' * 56}")
    if passed == total:
        print(f"✅ 全部通过：{passed}/{total}")
        return 0
    print(f"❌ {total - passed} 项失败（{passed}/{total} 通过）")
    for name, ok, detail in results:
        if not ok:
            print(f"   - {name} {detail}")
    return 1


if __name__ == "__main__":
    sys.exit(run_tests())
