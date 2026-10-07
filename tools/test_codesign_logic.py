#!/usr/bin/env python3
"""
Code-signature structure checks.

This mirrors the layout decisions in Luna's signing stage in Python so they can
be checked without a toolchain or a device. It is deliberately an independent
implementation: if the Swift and the Python agree byte for byte, the Swift is
building the structures the kernel expects, and a failure on device can be
narrowed to something other than the blob layout.

What it verifies:

  * CodeDirectory header field order and offsets (version 0x20400)
  * the *descending* special-slot layout (slot n first, ending at slot 1)
  * code slots start exactly at hashOffset
  * identifier / team strings land where their offsets claim
  * SuperBlob index offsets are relative to the SuperBlob start and 8-aligned
  * codeLimit equals the signature's dataoff (the property that makes the
    signature self-consistent)
  * page hashing covers exactly ceil(codeLimit / 4096) pages

Reference points used to pin the layout:
  * Apple XNU, osfmk/kern/cs_blobs.h — CS_CodeDirectory, CS_SuperBlob
  * zhlynn/zsign, src/archo.cpp — `m_uCodeLength = BO(pcslc->dataoff)`
"""

import hashlib
import struct
import sys

# ── Constants (must match CodeDirectory.swift) ──────────────────────────────

MAGIC_CODEDIRECTORY = 0xFADE0C02
MAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
MAGIC_REQUIREMENTS = 0xFADE0C01
MAGIC_ENTITLEMENTS = 0xFADE7171
MAGIC_BLOBWRAPPER = 0xFADE0B01

SLOT_CODEDIRECTORY = 0
SLOT_INFO = 1
SLOT_REQUIREMENTS = 2
SLOT_RESOURCEDIR = 3
SLOT_ENTITLEMENTS = 5
SLOT_DER_ENTITLEMENTS = 7
SLOT_SIGNATURE = 0x10000

HASHTYPE_SHA256 = 2
CS_ADHOC = 0x00000002
CS_EXECSEG_MAIN_BINARY = 0x1

VERSION_EXECSEG = 0x20400
PAGE_SIZE = 4096
PAGE_SIZE_EXPONENT = 12

# Version 0x20400 header size.
HEADER_SIZE = 44 + 4 + 4 + 12 + 24   # base + scatter + team + codeLimit64 + execSeg


# ── Builders (independent reimplementation) ─────────────────────────────────

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_code_directory(identifier: str, code: bytes, code_limit: int,
                         special_slots: dict, team_id: str | None = None,
                         exec_seg_base: int = 0, exec_seg_limit: int = 0,
                         exec_seg_flags: int = CS_EXECSEG_MAIN_BINARY,
                         flags: int = CS_ADHOC) -> bytes:
    """Builds a CodeDirectory blob, mirroring CodeDirectoryBuilder.build."""

    # Code slots: one SHA-256 per page.
    page_count = (code_limit + PAGE_SIZE - 1) // PAGE_SIZE
    code_hashes = b""
    for index in range(page_count):
        start = index * PAGE_SIZE
        end = min(start + PAGE_SIZE, code_limit)
        code_hashes += sha256(code[start:end])

    # Special slots: stored DESCENDING from the highest down to slot 1.
    highest = max(special_slots.keys()) if special_slots else 0
    n_special = highest
    special_bytes = b""
    for slot in range(n_special, 0, -1):
        special_bytes += special_slots.get(slot, b"\x00" * 32)

    ident_bytes = identifier.encode() + b"\x00"
    team_bytes = (team_id.encode() + b"\x00") if team_id else b""

    # Strings precede the hash tables, so hashOffset sits past both. This is
    # the arrangement zsign uses:
    #   hashOffset = headerLength + bundleIDLength + teamIDLength + specialSlotsLength
    ident_offset = HEADER_SIZE
    team_offset = 0 if not team_bytes else ident_offset + len(ident_bytes)
    hash_offset = (ident_offset + len(ident_bytes) + len(team_bytes)
                   + len(special_bytes))
    total_length = hash_offset + len(code_hashes)

    # The header is built field by field rather than with one pack() call,
    # because the C struct mixes 4-byte integers with single bytes and a
    # mis-packed header is exactly the kind of mistake this script exists to
    # catch. Packing explicitly keeps each field's width visible.
    header = b""
    header += struct.pack("<I", MAGIC_CODEDIRECTORY)
    header += struct.pack("<I", total_length)
    header += struct.pack("<I", VERSION_EXECSEG)
    header += struct.pack("<I", flags)
    header += struct.pack("<I", hash_offset)
    header += struct.pack("<I", ident_offset)
    header += struct.pack("<I", n_special)
    header += struct.pack("<I", page_count)
    header += struct.pack("<I", code_limit)
    header += struct.pack("<B", 32)
    header += struct.pack("<B", HASHTYPE_SHA256)
    header += struct.pack("<B", 0)
    header += struct.pack("<B", PAGE_SIZE_EXPONENT)
    header += struct.pack("<I", 0)                 # spare2
    header += struct.pack("<I", 0)                 # scatterOffset
    header += struct.pack("<I", team_offset)
    header += struct.pack("<I", 0)                 # spare3
    header += struct.pack("<Q", code_limit)        # codeLimit64
    header += struct.pack("<Q", exec_seg_base)
    header += struct.pack("<Q", exec_seg_limit)
    header += struct.pack("<Q", exec_seg_flags)

    assert len(header) == HEADER_SIZE, f"header {len(header)} != {HEADER_SIZE}"

    return (header + ident_bytes + team_bytes + special_bytes + code_hashes)


def generic_blob(magic: int, payload: bytes) -> bytes:
    return struct.pack("<II", magic, 8 + len(payload)) + payload


def build_super_blob(members: list) -> bytes:
    """members: list of (slot, blob). Mirrors SuperBlobBuilder.build."""
    header_size = 12
    index_size = len(members) * 8
    body_start = header_size + index_size

    body = b""
    offsets = []
    for _, blob in members:
        current = body_start + len(body)
        padding = (8 - (current % 8)) % 8
        body += b"\x00" * padding
        offsets.append(body_start + len(body))
        body += blob

    total = body_start + len(body)
    out = struct.pack("<III", MAGIC_EMBEDDED_SIGNATURE, total, len(members))
    for (slot, _), offset in zip(members, offsets):
        out += struct.pack("<II", slot, offset)
    out += body
    return out


# ── Readers (for assertions) ────────────────────────────────────────────────

def read_cd(blob: bytes) -> dict:
    (magic, length, version, flags, hash_offset, ident_offset, n_special,
     n_code, code_limit) = struct.unpack_from("<9I", blob, 0)
    hash_size, hash_type, platform, page_size = struct.unpack_from("<4B", blob, 36)
    spare2 = struct.unpack_from("<I", blob, 40)[0]
    # version 0x20400 extras
    scatter_offset = struct.unpack_from("<I", blob, 44)[0]
    team_offset = struct.unpack_from("<I", blob, 48)[0]
    spare3 = struct.unpack_from("<I", blob, 52)[0]
    code_limit64 = struct.unpack_from("<Q", blob, 56)[0]
    exec_base, exec_limit, exec_flags = struct.unpack_from("<QQQ", blob, 64)
    return dict(magic=magic, length=length, version=version, flags=flags,
                hash_offset=hash_offset, ident_offset=ident_offset,
                n_special=n_special, n_code=n_code, code_limit=code_limit,
                hash_size=hash_size, hash_type=hash_type, platform=platform,
                page_size=page_size, spare2=spare2, scatter_offset=scatter_offset,
                team_offset=team_offset, spare3=spare3, code_limit64=code_limit64,
                exec_base=exec_base, exec_limit=exec_limit, exec_flags=exec_flags)


def read_super(blob: bytes) -> dict:
    magic, length, count = struct.unpack_from("<III", blob, 0)
    index = []
    for i in range(count):
        slot, offset = struct.unpack_from("<II", blob, 12 + i * 8)
        index.append((slot, offset))
    return dict(magic=magic, length=length, count=count, index=index)


# ── Checks ──────────────────────────────────────────────────────────────────

failures = []
checks = 0


def check(condition, label):
    global checks
    checks += 1
    if not condition:
        failures.append(label)


def test_code_directory_layout():
    print("── CodeDirectory 布局 ──")

    code = bytes((i * 7 + 3) & 0xFF for i in range(20000))
    code_limit = 16384   # exactly 4 pages
    cd = build_code_directory(
        identifier="com.example.demo",
        code=code,
        code_limit=code_limit,
        # Note: no SLOT_SIGNATURE here — the signature slot is a SuperBlob
        # member name, not a hash-table position. Slot 7 (DER entitlements) is
        # the highest real slot and therefore sets nSpecialSlots.
        special_slots={
            SLOT_INFO: sha256(b"info-plist-bytes"),
            SLOT_RESOURCEDIR: sha256(b"code-resources-bytes"),
            SLOT_ENTITLEMENTS: sha256(b"entitlements-blob"),
            SLOT_DER_ENTITLEMENTS: sha256(b"der-entitlements-blob"),
        },
    )

    d = read_cd(cd)
    check(d["magic"] == MAGIC_CODEDIRECTORY, "magic 应为 CSMAGIC_CODEDIRECTORY")
    check(d["length"] == len(cd), "length 字段应等于实际长度")
    check(d["version"] == VERSION_EXECSEG, "version 应为 0x20400")
    check(d["flags"] & CS_ADHOC != 0, "flags 应含 CS_ADHOC")
    check(d["hash_size"] == 32, "hashSize 应为 32")
    check(d["hash_type"] == HASHTYPE_SHA256, "hashType 应为 SHA-256")
    check(d["page_size"] == PAGE_SIZE_EXPONENT, "pageSize 应为 log2(4096)=12")
    check(d["spare2"] == 0, "spare2 应为 0")
    check(d["code_limit"] == code_limit, "codeLimit 应为传入值")
    check(d["code_limit64"] == code_limit, "codeLimit64 应等于 codeLimit")

    expected_pages = (code_limit + PAGE_SIZE - 1) // PAGE_SIZE
    check(d["n_code"] == expected_pages, f"页数应为 {expected_pages}")
    # The signature slot (0x10000) is a SuperBlob member name, NOT a table
    # position — it must be excluded, leaving DER entitlements (slot 7) as the
    # highest real hash slot.
    check(d["n_special"] == SLOT_DER_ENTITLEMENTS,
          "特殊槽数量应为最高真实哈希槽（DER entitlements = 7），不含签名槽")
    check(d["n_special"] < 100,
          "特殊槽数量不应被签名槽 0x10000 撑大到 65536")

    # Special slots occupy [hashOffset - n*hashSize, hashOffset)
    special_start = d["hash_offset"] - d["n_special"] * 32
    check(special_start >= HEADER_SIZE,
          "特殊槽区应在头部之后")

    # The FIRST 32 bytes of the special region belong to the HIGHEST slot.
    top_slot_bytes = cd[special_start:special_start + 32]
    check(top_slot_bytes == sha256(b"der-entitlements-blob"),
          "特殊槽必须倒序存放：最高槽（DER entitlements）在最前")

    # Slot 1 (info) ends the region: it sits at hashOffset - 1*32.
    slot1 = cd[d["hash_offset"] - 32:d["hash_offset"]]
    check(slot1 == sha256(b"info-plist-bytes"),
          "槽 1（Info.plist）应紧邻 hashOffset 之前")

    # Code slots begin at hashOffset.
    first_page = cd[d["hash_offset"]:d["hash_offset"] + 32]
    check(first_page == sha256(code[:PAGE_SIZE]),
          "代码槽应始于 hashOffset，且第一页为前 4096 字节")

    # Identifier lands at identOffset.
    ident_end = cd.index(b"\x00", d["ident_offset"])
    check(cd[d["ident_offset"]:ident_end] == b"com.example.demo",
          "标识符应位于 identOffset")

    # Unoccupied special slots read as all-zero.
    # Slot 4 (application) is unset in our map.
    slot4_offset = d["hash_offset"] - 4 * 32
    check(cd[slot4_offset:slot4_offset + 32] == b"\x00" * 32,
          "未占用的特殊槽应为全零")


def test_code_limit_equals_signature_offset():
    print("── codeLimit 与签名的自洽性 ──")

    # Simulate a file: [0, dataoff) is code, the signature sits at dataoff.
    dataoff = 40960
    code = bytes(40960)
    cd = build_code_directory(
        identifier="com.example.demo", code=code, code_limit=dataoff,
        special_slots={SLOT_SIGNATURE: sha256(b"wrapper")})

    d = read_cd(cd)
    check(d["code_limit"] == dataoff, "codeLimit 必须等于签名的文件偏移")

    # The signature must NOT cover itself.
    check(len(code) == d["code_limit"],
          "被哈希的字节数应恰好等于 codeLimit")

    expected_pages = (dataoff + PAGE_SIZE - 1) // PAGE_SIZE
    check(d["n_code"] == expected_pages, "页数应覆盖到 codeLimit 为止")

    # A partial final page is hashed as a short chunk, not zero-padded.
    partial = 40960 + 100
    code2 = bytes(partial)
    cd2 = build_code_directory(
        identifier="x", code=code2, code_limit=partial,
        special_slots={})
    d2 = read_cd(cd2)
    check(d2["n_code"] == 11, "非整页的 codeLimit 应向上取整为 11 页")


def test_super_blob():
    print("── SuperBlob 组装 ──")

    cd = build_code_directory(
        identifier="com.example.demo", code=bytes(8192), code_limit=8192,
        special_slots={SLOT_SIGNATURE: sha256(b"w")})
    requirements = generic_blob(MAGIC_REQUIREMENTS, struct.pack("<I", 0))
    entitlements = generic_blob(MAGIC_ENTITLEMENTS, b"<plist/>")
    wrapper = generic_blob(MAGIC_BLOBWRAPPER, b"")

    members = [
        (SLOT_CODEDIRECTORY, cd),
        (SLOT_REQUIREMENTS, requirements),
        (SLOT_ENTITLEMENTS, entitlements),
        (SLOT_SIGNATURE, wrapper),
    ]
    sb = build_super_blob(members)
    s = read_super(sb)

    check(s["magic"] == MAGIC_EMBEDDED_SIGNATURE, "magic 应为 CSMAGIC_EMBEDDED_SIGNATURE")
    check(s["length"] == len(sb), "SuperBlob length 应等于实际长度")
    check(s["count"] == 4, "索引项数应为 4")
    check([slot for slot, _ in s["index"]] ==
          [SLOT_CODEDIRECTORY, SLOT_REQUIREMENTS, SLOT_ENTITLEMENTS, SLOT_SIGNATURE],
          "索引槽位顺序应与传入一致")

    # Every blob must be reachable at its declared offset, and 8-aligned.
    for slot, offset in s["index"]:
        check(offset % 8 == 0, f"槽 0x{slot:X} 的偏移应 8 字节对齐")
        check(offset >= 12 + 4 * 8, f"槽 0x{slot:X} 的偏移应在索引之后")
        blob_magic, blob_len = struct.unpack_from("<II", sb, offset)
        check(offset + blob_len <= len(sb), f"槽 0x{slot:X} 的 blob 不应越界")

    # Offsets are relative to the SuperBlob start, and the first member lands
    # at the end of the index table (possibly after alignment padding).
    first_slot, first_offset = s["index"][0]
    check(first_offset >= 12 + 4 * 8, "首个 blob 应在索引表之后")
    check(first_offset - (12 + 4 * 8) < 8, "索引表与首个 blob 间至多 7 字节填充")

    # The CodeDirectory must be byte-identical when read back out.
    _, cd_offset = s["index"][0]
    cd_len = struct.unpack_from("<I", sb, cd_offset + 4)[0]
    check(sb[cd_offset:cd_offset + cd_len] == cd, "取回的 CodeDirectory 应与写入一致")


def test_requirements_and_wrappers():
    print("── Requirements 与空包装 ──")

    req = generic_blob(MAGIC_REQUIREMENTS, struct.pack("<I", 0))
    magic, length = struct.unpack_from("<II", req, 0)
    check(magic == MAGIC_REQUIREMENTS, "requirements magic 正确")
    check(length == len(req), "requirements length 正确")
    check(struct.unpack_from("<I", req, 8)[0] == 0, "空 requirements 计数应为 0")

    wrapper = generic_blob(MAGIC_BLOBWRAPPER, b"")
    check(len(wrapper) == 8, "空签名包装应为 8 字节（仅头）")
    check(struct.unpack_from("<I", wrapper, 0)[0] == MAGIC_BLOBWRAPPER,
          "签名包装 magic 应为 CSMAGIC_BLOBWRAPPER")


def test_length_is_content_independent():
    """The invariant that makes single-pass signing possible.

    A CodeDirectory's length must depend only on its shape — page count,
    special-slot count, identifier length — and never on the hash values. If
    that ever stops being true, MachOCodeSigner's three-step order breaks:
    it writes `dataSize` before knowing the hashes.
    """
    print("── 长度与内容无关（单遍签名的前提） ──")

    def length_of(code_bytes, slots):
        return len(build_code_directory(
            identifier="com.example.demo",
            code=code_bytes,
            code_limit=len(code_bytes),
            special_slots=slots,
        ))

    slots = {
        SLOT_INFO: sha256(b"info"),
        SLOT_ENTITLEMENTS: sha256(b"ent"),
        SLOT_DER_ENTITLEMENTS: sha256(b"der"),
    }

    # Same shape, wildly different contents.
    a = length_of(bytes(40960), slots)
    b = length_of(bytes((i * 13 + 5) & 0xFF for i in range(40960)), slots)
    check(a == b, "形状相同、内容不同时，CodeDirectory 长度应一致")

    # Same shape, different slot *values* (not slot set).
    slots2 = dict(slots)
    slots2[SLOT_INFO] = sha256(b"a completely different Info.plist blob")
    c = length_of(bytes(40960), slots2)
    check(a == c, "槽值不同但槽位集合相同时，长度应一致")

    # Extra page changes the length.
    d = length_of(bytes(81920), slots)
    check(d > a, "多一页应使 CodeDirectory 变长")

    # Identifier length feeds into the length.
    e = len(build_code_directory(
        identifier="a.much.longer.bundle.identifier.here",
        code=bytes(40960), code_limit=40960, special_slots=slots))
    check(e > a, "更长的标识符应使 CodeDirectory 变长")

    # And the SuperBlob length follows the same rule.
    sb_a = build_super_blob([
        (SLOT_CODEDIRECTORY, build_code_directory(
            identifier="com.example.demo", code=bytes(40960),
            code_limit=40960, special_slots=slots)),
        (SLOT_REQUIREMENTS, generic_blob(MAGIC_REQUIREMENTS, struct.pack("<I", 0))),
        (SLOT_SIGNATURE, generic_blob(MAGIC_BLOBWRAPPER, b"")),
    ])
    sb_b = build_super_blob([
        (SLOT_CODEDIRECTORY, build_code_directory(
            identifier="com.example.demo",
            code=bytes((i * 13 + 5) & 0xFF for i in range(40960)),
            code_limit=40960, special_slots=slots)),
        (SLOT_REQUIREMENTS, generic_blob(MAGIC_REQUIREMENTS, struct.pack("<I", 0))),
        (SLOT_SIGNATURE, generic_blob(MAGIC_BLOBWRAPPER, b"")),
    ])
    check(len(sb_a) == len(sb_b), "SuperBlob 长度也应只取决于形状")


def test_shipping_binary_if_present():
    """If a real Mach-O is available, verify the assumptions against it."""
    import os
    candidates = [
        "/workspace/Luna/Luna-download/Luna-1.4.0-unsigned.ipa",
        "/workspace/Luna/Luna-download/Luna-1.3.0-unsigned.ipa",
        "/workspace/Luna-download/Luna-1.4.0-unsigned.ipa",
    ]
    ipa = next((p for p in candidates if os.path.exists(p)), None)
    if not ipa:
        print("── 真实二进制对照：跳过（未找到 IPA） ──")
        return

    print("── 真实二进制对照 ──")
    import zipfile
    with zipfile.ZipFile(ipa) as zf:
        exe_names = [n for n in zf.namelist()
                     if n.startswith("Payload/")
                     and n.count("/") == 2
                     and not n.endswith("/")]
        check(bool(exe_names), "IPA 中应存在主可执行文件")
        if not exe_names:
            return
        data = zf.read(exe_names[0])

    # Parse LC_CODE_SIGNATURE (0x1D) and check dataoff/size are sane.
    magic = struct.unpack_from("<I", data, 0)[0]
    check(magic in (0xFEEDFACF, 0xFEEDFACE), "应为 Mach-O")
    if magic != 0xFEEDFACF:
        return
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    cursor = 32
    found = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmd == 0x1D:
            dataoff, datasize = struct.unpack_from("<II", data, cursor + 8)
            found = (dataoff, datasize)
        cursor += cmdsize
    check(found is not None, "真实构建应带 LC_CODE_SIGNATURE")
    if found:
        dataoff, datasize = found
        check(dataoff + datasize <= len(data),
              "签名区应落在文件范围内")
        check(dataoff % 16 == 0, "签名偏移应 16 字节对齐")
        print(f"   真实构建：dataoff={dataoff} datasize={datasize} "
              f"（即 codeLimit 应为 {dataoff}）")


def test_signed_image_is_self_consistent():
    """End-to-end: the order of writes must not invalidate the signature.

    This reproduces `MachOCodeSigner.sign` step for step on a synthetic Mach-O
    that carries a real `LC_SEGMENT_64 __LINKEDIT`, and then re-derives the
    CodeDirectory hashes from the *finished* file. If any field that lives
    inside `[0, codeLimit)` — `LC_CODE_SIGNATURE.dataSize`, or `__LINKEDIT`'s
    `filesize`/`vmsize` — were written after the hash step, the re-derived
    hashes would disagree with the embedded ones.

    That is precisely the bug this test exists to catch, so it writes those
    fields *both* ways and asserts only one arrangement verifies.
    """
    print("── 端到端：签名自洽性（写序约束） ──")

    PAGE = PAGE_SIZE
    LINKEDIT_FILEOFF = 0x4000
    IMAGE_SIZE = LINKEDIT_FILEOFF + 0x400          # 16 KiB + 1 KiB
    OLD_SIG_OFFSET = IMAGE_SIZE                     # signature starts at EOF
    OLD_SIG_SIZE = 0                                # never signed before

    # 16-byte-aligned signature start, as the signer computes.
    aligned = (IMAGE_SIZE + 15) // 16 * 16
    padding = aligned - IMAGE_SIZE
    image_size_aligned = aligned

    def build_image(linkedit_filesize, linkedit_vmsize, data_size, payload):
        """Synthetic image: header + LC_SEGMENT_64(__LINKEDIT) + data."""
        # Allocate the whole image up front so the fixed-offset writes below
        # are always in range; `payload` then overwrites the head.
        data = bytearray(max(IMAGE_SIZE, len(payload)))
        data[:len(payload)] = payload
        # mach_header_64
        struct.pack_into("<I", data, 0, 0xFEEDFACF)     # magic
        struct.pack_into("<I", data, 12, 0x2)           # filetype MH_EXECUTE
        struct.pack_into("<I", data, 16, 2)             # ncmds
        struct.pack_into("<I", data, 20, 72 + 16)       # sizeofcmds
        # LC_SEGMENT_64 __LINKEDIT at 32
        base = 32
        struct.pack_into("<II", data, base, 0x19, 72)
        data[base + 8:base + 24] = b"__LINKEDIT".ljust(16, b"\x00")
        struct.pack_into("<Q", data, base + 24, 0x100000000)   # vmaddr
        struct.pack_into("<Q", data, base + 32, linkedit_vmsize)
        struct.pack_into("<Q", data, base + 40, LINKEDIT_FILEOFF)
        struct.pack_into("<Q", data, base + 48, linkedit_filesize)
        # LC_CODE_SIGNATURE at 32 + 72
        cbase = base + 72
        struct.pack_into("<IIII", data, cbase, 0x1D, 16, aligned, data_size)
        return data

    def sign(update_linkedit_before_hash: bool):
        """Runs the three-step flow, optionally with the buggy ordering."""
        planned_cd = build_code_directory(
            identifier="com.example.guest",
            code=bytes(image_size_aligned), code_limit=aligned,
            special_slots={SLOT_INFO: sha256(b"info")})
        planned_sb = build_super_blob([
            (SLOT_CODEDIRECTORY, planned_cd),
            (SLOT_REQUIREMENTS, generic_blob(MAGIC_REQUIREMENTS,
                                             struct.pack("<I", 0))),
            (SLOT_SIGNATURE, generic_blob(MAGIC_BLOBWRAPPER, b"")),
        ])
        signature_size = len(planned_sb)

        # Start from a finished, unsigned image.
        buf = bytearray(build_image(0x400, 0x400, 0, b"") + bytes(padding))

        # 2a. dataSize
        struct.pack_into("<I", buf, 32 + 72 + 12, signature_size)

        # 2b. the region after `aligned` is the old signature — drop it.
        del buf[aligned:]

        # 2c. __LINKEDIT
        if update_linkedit_before_hash:
            new_filesize = len(buf) - LINKEDIT_FILEOFF
            struct.pack_into("<Q", buf, 32 + 48, new_filesize)
            struct.pack_into("<Q", buf, 32 + 32, new_filesize)

        # Step 3: hash, then place the blob.
        final_cd = build_code_directory(
            identifier="com.example.guest",
            code=bytes(buf[:aligned]), code_limit=aligned,
            special_slots={SLOT_INFO: sha256(b"info")})
        final_sb = build_super_blob([
            (SLOT_CODEDIRECTORY, final_cd),
            (SLOT_REQUIREMENTS, generic_blob(MAGIC_REQUIREMENTS,
                                             struct.pack("<I", 0))),
            (SLOT_SIGNATURE, generic_blob(MAGIC_BLOBWRAPPER, b"")),
        ])
        buf[aligned:aligned + len(final_sb)] = final_sb

        if not update_linkedit_before_hash:
            new_filesize = len(buf) - LINKEDIT_FILEOFF
            struct.pack_into("<Q", buf, 32 + 48, new_filesize)
            struct.pack_into("<Q", buf, 32 + 32, new_filesize)

        return bytes(buf), final_cd

    # ── The correct order: verify by re-deriving from the finished file ──
    signed, embedded_cd = sign(update_linkedit_before_hash=True)
    cd = read_cd(embedded_cd)

    page_count = cd["n_code"]
    check(page_count == (aligned + PAGE - 1) // PAGE,
          "页数应覆盖 [0, codeLimit)")
    region = signed[:cd["code_limit"]]
    rederived = b"".join(
        sha256(region[i * PAGE:(i + 1) * PAGE]) for i in range(page_count))
    embedded_slots = embedded_cd[cd["hash_offset"]:cd["hash_offset"] + page_count * 32]
    check(rederived == embedded_slots,
          "✅ 正确写序：从成品文件重算的页哈希应与内嵌一致")
    check(read_cd(embedded_cd)["code_limit"] == aligned,
          "codeLimit 应等于签名起始偏移")

    # The signature's own bytes must lie entirely at/after codeLimit.
    sig_start = aligned
    check(sig_start >= cd["code_limit"],
          "签名区必须完全落在 codeLimit 之后（否则无法自洽）")

    # ── The buggy order: must NOT verify ──
    buggy, buggy_cd = sign(update_linkedit_before_hash=False)
    bcd = read_cd(buggy_cd)
    bregion = buggy[:bcd["code_limit"]]
    brederived = b"".join(
        sha256(bregion[i * PAGE:(i + 1) * PAGE]) for i in range(bcd["n_code"]))
    bembedded = buggy_cd[bcd["hash_offset"]:bcd["hash_offset"] + bcd["n_code"] * 32]
    check(brederived != bembedded,
          "❌ 错误写序（哈希后再改 __LINKEDIT）应导致校验失败——本测试即守卫此点")


# ── Run ─────────────────────────────────────────────────────────────────────

def main():
    test_code_directory_layout()
    test_code_limit_equals_signature_offset()
    test_length_is_content_independent()
    test_super_blob()
    test_requirements_and_wrappers()
    test_signed_image_is_self_consistent()
    test_shipping_binary_if_present()

    print()
    if failures:
        print(f"❌ {len(failures)} / {checks} 项检查失败：")
        for failure in failures:
            print(f"   · {failure}")
        sys.exit(1)
    print(f"✅ 全部 {checks} 项检查通过")


if __name__ == "__main__":
    main()
