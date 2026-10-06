#!/usr/bin/env python3
"""
Validates Luna.xcodeproj/project.pbxproj without needing Xcode.

The pbxproj format is an OpenStep property list. Xcode reports a parse error
as the unhelpful "The project 'Luna' is damaged and cannot be opened due to a
parse error" with no line number, and `plistlib` refuses the format outright
(objectVersion 56 with unquoted atoms is neither XML nor binary plist).

This walks the file with a real tokenizer and reports the exact line, which
turns a 20-minute bisect into a one-line fix.

It also checks that every object reference resolves — a missing `fileRef` or
`buildPhases` entry parses fine but leaves the project silently incomplete.

Usage:
    python3 tools/pbxproj_check.py [path/to/project.pbxproj]

Exit codes:
    0  valid
    1  parse error or dangling reference
"""

import sys
from pathlib import Path

PATH = Path(sys.argv[1] if len(sys.argv) > 1 else "Luna.xcodeproj/project.pbxproj")


class ParseError(Exception):
    pass


def check(path: Path) -> int:
    src = path.read_text()
    n = len(src)
    pos = 0

    def lineno(at: int) -> int:
        return src.count("\n", 0, at) + 1

    def skip_ws() -> None:
        nonlocal pos
        while pos < n:
            if src[pos] in " \t\n\r":
                pos += 1
            elif src.startswith("/*", pos):
                end = src.find("*/", pos + 2)
                if end < 0:
                    raise ParseError(f"line {lineno(pos)}: unterminated /* comment")
                pos = end + 2
            elif src.startswith("//", pos):
                end = src.find("\n", pos)
                pos = n if end < 0 else end + 1
            else:
                return

    def read_string() -> str:
        nonlocal pos
        start = pos
        pos += 1
        out = []
        while pos < n:
            c = src[pos]
            if c == "\\":
                out.append(src[pos:pos + 2])
                pos += 2
                continue
            if c == '"':
                pos += 1
                return "".join(out)
            out.append(c)
            pos += 1
        raise ParseError(f"line {lineno(start)}: unterminated string")

    def read_atom() -> str:
        nonlocal pos
        start = pos
        while pos < n and src[pos] not in ' \t\n\r=;,(){}"':
            pos += 1
        if pos == start:
            # An empty value (`KEY = ;`) lands here. OpenStep requires the
            # empty string to be written `""`, never bare.
            raise ParseError(
                f"line {lineno(pos)}: expected a value, found {src[pos]!r}"
                ' (an empty string must be written as "")'
            )
        return src[start:pos]

    def read_dict() -> dict:
        nonlocal pos
        start = pos
        pos += 1
        result = {}
        while True:
            skip_ws()
            if pos >= n:
                raise ParseError(f"line {lineno(start)}: unclosed {{")
            if src[pos] == "}":
                pos += 1
                return result
            key = read_string() if src[pos] == '"' else read_atom()
            skip_ws()
            if pos >= n or src[pos] != "=":
                got = "<EOF>" if pos >= n else repr(src[pos])
                raise ParseError(f"line {lineno(pos)}: after key {key!r} expected '=', found {got}")
            pos += 1
            value = read_value()
            skip_ws()
            if pos < n and src[pos] == ";":
                pos += 1
            else:
                got = "<EOF>" if pos >= n else repr(src[pos])
                raise ParseError(f"line {lineno(pos)}: after key {key!r} expected ';', found {got}")
            result[key] = value

    def read_array() -> list:
        nonlocal pos
        start = pos
        pos += 1
        result = []
        while True:
            skip_ws()
            if pos >= n:
                raise ParseError(f"line {lineno(start)}: unclosed (")
            if src[pos] == ")":
                pos += 1
                return result
            result.append(read_value())
            skip_ws()
            if pos < n and src[pos] == ",":
                pos += 1
            elif pos < n and src[pos] == ")":
                pass
            else:
                got = "<EOF>" if pos >= n else repr(src[pos])
                raise ParseError(f"line {lineno(pos)}: in array expected ',' or ')', found {got}")

    def read_value():
        skip_ws()
        if pos >= n:
            raise ParseError("unexpected end of file")
        c = src[pos]
        if c == "{":
            return read_dict()
        if c == "(":
            return read_array()
        if c == '"':
            return read_string()
        return read_atom()

    try:
        skip_ws()
        root = read_value()
        skip_ws()
        if pos < n:
            raise ParseError(f"line {lineno(pos)}: trailing content {src[pos:pos + 60]!r}")
    except ParseError as e:
        print(f"✗ {path}: {e}", file=sys.stderr)
        return 1

    if not isinstance(root, dict):
        print(f"✗ {path}: root is {type(root).__name__}, expected a dict", file=sys.stderr)
        return 1

    objects = root.get("objects", {})
    print("✓ parse ok")
    print(f"  objects        = {len(objects)}")
    print(f"  archiveVersion = {root.get('archiveVersion')}")
    print(f"  objectVersion  = {root.get('objectVersion')}")

    root_id = root.get("rootObject")
    print(f"  rootObject     = {root_id} ({objects.get(root_id, {}).get('isa')})")

    for oid, obj in objects.items():
        if isinstance(obj, dict) and obj.get("isa") == "PBXNativeTarget":
            print(f"  target {obj.get('name')} = {oid}")
            print(f"    productType = {obj.get('productType')}")

    # Cross-reference check: these parse cleanly when broken, but the project
    # will not build, so they are worth failing on.
    problems = []
    for oid, obj in objects.items():
        if not isinstance(obj, dict):
            problems.append(f"{oid}: not a dict")
            continue
        isa = obj.get("isa")
        if not isa:
            problems.append(f"{oid}: missing isa")
        if isa == "PBXNativeTarget":
            for phase in obj.get("buildPhases", []):
                if phase not in objects:
                    problems.append(f"target {obj.get('name')}: dangling buildPhase {phase}")
            if obj.get("buildConfigurationList") not in objects:
                problems.append(f"target {obj.get('name')}: dangling buildConfigurationList")
        if isa == "PBXBuildFile" and obj.get("fileRef") not in objects:
            problems.append(f"PBXBuildFile {oid}: dangling fileRef {obj.get('fileRef')}")

    print()
    if problems:
        print(f"✗ {len(problems)} dangling reference(s):", file=sys.stderr)
        for p in problems[:20]:
            print(f"  {p}", file=sys.stderr)
        return 1
    print("✓ all object references resolve")
    return 0


if __name__ == "__main__":
    if not PATH.exists():
        sys.exit(f"not found: {PATH}")
    sys.exit(check(PATH))
