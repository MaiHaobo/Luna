#!/usr/bin/env python3
"""Verify that every PBXFileReference in the project resolves to a real file on disk.

Why this exists
---------------
`tools/pbxproj_check.py` verifies that object references resolve — that every id
mentioned in a `children`, `files`, or `buildPhases` list actually exists as an
object. It does *not* verify that the concatenated path lands on a file.

That blind spot cost us a CI cycle. `CertificateListView.swift` was registered
under the `AppLibrary` group while living in `Features/Import/` on disk. Since a
PBXFileReference's `path` is relative to its *enclosing group*, Xcode resolved it
to `Features/AppLibrary/CertificateListView.swift` — a file that has never
existed. All eleven static checks passed; the build died at step 12 with:

    error: Build input file cannot be found: '.../Features/AppLibrary/CertificateListView.swift'

This script closes that gap. It walks the group tree from the main group,
accumulating each group's `path` (and honouring `sourceTree`), then asserts that
every file reference it reaches actually exists.

Rules it encodes
----------------
* A group with no `path` contributes nothing — it is a virtual grouping, which is
  how `AppLibrary`-style folders-in-name-only are expressed.
* `sourceTree = "<group>"` (the default for files) means "relative to the parent
  group", so the accumulated prefix applies.
* `sourceTree = SOURCE_ROOT` means "relative to the project directory", so the
  accumulated prefix is *discarded*.
* `sourceTree = "<absolute>"` carries its own absolute path; nothing is prefixed.
* `BUILT_PRODUCTS_DIR` / `SDKROOT` / `DEVELOPER_DIR` references are not files in
  the repository, so they are skipped rather than reported.

Exit code is 0 when every reference resolves, 1 otherwise.
"""

from __future__ import annotations

import os
import re
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PBXPROJ = os.path.join(PROJECT_DIR, "Luna.xcodeproj", "project.pbxproj")

# sourceTrees whose targets live outside the repository.
EXTERNAL_SOURCE_TREES = {
    "BUILT_PRODUCTS_DIR",
    "SDKROOT",
    "DEVELOPER_DIR",
}

failures: list[str] = []
checked = 0


def fail(message: str) -> None:
    failures.append(message)


def parse_sections(text: str) -> dict[str, str]:
    """Split the pbxproj into its `/* Begin X section */ … /* End X section */` blocks."""
    sections: dict[str, str] = {}
    for name, body in re.findall(
        r"/\* Begin (\w+) section \*/(.*?)/\* End \1 section \*/", text, re.S
    ):
        sections[name] = body
    return sections


def parse_objects(body: str) -> dict[str, str]:
    """Map each 24-hex object id to its object body inside a section.

    Indentation in a pbxproj climbs with nesting depth, so the per-object indent
    is *not* fixed — object declarations sit at different columns depending on how
    deep in the tree they are.

    We cannot just regex `= \\{(.*?)^\\s*\\};` because an object body contains
    *nested* brace groups of its own (e.g. `PBXProject.attributes` and
    `TargetAttributes`), and a non-greedy match would stop at the first `};`,
    truncating the body before fields like `mainGroup` that come afterwards.

    So we locate each object's opening line, then find its matching close by
    tracking brace depth line by line.
    """
    objects: dict[str, str] = {}
    lines = body.splitlines()

    index = 0
    while index < len(lines):
        opening = re.match(r"^[ \t]*([0-9A-F]{24})\b", lines[index])
        if not opening:
            index += 1
            continue

        object_id = opening.group(1)
        # A one-line value (`ID = "x";`) rather than a brace body.
        if "{" not in lines[index]:
            if ";" in lines[index]:
                objects[object_id] = lines[index].split("=", 1)[1].rstrip(";").strip()
            index += 1
            continue

        depth = lines[index].count("{") - lines[index].count("}")
        collected = [lines[index]]
        index += 1
        while index < len(lines) and depth > 0:
            depth += lines[index].count("{") - lines[index].count("}")
            collected.append(lines[index])
            index += 1
        objects[object_id] = "\n".join(collected)
    return objects


def field(body: str, name: str) -> str | None:
    match = re.search(rf"\b{name} = ([^;\n]+);", body)
    return match.group(1).strip() if match else None


def children_of(body: str) -> list[str]:
    match = re.search(r"children = \((.*?)\);", body, re.S)
    if not match:
        return []
    return re.findall(r"([0-9A-F]{24})", match.group(1))


def child_name(body: str, child_id: str) -> str:
    match = re.search(rf"{child_id} /\* (.*?) \*/", body)
    return match.group(1) if match else "?"


def walk(
    object_id: str,
    prefix: str,
    objects: dict[str, str],
    group_bodies: dict[str, str],
    names: dict[str, str],
) -> None:
    """Recurse the group tree, resolving every file reference to a disk path."""
    global checked
    body = objects.get(object_id)
    if body is None:
        fail(f"{names.get(object_id, object_id)}: object {object_id} is referenced but never defined")
        return

    isa = field(body, "isa")
    path = field(body, "path")

    if isa == "PBXGroup" or isa == "PBXVariantGroup":
        # A virtual group with no `path` contributes no path segment.
        here = ""
        if path:
            path = path.strip('"')
            here = os.path.join(prefix, path)
        for child_id in children_of(body):
            walk(child_id, here, objects, group_bodies, names)
        return

    if isa != "PBXFileReference":
        # Unknown leaf; not our business here.
        return

    source_tree = field(body, "sourceTree") or '"<group>"'
    source_tree = source_tree.strip('"')
    if source_tree in EXTERNAL_SOURCE_TREES:
        return

    if path is None:
        fail(f"{names.get(object_id, object_id)}: file reference has no `path`")
        return
    path = path.strip('"')

    if source_tree == "<absolute>":
        resolved = path
    elif source_tree == "SOURCE_ROOT":
        resolved = os.path.join(PROJECT_DIR, path)
    else:  # "<group>" and anything else we treat as group-relative
        resolved = os.path.join(PROJECT_DIR, prefix, path)

    checked += 1
    if not os.path.exists(resolved):
        relative = os.path.relpath(resolved, PROJECT_DIR)
        fail(
            f"{names.get(object_id, object_id)}\n"
            f"      group resolves to : {relative}\n"
            f"      this file does not exist on disk"
        )


def main() -> int:
    with open(PBXPROJ, encoding="utf-8") as handle:
        text = handle.read()

    sections = parse_sections(text)
    root_match = re.search(r"rootObject = ([0-9A-F]{24})", text)
    if not root_match:
        print("could not find rootObject in project.pbxproj")
        return 1
    root_id = root_match.group(1)

    objects: dict[str, str] = {}
    for section in ("PBXGroup", "PBXFileReference", "PBXVariantGroup"):
        objects.update(parse_objects(sections.get(section, "")))

    # The main group is the single group the project object points at.
    project_body = parse_objects(sections.get("PBXProject", "")).get(root_id, "")
    main_group = field(project_body, "mainGroup")
    if not main_group:
        # Fall back: the one group with no `name`/`path` that has children.
        print("could not find mainGroup on the project object")
        return 1

    names = {match.group(1): match.group(2) for match in re.finditer(r"([0-9A-F]{24}) /\* (.*?) \*/", text)}

    walk(main_group, "", objects, objects, names)

    print(f"checked {checked} file references")
    if failures:
        print()
        print(f"{len(failures)} file reference(s) do not resolve to a file on disk:")
        print()
        for failure in failures:
            print(f"  - {failure}")
        print()
        print("A PBXFileReference `path` is relative to its enclosing group.")
        print("Move the file to where the group points, or move the entry to the group")
        print("that matches where the file actually lives.")
        return 1

    print("every file reference resolves to a real file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
