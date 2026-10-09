#!/usr/bin/env python3
"""
A structural Swift sanity checker.

This is not a compiler. It cannot type-check. What it *can* do is catch the
class of mistakes that actually break a build in a repo like this one, where
the code was written without a toolchain at hand:

  * unbalanced braces / parens / brackets
  * unterminated string literals (including multiline ones)
  * unterminated block comments
  * duplicate type declarations across files
  * private helpers that nothing references
  * doubled argument labels in a call (the artifact of a bad edit)

It reports findings with file:line so they can be checked by hand.
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent if len(sys.argv) < 2 else Path(sys.argv[1])
FILES = sorted(ROOT.rglob("*.swift"))

problems = []
warnings = []


def strip_noise(src: str):
    """Remove comments and string literals, preserving line structure."""
    out = []
    i = 0
    n = len(src)
    line = 1
    while i < n:
        ch = src[i]

        # Block comment
        if src.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src.startswith("/*", i):
                    depth += 1
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if src[i] == "\n":
                        line += 1
                    i += 1
            out.append(" " * 1)
            continue

        # Line comment
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
            continue

        # Multiline string
        if src.startswith('"""', i):
            i += 3
            while i < n and not src.startswith('"""', i):
                if src[i] == "\n":
                    line += 1
                    out.append("\n")
                i += 1
            i += 3
            out.append('""')
            continue

        # Line string (handle escapes; no interpolation parsing needed for balance)
        if ch == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    i += 1
                if i < n and src[i] == "\n":
                    line += 1
                    out.append("\n")
                i += 1
            i += 1
            out.append('""')
            continue

        if ch == "\n":
            line += 1
        out.append(ch)
        i += 1

    return "".join(out)


def check_balance(path: Path, src: str):
    clean = strip_noise(src)
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    line = 1
    for idx, ch in enumerate(clean):
        if ch == "\n":
            line += 1
        elif ch in "([{":
            stack.append((ch, line))
        elif ch in ")]}":
            if not stack:
                problems.append(f"{path}:{line}: 多余的 '{ch}'")
                return
            opener, oline = stack.pop()
            if opener != pairs[ch]:
                problems.append(
                    f"{path}:{line}: '{ch}' 与第 {oline} 行的 '{opener}' 不匹配")
                return
    for opener, oline in stack:
        problems.append(f"{path}:{oline}: '{opener}' 未闭合")

    # Read the source once more for raw-string problems the stripper hides.
    # A multiline literal is ambiguous to a line-based checker, so instead of
    # counting quotes we ask the stripper: if it consumed the whole file
    # without finding the closing delimiter, `strip_noise` will have dropped
    # a `"""` and the resulting brace/paren balance above would already be
    # wrong. Here we only verify the delimiters come in pairs by scanning the
    # real text and tracking state.
    in_multiline = False
    for n, l in enumerate(src.splitlines(), 1):
        occurrences = l.count('"""')
        if occurrences == 0:
            continue
        if in_multiline:
            if occurrences % 2 == 1:
                in_multiline = False
        else:
            if occurrences % 2 == 1:
                in_multiline = True
    if in_multiline:
        problems.append(f"{path}: 多行字符串 \"\"\" 未闭合")


def check_duplicate_types():
    decl = re.compile(r'^\s*(?:public |internal |private |fileprivate |final |open )*'
                      r'(class|struct|enum|protocol|actor|extension)\s+([A-Za-z_][A-Za-z0-9_]*)')
    seen = defaultdict(list)
    for path in FILES:
        for n, line in enumerate(path.read_text().splitlines(), 1):
            m = decl.match(line)
            if m:
                kind, name = m.group(1), m.group(2)
                # Extensions may legitimately repeat.
                if kind == "extension":
                    continue
                seen[name].append((kind, path, n))
    for name, occurrences in seen.items():
        kinds = {k for k, _, _ in occurrences}
        if len(occurrences) > 1 and len(kinds) == 1:
            where = ", ".join(f"{p.name}:{n}" for _, p, n in occurrences)
            problems.append(f"类型 '{name}' 重复声明于 {where}")


def check_private_helpers():
    """Flag `private` free functions / static helpers nothing references."""
    helper = re.compile(r'^\s*private\s+(?:static\s+)?func\s+([A-Za-z_][A-Za-z0-9_]*)')
    all_src = "\n".join(p.read_text() for p in FILES)
    for path in FILES:
        for n, line in enumerate(path.read_text().splitlines(), 1):
            m = helper.match(line)
            if not m:
                continue
            name = m.group(1)
            # Count usages beyond the declaration itself.
            uses = len(re.findall(r'\b' + re.escape(name) + r'\b', all_src))
            if uses <= 1:
                warnings.append(
                    f"{path}:{n}: 声明了 '{name}' 但全仓库没有其他引用")


def check_call_labels():
    """Catch `foo(a: x, a: y)` — the signature of a botched edit."""
    for path in FILES:
        text = strip_noise(path.read_text())
        for n, line in enumerate(text.splitlines(), 1):
            for call in re.finditer(r'([a-zA-Z_][A-Za-z0-9_]*)\s*\((.*)\)', line):
                args = call.group(2)
                labels = re.findall(r'(?:^|,)\s*([a-zA-Z_][A-Za-z0-9_]*)\s*:', args)
                dupes = {l for l in labels if labels.count(l) > 1}
                if dupes:
                    warnings.append(
                        f"{path}:{n}: 调用 '{call.group(1)}' 出现重复参数标签 {sorted(dupes)}")


def check_ambiguous_trailing_closures():
    """Catch `Section { … } header: { … }` where the content ends in a bare `if`.

    `Section { content } header: { … } footer: { … }` is legal Swift (multiple
    trailing closures, 5.3+). But it stops being parseable when the *content*
    closure's last statement is an `if` with no `else`: the parser reads the
    closing brace as the end of that `if`, and then sees `header:` as a new
    statement. The errors are reported two lines apart and look unrelated:

        error: consecutive statements on a line must be separated by ';'
        error: labeled block needs 'do'

    This cost a full CI cycle in `GuestDetailView.signatureSection`. The fix is
    to name the first closure (`Section(content: { … }, header: { … })`), which
    removes the ambiguity.

    We find it structurally rather than by regex: track brace depth over the
    stripped source, and whenever a line closes a brace group, look at what that
    group was opened by and what its final non-blank line is.
    """
    opener = re.compile(r'(Section|Group|List|Form)\s*\{\s*$')
    label_follow = re.compile(r'^\s*\}\s*(header|footer|title)\s*:\s*\{\s*$')

    for path in FILES:
        lines = strip_noise(path.read_text()).splitlines()

        for n, line in enumerate(lines):
            if not label_follow.match(line.rstrip()):
                continue

            # Find the line that opened the group this one closes.
            #
            # A brace balance is the wrong tool: the line we are on contains both
            # a `}` and a `{`, so the walk steps over the group's own opener when
            # the body's last statement is a nested `if let … { … }`.
            #
            # Indentation alone is not enough either — the opener sits at the
            # *same* column as the `} header:` that closes it, while the body is
            # deeper. So: scan upward for the first line that opens a brace
            # (ends in `{`) and does not itself close one (contains no `}`),
            # skipping any line indented deeper than the closing brace.
            indent = len(line) - len(line.lstrip())
            opener_line = None
            for back in range(n - 1, max(-1, n - 400), -1):
                candidate = lines[back]
                if not candidate.strip():
                    continue
                if len(candidate) - len(candidate.lstrip()) > indent:
                    continue
                body = candidate.strip()
                if "}" in body:
                    # Either a closing line, or a `} else {` — keep looking.
                    continue
                if body.endswith("{") or body.endswith(") {"):
                    opener_line = back
                    break
            if opener_line is None:
                continue

            opener_match = opener.search(lines[opener_line].rstrip())
            if not opener_match:
                continue

            # The last top-level statement inside that group. A nested block
            # (`if let … { … }`) spans several lines, so taking the line directly
            # above the closing brace picks up the nested block's own `}`. We want
            # the *outermost* statement, so walk up past bare closing braces and
            # take the first real line at the group body's indent.
            body_indent = None
            for probe in range(opener_line + 1, n):
                stripped = lines[probe]
                if stripped.strip():
                    body_indent = len(stripped) - len(stripped.lstrip())
                    break
            if body_indent is None:
                continue

            last = ""
            for probe in range(n - 1, opener_line, -1):
                candidate = lines[probe]
                if not candidate.strip():
                    continue
                if len(candidate) - len(candidate.lstrip()) != body_indent:
                    continue
                stripped = candidate.strip()
                # A bare `}` closes a nested block; keep climbing to find the
                # statement that block belongs to.
                if stripped in ("}", "};"):
                    continue
                last = stripped
                break

            if not (last.startswith("if ") or last.startswith("if let ")
                    or last.startswith("if var ") or last.startswith("guard ")):
                continue
            # A `} else {` / `} else if …` closes the branch, so the parser is
            # not left hanging.
            if last.startswith("}") or " else" in last:
                continue

            problems.append(
                f"{path}:{opener_line + 1}: '{opener_match.group(1)} {{ … }}' 的"
                f"内容闭包以 '{last[:44]}' 结尾，其后（第 {n + 1} 行）又跟尾随闭包。"
                f"无 else 的 if 会让解析器把闭合的 '}}' 当作 if 的结束，"
                f"从而在 'header:'/'footer:' 处报 \"consecutive statements on a line "
                f"must be separated by ';'\"。把第一个闭包写成显式 'content:' 标签即可")


def main():
    if not FILES:
        print("没有找到 Swift 文件")
        return 1

    print(f"检查 {len(FILES)} 个 Swift 文件…\n")

    for path in FILES:
        src = path.read_text()
        if "import Foundation" not in src and "import SwiftUI" not in src \
                and "import UIKit" not in src:
            warnings.append(f"{path}: 没有任何 import")
        check_balance(path, src)

    check_duplicate_types()
    check_private_helpers()
    check_call_labels()
    check_ambiguous_trailing_closures()

    if problems:
        print("❌ 错误：")
        for p in problems:
            print("  " + p)
        print()

    if warnings:
        print("⚠️  警告：")
        for w in warnings:
            print("  " + w)
        print()

    if not problems:
        print(f"✅ 结构检查通过（{len(warnings)} 条警告）")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
