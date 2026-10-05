#!/usr/bin/env python3
"""
Pushes a local git repository to GitHub using the REST Git Data API.

Why this exists: in some sandboxed environments `api.github.com` is reachable
but `github.com` (the git-over-HTTPS host) is not, so `git push` hangs or
returns an empty response. The Git Data API exposes the same operations over
the reachable host — blobs, trees, commits, refs — so the push can be
reconstructed.

This is slower than a real push (one request per blob) but it works.

Usage:
    GITHUB_TOKEN=... python3 tools/api_push.py [repo_root]

Environment:
    GITHUB_TOKEN   required — token with `contents: write`
    LUNA_REPO      default MaiHaobo/Luna
    LUNA_BRANCH    default main

Exit codes:
    0  pushed
    1  failed (message printed to stderr)
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
REPO = os.environ.get("LUNA_REPO", "MaiHaobo/Luna")
BRANCH = os.environ.get("LUNA_BRANCH", "main")
ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
if not TOKEN:
    sys.exit("GITHUB_TOKEN is not set")


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def request(method: str, path: str, payload=None, retries: int = 4):
    """One authenticated API call. Raises RuntimeError with the server's own
    message on failure — 401/403/404 are not retried, they will not change."""
    url = f"{API}{path}"
    data = json.dumps(payload).encode() if payload is not None else None

    req = urllib.request.Request(url, data=data, method=method)
    # `token` works for both classic PATs and App installation tokens and is
    # what the git-over-HTTPS host expects too; `Bearer` is the newer spelling
    # but some proxies in front of the API only accept `token`.
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "Luna-API-Push")
    if data:
        req.add_header("Content-Type", "application/json")

    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:400]
            last = f"HTTP {e.code}: {detail}"
            if e.code in (401, 403, 404, 422):
                break
            time.sleep(1.5 * (attempt + 1))
        except Exception as e:  # noqa: BLE001 — network layer, report verbatim
            last = str(e)
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{method} {path} → {last}")


# --------------------------------------------------------------------------- #
# Git plumbing (local)
# --------------------------------------------------------------------------- #

def git(*args: str) -> str:
    out = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def tracked_files() -> list[str]:
    """Every file git tracks, as repo-relative paths."""
    raw = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT,
        capture_output=True, check=True).stdout
    return [p.decode() for p in raw.split(b"\x00") if p]


def file_mode(rel: str) -> str:
    """
    Git's canonical mode bits. We ask git rather than stat()-ing the working
    tree, because the executable bit is a tracked index property and may
    differ from the checkout (e.g. after a clone on a noexec mount).
    """
    try:
        return "100755" if git("ls-files", "-s", "--", rel).split()[0] == "100755" else "100644"
    except Exception:  # noqa: BLE001
        return "100644"


# --------------------------------------------------------------------------- #
# Git Data API
# --------------------------------------------------------------------------- #

def create_blob(rel: str) -> str:
    """Uploads one file as a blob. base64 keeps it JSON-safe for binary."""
    encoded = base64.b64encode((ROOT / rel).read_bytes()).decode()
    return request("POST", f"/repos/{REPO}/git/blobs", {
        "content": encoded,
        "encoding": "base64",
    })["sha"]


def upload_tree(files: list[str], blobs: dict[str, str]) -> str:
    """
    Uploads blobs, then assembles the tree bottom-up.

    GitHub's tree endpoint takes one level per call: a nested `tree` array may
    reference subtrees only by an already-existing sha. So we group files by
    parent directory, build the deepest directories first, and memoise each
    directory's sha.
    """
    # parent dir path -> list of (child name, is_dir)
    children: dict[str, list[tuple[str, bool]]] = {}
    for rel in files:
        parts = rel.split("/")
        for i, part in enumerate(parts):
            parent = "/".join(parts[:i])
            is_dir = i < len(parts) - 1
            bucket = children.setdefault(parent, [])
            if (part, is_dir) not in bucket:
                bucket.append((part, is_dir))

    tree_sha: dict[str, str] = {}

    def build(dir_path: str) -> str:
        if dir_path in tree_sha:
            return tree_sha[dir_path]
        entries = []
        for name, is_dir in sorted(children.get(dir_path, [])):
            full = f"{dir_path}/{name}" if dir_path else name
            if is_dir:
                entries.append({
                    "path": name, "mode": "040000", "type": "tree",
                    "sha": build(full),
                })
            else:
                entries.append({
                    "path": name, "mode": file_mode(full), "type": "blob",
                    "sha": blobs[full],
                })
        sha = request("POST", f"/repos/{REPO}/git/trees", {"tree": entries})["sha"]
        tree_sha[dir_path] = sha
        return sha

    return build("")


# --------------------------------------------------------------------------- #

def main() -> int:
    files = tracked_files()
    print(f"→ {len(files)} 个文件 → {REPO}@{BRANCH}\n")

    # Probe read access before doing any work, so a bad repo name fails fast.
    try:
        repo = request("GET", f"/repos/{REPO}")
        print(f"✓ 仓库可访问：{repo['full_name']} (private={repo['private']})")
    except RuntimeError as e:
        print(f"✗ 无法访问仓库：{e}", file=sys.stderr)
        return 1

    # 1. Blobs — one request each, so report progress for large trees.
    print(f"\n① 上传 {len(files)} 个 blob…")
    blobs: dict[str, str] = {}
    for i, rel in enumerate(files, 1):
        blobs[rel] = create_blob(rel)
        if i % 10 == 0 or i == len(files):
            print(f"   {i}/{len(files)}")

    # 2. Tree — assembled bottom-up, one call per directory.
    print("\n② 组装目录树…")
    root_tree = upload_tree(files, blobs)
    print(f"   根 tree = {root_tree[:12]}…")

    # 3. Commit — parented on the existing branch head when there is one.
    message = git("log", "-1", "--pretty=%B")
    parents: list[str] = []
    try:
        parents = [request("GET", f"/repos/{REPO}/git/ref/heads/{BRANCH}")["object"]["sha"]]
        print(f"\n③ 创建 commit（父提交 {parents[0][:12]}…）")
    except RuntimeError:
        print(f"\n③ 创建 commit（{BRANCH} 尚不存在，作为首个提交）")

    commit = request("POST", f"/repos/{REPO}/git/commits", {
        "message": message,
        "tree": root_tree,
        "parents": parents,
    })["sha"]
    print(f"   commit = {commit[:12]}…")

    # 4. Ref — force, because the API-created tree may not fast-forward.
    print(f"\n④ 更新 refs/heads/{BRANCH}…")
    if parents:
        request("PATCH", f"/repos/{REPO}/git/refs/heads/{BRANCH}",
                {"sha": commit, "force": True})
    else:
        request("POST", f"/repos/{REPO}/git/refs",
                {"ref": f"refs/heads/{BRANCH}", "sha": commit})

    head = request("GET", f"/repos/{REPO}/git/ref/heads/{BRANCH}")["object"]["sha"]
    print("\n✅ 推送完成")
    print(f"   {repo['html_url']}/tree/{BRANCH}")
    print(f"   HEAD = {head[:12]}…")

    if head != commit:
        print(f"⚠️  远端 HEAD ({head[:12]}) 与本次 commit ({commit[:12]}) 不一致", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
