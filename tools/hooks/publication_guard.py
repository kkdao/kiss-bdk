#!/usr/bin/env python3
"""Local checks only: this program never pushes or calls a remote API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

NAMES = r"codex|chatgpt|openai|claude|anthropic|copilot|gemini|devin|aider|superpowers"
PROSE = re.compile(r"(?<![a-z0-9])(?:" + NAMES + r"|cursor)(?![a-z0-9])", re.I)
# A source-code cursor is ordinary vocabulary; a named coding tool is not.
CONTENT = re.compile(r"(?<![a-z0-9])(?:" + NAMES + r")(?![a-z0-9])|cursor (?:ai|ide|agent)|co-authored-by:.*(?:cursor|gpt-)", re.I)
POLICY_FILES = {
    ".github/workflows/attribution.yml", ".gitignore",
    "tools/hooks/commit-msg", "tools/install_hooks.sh",
    "tools/hooks/publication_guard.py", "tools/hooks/test_publication_guard.py",
}


def check(label, value, pattern=PROSE):
    if pattern.search(value):
        raise ValueError(f"REFUSED: {label} contains a prohibited tool name")


def git(*args):
    return subprocess.check_output(["git", *args], text=True, encoding="utf-8", errors="strict")


def check_diff(diff):
    path = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            # Check rename-only changes too: these need not have a +++ header.
            if '"' in line:
                raise ValueError("REFUSED: quoted diff paths require manual review")
            parts = shlex.split(line)
            if len(parts) != 4 or not parts[3].startswith("b/"):
                raise ValueError("REFUSED: unrecognized diff header")
            check("changed path", parts[3][2:])
            path = None
        elif line.startswith("+++ b/"):
            path = line[6:]
            check("changed path", path)
        elif line.startswith("+++ "):
            # Unusual/quoted paths need manual review, never a silent exemption.
            if line != "+++ /dev/null":
                raise ValueError("REFUSED: unrecognized diff path encoding")
        elif line.startswith("+"):
            if path is None:
                raise ValueError("REFUSED: added content without a recognized path")
            if path not in POLICY_FILES:
                check(f"added content in {path}", line[1:], CONTENT)


def check_commit(oid):
    check("commit message or identity", git("show", "-s", "--format=%an <%ae>%n%cn <%ce>%n%B", oid))
    # Inspect each new commit, including changes later reverted in the same push.
    check_diff(git("show", "--format=", "--first-parent", "--diff-merges=first-parent",
                   "--no-ext-diff", "--no-textconv", "--unified=0", oid, "--"))


def check_push(remote, lines):
    if not remote or remote.startswith("-"):
        raise ValueError("REFUSED: invalid remote name")
    checked = set()
    for line in lines.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            raise ValueError("REFUSED: malformed pre-push input")
        local_ref, local_oid, remote_ref, remote_oid = fields
        # Deleting a bad name must remain possible.
        if set(local_oid) == {"0"}:
            continue
        check("local ref", local_ref)
        check("destination ref", remote_ref)
        obj = local_oid
        while git("cat-file", "-t", obj).strip() == "tag":
            annotation = git("cat-file", "-p", obj)
            check("tag message or identity", annotation)
            obj = annotation.splitlines()[0].removeprefix("object ")
        tip = git("rev-parse", "--verify", local_oid + "^{commit}").strip()
        if set(remote_oid) == {"0"}:
            commits = git("rev-list", tip, "--not", "--remotes=" + remote).splitlines()
        else:
            # Missing remote history is an error; fetch it before retrying.
            git("cat-file", "-e", remote_oid + "^{commit}")
            commits = git("rev-list", remote_oid + ".." + tip).splitlines()
        for oid in commits:
            if oid not in checked:
                check_commit(oid)
                checked.add(oid)


def review(path):
    raw = path.read_text()
    data = json.loads(raw)
    required = {"account", "destination", "branch", "base", "title", "body", "diff"}
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("REFUSED: review needs exactly account, destination, branch, base, title, body, diff")
    for key, value in data.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"REFUSED: missing/empty {key}")
        if key == "diff":
            if not value.startswith("diff --git ") or "\n@@" not in value:
                raise ValueError("REFUSED: review requires an actual Git text diff")
            check_diff(value)
        else:
            check(key, value)
    normalized = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2)
    print(normalized)
    print("Review SHA256:", hashlib.sha256(normalized.encode()).hexdigest())
    print("LOCAL CHECK ONLY. Show every field above and obtain explicit approval.")
    print("A changed field requires a new review and approval. This command grants no approval.")
    print("Policy files may contain detection rules; inspect those changes manually.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("ref").add_argument("value")
    modes.add_parser("message").add_argument("path", type=Path)
    modes.add_parser("push").add_argument("remote")
    modes.add_parser("review").add_argument("path", type=Path)
    modes.add_parser("event").add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "ref":
            check("ref", args.value)
        elif args.mode == "message":
            check("commit message", args.path.read_text())
            check("author identity", git("var", "GIT_AUTHOR_IDENT"))
            check("committer identity", git("var", "GIT_COMMITTER_IDENT"))
        elif args.mode == "push":
            check_push(args.remote, sys.stdin.read())
        elif args.mode == "event":
            event = json.loads(args.path.read_text())
            check("published ref", os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME", ""))
            if "pull_request" in event:
                pr = event["pull_request"]
                for label, value in [("PR title", pr["title"]), ("PR body", pr.get("body") or ""),
                                     ("PR head", pr["head"]["label"]), ("PR base", pr["base"]["label"])]:
                    check(label, value)
        else:
            review(args.path)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
