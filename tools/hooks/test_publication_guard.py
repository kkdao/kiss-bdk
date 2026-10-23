#!/usr/bin/env python3
"""Regression tests use disposable local repositories and never contact GitHub."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("guard", HERE / "publication_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_names_case_and_ref_boundaries(self):
        for name in ["codex", "Claude", "CHATGPT", "openai", "copilot", "cursor"]:
            for value in [name + "/fix", "refs/heads/fix-" + name, "kkdao:" + name + "/fix"]:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    guard.check("ref", value)
        guard.check("ref", "feature/add-kiss-projects")

    def test_diff_names_and_narrow_policy_exception(self):
        guard.check_diff("diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+cursor.next()")
        for path in ["README.md", "tools/hooks/unrelated.py"]:
            with self.assertRaises(ValueError):
                guard.check_diff(f"diff --git a/{path} b/{path}\n+++ b/{path}\n@@ -0,0 +1 @@\n+Generated with Codex")
        guard.check_diff("diff --git a/tools/hooks/publication_guard.py b/tools/hooks/publication_guard.py\n+++ b/tools/hooks/publication_guard.py\n@@ -0,0 +1 @@\n+Codex")
        with self.assertRaises(ValueError):
            guard.check_diff("+unparsed content")
        with self.assertRaises(ValueError):
            guard.check_diff("diff --git a/old.md b/codex.md\nrename from old.md\nrename to codex.md")

    def test_review_requires_every_public_field_and_changes_digest(self):
        data = dict(account="kkdao", destination="owner/project", branch="feature/add-kiss",
                    base="master", title="Add KISS", body="Add the two projects.",
                    diff="diff --git a/a b/a\n+++ b/a\n@@ -0,0 +1 @@\n+KISS\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.json"
            def run(value):
                path.write_text(json.dumps(value))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    guard.review(path)
                return output.getvalue()
            first = run(data)
            self.assertIn('"branch": "feature/add-kiss"', first)
            second = run(dict(data, title="Add both projects"))
            self.assertNotEqual(first.split("Review SHA256:")[1], second.split("Review SHA256:")[1])
            for field in data:
                absent = dict(data)
                del absent[field]
                with self.assertRaises(ValueError):
                    run(absent)
                if field != "diff":
                    with self.assertRaises(ValueError):
                        run(dict(data, **{field: "Codex"}))
            with self.assertRaises(ValueError):
                run(dict(data, diff="not a diff"))

    def test_ci_event_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            pr = dict(title="A normal change", body="Useful description", head={"label": "owner:feature/test"}, base={"label": "owner:main"})
            env = dict(os.environ, GITHUB_HEAD_REF="feature/test", GITHUB_REF_NAME="feature/test")
            def run(value):
                path.write_text(json.dumps(value))
                return subprocess.run(["python3", str(HERE / "publication_guard.py"), "event", str(path)], env=env, capture_output=True).returncode
            self.assertEqual(run({"pull_request": pr}), 0)
            for field in ["title", "body"]:
                self.assertNotEqual(run({"pull_request": dict(pr, **{field: "Codex"})}), 0)
            self.assertNotEqual(run({"pull_request": dict(pr, head={"label": "owner:codex/test"})}), 0)
            self.assertNotEqual(run({"pull_request": {}}), 0)

    def test_real_pushes_and_commit_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, remote = root / "work", root / "remote.git"
            env = dict(os.environ)
            for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"]:
                env.pop(name, None)
            def run(*args, ok=True, extra_env=None):
                result = subprocess.run(["git", "-C", str(repo), *args], text=True,
                    capture_output=True, env=env | (extra_env or {}))
                if ok:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                return result
            repo.mkdir()
            run("init", "--template=", "-q", "-b", "feature/test")
            subprocess.run(["git", "init", "--template=", "--bare", "-q", str(remote)], check=True, env=env)
            run("config", "user.name", "Test User")
            run("config", "user.email", "test@example.invalid")
            run("config", "commit.gpgsign", "false")
            hooks = repo / ".git/hooks"
            hooks.mkdir(exist_ok=True)
            run("config", "core.hooksPath", str(hooks))
            run("remote", "add", "origin", str(remote))
            run("commit", "--allow-empty", "-qm", "Initial")
            run("push", "origin", "HEAD")
            (repo / "tools/hooks").mkdir(parents=True)
            shutil.copy(HERE / "publication_guard.py", repo / "tools/hooks/publication_guard.py")
            shutil.copy(HERE / "pre-push", hooks / "pre-push")
            (hooks / "pre-push").chmod(0o755)
            run("push", "origin", "HEAD:refs/heads/codex/test", ok=False)
            # Safe local branch -> prohibited destination is also blocked.
            self.assertNotIn("codex/test", run("ls-remote", "origin").stdout)
            run("commit", "--allow-empty", "-qm", "Safe change")
            run("push", "origin", "HEAD")
            run("commit", "--allow-empty", "-qm", "Codex wrote this")
            run("push", "origin", "HEAD", ok=False)
            run("reset", "--hard", "origin/feature/test")
            run("commit", "--allow-empty", "-qm", "Safe subject", extra_env={"GIT_AUTHOR_NAME": "Codex"})
            run("push", "origin", "HEAD", ok=False)
            run("reset", "--hard", "origin/feature/test")
            (repo / "README.md").write_text("Generated with Codex\n")
            run("add", "README.md")
            run("commit", "-qm", "Add document")
            (repo / "README.md").write_text("Clean now\n")
            run("add", "README.md")
            run("commit", "-qm", "Revise document")
            run("push", "origin", "HEAD", ok=False)
            run("reset", "--hard", "origin/feature/test")
            run("tag", "-a", "v-test", "-m", "Generated with Codex")
            run("push", "origin", "refs/tags/v-test", ok=False)
            # Install the actual commit hook plus its sibling policy module.
            for name in ["commit-msg", "publication_guard.py"]:
                shutil.copy(HERE / name, hooks / name)
                (hooks / name).chmod(0o755)
            run("commit", "--allow-empty", "-qm", "Codex wrote this", ok=False)
            run("commit", "--allow-empty", "-qm", "Safe subject", ok=False,
                extra_env={"GIT_AUTHOR_NAME": "Codex"})
            run("commit", "--allow-empty", "-qm", "Safe subject")
            # Removing an already existing prohibited ref is allowed.
            guard.check_push("origin", "(delete) " + "0" * 40 + " refs/heads/codex/test " + "1" * 40)
            with self.assertRaises(ValueError):
                guard.check_push("origin", "malformed")


if __name__ == "__main__":
    unittest.main()
