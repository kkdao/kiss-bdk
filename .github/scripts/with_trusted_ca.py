#!/usr/bin/env python3
"""Run build tools with a CA bundle excluding the eMudhra trust paths.

See https://emudhra.we-have-a-problem.com/ . Both the emSign root and
AAA Certificate Services must be excluded because of the cross-signs.
The source is the installed system bundle; no certificates are downloaded.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import ssl
import subprocess
import tempfile

BLOCKED = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
}


def prepare(directory):
    source = ssl.get_default_verify_paths().cafile
    if not source:
        raise RuntimeError("No system CA file found; install ca-certificates first")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        Path(source).read_text(),
        re.S,
    )
    if not blocks:
        raise RuntimeError("System CA file contains no certificates")
    kept = [
        pem for pem in blocks
        if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() not in BLOCKED
    ]
    if not kept:
        raise RuntimeError("Refusing an empty CA bundle")
    bundle = directory / "ca.pem"
    bundle.write_text("\n".join(kept) + "\n")
    empty = directory / "empty-ca-directory"
    empty.mkdir(exist_ok=True)
    # Do not let OpenSSL fall back to a directory containing the removed roots.
    env = {name: str(bundle) for name in (
        "SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
        "PIP_CERT", "GIT_SSL_CAINFO",
    )}
    env["SSL_CERT_DIR"] = str(empty)
    # Wget does not use OpenSSL's SSL_CERT_FILE environment setting.
    wgetrc = directory / "wgetrc"
    wgetrc.write_text(f"ca_certificate = {bundle}\n")
    env["WGETRC"] = str(wgetrc)
    env["NODE_EXTRA_CA_CERTS"] = ""
    options = [x for x in shlex.split(os.environ.get("NODE_OPTIONS", ""))
               if x not in ("--use-bundled-ca", "--use-system-ca", "--use-openssl-ca")]
    env["NODE_OPTIONS"] = shlex.join(options + ["--use-openssl-ca"])
    if os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        raise RuntimeError("TLS verification must not be disabled")
    # Validate the generated bundle before any package manager can use it.
    ssl.create_default_context(cafile=str(bundle))
    print(f"TLS trust: retained {len(kept)} roots; excluded {len(blocks)-len(kept)}", flush=True)
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-env", action="store_true")
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if args.bundle_dir:
        if command or args.github_env:
            parser.error("--bundle-dir cannot be combined with another mode")
        args.bundle_dir.mkdir(parents=True, exist_ok=True)
        prepare(args.bundle_dir)
        return 0
    if args.github_env:
        # GitHub owns RUNNER_TEMP and removes these files after the job.
        if command:
            parser.error("--github-env does not accept a command")
        target = os.environ["GITHUB_ENV"]
        directory = Path(tempfile.mkdtemp(prefix="tls-ca-", dir=os.environ["RUNNER_TEMP"]))
        env = prepare(directory)
        with open(target, "a", encoding="utf-8") as output:
            for key, value in env.items():
                # GitHub forbids setting NODE_OPTIONS through GITHUB_ENV.
                # Workflows set it explicitly at workflow scope instead.
                if key == "NODE_OPTIONS":
                    continue
                if "\n" in value or "\r" in value:
                    raise RuntimeError("Invalid multiline environment value")
                output.write(f"{key}={value}\n")
        return 0
    if not command:
        parser.error("provide a command, or use --github-env")
    with tempfile.TemporaryDirectory(prefix="tls-ca-") as directory:
        env = dict(os.environ, **prepare(Path(directory)))
        return subprocess.run(command, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
