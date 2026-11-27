#!/usr/bin/env python3
"""Collect reproducible Telegram/Android target metadata without dumping secrets."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from typing import Any


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result


def choose_serial(adb: str, requested: str | None) -> str:
    if requested:
        return requested
    lines = run([adb, "devices"]).stdout.splitlines()[1:]
    devices = [line.split()[0] for line in lines if line.strip().endswith("\tdevice")]
    if len(devices) != 1:
        raise RuntimeError(f"expected one authorized device, found {devices!r}; pass --serial")
    return devices[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=os.environ.get("ADB", shutil.which("adb") or "adb"))
    parser.add_argument("--serial")
    parser.add_argument("--package", default="org.telegram.messenger")
    parser.add_argument("--library", default="libtmessages.49.so")
    parser.add_argument("--root-command", default="/data/local/tmp/ksud shell")
    args = parser.parse_args()
    serial = choose_serial(args.adb, args.serial)

    def shell_result(script: str) -> subprocess.CompletedProcess[str]:
        return run([args.adb, "-s", serial, "shell", script], check=False)

    def shell(script: str) -> str:
        return shell_result(script).stdout.strip()

    def root_result(script: str) -> subprocess.CompletedProcess[str]:
        return shell_result(args.root_command + " " + shlex.quote(script))

    def prop(name: str) -> str:
        return shell(f"getprop {shlex.quote(name)}")

    package_q = shlex.quote(args.package)
    dumpsys = shell(f"dumpsys package {package_q}")
    package_fields: dict[str, str] = {}
    for name in ("versionCode", "versionName", "primaryCpuAbi", "secondaryCpuAbi"):
        match = re.search(rf"\b{name}=([^\s]+)", dumpsys)
        if match:
            package_fields[name] = match.group(1)

    uid_line = shell(f"cmd package list packages -U {package_q}")
    uid_match = re.search(r"\buid:(\d+)", uid_line)
    pid_text = shell(f"pidof {package_q}")
    pids = [int(value) for value in pid_text.split() if value.isdigit()]
    root_id = root_result("id")
    root_active = root_id.returncode == 0 and "uid=0" in root_id.stdout
    native: dict[str, Any] | None = None
    if root_active and pids:
        maps = root_result(f"cat /proc/{pids[0]}/maps").stdout.splitlines()
        candidates = [line for line in maps if line.rstrip().endswith("/" + args.library)]
        if candidates:
            first = candidates[0].split()
            library_path = first[-1]
            digest = root_result(f"sha256sum {shlex.quote(library_path)}").stdout.split()
            size = root_result(f"stat -c %s {shlex.quote(library_path)}").stdout.strip()
            native = {
                "name": args.library,
                "path": library_path,
                "first_mapping": candidates[0],
                "mapping_count": len(candidates),
                "sha256": digest[0] if digest else None,
                "bytes": int(size) if size.isdigit() else None,
            }

    report = {
        "adb_serial": serial,
        "device": {
            "manufacturer": prop("ro.product.manufacturer"),
            "model": prop("ro.product.model"),
            "device": prop("ro.product.device"),
            "android_release": prop("ro.build.version.release"),
            "sdk": prop("ro.build.version.sdk"),
            "build_id": prop("ro.build.id"),
            "fingerprint": prop("ro.build.fingerprint"),
            "abi_list": prop("ro.product.cpu.abilist"),
            "kernel": shell("uname -a"),
            "page_size": shell("getconf PAGE_SIZE"),
            "selinux": shell("getenforce"),
        },
        "telegram": {
            "package": args.package,
            "uid": int(uid_match.group(1)) if uid_match else None,
            "package_fields": package_fields,
            "apk_paths": shell(f"pm path {package_q}").splitlines(),
            "pids": pids,
            "native_library": native,
        },
        "debug": {
            "root_active": root_active,
            "frida_server_pids": shell("pidof frida-server").split(),
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"event": "error", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
