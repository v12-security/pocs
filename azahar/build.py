#!/usr/bin/env python3
"""Build the animated 3DS homebrew for the Azahar guest-to-host PoC."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET = "v12-azahar-escape-win"


def run(argv: list[str]) -> None:
    print("+", " ".join(argv))
    subprocess.run(argv, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--image", default="devkitpro/devkitarm:latest")
    parser.add_argument("--output", type=Path, default=ROOT / f"{TARGET}.3dsx")
    args = parser.parse_args()

    shutil.rmtree(ROOT / "build", ignore_errors=True)
    script = "\n".join(
        [
            "set -eu",
            "export DEVKITPRO=/opt/devkitpro",
            "export DEVKITARM=/opt/devkitpro/devkitARM",
            "export PATH=$DEVKITARM/bin:$DEVKITPRO/tools/bin:$PATH",
            "make -C /work clean >/dev/null",
            "make -C /work",
        ]
    )
    run(
        [
            args.docker,
            "run",
            "--rm",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{ROOT}:/work",
            "-w",
            "/work",
            args.image,
            "bash",
            "-lc",
            script,
        ]
    )

    built = ROOT / f"{TARGET}.3dsx"
    if not built.is_file():
        raise FileNotFoundError(built)
    output = args.output.resolve()
    if output != built:
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(built, output)

    payload = output.read_bytes()
    print(f"\nBuilt {output}")
    print(f"3DSX: {len(payload)} bytes")
    print(f"SHA256: {hashlib.sha256(payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
