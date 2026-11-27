# Telegram Android WidgetSandbox Remote Code Execution

This research was performed by hexamine and rdjgr of the V12 security team.

> Want to find issues like this in your own code? Try V12 at
> [v12.sh](https://v12.sh).

## Abstract

Telegram Android 13.2.1 evaluates bot-delivered widget HTML in a native QuickJS
runtime. An `await using` lifetime bug leaves a `JSVarRef` pointing into a
released interpreter stack allocation. Reusing that allocation with a
controlled frame shape turns the stale reference into pointer disclosure and
arbitrary 64-bit read/write.

The exploit locates the live `JSStackFrame`, derives the randomized
`libtmessages.49.so` base, overwrites the unsigned saved return address of
`JS_CallInternal`, and calls `mprotect` on an attacker-controlled `ArrayBuffer`.
A position-independent ARM64 payload then attaches the widget thread to the JVM
and launches Android Calculator through JNI.

**Impact: native code execution in the Telegram process when a malicious widget
message is rendered.**

## Affected Build

```text
Package:         org.telegram.messenger
Telegram:        13.2.1 (versionCode 72911)
Architecture:    ARM64
Native library:  libtmessages.49.so
Build ID:        1c52ec7a526ed8d55c00f763261fbdc9929d0931
SHA-256:         01566203c5d4d72a8383d19743c976fada0542a58a80f5bef1b339e5ad9f463a
```

The embedded RVAs and object layouts are specific to this build.

## PoC

[`poc.html`](poc.html) is the complete self-contained exploit. It contains the
QuickJS memory-corruption chain and the ARM64/JNI payload; no Frida dependency
or native helper library is required.

```text
Size:        8869 bytes
zlib-9:      4094 bytes
SHA-256:     6630b003766baed1fa86cea880d22e41dc416f63d800de3246941ede2396ad48
```

## Reproduction

Install the host dependencies and record the exact Telegram build:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 tools/collect_target.py --serial YOUR_SERIAL
```

For local injection on an authorized rooted device with matching
`frida-server`:

```bash
python3 tools/inject_widget.py \
  --serial YOUR_SERIAL \
  --html poc.html \
  --expect-text BOOM
```

For the normal Telegram delivery path, copy `config/telegram.env.example` to
`~/.config/widget-sandbox/telegram-live-test.env`, set a dedicated bot token
and the tester's private chat ID, and set mode `0600`.

```bash
./send-calc-widget.sh --dry-run
./send-calc-widget.sh
```

Open the resulting chat and scroll the widget into view. No click inside the
widget is required. On the targeted build, Calculator launches after the
countdown. Delete the message afterward:

```bash
python3 tools/send_widget.py delete
```

## Exploit Chain

1. `await using` cleanup leaves a closure-backed `JSVarRef` referring to a
   returned `JS_CallInternal` frame.
2. A controlled replacement frame exposes the stale value slot. A
   length-eight `Uint8Array` discloses its object and backing-store pointers.
3. Retargeting the typed array yields reusable arbitrary read/write.
4. The exploit finds the live `JSStackFrame`, follows it to `JSContext` and
   `JSRuntime`, and reads Telegram's interrupt handler.
5. Subtracting interrupt-handler RVA `0x77b754` yields the ELF base. ELF magic
   and instruction words validate the target before control data is changed.
6. The saved return state is replaced so Telegram sequences at RVAs `0xfe9d9c`
   and `0x11a8910` call `mprotect@plt` at RVA `0x18bb730` with `PROT_RWX`.
7. Execution returns into the controlled ARM64 payload, which obtains `JNIEnv*`
   and calls `Context.startActivity()` with an explicit Calculator intent.
