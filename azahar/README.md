# Azahar Guest-to-Host RCE

These vulnerabilities were discovered with [V12](https://v12.sh) by Nihal Talur
of the [V12 security team](https://x.com/v12sec).

## Abstract

This PoC is a single animated 3DS homebrew file that chains two memory-safety
bugs in Azahar's AM (application manager) install-file backends and opens
Calculator on the Windows host:

- `TicketFile::Read()` reports success without writing to the host read buffer,
  so uninitialized host heap bytes are copied into guest memory, leaking module
  and heap pointers and defeating ASLR;
- `TicketFile::Write()` resizes its host `std::vector` from a cumulative byte
  counter but forms the copy destination from an unchecked guest-supplied
  64-bit offset, giving an arbitrary-offset write out of that vector.

**Impact: full guest-to-host escape.** A malicious 3DS homebrew file or game
can execute native code with the privileges of the Azahar process.

The exploit targets the official **Azahar 2126.1.2 Windows x64 (MSVC)** build
with ASLR and DEP enabled.  

Reported as
[GHSA-h74v-5mw8-qg8r](https://github.com/azahar-emu/azahar/security/advisories/GHSA-h74v-5mw8-qg8r#advisory-comment-321589)
and patched in Azahar 2126.2.

## Build

Requirements are Python 3 and Docker. The build uses the official
`devkitpro/devkitarm:latest` image and has no host devkitARM requirement.

```bash
python3 build.py
# output: v12-azahar-escape-win.3dsx
```

The build is reproducible: the checked-in `v12-azahar-escape-win.3dsx` has
SHA-256 `af5e8ed29ddf47a6f2837e0c2fdf09cfe266437db98575eee1fc7e70b258c386`.
The normal build uses the checked-in logo data. To regenerate
`source/v12_logo.h`, install Pillow, run `python3 tools/gen_fancy.py`, then
rerun `build.py`.

## How It Works

1. The guest opens AM ticket and temporary-program install handles through
   `am:net` (`AMNET_InstallTicketBegin`, `AM_StartTempCiaInstall`).
2. Reads from the ticket backend return stale host heap bytes verbatim:
   `TicketFile::Read()` is `UNIMPLEMENTED()` but returns `length`, and
   `src/core/hle/service/fs/file.cpp` allocates its buffer with
   `make_unique_for_overwrite` and copies the reported count into guest memory.
3. Repeated `AM_StartTempCiaInstall` / `AM_CancelCIAInstall` cycles place a
   freed `CIAFile` wrapper in that hole. `parse_cia_leak()` recovers two
   module-relative vtable pointers and the backend object pointer, converting
   them to the randomized image base.
4. Ticket writes spray host vectors in the `CIAFile` size class so the only
   reusable large hole is the one the leak just identified. The next ticket
   vector lands at a known address, and the payload fills it with a fake vtable
   plus the Calculator path at `+0x100`.
5. A single eight-byte `TicketFile::Write()` with a large offset
   (`offset = target_backend - vector`) overwrites a live `CIAFile` backend's
   vtable pointer with the controlled vector address. Candidate backends are
   sampled first, so the write covers the allocator's slot rotation.
6. `FSFILE_SetSize()` on that install handle dispatches through the fake table.
   The size argument is attacker-chosen, so the chain is a two-step call:

   | Fake vtable slot | `FileBackend` virtual | Value (RVA in `azahar.exe`) | Role |
   | --- | --- | --- | --- |
   | `+0x08` | `Read` | `0x0c4b7c0` | `SDL_OpenURL` wrapper, reached via the gadget's `[rax+8]` |
   | `+0x20` | `SetSize` | `0x037f3f3` | `mov rcx, rdx ; jmp qword ptr [rax+8]` |
   | `+0x38` | `AllowsCachedReads` | `0x0116f60` | `xor al, al ; ret`, keeps the corrupted object answering `false` |

   `src/core/file_sys/file_backend.h` fixes that order, and MSVC puts the
   destructor in slot 0, so `SetSize` is slot 4. The dispatch enters the gadget
   with `rax` = fake vtable and `rdx` = the requested size. The gadget moves that
   size into `rcx` and tail-jumps to the `SDL_OpenURL` wrapper, which converts
   the UTF-8 string, calls `ShellExecuteW(NULL, L"open", …)`, and launches
   Calculator. The size passed to `FSFILE_SetSize()` is therefore
   `vector + 0x100`: the address of `C:\Windows\System32\calc.exe` inside the
   guest-controlled vector.

