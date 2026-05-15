# QEMUtiny

https://github.com/user-attachments/assets/9ff4e5f2-9bfe-405a-a6b9-2ee43fb8352a

## Abstract

QEMUtiny is a memory corruption vulnerability in QEMU's implementation of CXL Type-3
device emulation, reported against QEMU master `007b29752e` and confirmed
working against `5e61afe` (May 11, 2026).

QEMUtiny was discovered autonomously with [V12](https://v12.sh) by Aaron Esau of the
[V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at [v12.sh](https://v12.sh).

The PoC chains two CXL mailbox bugs in `hw/cxl/cxl-mailbox-utils.c`: an
out-of-bounds read in `GET_LOG`, followed by an out-of-bounds write in
`SET_FEATURE`.

1. **OOB read:** `cmd_logs_get_log()` treats the CEL log offset as an array
   index in the `memmove()` source expression even though the CXL mailbox
   offset is in bytes.
2. **OOB write:** `cmd_features_set_feature()` accepts byte offsets into
   several small feature write-attribute structures without checking that
   `offset + bytes_to_copy` stays inside the selected structure.

We reported the bugs upstream. Maintainers state CXL support is currently for at non-virtualization use cases, so we feel comfortable release the PoC publicly.

The included `poc.c` is a working exploit that drives the emulated CXL mailbox from the guest through the device BAR. It depends on offsets for the specific QEMU build and host libc layout.
The exploit can be weaponized to work reliably across many QEMU versions using the OOB read to scan memory. However this is out of scope for this PoC.

## "QEMUtiny"?

QEMU + Mutiny.

## Offsets (USER FRIENDLY VERSION)

- Replace `0x047E735` with `$(readelf -s qemu-system-x86_64  | grep cmd_logs_get_log | awk '{print $2}')`
- Replace `0x0341BB0` with `$(objdump -S qemu-system-x86_64 | grep "<memmove@plt>:" | awk '{print $1}')`
- Replace `0x01E72FF8` with `$(objdump -S qemu-system-x86_64 | grep "libc_start_main" | awk '{print $(NF-1)}')`
- Find libc: `ldd ./qemu-system-x86_64 | grep libc.so`
- Replace `0x2A200` with `readelf -sW /lib/x86_64-linux-gnu/libc.so.6 | grep -i __libc_start_main | awk '{print $2}'`
- Replace `0x058750` with `readelf -sW /lib/x86_64-linux-gnu/libc.so.6 | grep -i system@ | awk '{print $2}'`

## Building

```
gcc -O2 -Wall -Wextra -o exp poc.c
```

The reproducer must be run as root inside the guest because it writes PCI config
space and mmaps the CXL device BAR through sysfs.

```
sudo ./exp
```

One-line version:

```
git clone https://github.com/v12-security/pocs.git && cd pocs/qemu && gcc -O2 -Wall -Wextra -o exp poc.c && sudo ./exp
```

## Test Setup

Use `./run_qemu_shell.sh`. Then in the guest, use `/exp`


`poc.c` assumes the CXL Type-3 device appears in the guest at:

```
/sys/bus/pci/devices/0000:35:00.0
```

and that BAR2 is exposed as:

```
/sys/bus/pci/devices/0000:35:00.0/resource2
```

If your guest enumerates the device at a different BDF, update the two sysfs
paths in `main()`.

## How It Works

1. **Mailbox access.** The guest enables PCI memory decoding for the CXL device,
   maps BAR2, and sends CXL mailbox commands by writing the mailbox payload,
   command, and control registers directly.

2. **CEL out-of-bounds read.** `cmd_logs_get_log()` checks the requested CEL
   range as if `offset` were a byte offset, but then performs pointer arithmetic
   on `cci->cel_log` as a `struct cel_log *`. `poc.c` uses
   `GET_LOG_OOB_BASE_OFFSET` to land just past the CEL buffer and read adjacent
   QEMU CXL state.

3. **QEMU address discovery.** The out-of-bounds CEL read leaks a CXL mailbox
   command handler pointer and the `CXLType3Dev` heap address. The handler
   pointer gives the QEMU PIE base for this build.

4. **Rank sparing overflow.** The demo sends `SET_FEATURE / RANK_SPARING` with
   a non-zero feature offset and a large payload. The rank sparing case copies
   into `ct3d->rank_sparing_wr_attrs + hdr->offset` without bounding the copy to
   `sizeof(ct3d->rank_sparing_wr_attrs)`, so the payload continues into later
   `CXLType3Dev` fields.

5. **Fake memory dispatch state.** The overflowed payload plants enough fake
   `FlatView`, dispatch, section, `MemoryRegion`, and `MemoryRegionOps` state
   for the sanitize path to call a controlled `MemoryRegionOps.write` callback.

6. **Callback trigger.** `MEDIA_OPERATIONS / SANITIZE` starts a background
   operation. When the sanitize worker reaches `address_space_set()`, it walks
   the corrupted dispatch state and invokes the forged write callback. The demo
   first uses this to call `memmove()` and leak libc, then repoints the callback
   to `system("/bin/bash")`.

## Affected Code Paths

The missing `SET_FEATURE` bounds check affects the PPR paths and the sparing
write-attribute paths:

- `soft_ppr_wr_attrs`
- `hard_ppr_wr_attrs`
- `cacheline_sparing_wr_attrs`
- `row_sparing_wr_attrs`
- `bank_sparing_wr_attrs`
- `rank_sparing_wr_attrs`

`patrol_scrub_wr_attrs` already has the intended style of bounds check.

## Affected Versions

The full QEMUtiny chain uses two bugs.

- **OOB read:** the vulnerable `GET_LOG` path was introduced by
  `056172691b` (`hw/cxl/device: Add log commands (8.2.9.4) + CEL`), first
  released in QEMU `v7.1.0`.
- **OOB write:** the vulnerable PPR and memory sparing `SET_FEATURE` paths were
  introduced by `5e5a86bab8` and `da5cafdc4d`, released in QEMU v11.0.0.

## Credit

Found with V12 by Aaron Esau of the V12 security team. The weaponized PoC (qemu escape) was prepared by [@xia0o0o0o](https://xia0.sh/).
