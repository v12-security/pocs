# PinTheft

https://github.com/user-attachments/assets/5d411fb7-24c3-49d6-b8f7-ae73f80300a9

## Abstract

PinTheft is a Linux local privilege escalation exploit for an RDS zerocopy
double-free that can be turned into a page-cache overwrite through `io_uring`
fixed buffers.

PinTheft was discovered with [V12](https://v12.sh) by Aaron Esau of the
[V12 security team](https://x.com/v12sec). We duped on this bug with some other teams
and a [patch](https://lore.kernel.org/netdev/20260505234336.2132721-1-achender@kernel.org/) is available
so we are releasing our PoC.

> Want to find issues like this in your own code? Try V12 at [v12.sh](https://v12.sh).

The bug lived in the RDS zerocopy send path. `rds_message_zcopy_from_user()`
pins user pages one at a time. If a later page faults, the error path drops the
pages it already pinned, and later RDS message cleanup drops them again because
the scatterlist entries and entry count remain live after the zcopy notifier is
cleared. Each failed zerocopy send can steal one reference from the first page.

The PoC uses `io_uring` to make that refcount bug useful. It registers an
anonymous page as a fixed buffer, giving the page a `FOLL_PIN` bias of 1024
references. It then steals those references with failing RDS zerocopy sends,
frees the page, reclaims it as page cache for a SUID-root binary, and uses the
stale `io_uring` fixed-buffer page pointer to overwrite that page cache with a
small ELF payload. Executing the SUID binary drops into a root shell.

Sadly, the RDS kernel module this requires is only default on Arch Linux among
the common distributions we tested.

## "PinTheft"?

Because the exploit steals `FOLL_PIN` references until `io_uring` is left
holding a stolen page pointer.

## Exploitation

```
cd pintheft && gcc exp poc.c && ./exp
```

One-line version:

```
git clone https://github.com/v12-security/pocs.git && cd pocs/pintheft && gcc -o exp poc.c && ./exp
```

## Requirements

PinTheft requires:

- `CONFIG_RDS`
- `CONFIG_RDS_TCP`
- `CONFIG_IO_URING`
- `io_uring_disabled=0`
- a readable SUID-root binary
- x86_64 for the included payload

The technique is architecture-independent, but the embedded shell ELF in
`poc.c` is x86_64.

The exploit asks RDS for TCP transport with `SO_RDS_TRANSPORT=2`, which can
autoload `rds_tcp` on systems where the module exists and module autoloading is
allowed.

## Cleanup Warning

PinTheft modifies the target SUID binary's page cache. The on-disk binary is
backed up before exploitation and the exploit prints a restore command before
executing the corrupted target:

```
sudo cp /tmp/.backup_<name>_<pid> <target> && sudo chmod u+s <target>
```

If you are testing on a disposable machine, rebooting or dropping caches also
clears the in-memory page-cache overwrite. Do not leave the machine in a state
where common SUID programs such as `su`, `mount`, or `passwd` execute the
payload from cache.

## How It Works

1. **Target selection.** The PoC searches for a readable SUID-root binary,
   preferring paths such as `/usr/bin/su`, `/bin/su`, `/usr/bin/mount`,
   `/usr/bin/passwd`, and `/usr/bin/pkexec`.

2. **Safety backup.** The selected target is copied to `/tmp/.backup_<name>_<pid>`
   before exploitation.

3. **Page setup.** The exploit pins itself to CPU 0, maps two pages, touches the
   first page, and marks the second page `PROT_NONE` so a two-page RDS zcopy
   send will fault after the first page has already been pinned.

4. **Fixed-buffer registration.** The first page is registered with `io_uring`
   through `IORING_REGISTER_BUFFERS`. This pins the page with
   `GUP_PIN_COUNTING_BIAS`, adding 1024 references.

5. **Clone-buffer hold.** The fixed buffer is cloned into a second `io_uring`
   instance with `IORING_REGISTER_CLONE_BUFFERS`. A daemon child keeps that
   second ring fd open so `io_buffer_unmap()` does not later unpin the buffer
   and corrupt whatever page has been reclaimed into the freed frame.

6. **Reference theft.** The exploit performs 1024 failing RDS zerocopy sends.
   Each send pins the first page, faults on the guard page, and then double-drops
   the first page during the RDS error cleanup path. This consumes the 1024
   `FOLL_PIN` references while `io_uring` still retains the raw `struct page *`.

7. **Clean free.** The selected SUID binary's first page is evicted from page
   cache. The exploit drains the per-CPU page list, then unmaps the user page.
   Because the remaining reference is the normal mapping reference, the free
   path clears memcg state cleanly before returning the page to the allocator.

8. **Page-cache reclaim.** Reading the SUID binary immediately after the free
   causes page cache allocation to reuse the just-freed page. The stale
   `io_uring` fixed-buffer entry now points at a live page-cache page.

9. **Dangling fixed-buffer write.** The exploit creates a temporary payload file
   and submits `IORING_OP_READ_FIXED`. The kernel reads payload bytes into the
   registered fixed buffer, but that fixed buffer's `struct page *` now refers
   to the SUID binary's page cache.

10. **Verification and execution.** The PoC verifies that the SUID binary's
    first cached bytes match the embedded ELF payload, destroys the first ring,
    and execs the target to obtain a root shell.

## Affected Code Paths

The PoC targets the RDS zerocopy send path and depends on TCP transport:

- `rds_message_zcopy_from_user()`
- RDS zerocopy error cleanup
- RDS message purge cleanup
- `SO_RDS_TRANSPORT=RDS_TRANS_TCP`

The exploitation primitive also depends on `io_uring` fixed-buffer behavior,
specifically registered buffers retaining raw page references and cloned buffer
state delaying unpin cleanup.

## Affected Versions

The PoC was written for kernels with RDS, RDS TCP, and `io_uring` enabled. It
also handles kernels with `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` by arranging for the
target page to be populated after allocator zeroing and after the filesystem
fills the page from disk.

Confirmed default exposure is limited by module availability. The required RDS
module is default on Arch Linux, but not on most common distribution kernels we
checked.

## Mitigation

If RDS is not needed, disable or block it:

```
rmmod rds_tcp rds
printf 'install rds /bin/false\ninstall rds_tcp /bin/false\n' > /etc/modprobe.d/pintheft.conf
```

## Credit

Found with V12 by Aaron Esau of the V12 security team: [v12.sh](https://v12.sh): dangerously powerful agentic security.
