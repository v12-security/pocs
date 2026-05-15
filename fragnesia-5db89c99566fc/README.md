# fragnesia-5db89c99566fc

This is a variant of our [Fragnesia](../fragnesia/README.md) bug (CVE-2026-46300) that bypasses the merged fix (commit f84eca581739) by exploiting a separate path that remains unpatched in both mainline and the netdev `net` tree as of 2026-05-15 18:00 UTC.

The bug is in `skb_segment()` in `net/core/skbuff.c`. When building GSO segments from an skb that has a `frag_list`, the function propagates `SKBFL_SHARED_FRAG` only from the head skb. If a frag_list member carries page-cache-backed frags with the flag set but the head does not, the resulting segment skbs lose the marker. This lets them pass the `skip_cow` guard in `esp_input()` and get decrypted in place over page-cache pages, same primitive as the original Dirty Frag and Fragnesia exploits.

Triggering it requires three network namespaces connected by veth pairs. The sender does a normal `send()` followed by `splice()` on the same TCP connection. GRO on the forwarding hop coalesces the two into a single skb where the `send()` segment becomes the head (no flag) and the `splice()` segment goes into the frag_list (flag set). The forwarder has GSO disabled on its egress veth, so `skb_segment()` fires and strips the flag. The segments then reach an espintcp receiver that decrypts in place. The GRO coalescing step requires both segments to arrive in the same NAPI poll cycle, which is reliable with back-to-back sends but not fully deterministic, so the exploit retries on failure. The rest of the exploitation is identical to Fragnesia: AES-GCM keystream control gives a deterministic one-byte page-cache write per trigger, and the exploit iterates over a small ELF payload to overwrite a SUID binary.

We have reported this to the relevant parties. There is a pending patch (not currently accepted or merged) on the netdev list that would incidentally help prevent this by propagating the flag earlier in the GRO path, though it was not written to address this bug specifically, and no patch currently proposed fixes the root cause in `skb_segment()` itself.

## Building and running

```
make
sudo modprobe esp4
./skb_segment_exploit
```

It auto-discovers a suitable SUID-root binary, backs it up to `/tmp`, and prints a restore command before launching the root shell. The page-cache corruption is not written to disk. To restore normal operation without rebooting:

```
echo 1 | sudo tee /proc/sys/vm/drop_caches
```

Ubuntu users need to disable the AppArmor userns restriction first. See the [Fragnesia README](../fragnesia/README.md) for details.

## Mitigation

Same mitigation as Fragnesia and Dirty Frag. See [the Fragnesia README](../fragnesia/README.md) for instructions. Blacklisting `esp4`, `esp6`, and `rxrpc` blocks the attack surface.

## Credit

Found with [V12](https://v12.sh) by the V12 team.
