#!/bin/sh
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMPDIR=${TMPDIR:-"$DIR/tmp"}
export TMPDIR

ROOTFS="$DIR/images/alpine"
ROOTFS_GZ="$ROOTFS.gz"

mkdir -p "$TMPDIR"

if [ ! -e "$ROOTFS" ]; then
  if [ ! -f "$ROOTFS_GZ" ]; then
    echo "missing rootfs: $ROOTFS_GZ" >&2
    exit 1
  fi

  ROOTFS_TMP="$ROOTFS.$$"
  trap 'rm -f "$ROOTFS_TMP"' EXIT HUP INT TERM
  gzip -dc "$ROOTFS_GZ" > "$ROOTFS_TMP"
  mv "$ROOTFS_TMP" "$ROOTFS"
  trap - EXIT HUP INT TERM
fi

exec "$DIR/qemu-system-x86_64" \
  -accel tcg \
  -machine q35,cxl=on \
  -m 512M,maxmem=2G,slots=4 \
  -smp 1 \
  -nographic -no-reboot -snapshot \
  -kernel "$DIR/images/vmlinuz-linux" \
  -append "root=/dev/vda rw console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200 loglevel=8 ignore_loglevel printk.time=1 devtmpfs.mount=1 pci=realloc" \
  -drive file="$ROOTFS",file.locking=off,if=none,format=raw,id=rootfs \
  -device virtio-blk-pci,drive=rootfs \
  -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
  -device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 \
  -object memory-backend-ram,id=cxl-mem0,size=256M \
  -object memory-backend-ram,id=dc-mem0,size=256M \
  -device cxl-type3,bus=rp0,volatile-memdev=cxl-mem0,volatile-dc-memdev=dc-mem0,num-dc-regions=1,id=mem0 \
  -M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=512M
