#!/bin/sh
set -eux

mkdir -p images
mkdir -p poc

cp /boot/vmlinuz-linux images/vmlinuz-linux
chmod 0755 images/vmlinuz-linux

curl -L --fail --show-error \
  -o images/alpine-latest-releases.yaml \
  https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/latest-releases.yaml

curl -L --fail --show-error \
  -o images/alpine-minirootfs-3.23.4-x86_64.tar.gz \
  https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/alpine-minirootfs-3.23.4-x86_64.tar.gz

rm -rf alpine_root_fs.tmp
mkdir -p alpine_root_fs.tmp
tar -xzf images/alpine-minirootfs-3.23.4-x86_64.tar.gz -C alpine_root_fs.tmp

printf '%s\n' \
  https://dl-cdn.alpinelinux.org/alpine/v3.23/main \
  https://dl-cdn.alpinelinux.org/alpine/v3.23/community \
  > alpine_root_fs.tmp/etc/apk/repositories

rm -f alpine_root_fs.tmp/sbin/init
cat > alpine_root_fs.tmp/sbin/init <<'EOF'
#!/bin/sh

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true

exec /bin/sh </dev/console >/dev/console 2>&1
EOF
chmod 0755 alpine_root_fs.tmp/sbin/init

gcc -static -O2 -Wall -Wextra -o exp/exp exp/exp.c

cp exp/exp alpine_root_fs.tmp/exp
chmod 0755 alpine_root_fs.tmp/exp

rm -f images/alpine.tmp
truncate -s 128M images/alpine.tmp
mkfs.ext4 -q -F -d alpine_root_fs.tmp images/alpine.tmp

rm -rf alpine_root_fs
mv alpine_root_fs.tmp alpine_root_fs
mv images/alpine.tmp images/alpine

echo done
