#!/bin/bash
# pve_vm_screens.sh — capture the console screen of every running VM on a
# Proxmox host as a PNG, through QEMU's monitor (screendump), and copy them
# here.  For reading what a guest showed when it failed (an installer's error
# dialog, a kernel panic) without a VNC client.
#
# Usage: scripts/pve_vm_screens.sh <host> <outdir> [vmid ...]
#   (no vmid: every running VM on the host)
# Writes <outdir>/<host>-vm<vmid>.png; prints one line per VM.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
[ "$#" -ge 2 ] || { echo "usage: $0 <host> <outdir> [vmid ...]"; exit 2; }
HOST=$1; OUT=$2; shift 2
mkdir -p "$OUT" || exit 1
on() { timeout "${2:-30}" "$SSHP" "$HOST" "$1" </dev/null 2>/dev/null | grep -avE '^Warning:|^Unauthorized|^If you'; }
IDS=("$@")
if [ "${#IDS[@]}" = 0 ]; then
    read -r -a IDS <<<"$(on "qm list 2>/dev/null | awk 'NR>1 && \$3==\"running\" {print \$1}' | tr '\n' ' '")"
fi
for id in "${IDS[@]}"; do
    # Proxmox builds QEMU without libpng ("Enable PNG support with libpng for
    # screendump"), so the guest screen is dumped as PPM by the QEMU process
    # on the host, gzipped, read back over ssh as base64 and turned into a
    # PNG here.  HMP syntax: screendump filename [-f format] [device [head]]
    on "rm -f /tmp/pve_vm_screen_$id.ppm; echo 'screendump /tmp/pve_vm_screen_$id.ppm' | qm monitor $id >/dev/null 2>&1; sleep 1; test -s /tmp/pve_vm_screen_$id.ppm && gzip -c /tmp/pve_vm_screen_$id.ppm | base64 -w0; rm -f /tmp/pve_vm_screen_$id.ppm" 60 \
        | base64 -d 2>/dev/null | gunzip -c 2>/dev/null \
        | python3 -c 'import sys, io; from PIL import Image; Image.open(io.BytesIO(sys.stdin.buffer.read())).save(sys.argv[1], "PNG")' "$OUT/$HOST-vm$id.png" 2>/dev/null
    if [ -s "$OUT/$HOST-vm$id.png" ]; then
        echo "$HOST vm $id: $OUT/$HOST-vm$id.png ($(stat -c %s "$OUT/$HOST-vm$id.png") bytes)"
    else
        rm -f "$OUT/$HOST-vm$id.png"
        echo "$HOST vm $id: no screen captured"
    fi
done
