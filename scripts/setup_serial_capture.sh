#!/bin/bash
# setup_serial_capture.sh — enable panic-capturing serial consoles on ALL test VMs
# (ccloop 46efd8b6 sess2: test12 panicked mid-run; panic text lost — only
# test1-4 had serial logs, and append='off' truncates on virsh destroy/start.)
#
# Guest side: ensure console=ttyS0,115200 log_buf_len=16M loglevel=3 in
#   GRUB_CMDLINE_LINUX_DEFAULT + update-grub.
# Host side: ensure <log file='/var/log/libvirt/qemu/testN-serial.log'
#   append='on'/> inside the <serial type='pty'> device.
# Then power-cycle the VM so both take effect.
#
# Usage: setup_serial_capture.sh [N]   (default 32) — processes test1..testN in parallel.
set -u
N="${1:-32}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fix_guest() {  # <node> — returns 0 if grub was already right (no reboot needed for guest side)
    local n="$1"
    timeout 60 "$SSH" "$n" "$PF" '
        set -e
        G=/etc/default/grub
        want="log_buf_len=16M console=ttyS0,115200 loglevel=3"
        if grep -q "console=ttyS0" /proc/cmdline; then echo GUEST_LIVE_OK; fi
        if grep -q "console=ttyS0,115200" "$G"; then
            echo GUEST_GRUB_OK
        else
            cp "$G" "$G.pre_serial"
            sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"$want /" "$G"
            update-grub >/dev/null 2>&1
            echo GUEST_GRUB_PATCHED
        fi' 2>/dev/null
}

fix_host_xml() {  # <node> — returns HOST_OK / HOST_PATCHED / HOST_FAIL
    local n="$1" x="$TMP/$n.xml"
    virsh -c qemu:///system dumpxml "$n" > "$x" 2>/dev/null || { echo HOST_FAIL; return; }
    python3 - "$x" "$n" <<'PY'
import re, sys
p, node = sys.argv[1], sys.argv[2]
s = open(p).read()
logline = f"      <log file='/var/log/libvirt/qemu/{node}-serial.log' append='on'/>\n"
m = re.search(r"(    <serial type='pty'>\n)(.*?)(    </serial>)", s, re.S)
if not m:
    print("HOST_FAIL_NO_SERIAL"); sys.exit(0)
body = m.group(2)
if "append='on'" in body and '-serial.log' in body:
    print("HOST_OK"); sys.exit(0)
if '<log ' in body:
    body2 = re.sub(r"      <log [^\n]*\n", logline, body)
else:
    body2 = logline + body
s2 = s[:m.start(2)] + body2 + s[m.end(2):]
open(p, 'w').write(s2)
print("HOST_PATCHED")
PY
}

do_node() {
    local i="$1" n="test$1" g h defrc=0
    g=$(fix_guest "$n")
    h=$(fix_host_xml "$n")
    if [ "$h" = HOST_PATCHED ]; then
        virsh -c qemu:///system define "$TMP/$n.xml" >/dev/null 2>&1 || { echo "$n: DEFINE_FAIL"; return 1; }
    fi
    # Reboot needed if guest cmdline lacks console OR host XML changed (new
    # device config only applies on next QEMU start = destroy+start).
    if ! echo "$g" | grep -q GUEST_LIVE_OK || [ "$h" = HOST_PATCHED ]; then
        virsh -c qemu:///system destroy "$n" >/dev/null 2>&1
        sleep 1
        virsh -c qemu:///system start "$n" >/dev/null 2>&1
        echo "$n: $g $h CYCLED"
    else
        echo "$n: $g $h no-cycle"
    fi
}

pids=()
for i in $(seq 1 "$N"); do do_node "$i" & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
echo "=== all $N nodes processed ==="
