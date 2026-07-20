#!/bin/bash
# repro_logwedge_full.sh — reproduce the single-node log WEDGE with the FULL
# recursive rsync (the subset variant in repro_logwedge.sh does NOT reliably
# wedge at 32MB slice; the full concurrent recursive copy does).
#
# Mounts single-node mxfs fresh with mxfs.instr=1 so the P-LWEDGE diagnostic
# in xfsaild_push fires, runs `rsync -a $SRC/ $MNT/w/`, and once the wedge is
# detected (D-state on xlog_grant_head_wait) dumps:
#   - the last P-LWEDGE lines (xfsaild push verdict: success/pinned/locked/flushing)
#   - xfsaild stack + state
#   - grant-waiting writer stacks
#
# Usage: tests/repro_logwedge_full.sh [node]   (default test1)
set -u
N="${1:-test1}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
SRC=/root/open-gpu-kernel-modules
MNT=/mnt/shared

ssh_n() { timeout "${2:-60}" "$SSH" "$N" "$PASS" "$1" 2>&1 | grep -vE 'Warning|Unauthorized|disconnect|^$'; }

echo "=== fresh single-node mxfs mount on $N (instr=1) ==="
ssh_n 'umount '"$MNT"' 2>/dev/null; rmmod mxfs 2>/dev/null; true' 40 >/dev/null
ssh_n '/src/mxfs/tools/prep_tcm_node_scst.sh >/tmp/p.log 2>&1; modprobe libcrc32c; lsmod|grep -q "^mxfs " || insmod /src/mxfs/mxfs.ko instr=1; echo 1 > /sys/module/mxfs/parameters/instr; echo "instr=$(cat /sys/module/mxfs/parameters/instr)"; sg_persist --out --register-ignore --param-sark=0x5eed /dev/sda >/dev/null 2>&1; sg_persist --out --clear --param-rk=0x5eed /dev/sda >/dev/null 2>&1; echo y|/src/mxfs/tools/mkfs_mxfs /dev/sda >/tmp/m.log 2>&1 && echo MKFS_OK; grep -i "slice\|log:" /tmp/m.log; mount -t mxfs /dev/sda '"$MNT"' && echo MOUNT_OK' 90

echo "=== clear dmesg, start FULL recursive rsync ==="
ssh_n 'dmesg -C; rm -rf '"$MNT"'/w; mkdir -p '"$MNT"'/w; (rsync -a '"$SRC"'/ '"$MNT"'/w/ >/tmp/rs.log 2>&1; echo DONE_$? >/tmp/rs.done) & echo started' 15 >/dev/null

res="TIMEOUT"
for t in $(seq 1 36); do
    sleep 5
    d=$(ssh_n 'cat /tmp/rs.done 2>/dev/null' 8)
    if [ -n "$d" ]; then res="$d"; break; fi
    w=$(ssh_n 'for p in $(ps -eo pid,stat|awk "\$2~/D/{print \$1}"); do grep -ql xlog_grant_head_wait /proc/$p/stack 2>/dev/null && echo W; done | head -1' 12)
    if [ "$w" = "W" ]; then res="WEDGED(log_reserve)"; break; fi
done
echo "  rsync result -> $res  (after ~$((t*5))s)"

echo "=== xfsaild state + stack ==="
ssh_n 'for p in $(pgrep -f "xfsaild/sda"); do echo "pid=$p stat=$(cat /proc/$p/stat|awk "{print \$3}")"; cat /proc/$p/stack 2>/dev/null; done' 12

echo "=== grant-waiting writers (D on xlog_grant_head_wait) ==="
ssh_n 'for p in $(ps -eo pid,stat|awk "\$2~/D/{print \$1}"); do if grep -ql xlog_grant_head_wait /proc/$p/stack 2>/dev/null; then echo "pid=$p comm=$(cat /proc/$p/comm)"; fi; done' 12

echo "=== last 25 P-LWEDGE lines (xfsaild push verdict) ==="
ssh_n 'dmesg | grep P-LWEDGE | tail -25' 12

echo "=== RESULT: $res ==="
[ "$res" = "WEDGED(log_reserve)" ] && exit 1 || exit 0
