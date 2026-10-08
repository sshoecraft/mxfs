#!/bin/bash
# pve_delalloc_overcommit.sh — can two hosts both accept buffered writes for
# the same last free blocks?
#
# A buffered write reserves its blocks (delayed allocation) from the writing
# host's own free-space counter and allocates them only at writeback.  Each
# host's counter counts the same physical free space, so near full both hosts
# can accept writes that together need more than is free; the host whose
# writeback allocates second then finds no blocks, and data write() already
# accepted is lost (fsync reports it).  Upstream XFS never fails writeback for
# space: its reservation is the whole filesystem's.
#
# Participant 0 fills the filesystem with fallocate until LEFT_MIB remain;
# then both hosts write WRITE_MIB buffered at once (dd, no sync until the end,
# conv=fsync) and report how the write and the fsync ended, and both hosts'
# kernel logs are read for writeback errors.  Correct: whatever does not fit is
# refused at write() time (dd's write error), never by the fsync after it.
#
# Usage: tests/pve_delalloc_overcommit.sh [label]
# Env:
#   PVE_PAIR   "<addr> <addr>" (default nested pair A); participant 0 fills
#   LEFT_MIB   free space left before the writes (3072)
#   WRITE_MIB  each host's buffered write (2048: two of them need more than
#              LEFT_MIB, one fits)
#   STEP_BUDGET seconds the writes and the fsync may take (180: 2 GiB buffered
#              on the nested pair's replicated disk).  On the physical pair
#              pass 210: the two writes put LEFT_MIB (3 GiB) on each disk,
#              which XFS on a scratch DRBD resource there writes in ~104 s
#              (tests/evidence/yardstick-3g-0.90.105.log), twice that
# Exit 0 when neither host's fsync failed after its writes were accepted and
# neither kernel log shows a writeback error or a shutdown.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
LABEL=${1:-run}
read -r -a H <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
MNT=/mnt/shared
LEFT_MIB=${LEFT_MIB:-3072}
WRITE_MIB=${WRITE_MIB:-2048}
BUDGET=${STEP_BUDGET:-180}
D=$MNT/overcommit
EVID="$REPO/tests/evidence/pve_delalloc_overcommit/$(date -u +%Y%m%dT%H%M%SZ)-$LABEL"
mkdir -p "$EVID" || exit 1
bad=0

on() {  # <host> <cmd> <timeout>
    timeout "$3" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }

T0=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
say "label=$LABEL pair=${H[*]} left=${LEFT_MIB}MiB write=${WRITE_MIB}MiB evidence=$EVID"
for h in "${H[@]}"; do
    say "$(on "$h" "echo \$(uname -n) build=\$(cat /sys/module/mxfs/srcversion) \$(df -k --output=size,used,avail $MNT | tail -1)" 30)"
done
avail=$(on "${H[0]}" "mkdir -p $D && df -k --output=avail $MNT | tail -1" 30 | tr -d ' ')
fill=$(( avail / 1024 - LEFT_MIB ))
[ "$fill" -gt 0 ] || { say "only $avail KiB available; nothing to fill"; exit 1; }
say "fill $(on "${H[0]}" "fallocate -l ${fill}M $D/fill && sync && echo ok" 120)"
for h in "${H[@]}"; do
    say "after fill: $(on "$h" "uname -n; df -k --output=avail $MNT | tail -1" 30 | tr '\n' ' ')"
done

pids=()
for p in 0 1; do
    on "${H[$p]}" "dd if=/dev/zero of=$D/w$p bs=1M count=$WRITE_MIB conv=fsync 2>&1 | tail -3; echo DD_RC=\${PIPESTATUS[0]}; ls -l $D/w$p | awk '{print \"SIZE=\"\$5}'" "$BUDGET" > "$EVID/dd-p$p.out" 2>&1 &
    pids+=($!)
done
# every 10 s, per writer: its file size, the host's Dirty and Writeback (kB)
# and where dd waits, so a write that overruns the budget says whether it was
# accepting writes, flushing them (fsync), or stopped
t=0
while kill -0 "${pids[0]}" 2>/dev/null || kill -0 "${pids[1]}" 2>/dev/null; do
    sleep 10
    t=$((t + 10))
    for p in 0 1; do
        echo "t=${t}s p$p $(on "${H[$p]}" "echo \$(stat -c %s $D/w$p 2>/dev/null) \$(awk '/^(Dirty|Writeback):/ {printf \"%s=%s \", \$1, \$2}' /proc/meminfo) dd=\$(ps -o wchan:32= -C dd | tr -d ' ' | head -1)" 8 | tr '\n' ' ')" >> "$EVID/progress"
    done
done
wait "${pids[@]}"
say "progress (last 10 s samples): $(tail -4 "$EVID/progress" | tr '\n' ' ')"
for p in 0 1; do
    say "p$p ${H[$p]}: $(tr '\n' ' ' < "$EVID/dd-p$p.out")"
done
for p in 0 1; do
    out=$(cat "$EVID/dd-p$p.out")
    rc=$(grep -o 'DD_RC=[0-9]*' <<<"$out" | cut -d= -f2)
    size=$(grep -o 'SIZE=[0-9]*' <<<"$out" | cut -d= -f2)
    if [ -z "$rc" ]; then
        say "p$p: the write did not finish within ${BUDGET} s; last samples: $(grep " p$p " "$EVID/progress" | tail -3 | tr '\n' ' ')"
        bad=1
        continue
    fi
    # every byte accepted (the file reached its full size) and still a
    # failure: the refusal came after write(), from the fsync
    if [ "${rc:-1}" != 0 ] && [ "${size:-0}" -ge $(( WRITE_MIB * 1048576 )) ]; then
        say "p$p: every write accepted, then the fsync failed: data lost"
        bad=1
    fi
done
for h in "${H[@]}"; do
    # data lost or the filesystem stopped: a failure.  So is a task blocked
    # past the hung-task timeout: a write refused for want of space must be
    # refused promptly, not after the host's whole dirty set is written back.
    k=$(on "$h" "journalctl -k --no-pager --since '$T0' | grep -aiE 'writeback error|page discard|shut.?down|metadata I/O error|corrupt' | sed 's/^.*kernel: //' | cut -c1-200 | tail -12" 60)
    hung=$(on "$h" "journalctl -k --no-pager --since '$T0' | grep -ac 'blocked for more than'" 60)
    printf '%s\n' "$k" > "$EVID/klog-$h"
    say "$h hung-task reports: ${hung:-0}"
    [ "${hung:-0}" = 0 ] || bad=1
    if [ -n "$k" ]; then
        say "$h kernel log:"; printf '%s\n' "$k" | tee -a "$EVID/log"
        bad=1
    fi
done
say "cleanup $(on "${H[0]}" "rm -rf $D && sync && echo ok" 120)"
[ "$bad" = 0 ] && say "RESULT PASS" || say "RESULT FAIL"
exit "$bad"
