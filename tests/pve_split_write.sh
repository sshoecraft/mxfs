#!/bin/bash
# pve_split_write.sh — large writes through the DRBD write window on each host
# of an MXFS-on-DRBD Proxmox pair, and the peer reading them back.
#
# The window (pal/linux/drbd.c, mxfs_pal_ioq_admit) splits any write larger
# than its chunk (1 MiB) into pieces chained to the rest and hooks each
# piece's completion.  Until 0.90.110 the hook called the restored completion
# directly, which for a chained piece is bio_chain_endio: a BUG() on Linux 7.0
# (kernel BUG at block/bio.c:367), so a host on Proxmox's 7.0 kernel crashed
# on its first large writeback.  This writes SIZE_MIB of random data with
# fsync, LAPS times on each host, checks every write's exit status and wall,
# the peer's read of it against the source's md5, and both kernels for a BUG,
# Oops, DRBD BrokenPipe or heartbeat stall that was not there before.  CYCLE=1 also stops and starts
# the first host's unit and prints its window's P-DRBD-IOQ-DONE line, whose
# split= count says the window did split (a run with split=0 proves nothing).
#
# Usage: tests/pve_split_write.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default the nested pair, which runs the 7.0
#              kernel; the physical pair runs 6.17)
#   SIZE_MIB   per write (default 256)
#   LAPS       writes per host (default 3)
#   WRITE_BUDGET  seconds per write (default 20: 2.4 s measured on the nested
#              pair, with room for a loaded clyde)
#   CYCLE      1 = stop/start the first host's unit afterwards (default 1)
# Evidence: tests/evidence/pve_split_write/<UTC stamp>/log
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.120.192 192.168.120.137}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_split_write: PVE_PAIR must name two hosts"; exit 2; }
SIZE_MIB=${SIZE_MIB:-256}
LAPS=${LAPS:-3}
WRITE_BUDGET=${WRITE_BUDGET:-20}
CYCLE=${CYCLE:-1}
MNT=/mnt/shared
EVID="$REPO/tests/evidence/pve_split_write/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 2
bad=0

on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
faults() { on "$1" "dmesg | grep -acE 'kernel BUG|Oops|bio_chain_endio|BrokenPipe|P278-HB-STALL'" 20; }

declare -A before
for h in "${PAIR[@]}"; do
    before[$h]=$(faults "$h")
    say "$h: $(on "$h" 'cat /sys/module/mxfs/srcversion; uname -r; drbdadm cstate mxfs' 20 | tr '\n' ' ') faults_before=${before[$h]}"
done
peer() { [ "$1" = "${PAIR[0]}" ] && echo "${PAIR[1]}" || echo "${PAIR[0]}"; }
for h in "${PAIR[@]}"; do
    p=$(peer "$h")
    on "$h" "dd if=/dev/urandom of=/root/split-src bs=1M count=$SIZE_MIB status=none && echo OK" 120 | grep -q OK \
        || { say "FAIL: $h could not make its source"; bad=1; continue; }
    src=$(on "$h" "md5sum < /root/split-src | cut -d' ' -f1" 60)
    for k in $(seq 1 "$LAPS"); do
        f="$MNT/split-write-$(on "$h" hostname 10)-$k"
        r=$(on "$h" "s=\$(date +%s%N); timeout $WRITE_BUDGET dd if=/root/split-src of=$f bs=4M conv=fsync status=none; rc=\$?; echo rc=\$rc ms=\$(( (\$(date +%s%N) - s) / 1000000 ))" $((WRITE_BUDGET + 15)))
        got=$(on "$p" "md5sum < $f | cut -d' ' -f1" 60)
        v=PASS
        grep -q 'rc=0 ' <<<"$r " || v=FAIL
        [ "$got" = "$src" ] || v=FAIL
        [ "$v" = PASS ] || bad=1
        say "$h write $k: ${r:-no answer} peer_md5_matches=$([ "$got" = "$src" ] && echo yes || echo "no ($got vs $src)") -> $v"
        on "$h" "rm -f $f" 60 >/dev/null
    done
    on "$h" "rm -f /root/split-src" 20 >/dev/null
done
for h in "${PAIR[@]}"; do
    n=$(faults "$h")
    say "$h: faults_after=${n:-unanswered} (before ${before[$h]})"
    [ -n "$n" ] && [ "$n" = "${before[$h]}" ] || bad=1
done
if [ "$CYCLE" = 1 ]; then
    h=${PAIR[0]}
    t=$(on "$h" "date +%s" 20)
    on "$h" "systemctl stop mxfs-drbd@mxfs" 200 >/dev/null
    say "$h window at unmount: $(on "$h" "journalctl -k --since @$t --no-pager -o cat | grep -a 'P-DRBD-IOQ-DONE' | tail -1 | grep -oE 'admitted=[0-9]+ split=[0-9]+'" 30)"
    on "$h" "systemctl start mxfs-drbd@mxfs" 200 >/dev/null
    t1=$(date +%s)
    until on "$h" "grep -q ' $MNT mxfs ' /proc/mounts && [ \"\$(drbdadm cstate mxfs)\" = Connected ] && [ \"\$(drbdadm dstate mxfs)\" = UpToDate/UpToDate ] && echo WHOLE" 20 | grep -q WHOLE; do
        [ $(( $(date +%s) - t1 )) -lt 300 ] || { say "FAIL: $h not whole again within 300 s"; bad=1; break; }
        sleep 5
    done
fi
[ "$bad" = 0 ] && say "RESULT: PASS" || say "RESULT: FAIL"
exit "$bad"
