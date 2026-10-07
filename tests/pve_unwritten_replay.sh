#!/bin/bash
# pve_unwritten_replay.sh — does a survivor's replay of its dead peer's journal
# keep the peer's unwritten-to-written conversions?
#
# A write into an unwritten extent (a fallocated region, or the unwritten
# extent XFS allocates for a direct write into a hole) converts it to written
# when the I/O completes.  Where the conversion only grows the written extent
# before it (a sequential writer), the extent count does not change and the
# transaction logs the data fork alone, without the core; on a clustered mount
# di_changecount moves only when the core is logged.  The foreign replay's
# gate keeps a logged inode image only when its change count is above the
# newer of the buffer slot's and the platter's, so every image after the first
# one of an unmoved count would be skipped, the extent left unwritten, and
# data the dead host had written and fdatasync'ed would read back as zeros.
#
# Participant 1 fallocates a file, then writes COUNT blocks of BLOCK bytes
# sequentially (STRIDE apart) with O_DIRECT and an fdatasync after each,
# reporting each block once its fdatasync has returned, and resets itself the
# moment the last one returns.  Participant 0 recovers it and reads every block
# reported durable; so does participant 1 once it has rejoined.  The survivor's
# replay verdicts on the file's inode are kept (P77-FRINODE, switched on for
# the run).
#
# Usage: tests/pve_unwritten_replay.sh
# Env:   PVE_PAIR (default the nested pair "192.168.120.137 192.168.120.192";
#        participant 0 is the lower address), COUNT (64), BLOCK (65536),
#        STRIDE (65536: back to back)
# Evidence: tests/evidence/pve_unwritten_replay/<UTC stamp>-<participant 0>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PROG="$REPO/tests/pve_unwritten_replay.py"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_unwritten_replay: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
COUNT=${COUNT:-64}
BLOCK=${BLOCK:-65536}
STRIDE=${STRIDE:-65536}
# The writer: COUNT direct writes and fdatasyncs through DRBD, ~10-20 ms each
# on either pair; twice that, rounded up.
WRITE_BUDGET=60
# From the reset to the survivor's P163-RECOVERY-COMPLETE (tests/pve_pair_failover.sh).
RECOVER_BUDGET=60
# From the reset to participant 1 mounted as half of the pair again: its boot
# (BOOT_BUDGET of the suite) plus the rejoin (REJOIN_BUDGET of the suite).
REJOIN_BUDGET=480
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
EVID="$REPO/tests/evidence/pve_unwritten_replay/$STAMP-$P0"
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
die() { say "FAIL: $*"; on "$P0" "echo 'format P77-FRINODE -p' > /proc/dynamic_debug/control" 15 >/dev/null; exit 1; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
on_prog() {  # <host> <args> [timeout]: the program fed on stdin
    timeout "${3:-60}" "$SSHP" "$1" "python3 - $2" <"$PROG" 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
STATE_CMD='echo "unit=$(systemctl is-active mxfs-drbd@'"$RES"') mnt=$(awk '\''$2 == "'"$MNT"'" && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1) role=$(drbdadm role '"$RES"' 2>/dev/null) cs=$(drbdadm cstate '"$RES"' 2>/dev/null) ds=$(drbdadm dstate '"$RES"' 2>/dev/null) build=$(cat /sys/module/mxfs/srcversion 2>/dev/null)"'
state() { on "$1" "$STATE_CMD" 20 | grep '^unit='; }
pair_ok() { case "$1" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate "*) return 0 ;; esac; return 1; }

s0=$(state "$P0"); s1=$(state "$P1")
pair_ok "$s0" || die "$P0 is not up as half of the pair: ${s0:-no answer}"
pair_ok "$s1" || die "$P1 is not up as half of the pair: ${s1:-no answer}"
BUILD=${s0##*build=}
[ "$BUILD" = "${s1##*build=}" ] || die "the hosts run different builds: $s0 / $s1"
say "unwritten replay: participant 0 $P0 survives, participant 1 $P1 writes and is reset; build $BUILD; $COUNT blocks of $BLOCK bytes, $STRIDE apart; evidence $EVID"

# the survivor's per-inode replay verdicts, for this run only
on "$P0" "echo 'format P77-FRINODE +p' > /proc/dynamic_debug/control && grep -c 'P77-FRINODE' /proc/dynamic_debug/control" 15 | grep -q '^[1-9]' \
    || die "could not switch P77-FRINODE on on $P0"

F=$MNT/uwr/$STAMP
# An unwritten tail stays past the last block written: the write that reached
# the end would merge the two extents into one, change the extent count, log
# the core and move the change count, and its image would carry every block.
ino=$(on "$P1" "echo 1 > /proc/sys/kernel/sysrq && mkdir -p $MNT/uwr && fallocate -l $(( (COUNT + 8) * STRIDE )) $F && sync -f $MNT/uwr && stat -c %i $F" 60 | tail -1)
[ -n "$ino" ] && [ "$ino" -gt 0 ] 2>/dev/null || die "$P1 could not fallocate $F: $ino"
say "  $P1 fallocated $F (inode $ino, $(( (COUNT + 8) * STRIDE )) bytes, unwritten)"

t0=$(date +%s)
on_prog "$P1" "write $F 0 $COUNT $BLOCK $STRIDE 1" "$WRITE_BUDGET" > "$EVID/writer.out"
durable=$(sed -n 's/^DURABLE //p' "$EVID/writer.out" | tr '\n' ' ')
nd=$(wc -w <<<"$durable")
grep -q '^SHORT' "$EVID/writer.out" && die "a write came back short: $(grep '^SHORT' "$EVID/writer.out")"
[ "$nd" -gt 1 ] || die "INVALID RUN: $P1 reported $nd durable blocks before its reset"
say "  $P1 reset after its last fdatasync; $nd of $COUNT blocks reported durable ($(( $(date +%s) - t0 )) s)"

t1=$(date +%s)
while :; do
    out=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P163-RECOVERY-COMPLETE|P-RBLK-(COVERS|DENY)-[A-Z-]+|P240-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
    grep -q P163-RECOVERY-COMPLETE <<<"$out" && break
    [ $(( $(date +%s) - t1 )) -lt "$RECOVER_BUDGET" ] || die "$P0 did not complete the recovery within ${RECOVER_BUDGET}s: $out"
    sleep 3
done
say "  $P0 recovered $P1 $(( $(date +%s) - t0 )) s after the reset: $out"

on_prog "$P0" "read $F $BLOCK $STRIDE $durable" 120 > "$EVID/read.$P0"
on "$P0" "journalctl -k --no-pager -o short-iso --since @$t0 | grep -aE 'P77-|P163-|P236-FENCE-CERTIFIED|P226-|foreign replay|XFS' | cut -c1-500" 60 > "$EVID/klog.$P0"
on "$P0" "echo 'format P77-FRINODE -p' > /proc/dynamic_debug/control" 15 >/dev/null
v0=$(awk '{print $3}' "$EVID/read.$P0" | sort | uniq -c | tr '\n' ' ')
say "  $P0 reads the $nd durable blocks: $v0"
say "  $P0's replay verdicts on inode $ino: $(grep -aE "P77-FRINODE [a-z]+ ino=$ino " "$EVID/klog.$P0" | grep -aoE 'disk_cc=[0-9]+ log_cc=[0-9]+|verdict=[A-Z]+' | paste -d' ' - - | sort | uniq -c | tr '\n' ';')"

t2=$(date +%s)
while :; do
    s=$(state "$P1")
    pair_ok "$s" && break
    [ $(( $(date +%s) - t0 )) -lt "$REJOIN_BUDGET" ] || die "$P1 not mounted as half of the pair within ${REJOIN_BUDGET}s of its reset: ${s:-no answer}"
    sleep 5
done
say "  $P1 mounted again $(( $(date +%s) - t0 )) s after its reset"
on_prog "$P1" "read $F $BLOCK $STRIDE $durable" 120 > "$EVID/read.$P1"
v1=$(awk '{print $3}' "$EVID/read.$P1" | sort | uniq -c | tr '\n' ' ')
say "  $P1 reads the $nd durable blocks: $v1"

bad=$(cat "$EVID/read.$P0" "$EVID/read.$P1" | grep -vc ' OK ')
n0=$(grep -c ' OK ' "$EVID/read.$P0"); n1=$(grep -c ' OK ' "$EVID/read.$P1")
[ "$n0" = "$nd" ] && [ "$n1" = "$nd" ] && [ "$bad" = 0 ] || die "durable blocks lost: $P0 reads $n0 of $nd intact ($v0), $P1 reads $n1 of $nd ($v1); first bad: $(grep -vh ' OK ' "$EVID/read.$P0" "$EVID/read.$P1" | head -3 | tr '\n' ' ')"
say "PASS: every block $P1 reported durable reads back intact on both hosts"
