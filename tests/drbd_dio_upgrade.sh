#!/bin/bash
# drbd_dio_upgrade.sh — does a synchronous direct write that allocates finish
# while the peer holds the file's inode lock shared?
#
# An aligned direct write takes the IOLOCK shared (the inode's cluster lock at
# PR) and, when it lands in a hole, allocates under the ILOCK exclusive: an
# upgrade of the same cluster lock to EX, in the same task, while its own PR
# hold is still counted.  When the peer holds the inode at PR (one stat leaves
# it cached there) the master refuses the upgrade (P-CONVBLK-DENY, -EDEADLK)
# and the writer must drop its PR through the release drain first, which its
# own hold keeps from completing (P15-REL-ABORT).  Proxmox stats every image on
# shared storage from both hosts, so a VM's allocating writes meet exactly this.
#
# Each round: the writer node writes one block into its file (so the inode
# exists and its lock is held there), the peer stats the file, then the writer
# times one 1 MiB O_DIRECT write into a hole of the file.
#
# Usage: tests/drbd_dio_upgrade.sh <writer node> <peer node> [rounds]
#   nodes are rig names (tools/mxfs_lab.sh) or addresses; MXFS mounted at
#   $MNT (default /mnt/shared) on both.
# Env: WRITE_BUDGET_MS  per write (default 1000: a 1 MiB direct write on the
#      rig's DRBD takes ~10-30 ms, one lock upgrade round trip and its ledger
#      commit some tens more; a refused upgrade that has to be retried is the
#      failure this measures)
#      MNT, EVID
# Exit 0 only when every write finished within its budget and neither node
# logged a shutdown.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO/tools/mxfs_lab.sh"
SSH="$REPO/tools/mxfs_sshpass.sh"
W=${1:?writer node}; P=${2:?peer node}; ROUNDS=${3:-10}
MNT=${MNT:-/mnt/shared}
BUDGET=${WRITE_BUDGET_MS:-1000}
EVID=${EVID:-$REPO/tests/evidence/drbd_dio_upgrade/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$EVID" || exit 1
SUM="$EVID/summary.txt"
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUM"; }
addr() { case "$1" in [0-9]*) echo "$1" ;; *) lab_addr "$1" ;; esac; }
WA=$(addr "$W"); PA=$(addr "$P")
on() {  # <addr> <cmd> [timeout]
    timeout "${3:-30}" "$SSH" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
DIR="$MNT/dio_upgrade.$$"
TAGS='P-CONVBLK-DENY|P15-REL-ABORT|P79-STALEBAST-CLEAR|P109-EDEADLK|EDEADLK retry livelock|EDEADLK-NL retry livelock|xfs_do_force_shutdown|Filesystem has been shut down|P131-SELF-FENCE'
for a in "$WA" "$PA"; do
    on "$a" "echo '<5>mxfs-test: dio_upgrade start $$' > /dev/kmsg"
done
on "$WA" "mkdir -p $DIR && echo DIR_OK" | grep -q DIR_OK || { say "ABORT: cannot create $DIR on $W"; exit 1; }
fails=0
for r in $(seq 1 "$ROUNDS"); do
    f="$DIR/f$r"
    # the file, its inode lock held on the writer
    on "$WA" "dd if=/dev/zero of=$f bs=4096 count=1 oflag=direct conv=fsync status=none && truncate -s 1G $f && echo MK_OK" \
        | grep -q MK_OK || { say "round $r: ABORT: could not create $f on $W"; fails=$((fails + 1)); break; }
    # the peer takes the inode at PR and keeps it cached
    on "$PA" "stat -c '%s %i' $f" > "$EVID/r$r.peerstat" 2>&1
    # one direct write into a hole, in this task: IOLOCK shared, then allocation
    out=$(on "$WA" "s=\$(date +%s%N); timeout 120 dd if=/dev/zero of=$f bs=1M count=1 seek=$((100 + r)) oflag=direct conv=notrunc status=none; rc=\$?; echo WRITE rc=\$rc ms=\$(( (\$(date +%s%N) - s) / 1000000 ))" 150)
    echo "$out" > "$EVID/r$r.write"
    ms=$(sed -n 's/.*WRITE rc=\([0-9]*\) ms=\([0-9]*\).*/\2/p' <<<"$out")
    rc=$(sed -n 's/.*WRITE rc=\([0-9]*\) ms=.*/\1/p' <<<"$out")
    if [ -z "$ms" ] || [ "$rc" != 0 ] || [ "$ms" -gt "$BUDGET" ]; then
        say "round $r: FAIL write rc=${rc:-none} ms=${ms:-none} (budget ${BUDGET} ms); peer stat: $(tr '\n' ' ' < "$EVID/r$r.peerstat")"
        fails=$((fails + 1))
    else
        say "round $r: write rc=0 ms=$ms"
    fi
done
on "$WA" "rm -rf $DIR" 60 >/dev/null
for a in "$WA" "$PA"; do
    on "$a" "dmesg | sed -n '/mxfs-test: dio_upgrade start $$/,\$p'" 60 > "$EVID/kmsg.$a"
    say "$a: $(grep -aoE "$TAGS" "$EVID/kmsg.$a" | sort | uniq -c | tr '\n' ';' | tr -s ' ')"
done
shut=$(grep -alE 'xfs_do_force_shutdown|Filesystem has been shut down|retry livelock|P131-SELF-FENCE' "$EVID"/kmsg.* | wc -l)
if [ "$fails" = 0 ] && [ "$shut" = 0 ]; then
    say "PASS: $ROUNDS direct writes into a hole, each within ${BUDGET} ms, with the peer holding the inode shared; evidence $EVID"
    exit 0
fi
say "FAIL: $fails of $ROUNDS writes failed or overran, $shut node(s) logged a shutdown; evidence $EVID"
exit 1
