#!/bin/bash
# pve_release_ack_trace.sh — do the lock releases a host gives up on
# (P-TAUTH-RELEASE-UNACKED) still get acknowledged by their master, later?
#
# A holder re-sends an unacknowledged release once a second and, after ten
# sends, frees it and logs P-TAUTH-RELEASE-UNACKED at error level.  The master
# acknowledges a release only once the ledger transition that retires it has
# committed, and a burst of releases (a node sweeping its idle read grants)
# queues those commits one behind another.  If the commits merely ran past the
# ten seconds, every given-up release is acknowledged later and the ack finds
# nothing to match: mxfs_dlm_process_release_ack returns -ENOENT.  If instead
# the masters never answer them, those late acks do not come.
#
# On both hosts a return probe on mxfs_dlm_process_release_ack records each
# ack's result in a tracing instance of its own (nothing goes to the kernel
# log), the given command runs from here, the hosts are left SETTLE_S to
# finish, and then, per host: acks matched (0), acks that matched nothing
# (-2), anything else, and the P-TAUTH-RELEASE-UNACKED lines over the window.
#
# Usage: tests/pve_release_ack_trace.sh <command ...>
#        e.g. tests/pve_release_ack_trace.sh tests/pve_tree_walk.sh seed both touch0
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), SETTLE_S (default 120:
#        a ten-send window plus the slowest burst measured, ~60 s, twice)
# Evidence: tests/evidence/pve_release_ack_trace/<UTC stamp>-<addr>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_release_ack_trace: PVE_PAIR must name two hosts"; exit 2; }
[ "$#" -gt 0 ] || { echo "usage: $0 <command ...>"; exit 2; }
SETTLE_S=${SETTLE_S:-120}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_release_ack_trace/$STAMP-${PAIR[0]}"
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

T=/sys/kernel/tracing
I=$T/instances/mxfs_relack
# Each ack's identity as it enters the handler, read from struct
# mxfs_dlm_release_ack (include/mxfs/mxfs_dlm.h, natural alignment): a 32-byte
# header, the 32-byte resource id (ino at +8 within it), grant_gen at 64,
# rel_id at 68, status at 88.  An entry probe and a return probe: the return
# says whether the ack matched a pending release (0) or nothing (-2).
ARM="set -e
grep -q 'mxfs_relack_in ' $T/kprobe_events 2>/dev/null || echo 'p:mxfs_relack_in mxfs_dlm_process_release_ack relid=+68(\$arg2):u32 ino=+40(\$arg2):u64 st=+88(\$arg2):u8' >> $T/kprobe_events
grep -q 'mxfs_relack ' $T/kprobe_events 2>/dev/null || echo 'r:mxfs_relack mxfs_dlm_process_release_ack ret=\$retval:s32' >> $T/kprobe_events
mkdir -p $I
echo 8192 > $I/buffer_size_kb
echo > $I/trace
echo 1 > $I/events/kprobes/mxfs_relack_in/enable
echo 1 > $I/events/kprobes/mxfs_relack/enable
echo 1 > $I/tracing_on
echo ARMED"
DISARM="echo 0 > $I/events/kprobes/mxfs_relack/enable 2>/dev/null; echo 0 > $I/events/kprobes/mxfs_relack_in/enable 2>/dev/null; echo 0 > $I/tracing_on 2>/dev/null; rmdir $I 2>/dev/null; echo '-:kprobes/mxfs_relack' >> $T/kprobe_events 2>/dev/null; echo '-:kprobes/mxfs_relack_in' >> $T/kprobe_events 2>/dev/null; echo DISARMED"
disarm() {
    local h
    for h in "${PAIR[@]}"; do on "$h" "$DISARM" 30 > /dev/null; done
}
trap disarm EXIT

for h in "${PAIR[@]}"; do
    on "$h" "$ARM" 60 | grep -q ARMED || { say "ABORT: could not arm the probe on $h"; exit 1; }
done
t0=$(date +%s)
say "probes armed on ${PAIR[*]}; running: $*"
"$@" > "$EVID/command.log" 2>&1
rc=$?
say "command rc=$rc (output in $EVID/command.log); settling ${SETTLE_S}s"
sleep "$SETTLE_S"
# Run on each host as: <since epoch s> <instance dir>.  Prints the ack return
# counts, then for every release this host gave up on (rel_id and ino from its
# P-TAUTH-RELEASE-UNACKED line) whether an ack naming it arrived at all, and
# with which status (0 = the master retired it).
COLLECT=$(cat <<'EOF'
t0=$1; I=$2
awk '/ mxfs_relack:/ {for (i = 1; i <= NF; i++) if ($i ~ /^ret=/) c[substr($i, 5)]++} END {for (k in c) printf "ret=%s %d\n", k, c[k]}' $I/trace | sort
awk '/ mxfs_relack_in:/ {r = ""; n = ""; s = ""; for (i = 1; i <= NF; i++) {if ($i ~ /^relid=/) r = substr($i, 7); if ($i ~ /^ino=/) n = substr($i, 5); if ($i ~ /^st=/) s = substr($i, 4)} print r, n, s}' $I/trace > /dev/shm/mxfs-relack.acks
journalctl -k --since @$t0 --no-pager -o cat | grep -a P-TAUTH-RELEASE-UNACKED | sed -n 's/.* ino=\([0-9]*\) ag=[0-9]* rel_id=\([0-9]*\) .*/\2 \1/p' > /dev/shm/mxfs-relack.unacked
echo "UNACKED $(grep -c . /dev/shm/mxfs-relack.unacked)"
awk 'NR == FNR {st[$1 " " $2] = st[$1 " " $2] " " $3; next} {k = $1 " " $2; if (!(k in st)) never++; else if (st[k] ~ / 0( |$)/) ok++; else err++} END {printf "UNACKED_THEN_ACKED_OK %d\nUNACKED_THEN_ACKED_NOT_OK %d\nUNACKED_NEVER_ACKED %d\n", ok, err, never}' /dev/shm/mxfs-relack.acks /dev/shm/mxfs-relack.unacked
echo "OVERRUN $(awk '/overrun/ {s += $2} END {print s + 0}' $I/per_cpu/cpu*/stats)"
rm -f /dev/shm/mxfs-relack.acks /dev/shm/mxfs-relack.unacked
EOF
)
for h in "${PAIR[@]}"; do
    on "$h" "echo $(base64 -w0 <<<"$COLLECT") | base64 -d > /dev/shm/mxfs-relack-collect.sh && bash /dev/shm/mxfs-relack-collect.sh $t0 $I; rm -f /dev/shm/mxfs-relack-collect.sh" 60 > "$EVID/counts.$h"
    say "$h: $(tr '\n' ' ' < "$EVID/counts.$h")"
done
say "evidence: $EVID"
