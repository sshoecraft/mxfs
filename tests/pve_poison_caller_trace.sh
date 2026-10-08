#!/bin/bash
# pve_poison_caller_trace.sh — which system call poisons a reused inode's old
# in-core incarnation, and does the fd that fails ESTALE come from it?
#
# On a DRBD pair, when one host frees an inode the other still has in core and
# the number is reused, the other host's first write to the new file fails
# ESTALE while its open succeeded.  The poison (mxfs_incarn_poison) is decided
# by a protecting reload under a DLM grant.  If that reload runs inside the
# open's own protecting acquire (mxfs_dlm_open_protect), the open hands out an
# fd on an inode it has just poisoned; if it runs at the write, the open never
# saw anything to refuse.  A stack per poison call says which.
#
# On both hosts a kprobe on mxfs_incarn_poison records each call with its
# kernel stack in a tracing instance of its own (nothing goes to the kernel
# log), the given command runs from here, and then per host: the number of
# poison calls, how many stacks pass through xfs_file_open, mxfs_dlm_open_protect,
# a write path (xfs_file_write_iter / xfs_file_buffered_write) and lookup, and
# the first stacks verbatim.
#
# Usage: tests/pve_poison_caller_trace.sh <command ...>
#        e.g. PVE_PAIR="192.168.120.137 192.168.120.192" \
#             tests/pve_poison_caller_trace.sh env PVE_PAIR="..." CHURN=8 WORK_S=60 tests/pve_churn_fairness.sh
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), STACKS (stacks kept
#        verbatim per host, default 6)
# Evidence: tests/evidence/pve_poison_caller_trace/<UTC stamp>-<addr>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_poison_caller_trace: PVE_PAIR must name two hosts"; exit 2; }
[ "$#" -gt 0 ] || { echo "usage: $0 <command ...>"; exit 2; }
STACKS=${STACKS:-6}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_poison_caller_trace/$STAMP-${PAIR[0]}"
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

T=/sys/kernel/tracing
I=$T/instances/mxfs_poison
ARM="set -e
grep -q 'mxfs_poison ' $T/kprobe_events 2>/dev/null || echo 'p:mxfs_poison mxfs_incarn_poison ino=+0(\$arg1):u64' >> $T/kprobe_events
mkdir -p $I
echo 8192 > $I/buffer_size_kb
echo > $I/trace
echo stacktrace > $I/events/kprobes/mxfs_poison/trigger
echo 1 > $I/events/kprobes/mxfs_poison/enable
echo 1 > $I/tracing_on
echo ARMED"
DISARM="echo 0 > $I/events/kprobes/mxfs_poison/enable 2>/dev/null; echo '!stacktrace' > $I/events/kprobes/mxfs_poison/trigger 2>/dev/null; echo 0 > $I/tracing_on 2>/dev/null; rmdir $I 2>/dev/null; echo '-:kprobes/mxfs_poison' >> $T/kprobe_events 2>/dev/null; echo DISARMED"
disarm() {
    local h
    for h in "${PAIR[@]}"; do on "$h" "$DISARM" 30 > /dev/null; done
}
trap disarm EXIT

for h in "${PAIR[@]}"; do
    on "$h" "$ARM" 60 | grep -q ARMED || { say "ABORT: could not arm the probe on $h"; exit 1; }
done
say "probes armed on ${PAIR[*]}; running: $*"
"$@" > "$EVID/command.log" 2>&1
rc=$?
say "command rc=$rc (output in $EVID/command.log)"
for h in "${PAIR[@]}"; do
    on "$h" "cat $I/trace" 120 > "$EVID/trace.$h"
    # One record per poison call: its event line, then '=> frame' lines.
    awk -v n="$STACKS" '
        / mxfs_poison:/ { if (rec != "") done(); rec = $0 "\n"; next }
        /^ *=> / { if (rec != "") rec = rec $0 "\n"; next }
        function done() {
            calls++
            if (rec ~ /xfs_file_open/) open++
            if (rec ~ /mxfs_dlm_open_protect/) prot++
            if (rec ~ /xfs_file_write_iter|xfs_file_buffered_write/) wr++
            if (rec ~ /xfs_lookup|xfs_vn_lookup/) lk++
            if (kept < n) { printf "%s", rec > STK; kept++ }
            rec = ""
        }
        END {
            if (rec != "") done()
            printf "calls=%d via_open=%d via_open_protect=%d via_write=%d via_lookup=%d\n", calls, open, prot, wr, lk
        }' STK="$EVID/stacks.$h" "$EVID/trace.$h" > "$EVID/counts.$h"
    say "$h: $(cat "$EVID/counts.$h")"
done
say "evidence: $EVID"
exit "$rc"
