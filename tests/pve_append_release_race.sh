#!/bin/bash
# pve_append_release_race.sh — does a release owed to the peer while an
# append's completion updates the file size leave a demoter claim behind?
#
# xfs_setfilesize (the I/O completion of every append, run in an xfs-conv
# worker) joins the inode to its transaction with XFS_ILOCK_EXCL, so the inode
# is unlocked inside the commit while the transaction is still the task's
# current one.  When a peer's revocation is owed at that unlock,
# mxfs_dlm_ilock_end defers the release into the transaction
# (mxfs_inode_dlm_defer_bast takes a demoter claim), and the trans-free drain,
# being in I/O-completion context, punts it to the release work and RETAINS
# the claim for a post-commit unlock by the same task.  Here there is none:
# the unlock already happened inside the commit.
#
# Observed once on nested pair A (0.90.104): a kworker held such a claim
# (set at mxfs_inode_dlm_defer_bast) for 326 s, and while it stood every
# lookup of the inode number's next incarnation failed ESTALE after 201
# rounds (D-CAW-MKDIR-LOOKUP-ESTALE-TYPEFLIP-UNRESOLVED).
#
# Workload, WORK_S seconds: participant 0 appends APPEND_KIB with O_DSYNC in
# a loop to one file (every completion is a size update in the worker);
# participant 1 stats it and reads its first byte in a loop (a read grant
# each time, so a revocation of participant 0's grant is owed again and
# again).  Then both stop and the pair is left idle SETTLE_S seconds.
#
# Read from each host's counters (demoter_dump), over the run:
#   P215-DEFER set      releases deferred into a transaction (the claim taken)
#   P213-PUNT retain    of those, claims the punt retained
#   owner_clear/reclaim/selfclear   retained claims ended afterwards
#   outstanding = retain - owner_clear - reclaim - selfclear: still held
# and the kernel log for P214-DEMOTER-STRANDED / P-DEMOTER-DEAD-REAP.
#
# Verdict: FAIL when either host has a retained claim outstanding after the
# settle, a strand or a dead-reap.  The run also FAILS as unexercised when no
# release was deferred at all (set=0): then it proved nothing.
#
# Usage: tests/pve_append_release_race.sh [label]
# Env:
#   PVE_PAIR   "<addr> <addr>" (default nested pair A); participant 0 is the
#              lower address
#   WORK_S     seconds of the two loops (default 60)
#   APPEND_KIB size of each O_DSYNC append (default 64)
#   WRITERS    concurrent append loops on participant 0 (default 1)
#   READERS    concurrent stat+read loops on participant 1 (default 1)
#   SETTLE_S   idle seconds before the counters are read (default 15: three
#              times the 5 s grace after which a retained claim may be swept)
#   HOLD_MS    when set, arm dbg_sfs_hold_ino on the file before the loops:
#              the first append's completion parks HOLD_MS in
#              xfs_setfilesize holding ILOCK_EXCL, so participant 1's next
#              stat finds a live holder and the release is deferred into the
#              transaction for certain, instead of by a lucky race
#
# Also reported per host: wipe, the retentions whose record a task that does
# not hold the claim dropped at its own unlock (P-PUNT-WIPE).
#
# Budget: arming 5 s + WORK_S + SETTLE_S + collection ~20 s; 100 s at the
# defaults, so the outer timeout is WORK_S + SETTLE_S + 60.
#
# Evidence: tests/evidence/pve_append_release_race/<UTC stamp>[-label]/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_append_release_race: PVE_PAIR must name two hosts"; exit 2; }
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    H=("${PAIR[0]}" "${PAIR[1]}")
else
    H=("${PAIR[1]}" "${PAIR[0]}")
fi
WORK_S=${WORK_S:-60}
APPEND_KIB=${APPEND_KIB:-64}
SETTLE_S=${SETTLE_S:-15}
WRITERS=${WRITERS:-1}
READERS=${READERS:-1}
LABEL=${1:-}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_append_release_race/$STAMP${LABEL:+-$LABEL}"
mkdir -p "$EVID" || exit 2
D=/mnt/shared/appendrace-$STAMP
F=$D/f
MARK="mxfs-test: pve_append_release_race $STAMP start"

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
PROBES="P214-DEMOTER-STRANDED P214-DEMEV P152-TRANSDRAIN-PUNT P213-PUNT P215-DEFER P215-DRAIN-RESIDUE P216-CLAIM-RECYCLE P75-DEMOTER-CLAIM"
probes() {  # <host> <+p|-p>
    local cmd="" f
    for f in $PROBES; do
        cmd+="echo 'module mxfs format \"$f\" $2' > /proc/dynamic_debug/control; "
    done
    on "$1" "$cmd echo PROBES_DONE" 30 | grep -q PROBES_DONE
}
# demoter_dump's counters, as name=value words, from the line just printed
counters() {  # <host>
    on "$1" "echo 1 > /sys/module/mxfs/parameters/demoter_dump; sleep 1; journalctl -k --no-pager -n 400 -o cat | grep -aE 'P215-DEFER|P213-PUNT |P75-DEMOTER-DRAIN' | tail -3" 30 \
        | grep -oE '[a-z_]+=-?[0-9]+' | tr '\n' ' '
}
val() { grep -oE "(^| )$1=-?[0-9]+" <<<"$2" | tail -1 | cut -d= -f2; }

for h in "${H[@]}"; do
    say "$h build+mounted: $(on "$h" "cat /sys/module/mxfs/srcversion; awk '\$2 == \"/mnt/shared\" && \$3 == \"mxfs\"' /proc/mounts | wc -l" 20 | tr '\n' ' ')"
    probes "$h" +p || say "$h: could not turn the probes on"
    on "$h" "echo '<5>$MARK' > /dev/kmsg" 20
done
declare -A C0
for h in "${H[@]}"; do C0[$h]=$(counters "$h"); say "$h before: ${C0[$h]}"; done

on "${H[0]}" "mkdir -p $D && : > $F && sync -f $D && echo ok" 30 | grep -q ok || { say "could not make $F"; exit 2; }
if [ -n "${HOLD_MS:-}" ]; then
    say "hold armed: $(on "${H[0]}" "i=\$(stat -c %i $F); echo $HOLD_MS > /sys/module/mxfs/parameters/dbg_sfs_hold_ms; echo \$i > /sys/module/mxfs/parameters/dbg_sfs_hold_ino; echo ino=\$(cat /sys/module/mxfs/parameters/dbg_sfs_hold_ino) ms=\$(cat /sys/module/mxfs/parameters/dbg_sfs_hold_ms)" 20)"
fi
T=$(( $(date +%s) + 5 ))
for w in $(seq 1 "$WRITERS"); do
    on "${H[0]}" "cd $D; sleep \$(( $T - \$(date +%s) )); n=0; e=0; end=\$(( $T + $WORK_S )); while [ \$(date +%s) -lt \$end ]; do dd if=/dev/zero of=$F bs=${APPEND_KIB}k count=1 oflag=append,dsync conv=notrunc status=none || e=\$((e+1)); n=\$((n+1)); done; echo APPENDS=\$n ERRORS=\$e" $((WORK_S + 30)) > "$EVID/p0-$w.out" 2>&1 &
done
for r in $(seq 1 "$READERS"); do
    on "${H[1]}" "sleep \$(( $T - \$(date +%s) )); n=0; e=0; end=\$(( $T + $WORK_S )); while [ \$(date +%s) -lt \$end ]; do stat -c %s $F > /dev/null && head -c 1 $F > /dev/null || e=\$((e+1)); n=\$((n+1)); done; echo READS=\$n ERRORS=\$e" $((WORK_S + 30)) > "$EVID/p1-$r.out" 2>&1 &
done
wait
cat "$EVID"/p0-*.out > "$EVID/p0.out"; cat "$EVID"/p1-*.out > "$EVID/p1.out"
say "p0 ${H[0]}: $(tr '\n' ' ' < "$EVID/p0.out")"
say "p1 ${H[1]}: $(tr '\n' ' ' < "$EVID/p1.out")"
sleep "$SETTLE_S"

fail=0
set_total=0
for h in "${H[@]}"; do
    c1=$(counters "$h")
    d() { echo $(( $(val "$1" "$c1") - $(val "$1" "${C0[$h]}") )); }
    set_n=$(d set); retain=$(d retain); oc=$(d owner_clear); rc=$(d reclaim); sc=$(d selfclear); reap=$(d dead_reap)
    wipe=$(( $(val wipe "$c1") - $(val wipe "${C0[$h]}") ))
    out=$(( retain - oc - rc - sc ))
    set_total=$(( set_total + set_n ))
    on "$h" "journalctl -k --no-pager -o short-monotonic | awk -v m='$MARK' 'index(\$0, m) {p=1} p' | sed 's/^.*kernel: //' | grep -a 'mxfs'" 60 > "$EVID/klog-$h"
    strand=$(grep -ac 'P214-DEMOTER-STRANDED' "$EVID/klog-$h")
    punts=$(grep -ac 'P152-TRANSDRAIN-PUNT' "$EVID/klog-$h")
    say "$h deferred=$set_n punted=$punts retained=$retain owner_clear=$oc reclaim=$rc selfclear=$sc wipe=$wipe outstanding=$out dead_reap=$reap strand=$strand"
    grep -aE 'P-SFS-HOLD|P-PUNT-WIPE' "$EVID/klog-$h" | cut -c1-220 | head -6 | sed "s/^/  $h: /" | tee -a "$EVID/log"
    grep -a 'P152-TRANSDRAIN-PUNT' "$EVID/klog-$h" | sed 's/^.*why=/why=/' | sort | uniq -c | sed "s/^/  $h: /" | tee -a "$EVID/log"
    [ "$out" -le 0 ] && [ "$reap" = 0 ] && [ "$strand" = 0 ] || fail=1
    probes "$h" -p || say "$h: could not turn the probes off"
done
on "${H[0]}" "rm -rf $D" 60
! grep -qE 'ERRORS=[1-9]' "$EVID/p0.out" "$EVID/p1.out" && grep -q APPENDS= "$EVID/p0.out" && grep -q READS= "$EVID/p1.out" || { say "a loop reported errors"; fail=1; }
say "evidence $EVID"
if [ "$set_total" = 0 ]; then say "RESULT FAIL (unexercised: no release was deferred into a transaction)"; exit 1; fi
if [ "$fail" = 0 ]; then say "RESULT PASS"; exit 0; fi
say "RESULT FAIL"
exit 1
