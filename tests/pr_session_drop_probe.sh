#!/bin/bash
# tests/pr_session_drop_probe.sh — does the TARGET drop a node's PR registration
# when that node's iSCSI session dies, and what does a returning non-registrant
# get from the LUN afterwards?
#
# WHY THIS EXISTS (2026-09-04, first 2-node TCP dirty death on the QNAP LUN)
#   tests/tcp_death_replay.sh s500a_l1: 84 fsync-acknowledged files on the
#   victim, virsh destroy, and the survivor's fence found the victim's key
#   ALREADY ABSENT (P-PR-FENCE-ABSENT, PR generation unchanged) ~70 s after the
#   kill.  Absence is KEY_ABSENT_UNPROVEN by design (sess432 ruling: absence
#   causality is unknowable), the fence retried 27 times in 155 s, the slice
#   was never replayed and the survivor's EX stayed frozen.  On the SCST/LIO
#   rigs a dead initiator's key stays registered and the PREEMPT AND ABORT
#   proves exclusion; this NAS class behaves differently, and the difference
#   decides whether a node death is recoverable at all on the production
#   target.  Measure the target, not MXFS.
#
# THE MEASUREMENT (both nodes mounted on the LUN, cluster formed)
#   1. observer W polls READ KEYS + READ RESERVATION every second (gen, count).
#   2. V is virsh-destroyed (power cut: no logout, no PROUT of any kind).
#   3. the poll shows WHEN the count drops and whether the PR generation
#      moves — a PROUT bumps it; a target-internal purge may not.
#   4. V is started again (no MXFS mount; the initiator logs in at boot).
#      From V, as a non-registrant on a fresh nexus: READ KEYS (is anything
#      re-registered by the login?), then a WRITE of the scratch LBA with the
#      bytes it already holds (content unchanged whatever happens) -> under a
#      held Write Exclusive reservation the target must refuse it.
#   5. W's view again: did V's login add a registration?
#
# The scratch LBA is 131087, the sector below the disklock table, the same one
# tools/caw_verify and tests/pr_reregister_probe.sh use.
#
# Leaves V unmounted and W with a dead peer; re-prep afterwards.
#
# the budget rule (derived): gate 10 s + poll 110 s + victim boot to ssh ~60-90 s +
# victim probes 15 s => ~230 s; caller bound 300 s.
#
# usage: pr_session_drop_probe.sh <label> [W=test1] [V=test2]
# env:   MXFS_DEV (the LUN path as seen on the nodes), POLL_S (default 110)
set -u
LABEL=${1:?label}
W=${2:-test1}; V=${3:-test2}
POLL_S=${POLL_S:-110}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$W"; DEV=$MXFS_DEV_RESOLVED
LBA=${MXFS_SCRATCH_LBA:-131087}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_prsd_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS

say "=== pr_session_drop_probe label=$LABEL W=$W V=$V dev=$DEV out=$OUT ==="

# -- gate: both mounted, two keys, a Write Exclusive reservation held --
for n in "$W" "$V"; do
    m=$(timeout 15 $SSH "$n" "grep -c ' mxfs ' /proc/mounts; readlink -f $DEV" 2>/dev/null | filt | tr '\n' ' ')
    echo "  INFO $n mounts/dev: $m"
    [[ "$m" == 1\ * ]] || { echo "ABORT: $n not mounted ($m)"; exit 2; }
done
measure "$W" 20 "$OUT/rv_base_1.txt" 'PR generation=' "the PR keys and reservation on $W (an answered PR IN carries the generation header; an error message is non-empty too)" "sg_persist -i -k $DEV 2>&1 | grep -a 'PR generation\|^    0x'; sg_persist -i -r $DEV 2>&1 | grep -a 'scope\|Key='; printf '\nREAD_RC=%s\n' \$?"; base=$(grep -av '^READ_RC=' "$OUT/rv_base_1.txt")
echo "$base" | sed 's/^/  INFO base: /'
nk0=$(echo "$base" | grep -ac '^    0x')
gen0=$(echo "$base" | grep -a -m1 -oE 'generation=0x[0-9a-f]+' | cut -d= -f2)
ck "two registrations before the kill" "$nk0" "2"
ck "Write Exclusive reservation held before the kill" "$(echo "$base" | grep -ac 'Write Exclusive')" "1"

# -- poller on W: one line per second: epoch gen count held --
POLL='dev=$1; n=$2; for i in $(seq 1 $n); do g=$(sg_persist -i -k $dev 2>&1 | grep -a "PR generation" | grep -oE "generation=0x[0-9a-f]+" | cut -d= -f2); c=$(sg_persist -i -k $dev 2>&1 | grep -ac "^    0x"); h=$(sg_persist -i -r $dev 2>&1 | grep -ac "Write Exclusive"); echo "$(date +%s) gen=$g keys=$c held=$h"; sleep 1; done'
PB=$(printf '%s' "$POLL" | base64 -w0)
timeout 12 $SSH "$W" "echo $PB | base64 -d > /root/prsd_poll.sh; nohup bash /root/prsd_poll.sh $DEV $POLL_S > /root/prsd_poll.txt 2>&1 < /dev/null & echo started" 2>/dev/null | filt
sleep 4
tkill=$(date +%s)
$VIRSH destroy "$V" > "$OUT/virsh_destroy.txt" 2>&1; say "virsh destroy $V rc=$? (power cut, no logout)"

sleep $(( POLL_S - 2 ))
timeout 20 $SSH "$W" "cat /root/prsd_poll.txt" 2>/dev/null | filt > "$OUT/poll_$W.txt"
say "poll samples: $(grep -ac gen= "$OUT/poll_$W.txt")"
first_drop=$(awk -v k="$nk0" '/keys=/{split($3,a,"=");if(a[2]+0<k+0){print;exit}}' "$OUT/poll_$W.txt")
if [ -n "$first_drop" ]; then
    td=$(echo "$first_drop" | cut -d' ' -f1)
    say "first sample with fewer than $nk0 keys: $first_drop  (+$(( td - tkill )) s after the kill)"
    before=$(awk -v t="$td" '$1+0<t+0' "$OUT/poll_$W.txt" | tail -1)
    say "last sample before the drop: $before"
    ck "registration count dropped after the kill without any PROUT" "1" "1"
    g_before=$(echo "$before" | grep -oE 'gen=0x[0-9a-f]+' | cut -d= -f2)
    g_after=$(echo "$first_drop" | grep -oE 'gen=0x[0-9a-f]+' | cut -d= -f2)
    say "PR generation before=$g_before after=$g_after $( [ "$g_before" = "$g_after" ] && echo '(UNCHANGED: purge is target-internal, not a PROUT)' || echo '(moved)')"
    ck "reservation still held after the drop" "$(echo "$first_drop" | grep -oE 'held=[0-9]+' | cut -d= -f2)" "1"
else
    say "the registration count never dropped within ${POLL_S}s: $(tail -1 "$OUT/poll_$W.txt")"
    ck "registration survived the session loss (SCST/LIO behaviour)" "1" "1"
fi

# -- the victim returns, unmounted, as a non-registrant on a fresh nexus --
$VIRSH start "$V" > "$OUT/virsh_start.txt" 2>&1; say "virsh start $V rc=$?"
i=0; up=0
while [ $i -lt 150 ]; do
    if timeout 8 $SSH "$V" "true" >/dev/null 2>&1; then up=1; break; fi
    sleep 5; i=$((i+5))
done
say "$V ssh reachable=$up after ${i}s"
if [ $up = 1 ]; then
    sleep 5
    measure "$V" 60 "$OUT/rv_vres.txt" '^wrc=[0-9]+$' "V's PR view and write-back of LBA $LBA" "
        for t in 1 2 3 4 5 6; do [ -e $DEV ] && break; sleep 5; done
        R=\$(readlink -f $DEV); echo dev=\$R
        grep -c ' mxfs ' /proc/mounts
        echo '--- keys from $V'; sg_persist -i -k \$R 2>&1 | grep -a 'PR generation\|^    0x'
        echo '--- resv from $V'; sg_persist -i -r \$R 2>&1 | grep -a 'scope\|Key='
        dd if=\$R of=/root/prsd_lba.bin bs=512 skip=$LBA count=1 iflag=direct 2>&1 | tail -1
        echo \"--- write-back of LBA $LBA (same bytes)\"
        dd if=/root/prsd_lba.bin of=\$R bs=512 seek=$LBA count=1 oflag=direct conv=notrunc 2>&1 | tail -2; echo wrc=\${PIPESTATUS[0]}
        dmesg | grep -ai 'reservation conflict\|Sense Key\|sd .*Write' | tail -4
    "; vres=$(cat "$OUT/rv_vres.txt")
    echo "$vres" | sed 's/^/  INFO victim: /'
    echo "$vres" > "$OUT/victim_$V.txt"
    wrc=$(echo "$vres" | grep -a -oE 'wrc=[0-9]+' | cut -d= -f2)
    ck "non-registrant write refused by the held reservation (dd rc != 0)" "$( [ "${wrc:-0}" != 0 ] && echo refused || echo ALLOWED )" "refused"
    ck "victim's login added no registration (keys as seen from $V)" "$(echo "$vres" | grep -ac '^    0x')" "1"
fi
after=$(timeout 20 $SSH "$W" "sg_persist -i -k $DEV 2>&1 | grep -a 'PR generation\|^    0x'" 2>/dev/null | filt)
echo "$after" | sed 's/^/  INFO after: /'

if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; fi
exit $fails
