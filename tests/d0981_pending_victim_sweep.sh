#!/bin/bash
# d0981_pending_victim_sweep.sh — the deterministic arm for D-0981: a mount
# onto a LUN that carries a certified but UNOWNED recovery descriptor (stage
# FENCED, owner 0 — what a prover leaves when it sealed a victim's fence and
# its own mount was then refused at the admission bound) claimed the recovery
# in its first barrier round, and while the slice stability proof ran the
# mount's own orphan sweep took the victim's ledger pages over and retired its
# records; the replay's current-safety check then found the sealed manifest's
# entry gone and published a TERMINAL whole-filesystem quarantine (s66e:
# P-TAUTH-TAKEOVER-RETIRE ... cleared=1 via=orphan-sweep at :46,
# P-RMAN-POSTSEAL-MUTATION live{rc=-2} and P-RMAN-MUTATED-TERMINAL at :50,
# every later mount refused in 22 ms).
#
# THE PRECONDITION IS BUILT, NOT HOPED FOR.  A lap of the sole-survivor probe
# leaves this platter state only when its prover happens to seal before it is
# refused (s66d yes, s66h no), so the harness makes it itself: both VMs are
# destroyed with their mounts in flight (frozen ACTIVE records), and A mounts
# under the one-shot test knob mxfs.dbg_barrier_refuse_after_claim=1, which
# refuses A's mount the moment its barrier has fenced, sealed and CLAIMED the
# first frozen record's recovery, giving the lease back durably.  The platter
# then carries exactly a FENCED descriptor with owner 0/0, asserted from the
# dump before anything is judged (VACUOUS otherwise).
#
# WHAT IT PROVES.  B mounts (bounded).  Its sweep must MEET the pending
# victim and leave it alone (P-TAUTH-ORPHAN-AUTH ... judging=1 — the
# non-vacuity gate: a sweep that met no dead authority proves nothing), no
# takeover may retire the victim's records before its replay reached
# IMAGES_REPLAYED (P234-RECOV-STAGE ... 3->4), the replay must pass its
# judgement (every P-RMAN-EVAL postseal_mutations=0, no P-RMAN-MUTATED-
# TERMINAL, no P240-QUAR-IMPORT), recovery must complete (P163-RECOVERY-
# COMPLETE) and the mount must be admitted.  Then A mounts beside it.  After
# both, the platter carries no recovery descriptor.  Control: the same
# platter state on 0.89.2 (no guard) quarantined the filesystem, s66e.
#
# the budget rule (derived, not rounded): VM destroy+start+boot ~150 s
# (measured 152 s) + deploy ~20 s + A's knob mount: the dead window 62 s +
# fence, seal and claim ~10 s (s66g's control mount: 80 s wait) + B's mount:
# claim + 6 s stability proof + replay + the second ghost's window and fence
# ~90 s + A's mount ~10 s + captures ~40 s = ~380 s.  Caller bound 570 s
# (1.5x).  JOIN_BOUND 300 s bounds each mount.
#
# Usage: tests/d0981_pending_victim_sweep.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, MXFS_MODARGS,
#        JOIN_BOUND (default 300), VM_RESTART=1.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}          # the prover that is refused after its claim, then mounts last
B=${MXFS_NODE_LIST##*,}          # the mount under test: claims the unowned recovery
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
KO=/root/mxfs.ko.prep
JOIN_BOUND=${JOIN_BOUND:-300}
VM_RESTART=${VM_RESTART:-1}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0981_$LABEL
mkdir -p "$OUT"
fails=0
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
c() { grep -ac "$1" "$2"; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0981_pending_victim_sweep label=$LABEL A(prover,refused)=$A B(under test)=$B sv=$SV join_bound=${JOIN_BOUND}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)

if [ "$VM_RESTART" = 1 ]; then
    for n in $A $B; do
        timeout 30 virsh -c qemu:///system destroy "$n" > /dev/null 2>&1
        timeout 30 virsh -c qemu:///system start "$n" > /dev/null 2>&1
    done
    for n in $A $B; do
        w=0
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do
            w=$((w+1)); sleep 5
        done
        echo "STAGE boot-wait node=$n polls=$w"
    done
    echo "STAGE vm-restart wall=$(( $(date +%s) - s0 ))s"
fi

MD5=$(md5sum mxfs.ko | cut -c1-32)
for n in $A $B; do
    value_now_into got "$n" 150 "$OUT/rv_got_$n.txt" '^[0-9a-f]{32}$' "got on $n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n runs the tree build (md5)" "$got" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy fails=$fails"; exit 2; }

measure "$A" 60 "$OUT/hb_start.txt" '^slot +[0-9]+ magic=' "the platter dump on $A after the restart" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
echo "STAGE hb-start: $(grep -a 'flags=ACTIVE' "$OUT/hb_start.txt" | grep -avc ' epoch=0 ') frozen real-incarnation ACTIVE record(s)"

join() {   # join <tag> <node> <extra insmod args>
    local t=$1 n=$2 extra=$3 mark
    mark=$(date +%s)
    echo "MARK=$mark" > "$OUT/${t}_join.txt"
    rsx $((JOIN_BOUND + 60)) "$n" "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS $extra; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" >> "$OUT/${t}_join.txt"
    measure "$n" 60 "$OUT/${t}_journal.txt" '^JOURNAL_END$' "the kernel journal on $n since its join" "journalctl -k --since @$mark --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
    capture_require "$OUT/${t}_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $n"
    echo "STAGE $t: $n mount rc=$(field "$OUT/${t}_join.txt" MOUNT_RC) wall=$(field "$OUT/${t}_join.txt" WALL_MS)ms $(grep -a '^MOUNTED\|^NOT_MOUNTED' "$OUT/${t}_join.txt")"
}

# ---- P: A builds the precondition — fence, seal, claim, then refused.
join P "$A" "dbg_barrier_refuse_after_claim=1"
grep -a 'P236-FENCE-SEALED\|P238-RECOV-LEASE\|P-DBG-BARRIER-REFUSE-AFTER-CLAIM\|P-BARRIER-CLOCK' "$OUT/P_journal.txt" | sed 's/.*kernel: /    /' | cut -c1-200 | head -6
measure "$A" 60 "$OUT/hb_before.txt" '^slot +[0-9]+ magic=' "the platter dump on $A before the join under test" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
unowned=$(grep -a 'stage=FENCED' "$OUT/hb_before.txt" | grep -ac ' owner=0/0 ')
victim=$(grep -a 'stage=FENCED' "$OUT/hb_before.txt" | grep -a ' owner=0/0 ' | head -1 | grep -ao 'victim=[0-9]*/[0-9]*' | head -1 | cut -d= -f2)
vnode=${victim%%/*}
echo "STAGE precondition: unowned FENCED descriptor(s)=$unowned victim=${victim:-none}"
grep -a 'stage=\|flags=ACTIVE\|RECOVERY_GUARD' "$OUT/hb_before.txt" | sed 's/^/    /' | cut -c1-160
if [ "$(c 'P-DBG-BARRIER-REFUSE-AFTER-CLAIM' "$OUT/P_journal.txt")" -lt 1 ] || [ "${unowned:-0}" -lt 1 ]; then
    echo "  VACUOUS the precondition was not built: knob refusals=$(c 'P-DBG-BARRIER-REFUSE-AFTER-CLAIM' "$OUT/P_journal.txt") unowned FENCED descriptors=$unowned — the arm cannot be judged"
    echo "RESULT: VACUOUS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi

# ---- B: the mount under test — claims the unowned recovery.
join B "$B" ""
grep -a 'P-TAUTH-ORPHAN-AUTH\|P-TAUTH-ORPHAN-SWEEP \|P-TAUTH-TAKEOVER-UNDER-JUDGEMENT\|P-RMAN-EVAL\|MUTATED-TERMINAL\|QUAR\|P163-RECOVERY-COMPLETE\|P-BARRIER-CLOCK\|mount ABORTED\|P234-RECOV-STAGE' "$OUT/B_journal.txt" | sed 's/.*kernel: /    /' | cut -c1-200 | head -14
ckge "B: the orphan sweep met the pending victim and left it alone (P-TAUTH-ORPHAN-AUTH judging=1)" "$(grep -a 'P-TAUTH-ORPHAN-AUTH' "$OUT/B_journal.txt" | grep -ac ' judging=1 ')" 1
ck   "B: no takeover retired the victim's records before IMAGES_REPLAYED (P-TAUTH-TAKEOVER-RETIRE departed=$victim cleared>0 before P234-RECOV-STAGE victim=$vnode 3->4)" "$(awk -v v="departed=$victim " -v n="victim=$vnode " '/P234-RECOV-STAGE/ && index($0, n) && / 3->4/ {exit} /P-TAUTH-TAKEOVER-RETIRE/ && index($0, v) && / cleared=[1-9]/ {k++} END {print k+0}' "$OUT/B_journal.txt")" 0
ckge "B: the victim's replay reached IMAGES_REPLAYED (P234-RECOV-STAGE victim=$vnode 3->4)" "$(grep -a 'P234-RECOV-STAGE' "$OUT/B_journal.txt" | grep -a "victim=$vnode " | grep -ac ' 3->4')" 1
ckge "B: the replay evaluated its manifest (P-RMAN-EVAL)" "$(c 'P-RMAN-EVAL' "$OUT/B_journal.txt")" 1
ck   "B: the replay passed its manifest judgement (every P-RMAN-EVAL postseal_mutations=0)" "$(grep -a 'P-RMAN-EVAL' "$OUT/B_journal.txt" | grep -ac 'postseal_mutations=0 ')" "$(c 'P-RMAN-EVAL' "$OUT/B_journal.txt")"
ck   "B: no post-seal mutation verdict (P-RMAN-MUTATED-TERMINAL)" "$(c 'P-RMAN-MUTATED-TERMINAL' "$OUT/B_journal.txt")" 0
ck   "B: no quarantine imported (P240-QUAR-IMPORT)" "$(c 'P240-QUAR-IMPORT' "$OUT/B_journal.txt")" 0
ckge "B: the victim's recovery completed (P163-RECOVERY-COMPLETE)" "$(c 'P163-RECOVERY-COMPLETE' "$OUT/B_journal.txt")" 1
ck   "B: the mount was admitted" "$(c '^MOUNTED' "$OUT/B_join.txt")" 1

# ---- A: mounts beside it.
join A "$A" ""
ck   "A: the mount was admitted beside B" "$(c '^MOUNTED' "$OUT/A_join.txt")" 1
ck   "A: no quarantine (P240-QUAR-IMPORT)" "$(c 'P240-QUAR-IMPORT' "$OUT/A_journal.txt")" 0

for t in P B A; do
    ck "$t: zero shutdown / BUG / Oops" \
       "$(grep -ac 'shutting down filesystem\|BUG:\|Oops\|WARNING:' "$OUT/${t}_journal.txt")" 0
done
measure "$A" 60 "$OUT/hb_after.txt" '^slot +[0-9]+ magic=' "the platter dump on $A after the joins" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
ck   "platter: no recovery descriptor remains after both mounts" "$(grep -ac 'stage=FENC\|stage=SNAPSHOT\|RECOVERY_GUARD' "$OUT/hb_after.txt")" 0
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
