#!/bin/bash
# tests/fence_crash_cuts.sh — the fence-prover CRASH CUTS on the 2-node TCP
# rig (ledger D-FENCE-CRASH-MATRIX-UNTESTED; the design-consult ruling that
# fixed the cut set, the hold and what a cut may assert is banked in
# docs/rulings/fence-crash-matrix-cuts.md).  One cut per lap.
#
# THE MECHANISM.  A (the prover) fences B (the victim, destroyed).  The
# prover parks at cut N (mxfs.dbg_fence_crash_cut=N, one-shot, filtered to
# B's slot by dbg_fence_crash_slot, held dbg_fence_crash_hold_ms) and prints
# P-DBG-FENCE-CUT; this harness reads the state AT the cut from A (its
# kernel log, READ KEYS, the disklock table) and virsh-destroys A there.
# The QUIESCENT platter is then read by B's host on its fresh boot BEFORE it
# mounts — an iSCSI login registers no PR key and claims no slot, so that
# read changes no membership and no PR state (s70f: the rig's LUN is the
# QNAP's, not a file on this host, so there is no host-side read of it) —
# and compared with the state read at the cut: a platter that moved between
# the marker and B's return is a contaminated lap and is REJECTED (ABORT),
# never read as a recovery outcome.  Then B mounts alone, then A's host
# returns, and the takeover is measured on each.
#
#   cut 1 preintent  after the victim-key check, before fence_intent.
#                    Platter: no attempt on B's slot.  Keys: B present.
#   cut 2 prearm     fence_intent durable (FENCING, prover A), before the
#                    arm CAS.  Platter: FENCING, MAY_HAVE_RUN clear.  Keys: B
#                    present.
#   cut 3 armed      the arm CAS durable, the PROUT not issued.  Platter:
#                    FENCING, MAY_HAVE_RUN set.  Keys: B present (armed, not
#                    dispatched — the same bytes as cut 4 with a different
#                    target state, which is why both exist).
#   cut 4 proved     the P&A returned a proving kind, before fence_certify.
#                    Platter: as cut 3.  Keys: B ABSENT (the P&A consumed the
#                    registration — measured here, never inferred from the
#                    cut number).  The volatile-proof hole: the certificate
#                    is lost; a successor may recover only by a NEW proof
#                    under its own prerequisites, and the certificate must
#                    name that mechanism (never PREEMPT_ABORT_DONE on a key
#                    that was already absent).
#   cut 5 certified  fence_certify returned 0, before the manifest snapshot.
#                    Platter: SNAPSHOTTING with the certificate.  Successor:
#                    takes the durable certificate over; no new certificate.
#   cut 6 sealed     the manifest sealed FENCED, before the claim.
#                    Successor: acquires the execution lease from the sealed
#                    manifest; no new certificate.
#   cut 7 replay-partial (0.89.18, VICTIM=silent only)
#                    INSIDE the replay, not around the proof.  A nonempty
#                    prefix of the pass's buffers is durable on home storage,
#                    a nonempty required suffix was never issued, and no
#                    completion marker has advanced.  Platter: FENCED, the
#                    certificate standing, the execution lease held by A1, the
#                    slot NOT published.  Keys: B1 ABSENT (the P&A consumed
#                    it).  Disposition MUST RECOVER: the successor has to
#                    apply the suffix and bring back every acknowledged
#                    fsync, and repeating the prefix must not perform a
#                    destructive effect twice.
#
#                    Why it is not a cut NUMBER in the same series: a foreign
#                    replay does not write incrementally.  Every image it
#                    applies is held in core and submitted ONCE at the end of
#                    the pass, because a mid-pass write can put an
#                    intermediate image of a block on the platter ahead of the
#                    head transaction that overlays it and get the whole slice
#                    refused.  So the only place a durable prefix can coexist
#                    with an unissued suffix is inside that final submission —
#                    which is where a real crash leaves it, since the
#                    submission is many writes and nothing makes them atomic.
#                    The cut splits the list there, waits for the prefix and
#                    flushes it, and parks.  If the pass did not queue more
#                    buffers than the prefix asked for the module DECLINES the
#                    cut and says so: "everything was applied" is the ordinary
#                    success this lap is meant to differ from, so that is
#                    VACUOUS, not a pass.
#
# WHAT IS ASSERTED (the ruling's replacements for the naive assertions):
#   - the durable state at the cut is the predicted one, read twice (at the
#     cut from A, quiescent from the host) and identical;
#   - the target state at the cut is the predicted one (READ KEYS on A);
#   - the lap is not contaminated: the hold did not expire before the
#     destroy, and no self-fence, PR transition or descriptor change sits
#     between the marker and the destroy;
#   - the returning nodes MUST recover in this shape (both hosts return, no
#     partition, the target keeps its registrations): B's mount completes,
#     A1 (the dead prover) is certified, B1's attempt reaches
#     P163-RECOVERY-COMPLETE, and the mechanism that proved B1 is consistent
#     with the key evidence: PREEMPT_ABORT_DONE only when B1's key was still
#     registered when the successor arrived, otherwise SELF_SUCCESSION_DONE
#     or BOOT_SUCCESSION_ABSENT, and at cuts 5/6 NO new certificate for B1;
#   - no blocked state was left (P238-FENCE-UNRECORDED, P238-FENCE-BLOCKED),
#     no shutdown, BUG or Oops on either node, both nodes see the same root;
#   - the dirty-death oracle is kept: the files B1 fsynced before its death
#     are present with the same content after recovery.
#   The kernel's own gates (every destructive step under the current
#   exclusion evidence, the execution authority and the prerequisite stage)
#   are not re-derived from log order here — the ruling says logs are not an
#   I/O oracle — so this lap measures the durable state and the outcome and
#   leaves the per-step authorisation to the module's refusals, which are
#   counted: an unexpected refusal on the intended path is a liveness FAIL.
#
# NOT COVERED HERE (the ruling's list of missing cuts, each a further
# entry): a partial snapshot or seal, stage advances not durable, a zero with
# the acknowledgement lost, competing owners, target restart with and without
# APTPL.  Two entries have come OFF that list.  The in-flight P&A with its
# response lost is measured end to end by tests/fence_lost_response.sh, and
# the variant that kills the prover after the loss is cut 4 under another
# name — same durable descriptor, same completed command at the target, same
# destroyed prover — so building it would re-measure cut 4.  Replay partially
# applied is cut 7 above.  In the two-node shape nobody is left to declare the prover dead, so
# each lap exercises boot-boundary revocation of A1, never the certified-dead
# takeover of a live cluster; the two are not both credited.
#
# the budget rule (derived): prep ~60 s (bound 300) + B's creates ~5 s + the
# 62 s dead window + the fence to the cut ~5 s + captures at the cut ~10 s
# (must stay under the 20 s hold) + B boot ~60-150 s + NFS and module copy
# ~30 s + B's mount (bound JOIN_BOUND 300; measured 22-89 s on the sibling
# shapes) + captures ~20 s + A boot ~150 s + A's mount (bound 300; measured
# 3-14 s) + captures ~20 s ≈ 450-900 s.  Caller bound 1200 s.
#
# CUT 7 COSTS MORE, at both ends.  Its marker is further away than any fencing
# endpoint — the fence has to complete, certify, seal and claim the execution
# lease before the replay it cuts into starts — so the marker wait is 200 s
# rather than 110.  And it owes verification the other cuts do not: new work
# accepted after recovery ~20 s, a full unmount and remount through the
# ordinary path (bound 200, measured 22-89 s on the sibling shapes) ~90 s, and
# an offline consistency check with the fleet down ~60-120 s.  Add ~300 s:
# caller bound 1500 s for cut 7 — plus the two churn-oracle passes it owes
# (bounded 120 s each, one on the recovering kernel and one after the
# remount): caller bound 1740 s.  It also LEAVES THE FLEET UNMOUNTED, because
# the checker takes the device O_EXCL — run prep_cluster after it.
#
# TWO VICTIM ARMS (design-consult ruling, s72), credited separately:
#   VICTIM=destroy  B is virsh-destroyed.  On a target that purges a dead
#                   session's registration (data/rigs.json
#                   pr_registration_on_session_loss=purged, the qnap) B1's key
#                   is gone before any fence, so cut 4 is reached through the
#                   sole-survivor gate (kind EXCLUSIVE_WRITE_GATE) and cuts
#                   5/6 carry that certificate; on a persistent target the
#                   P&A consumes the key (PREEMPT_ABORT_DONE).
#   VICTIM=silent   B keeps running with its iSCSI session and registration
#                   up while its disklock heartbeat thread is parked
#                   (dl_inject_hb_pause_ms), and a writer on B keeps
#                   appending fsynced lines to the shared filesystem.  A's
#                   P&A then consumes a PRESENT key on either target class
#                   (PREEMPT_ABORT_DONE at cuts 4-6), and the lap also
#                   measures the still-running victim: every write after the
#                   P&A must fail, B must self-withdraw when its heartbeat
#                   resumes, and — the hazard the ruling named — no write
#                   from the fenced incarnation may land after A's death
#                   removed the last registration and reservation from a
#                   purging target.  B is destroyed and rebooted afterwards,
#                   so the successor obligations are those of a boot boundary.
#   The gate arm never receives credit for the P&A branch, nor the reverse.
#
# Usage: tests/fence_crash_cuts.sh <label> [cut]     (cut 1..6; env CUT)
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, HOLD_MS (30000),
#        JOIN_BOUND (300), NFILES (64), VICTIM (destroy|silent, default
#        destroy), PAUSE_MS (silent: 150000).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
CUT=${2:-${CUT:-}}
VICTIM=${VICTIM:-destroy}
PAUSE_MS=${PAUSE_MS:-150000}
case $VICTIM in destroy|silent) ;; *) echo "VICTIM must be destroy or silent"; exit 2;; esac
case ${CUT:-} in
    1) CNAME=preintent;; 2) CNAME=prearm;; 3) CNAME=armed;;
    4) CNAME=proved;;    5) CNAME=certified;; 6) CNAME=sealed;;
    7) CNAME=replay-partial;;
    *) echo "usage: $0 <label> <cut 1..7>"; exit 2;; esac
# Cut 7 lives INSIDE the replay, so it needs a replay to exist.  A destroyed
# victim's registration is purged with its iSCSI session on this rig, which
# leaves nothing for a PREEMPT AND ABORT to name, so the fence proves nothing,
# no certificate is minted and no slice is ever replayed — the cut would simply
# never fire and the lap would report VACUOUS after burning its whole budget.
# The silent victim keeps its registration, so the fence completes a real
# operation, certifies, seals and replays.  Refuse the combination up front
# rather than discover it at the marker wait.
if [ "$CUT" = 7 ] && [ "${VICTIM:-destroy}" != silent ]; then
    echo "ABORT: cut 7 cuts inside the replay, and a replay only happens when the fence certifies."
    echo "       On this rig a DESTROYED victim loses its registration with its session, so the"
    echo "       fence proves nothing and nothing is replayed.  Run it as: VICTIM=silent $0 <label> 7"
    exit 2
fi
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover; destroyed at the cut
B=${MXFS_NODE_LIST##*,}          # the victim; destroyed first, returns first
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
# 30 s: the three captures at the cut (window, READ KEYS, table) take 6-10 s
# after the marker is seen, and the marker is seen up to 4 s late; the hold
# must outlast that with margin and stay well under the 62 s dead window
HOLD_MS=${HOLD_MS:-30000}
JOIN_BOUND=${JOIN_BOUND:-300}
NFILES=${NFILES:-64}
# Cut 7 only: how many of the end-of-pass replay buffers are made durable
# before the pass parks.  It has to leave a NONEMPTY suffix — the module
# refuses the cut as vacuous otherwise and says so — and the count it is
# chosen against is the pass's own queued-buffer total, which the module
# prints as P-DRAIN-PEAK queued_buffers=N on every foreign replay.
#
# MEASURED 2026-09-20 (0.89.19): the 64 oracle files are `sync -f`'d, so at the
# fence they are ALREADY ON HOME STORAGE and the replay owes nothing for them,
# and the silent arm's only live workload was one file appended to every 500 ms.
# The whole replay therefore queued ONE buffer — that writer's inode — and the
# cut was correctly declined as vacuous.  A partial replay needs a victim whose
# journal holds committed work the victim has NOT yet checkpointed at the
# instant it is fenced, which means continuous metadata churn (CHURN_* below),
# not a data append.
#
# AND THE PREFIX IS 2, not 8, MEASURED on the first lap that fired: the churn
# leaves a queue in the low tens (14 there), so a prefix of 8 made the PREFIX
# the bulk of the work and left a 6-buffer suffix.  The whole point of the cut
# is that a successor which skipped the suffix would be caught, which wants the
# suffix to carry most of it.
CUT_PREFIX=${CUT_PREFIX:-2}
# Cut 7 only: the victim's metadata churn.  Each batch creates CHURN_NEW files,
# renames CHURN_REN of them, unlinks CHURN_DEL, and fsyncs the directory; a
# batch is acknowledged ONLY after that fsync returns, which is what makes the
# acknowledged set an oracle.  The interval is the pace knob: it has to keep
# committed-but-unwritten work in the log across the 62 s dead window and the
# fence without turning the lap into a throughput test.
CHURN_MS=${CHURN_MS:-250}
CHURN_NEW=8
CHURN_REN=4
CHURN_DEL=2
CHURN_MIN=${CHURN_MIN:-20}
CHK=/src/mxfs/tools/chk_mxfs
DUMP=/src/mxfs/tools/disklock_hb_dump.py
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fcut${CUT}_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
MARK="FCUT-MARK-$LABEL-$CUT"
echo "=== fence_crash_cuts cut=$CUT ($CNAME) label=$LABEL A(prover)=$A B(victim)=$B victim=$VICTIM hold=${HOLD_MS}ms nfiles=$NFILES $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# EVERY EXIT DISARMS.  This lap arms three families of one-shot kernel knobs —
# the fencing cut, the replay cut and the victim's heartbeat park — and starts
# two python helpers on the victim that outlive the stage that started them.
# Until this was added it had no cleanup on any path: the two VACUOUS exits
# (cut-not-reached, cut-declined) and the silence ABORT all returned with the
# prover's cut still armed, or the victim still parked for the rest of its
# PAUSE_MS, on a node that is still running and about to be prepped by the
# next lap in a queue.  An injector left armed across a lap boundary has
# already been measured pushing a following prep from a 45-58 s norm to 150 s,
# and a churner left looping on the mount makes the next unmount busy.
# Cleanup is idempotent, bounded, and must never change this lap's verdict, so
# every write's failure is ignored and the incoming status is passed through.
fcc_disarm() {
    local rc=$? n
    for n in "$A" "$B"; do
        rs 25 "$n" "for p in dbg_fence_crash_hold_ms dbg_fence_crash_slot dbg_fence_crash_cut dbg_replay_cut_hold_ms dbg_replay_cut_slot dbg_replay_cut_epoch dbg_replay_cut_prefix dl_inject_hb_pause_ms; do [ -w $PARM/\$p ] && echo 0 > $PARM/\$p; done; for f in /run/fcut_churn.pid /run/fcut_writer.pid; do q=\$(cat \$f 2>/dev/null); [ -n \"\$q\" ] && kill \"\$q\" 2>/dev/null; done; rm -f /run/fcut_churn.pid; rm -f /run/fcut_writer.pid; true" >/dev/null 2>&1 || true
    done
    return $rc
}
trap fcc_disarm EXIT
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
waitboot() {
    local n w=0 st
    # Start anything that is SHUT OFF before polling it.  Cut 7 ends by
    # destroying both nodes on purpose — the cold-restart boundary is its
    # subject — so the next lap begins with powered-off domains, and a loop
    # that only polls burns its whole 200 s on a node nobody asked to boot.
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
deploy_ko() {   # <node>: NFS back, the tree build copied and checked
    local n=$1
    value_now_into got "$n" 150 "$OUT/${n}_md5.txt" '^[0-9a-f]{32}$' "the module copy on $n" \
        "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n holds the tree build (md5)" "$got" "$MD5"
}
# READ KEYS from <node> into <file>: the PR IN passthrough, its own trailer
keys_into() {   # <node> <file> <what>
    # the PR generation (sg_persist READ KEYS header) rides along: every PROUT
    # moves it, a target-internal purge of a dead session's registration does
    # not, so an unchanged generation across a window says no command landed
    # and READ RESERVATION: the holder key and the type, or "no reservation"
    measure "$1" 40 "$2" '^KEYS_END$' "$3" "$CHK --pr-keys $MXFS_DEV 2>&1; sg_persist -i -k $MXFS_DEV 2>&1 | grep -ao 'PR generation=0x[0-9a-f]*'; sg_persist -i -r $MXFS_DEV 2>&1 | grep -a 'Key=\|type:\|no reservation' | sed 's/^/RESV /'; echo KEYS_END"
}
key_present() { grep -aoE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | grep -ac "^$2$"; }
# the kernel stamp (seconds since boot) of the first line matching <pattern>
ts_first() { grep -a "$2" "$1" | head -1 | grep -aoE '^\[ *[0-9]+\.[0-9]+' | tr -d '[ '; }
# yes when both stamps exist and the first precedes the second
ts_lt() { [ -n "$1" ] && [ -n "$2" ] && awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 < b+0)}' && echo yes || echo "no(${1:-none}<${2:-none})"; }
pr_gen() { grep -ao 'PR generation=0x[0-9a-f]*' "$1" | head -1 | cut -d= -f2; }
# the reservation in a keys capture: none | WE1:<holder key> | WEAR | other:<type text>
resv_of() {
    local t k
    grep -aiq 'RESV.*no reservation' "$1" && { echo none; return; }
    # the reservation's own line carries scope and type; the inquiry header
    # ("Peripheral device type: disk") also says "type:" and is not it
    t=$(grep -a 'RESV.*scope:.*type:' "$1" | head -1 | sed 's/.*type: *//')
    k=$(grep -ao 'RESV.*Key=0x[0-9a-f]*' "$1" | head -1 | grep -ao '0x[0-9a-f]*')
    case "$t" in
        "Write Exclusive, all registrants"*) echo WEAR ;;
        "Write Exclusive"*) echo "WE1:$(normkey "${k:-0}")" ;;
        '') echo none ;;
        *) echo "other:$t" ;;
    esac
}
normkey() { printf '0x%016x' "$(( $1 ))"; }
# the disklock table from <node> into <file>
dump_into() {   # <node> <file> <what>
    measure "$1" 60 "$2" '^slot +[0-9]+ magic=' "$3" "python3 $DUMP $MXFS_DEV"
}
# the victim slot's descriptor line and record line from a dump
desc_of()  { awk -v s="$2" '$1=="slot" && $2==s {f=1; print; next} f && /^    desc/ {print; exit} /^slot/ {f=0}' "$1" | grep -a '^    desc' | head -1; }
slot_of()  { grep -aE "^slot +$2 " "$1" | head -1; }
mounted_into() { value_now_into "$1" "$2" 20 "$3" '^mounted=[01]$' "$4" "mountpoint -q $MNT && echo mounted=1 || echo mounted=0"; }
bad_lines() { echo $(( $(cnt "$1" 'hutting down filesystem') + $(cnt "$1" 'BUG:\|Oops') )); }

# ---- 0. the fleet on the tree build, with the crash-cut injector in it
if [ "$(strings -a mxfs.ko | grep -c 'P-DBG-FENCE-CUT')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P-DBG-FENCE-CUT injector (build the tree first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
MD5=$(md5sum mxfs.ko | cut -c1-32)
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 1. identities: each node's slot from its own claim line; node ids and
#         B's incarnation from the table
for n in "$A" "$B"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "ASLOT=\$slot_$A; VSLOT=\$slot_$B"
dump_into "$A" "$OUT/hb_0.txt" "the disklock table before the arm"
PNODE=$(slot_of "$OUT/hb_0.txt" "$ASLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
VNODE=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
VEPOCH=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'epoch=[0-9]*' | cut -d= -f2)
VKEY=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'pr_key=0x[0-9a-f]*' | cut -d= -f2)
PKEY=$(slot_of "$OUT/hb_0.txt" "$ASLOT" | grep -ao 'pr_key=0x[0-9a-f]*' | cut -d= -f2)
# what this rig's target does with a dead session's registration decides the
# PR-state predictions below (data/rigs.json, measured by
# tests/pr_session_drop_probe.sh): "purged" — the victim key is already gone
# at every cut and the proofs are the successor kinds (boot succession, the
# sole-survivor gate); "persists" — the key stays as the fence target and a
# PREEMPT AND ABORT consumes it.  Sweep s71a failed every lap on predictions
# written for the wrong class.
PRCLASS=$(mxfs_rig_pr_class)
echo "STAGE identities: prover A1=$PNODE slot $ASLOT key $PKEY; victim B1=$VNODE/$VEPOCH slot $VSLOT key $VKEY; target class: registration $PRCLASS on session loss; victim arm: $VICTIM"
# the expectation selector: target class x victim arm.  A silent victim's
# session is up, so its key is present whatever the class and the P&A
# consumes it; a destroyed victim's key is present only on a persistent
# target.  GATE=1 marks the laps whose proof is the sole-survivor gate.
#
# THE KIND NAMES MOVED UNDER THIS HARNESS and the predictions here had not
# caught up — the banked cut sweeps ran on 0.89.10, before two revocations.
# PREEMPT_ABORT_DONE (code point 16) was RETIRED in 0.89.16 because it had two
# producers and only one of them ran an operation; what a completed PREEMPT AND
# ABORT earns now is PREEMPT_ABORT_PROVEN_V1 (23), which
# tests/fence_strong_basis.sh measures directly on every build.  Predicting the
# retired name would have failed cuts 5, 6 and 7 on a certificate that is
# exactly right.
#
# THE DESTROYED-VICTIM ARM ON A PURGING TARGET IS THE WITNESSED LU RESET NOW,
# and the prediction that stood here said the opposite — that the arm "can no
# longer produce a certificate at all".  It can.  Its old proof was
# EXCLUSIVE_WRITE_GATE (20), and the sole-survivor gate still cannot be
# certified, because with the victim's registration already purged its sark=0
# preempt aborts no task set belonging to the victim, so it proves ADMISSION and
# nothing else and refuses for want of a retirement basis.  What the prover
# reaches instead, under the same conditions that guard the gate, is a WITNESSED
# LOGICAL UNIT RESET: the operation is defined on the unit rather than on a
# nexus, so it terminates the tasks the target already accepted from the victim
# whether or not its registration survived, and the certificate is
# LU_RESET_WITNESSED_V1 (24) on retire_basis=completed-target-op.
#
# TWO PREDICTIONS INVERT WITH IT, and both are properties of the operation:
#
#   THE PR GENERATION DOES NOT MOVE.  An LU reset is a task-management function,
#   not a PERSISTENT RESERVE OUT, so it changes no reservation state — and the
#   reset's own convergence check REQUIRES that continuity (gen_before ==
#   gen_after) before the verdict is certified, so a moved generation across one
#   would be the failure rather than the evidence.  That the command reached the
#   target is established by its own witness instead, which is asserted
#   directly.
#
#   NO SINGLE-HOLDER GATE IS INSTALLED, so the all-registrants reservation still
#   stands at the cut.  The gate is deliberately not attempted here: installing
#   a single-holder Write Exclusive and then certifying by another name leaves a
#   gate standing with no recovery to release it and locks a returning
#   incarnation out of writing the LUN at all — the lockout measured and fixed
#   in 0.89.14.
#
# GENMOVE says whether the proving command is a PROUT and so whether the
# generation is expected to move; LURESET marks the laps whose proof is the
# witnessed reset.  GATE still marks a lap whose proof is the sole-survivor
# gate; it is 0 on every arm on this build, because that route needs a
# retirement basis no build since 0.89.16 can obtain, and its branches are kept
# because the route itself is still in the module.
if [ "$VICTIM" = silent ]; then
    KEYPRED=1; KINDPRED=PREEMPT_ABORT_PROVEN_V1; GATE=0; LURESET=0; GENMOVE=moved
elif [ "$PRCLASS" = purged ]; then
    KEYPRED=0; KINDPRED=LU_RESET_WITNESSED_V1;   GATE=0; LURESET=1; GENMOVE=same
else
    KEYPRED=1; KINDPRED=PREEMPT_ABORT_PROVEN_V1; GATE=0; LURESET=0; GENMOVE=moved
fi
echo "STAGE prediction: proving kind $KINDPRED, victim key at the cut $KEYPRED, PR generation $GENMOVE, sole-survivor gate $GATE, witnessed LU reset $LURESET"
if [ -z "$PNODE" ] || [ -z "$VNODE" ] || [ -z "$VKEY" ] || [ "$ASLOT" = "$VSLOT" ]; then
    echo "ABORT: the table did not yield two distinct live records for $A and $B"; echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2
fi
keys_into "$A" "$OUT/K0.txt" "READ KEYS before the arm"
ck "before the arm: B1's key is registered" "$(key_present "$OUT/K0.txt" "$(normkey "$VKEY")")" 1
ck "before the arm: A1's key is registered" "$(key_present "$OUT/K0.txt" "$(normkey "$PKEY")")" 1

# ---- 2. the dirty-death oracle: B fsyncs NFILES files and keeps its mount
measure "$B" 60 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/fcut_${LABEL}_$CUT; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'fcut %s cut $CUT file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before its death" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"

# ---- 3. arm the cut on A, destroy B, wait for the marker
# Cuts 1-6 park the PROVER at a fencing endpoint; cut 7 parks inside the
# REPLAY, which is a different injector with its own knobs.  Both are one-shot
# and both are filtered to this victim — cut 7 additionally by incarnation,
# because a heartbeat slot number is reused and a one-shot that fires on the
# wrong victim is not a deterministic test.
if [ "$CUT" = 7 ]; then
    measure "$A" 30 "$OUT/A_arm.txt" '^ARMED=[0-9]+ slot=-?[0-9]+ epoch=[0-9]+ hold=[0-9]+$' "the replay cut on $A" \
        "echo $MARK > /dev/kmsg; echo $HOLD_MS > $PARM/dbg_replay_cut_hold_ms; echo $VSLOT > $PARM/dbg_replay_cut_slot; echo $VEPOCH > $PARM/dbg_replay_cut_epoch; echo $CUT_PREFIX > $PARM/dbg_replay_cut_prefix; echo ARMED=\$(cat $PARM/dbg_replay_cut_prefix) slot=\$(cat $PARM/dbg_replay_cut_slot) epoch=\$(cat $PARM/dbg_replay_cut_epoch) hold=\$(cat $PARM/dbg_replay_cut_hold_ms)"
    ck "A armed the replay cut (prefix $CUT_PREFIX) for slot $VSLOT incarnation $VEPOCH" \
       "$(grep -a '^ARMED=' "$OUT/A_arm.txt")" "ARMED=$CUT_PREFIX slot=$VSLOT epoch=$VEPOCH hold=$HOLD_MS"
else
    measure "$A" 30 "$OUT/A_arm.txt" '^ARMED=[0-9]+ slot=-?[0-9]+ hold=[0-9]+$' "the arm on $A" \
        "echo $MARK > /dev/kmsg; echo $HOLD_MS > $PARM/dbg_fence_crash_hold_ms; echo $VSLOT > $PARM/dbg_fence_crash_slot; echo $CUT > $PARM/dbg_fence_crash_cut; echo ARMED=\$(cat $PARM/dbg_fence_crash_cut) slot=\$(cat $PARM/dbg_fence_crash_slot) hold=\$(cat $PARM/dbg_fence_crash_hold_ms)"
    ck "A armed cut $CUT for slot $VSLOT" "$(grep -a '^ARMED=' "$OUT/A_arm.txt")" "ARMED=$CUT slot=$VSLOT hold=$HOLD_MS"
fi
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }
T0=$(date +%s)
if [ "$VICTIM" = silent ]; then
    # B stays up: a writer keeps appending fsynced lines to the shared
    # filesystem and logging each attempt (its clock, rc) to this tree over
    # NFS, then B's heartbeat thread is parked for PAUSE_MS.  The pause must
    # outlast the 62 s dead window, the fence to the cut, the hold and the
    # captures, and end while this harness is still watching B.
    WRITER_B64=$(base64 -w0 <<'PY'
import os, sys, time
d, log = sys.argv[1], sys.argv[2]
for i in range(600):
    t = time.time_ns()
    try:
        fd = os.open(d + "/w", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.write(fd, (str(t) + "\n").encode()); os.fsync(fd); os.close(fd); rc = 0
    except Exception:
        rc = 1
    with open(log, "a") as f:
        f.write("%d rc=%d\n" % (t, rc))
    time.sleep(0.5)
PY
)
    # Cut 7 only: the churner.  The appending writer above is the FENCE oracle
    # (after the P&A no fsync of its may succeed); it is not a replay workload,
    # because one appended file is one dirty inode and the cut needs a queue.
    # This one keeps committed metadata in B1's journal ahead of B1's own
    # checkpointing — creates, renames and unlinks, with the directory fsynced
    # at the end of every batch — so that when A fences B the slice still owes
    # real, distinguishable home-state changes.  A batch is logged ONLY after
    # its directory fsync returns, which is what makes the acknowledged batches
    # an oracle: they are exactly the results the filesystem promised.
    CHURN_START=
    if [ "$CUT" = 7 ]; then
        CHURN_B64=$(base64 -w0 <<'PY'
import os, sys, time
d, log = sys.argv[1], sys.argv[2]
new, ren, dele, ms = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
try:
    os.makedirs(d)
except Exception:
    pass
b = 0
while True:
    try:
        for i in range(new):
            fd = os.open("%s/c%d_%d" % (d, b, i), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            os.write(fd, ("%d %d\n" % (b, i)).encode()); os.fsync(fd); os.close(fd)
        for i in range(ren):
            os.rename("%s/c%d_%d" % (d, b, i), "%s/k%d_%d" % (d, b, i))
        for i in range(ren, ren + dele):
            os.unlink("%s/c%d_%d" % (d, b, i))
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(dfd); os.close(dfd)
        rc = 0
    except Exception:
        rc = 1
    with open(log, "a") as f:
        f.write("BATCH %d rc=%d\n" % (b, rc))
    b += 1
    time.sleep(ms / 1000.0 if rc == 0 else 0.5)
PY
)
        # the pid is recorded because the churner's own loop is unbounded: on
        # the paths where B is never destroyed it would otherwise keep writing
        # to the mount the next lap has to unmount.
        CHURN_START="echo $CHURN_B64 | base64 -d > /run/fcut_churn.py; nohup python3 /run/fcut_churn.py \$d/churn /src/mxfs/$OUT/B_churn.txt $CHURN_NEW $CHURN_REN $CHURN_DEL $CHURN_MS > /dev/null 2>&1 & echo \$! > /run/fcut_churn.pid; "
    fi
    measure "$B" 30 "$OUT/B_silence.txt" '^PAUSE_SEEN=[0-9]+$' "the writer and the heartbeat park on $B" \
        "d=$MNT/fcut_${LABEL}_$CUT; echo $WRITER_B64 | base64 -d > /run/fcut_writer.py; nohup python3 /run/fcut_writer.py \$d /src/mxfs/$OUT/B_writer.txt > /dev/null 2>&1 & echo \$! > /run/fcut_writer.pid; ${CHURN_START}sleep 2; echo $MARK > /dev/kmsg; echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms; sleep 4; echo PAUSE_SEEN=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*pausing')"
    ck "B's heartbeat thread parked (P-HB-INJECT-PAUSE) with its session and writer alive" "$(field "$OUT/B_silence.txt" PAUSE_SEEN)" 1
    [ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=silence evidence=$OUT"; exit 2; }
    echo "STAGE $B silent (heartbeat parked ${PAUSE_MS} ms, writer running) at +$(el)s — waiting for A to reach cut $CUT (dead window 62 s)"
else
    $VIRSH destroy "$B" > /dev/null 2>&1
    echo "STAGE destroyed $B at +$(el)s — waiting for A to reach cut $CUT (dead window 62 s)"
fi
# Cut 7's marker is further away than any fencing endpoint: the fence has to
# complete, certify, seal and claim the execution lease before the replay it
# cuts into even starts.  Give it the extra time rather than report VACUOUS on
# a lap that was still making progress.
if [ "$CUT" = 7 ]; then
    CUTPAT="P-DBG-REPLAY-CUT slot=$VSLOT "
    wait_for_into parked "$A" 200 "$MARK" "P-DBG-REPLAY-CUT"
else
    CUTPAT="P-DBG-FENCE-CUT cut=$CUT "
    wait_for_into parked "$A" 110 "$MARK" "$CUTPAT"
fi
T_MARK=$(date +%s)
echo "STAGE marker: parked=$parked at +$(el)s ($(( T_MARK - T0 )) s after the destroy)"
if [ "$parked" = timeout ]; then
    window_into "$OUT/A_window_nocut.txt" "$A" 30 "$MARK"
    echo "  the prover never reached cut $CUT; its fence lines:"
    grep -a 'P236-FENCE\|P238-FENCE\|P-DBG-FENCE\|P-DBG-REPLAY\|P-DRAIN-PEAK\|P-PRKEY-FENCE\|MXFS-MEMBERSHIP' "$OUT/A_window_nocut.txt" | sed 's/.*mxfs: /    /; s/.*disklock: /    /' | cut -c1-180 | head -10
    echo "RESULT: VACUOUS label=$LABEL stage=cut-not-reached wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 4. AT THE CUT: A's kernel window (journald is volatile), READ KEYS,
#         the table — then destroy A.  Every capture is bounded so the three
#         of them stay inside the hold.
window_into "$OUT/A_at_cut.txt" "$A" 20 "$MARK"
# Cut 7 can DECLINE itself, and that has to be discovered before the prover is
# killed.  If the pass queued no more buffers than the prefix asked for there
# is no suffix, "everything was applied" is the ordinary success this lap is
# meant to differ from, and the module says so and submits normally.  Killing A
# at that point would cost a boot on both nodes to learn nothing, so the check
# sits here, between the window and the destroy, rather than after it.
if [ "$CUT" = 7 ] && [ "$(cnt "$OUT/A_at_cut.txt" 'P-DBG-REPLAY-CUT-VACUOUS')" != 0 ]; then
    echo "  the module declined the cut: the pass did not queue enough buffers to leave a suffix"
    grep -a 'P-DBG-REPLAY-CUT-VACUOUS\|P-DRAIN-PEAK' "$OUT/A_at_cut.txt" | sed 's/.*mxfs: /    /' | cut -c1-220
    echo "  raise the victim's dirty workload (NFILES) or lower CUT_PREFIX, then re-run — nothing was destroyed"
    echo "RESULT: VACUOUS label=$LABEL stage=cut-declined wall=$(el)s evidence=$OUT"; exit 3
fi
keys_into "$A" "$OUT/K1.txt" "READ KEYS at the cut"
dump_into "$A" "$OUT/hb_1_at_cut.txt" "the disklock table at the cut"
T_KILL=$(date +%s)
$VIRSH destroy "$A" > /dev/null 2>&1
echo "STAGE destroyed $A at +$(el)s ($(( T_KILL - T_MARK )) s after the marker; hold ${HOLD_MS} ms)"
cutline=$(grep -a "$CUTPAT" "$OUT/A_at_cut.txt" | grep -av 'hold expired' | head -1 | sed 's/.*mxfs: //' | cut -c1-200)
echo "    $cutline"
if [ "$CUT" = 7 ]; then
    PREFIX_N=$(grep -a 'P-DBG-REPLAY-CUT slot=' "$OUT/A_at_cut.txt" | head -1 | grep -ao 'prefix=[0-9]*' | cut -d= -f2)
    SUFFIX_N=$(grep -a 'P-DBG-REPLAY-CUT slot=' "$OUT/A_at_cut.txt" | head -1 | grep -ao 'suffix=[0-9]*' | cut -d= -f2)
    echo "STAGE the replay was cut with prefix=${PREFIX_N:-?} buffer(s) durable and suffix=${SUFFIX_N:-?} never issued"
fi
# contamination: the hold expired, a self-fence, or a PR/membership change
# between the marker and the destroy — any of them makes the lap not a
# measurement of cut $CUT.  A self-fence is the module's own P131/P236
# SELF-FENCE line; the TCP peer-death deferral ("deferring death ... EX
# frozen (self-fence)") is the prover freezing its OWN exclusive grants
# while it waits out the flap tolerance, printed on every lap on this
# transport, and it aborted every s70j cut when the count matched it.
if [ "$CUT" = 7 ]; then
    expired=$(cnt "$OUT/A_at_cut.txt" 'P-DBG-REPLAY-CUT-EXPIRED')
else
    expired=$(grep -a "$CUTPAT" "$OUT/A_at_cut.txt" | grep -ac 'hold expired')
fi
selffence=$(cnt "$OUT/A_at_cut.txt" 'P131-SELF-FENCE\|P236-SELF-FENCE\|hutting down filesystem')
if [ $(( T_KILL - T_MARK )) -ge $(( HOLD_MS / 1000 - 6 )) ] || [ "$expired" != 0 ] || [ "$selffence" != 0 ]; then
    echo "ABORT: contaminated lap — destroy $(( T_KILL - T_MARK )) s after the marker against a $(( HOLD_MS / 1000 )) s hold, hold-expired lines=$expired, self-fence/shutdown lines=$selffence"
    $VIRSH start "$B" > /dev/null 2>&1; $VIRSH start "$A" > /dev/null 2>&1
    echo "RESULT: ABORT label=$LABEL stage=contaminated wall=$(el)s evidence=$OUT"; exit 2
fi
S1=$(desc_of "$OUT/hb_1_at_cut.txt" "$VSLOT"); R1=$(slot_of "$OUT/hb_1_at_cut.txt" "$VSLOT")
k1_v=$(key_present "$OUT/K1.txt" "$(normkey "$VKEY")"); k1_p=$(key_present "$OUT/K1.txt" "$(normkey "$PKEY")")
gen0=$(pr_gen "$OUT/K0.txt"); gen1=$(pr_gen "$OUT/K1.txt")
echo "STAGE at the cut: B1 key present=$k1_v A1 key present=$k1_p PR generation ${gen0:-?} -> ${gen1:-?}"
echo "    ${R1:-no record}"
echo "    ${S1:-no descriptor}"

# ---- 4b. SILENT VICTIM: the still-running B after the prover's death.
#          Its heartbeat resumes at the end of the pause; it must then
#          contain itself (its key is gone from the target at cuts >= 4, or
#          its writes bounced on the reservation) and never write again.
#          The writer's log (B's clock, rc per fsync) is the record: after
#          the P&A no fsync may succeed, and in particular none after A's
#          death took the last registration and reservation with it.
if [ "$VICTIM" = silent ]; then
    resume_wait=$(( PAUSE_MS / 1000 + 45 - ( $(date +%s) - T0 ) )); [ $resume_wait -lt 20 ] && resume_wait=20
    wait_for_into resumed "$B" "$resume_wait" "$MARK" "P-HB-INJECT-PAUSE.*resumed"
    sleep 15
    measure "$B" 60 "$OUT/B_contain.txt" '^CONTAIN_END$' "B's containment lines after its heartbeat resumed" \
        "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P-HB-INJECT-PAUSE\|P277-\|P-PR-OWNKEY-GONE\|P305-RESV-SELF\|P-PR-SELFFENCE\|hutting down filesystem\|P131-SELF-FENCE\|P236-SELF-FENCE' | cut -c1-300; echo CONTAIN_END"
    # The counted set must be the SAME set the capture above collects.  It was
    # not: the capture took P131-SELF-FENCE and P236-SELF-FENCE and the count
    # left both out, so lap s108a read contain=0 while B's own kernel log
    # carried "P131-SELF-FENCE [AUTHORITY_LEASE_EXPIRED]" and every fsync after
    # it returned rc=1.  A node that self-fences on an expired authority lease
    # has contained itself by the definition this assertion's own name gives
    # ("self-withdraw / own key gone / shutdown"); naming only some of the ways
    # the module says so fails a containment that is working.
    contain=$(cnt "$OUT/B_contain.txt" 'P277-FENCED-SELF-WITHDRAW\|P-PR-OWNKEY-GONE\|P277-PR-FULLSTATUS\|P277-PR-READKEYS\|P305-RESV-SELF\|P-PR-SELFFENCE\|P131-SELF-FENCE\|P236-SELF-FENCE\|hutting down filesystem')
    echo "STAGE B resumed=$resumed containment lines=$contain at +$(el)s"
    grep -a 'P277-\|P-PR-OWNKEY\|P305-RESV\|hutting down' "$OUT/B_contain.txt" | sed 's/.*mxfs: /    /; s/.*scsipr: /    /' | cut -c1-200 | head -6
    wl=$OUT/B_writer.txt
    total_w=$(grep -ac 'rc=' "$wl" 2>/dev/null || echo 0)
    ok_after_mark=$(awk -v t="$(( T_MARK * 1000000000 + 5000000000 ))" '$2=="rc=0" && $1+0 > t' "$wl" 2>/dev/null | wc -l)
    ok_after_kill=$(awk -v t="$(( T_KILL * 1000000000 + 5000000000 ))" '$2=="rc=0" && $1+0 > t' "$wl" 2>/dev/null | wc -l)
    last_ok=$(awk '$2=="rc=0"{t=$1} END{print t+0}' "$wl" 2>/dev/null)
    echo "STAGE B writer: attempts=$total_w fsync-ok after the marker(+5 s)=$ok_after_mark after A's death(+5 s)=$ok_after_kill last-ok at $(( (last_ok - T0 * 1000000000) / 1000000000 )) s after the park"
    ckge "B (silent): fsynced $total_w attempts were logged (the writer ran)" "$total_w" 20
    if [ "$CUT" -ge 4 ]; then
        ck "B (silent, cut >= 4): NO fsync from the fenced incarnation succeeded after A's death removed the last registration and reservation (the ruling's unreserved-LUN hazard)" "$ok_after_kill" 0
        ck "B (silent, cut >= 4): no fsync succeeded after the P&A consumed B1's key (the marker +5 s)" "$ok_after_mark" 0
        ckge "B (silent): B contained itself when its heartbeat resumed (self-withdraw / own key gone / shutdown)" "$contain" 1
    else
        echo "  (cuts 1-3: no P&A was issued, B1 stays registered and its writes are legitimate until it is destroyed)"
    fi
    T_BKILL=$(date +%s)
    $VIRSH destroy "$B" > /dev/null 2>&1
    echo "STAGE destroyed $B at +$(el)s (silent arm: the boot boundary for the successor obligations)"
fi

# ---- 5. QUIESCENT: B's host returns; before it mounts, the platter and
#         READ KEYS from its fresh boot (an observer that registers nothing
#         and claims nothing), compared with the state at the cut
$VIRSH start "$B" > /dev/null 2>&1
waitboot "$B"
deploy_ko "$B"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=deploy evidence=$OUT"; $VIRSH start "$A" > /dev/null 2>&1; exit 2; }
mxfs_dev_check "$B"
dump_into "$B" "$OUT/hb_2_quiescent.txt" "the quiescent platter from $B's fresh boot, before its mount"
S2=$(desc_of "$OUT/hb_2_quiescent.txt" "$VSLOT"); R2=$(slot_of "$OUT/hb_2_quiescent.txt" "$VSLOT")
echo "STAGE quiescent (A dead, B booted and not mounted):"
echo "    ${R2:-no record}"
echo "    ${S2:-no descriptor}"
ck "the platter did not move between the marker and B's return (B1's descriptor identical at the cut and quiescent)" "$([ "$S1" = "$S2" ] && echo same || echo moved)" same
# the intent CAS turns the victim's record into RECOVERY_GUARD carrying the
# descriptor (the dump prints the descriptor only under that flag); before
# the intent the record is B1's stale ACTIVE heartbeat.  Either way nothing
# was published (zeroed) before the crash.
if [ "$CUT" = 1 ]; then
    # WHICH flag the victim's own record carries is the ARM's answer, not the
    # cut's, and asserting one of them on both arms fails a lap in which the
    # module did exactly what it says.  A DESTROYED victim stops beating where
    # it stood, so its last stamp is the ACTIVE one.  A SILENT victim's own
    # setup parks its heartbeat for PAUSE_MS, which outlasts the 30 s
    # authority lease, so it self-fences on an expired lease and stamps
    # WITHDRAWN before the prover is ever cut — measured on the s127 sweep,
    # P131-SELF-FENCE [AUTHORITY_LEASE_EXPIRED] with the slot's ts_ms frozen
    # at the instant of the self-fence.  Both are "no intent was published",
    # which is what cut 1 is for.
    if [ "$VICTIM" = silent ]; then
        ck "B1's own record stands as its self-fenced heartbeat, WITHDRAWN and carrying no intent" "$(echo "$R2" | grep -ac 'flags=WITHDRAWN')" 1
        ckge "B1 stamped WITHDRAWN because its parked heartbeat outlived its own authority lease, not because anyone fenced it" "$(cnt "$OUT/B_contain.txt" 'P131-SELF-FENCE.*AUTHORITY_LEASE_EXPIRED')" 1
    else
        ck "B1's own record still stands as its stale ACTIVE heartbeat (no intent yet)" "$(echo "$R2" | grep -ac 'flags=ACTIVE')" 1
    fi
else
    ck "B1's slot carries the attempt (RECOVERY_GUARD) and was not published" "$(echo "$R2" | grep -ac 'flags=RECOVERY_GUARD')" 1
fi
stage2=$(echo "$S2" | grep -ao 'stage=[A-Z_]*' | cut -d= -f2)
flags2=$(echo "$S2" | grep -ao 'flags=0x[0-9a-f]*' | cut -d= -f2)
kind2=$(echo "$S2" | grep -ao 'fence_kind=[A-Z0-9_]*' | cut -d= -f2)
prover2=$(echo "$S2" | grep -ao 'prover=[0-9]*' | cut -d= -f2)
owner2=$(echo "$S2" | grep -ao 'owner=[a-z0-9/]*' | cut -d= -f2)
[ "$owner2" = "0/0" ] && owner2=none     # the dump prints an unowned lease as 0/0
armed2=$(( ${flags2:-0} & 0x8 ))
echo "STAGE durable state at cut $CUT: stage=${stage2:-none} flags=${flags2:-0} may_have_run=$armed2 kind=${kind2:-none} prover=${prover2:-none} owner=${owner2:-none}"
# The PR predictions follow the target class (STAGE identities).  What holds
# for every class: cuts 1-3 leave the PR generation where the pre-arm capture
# found it (the intent and arm CASes are platter writes, the PROUT never
# left); cut 4's proving command moved it.  What follows the class: whether
# the victim key is still registered at cuts 1-3 (purged: gone with the
# session; persists: the fence target), and which mechanism cut 4 proves with
# (purged: the sole-survivor gate, since no P&A can consume an absent key;
# persists: the P&A consumed it) — read from the prover's own window and the
# reservation the capture saw, never inferred from the cut number.
gensame=$([ -n "$gen0" ] && [ "$gen0" = "$gen1" ] && echo same || echo "${gen0:-?}->${gen1:-?}")
genmoved=$([ -n "$gen0" ] && [ -n "$gen1" ] && [ "$gen0" != "$gen1" ] && echo moved || echo "${gen0:-?}->${gen1:-?}")
kind_at_cut=$(grep -a 'P236-FENCEKIND' "$OUT/A_at_cut.txt" | grep -a "node=$VNODE " | grep -ao 'kind=[A-Z0-9_]*' | tail -1 | cut -d= -f2)
resv1=$(resv_of "$OUT/K1.txt")
echo "STAGE at the cut: proving kind in A's window=${kind_at_cut:-none} reservation=$resv1"
case $CUT in
1)  ck "cut 1: no fencing attempt stands on B1's slot" "$(echo "$S2" | grep -ac 'stage=FENCING\|stage=SNAPSHOTTING\|stage=FENCED')" 0
    ck "cut 1: B1's key at the cut as the target class predicts (registration $PRCLASS)" "$k1_v" $KEYPRED
    ck "cut 1: PR generation unchanged from the pre-arm capture (no PROUT left)" "$gensame" same ;;
2)  ck "cut 2: FENCING intent durable, prover A1" "${stage2:-none}/${prover2:-none}" "FENCING/$PNODE"
    ck "cut 2: the arm CAS has NOT landed (MAY_HAVE_RUN clear)" "$armed2" 0
    ck "cut 2: B1's key at the cut as the target class predicts (registration $PRCLASS)" "$k1_v" $KEYPRED
    ck "cut 2: PR generation unchanged from the pre-arm capture (no PROUT left)" "$gensame" same ;;
3)  ck "cut 3: FENCING intent durable, prover A1" "${stage2:-none}/${prover2:-none}" "FENCING/$PNODE"
    ck "cut 3: armed (MAY_HAVE_RUN set), not dispatched" "$armed2" 8
    ck "cut 3: B1's key at the cut as the target class predicts (registration $PRCLASS)" "$k1_v" $KEYPRED
    ck "cut 3: PR generation unchanged from the pre-arm capture (the PROUT never left)" "$gensame" same ;;
4)  ck "cut 4: FENCING intent durable, prover A1" "${stage2:-none}/${prover2:-none}" "FENCING/$PNODE"
    ck "cut 4: armed (MAY_HAVE_RUN set)" "$armed2" 8
    ck "cut 4: the prover's window names the proving kind the class predicts ($KINDPRED)" "${kind_at_cut:-none}" "$KINDPRED"
    if [ "$GENMOVE" = moved ]; then
        ck "cut 4: PR generation moved (the proving PROUT reached the target)" "$genmoved" moved
    else
        ck "cut 4: PR generation unchanged (the proving operation is a task-management function, and its own convergence check requires that continuity)" "$gensame" same
    fi
    # For the witnessed reset the generation cannot say the command reached the
    # target, so the prover's own window has to: the reset was issued and its
    # verdict came back certified on a completed target operation.
    if [ "$LURESET" = 1 ]; then
        ckge "cut 4: the prover issued the reset before the cut (P305-LURESET-ISSUE in A's window)" "$(cnt "$OUT/A_at_cut.txt" 'P305-LURESET-ISSUE')" 1
        ckge "cut 4: the prover's verdict was certified on a completed target operation (P308-LURESET-FENCE)" "$(grep -a 'P308-LURESET-FENCE' "$OUT/A_at_cut.txt" | grep -ac 'certified=1 verdict=certified.*basis=completed-target-op')" 1
    fi
    ck "cut 4: B1's key ABSENT at the cut" "$k1_v" 0
    ck "cut 4: A1's own key still registered" "$k1_p" 1
    if [ "$GATE" = 1 ]; then
        ck "cut 4: the sole-survivor gate is in force: a single-holder Write Exclusive held by A1's key" "$resv1" "WE1:$(normkey "$PKEY")"
    elif [ "$LURESET" = 1 ]; then
        ck "cut 4: the all-registrants reservation stands (no single-holder gate was installed, which is what keeps a returning incarnation able to write the LUN)" "$resv1" WEAR
    else
        ck "cut 4: the all-registrants reservation stands (the P&A named only the victim)" "$resv1" WEAR
    fi
    ck "cut 4: no certificate on the platter (the proof was volatile)" "$(echo "$S2" | grep -ac 'stage=SNAPSHOTTING\|stage=FENCED')" 0 ;;
5)  ck "cut 5: certified (SNAPSHOTTING), kind $KINDPRED, prover A1" "${stage2:-none}/${kind2:-none}/${prover2:-none}" "SNAPSHOTTING/$KINDPRED/$PNODE"
    ck "cut 5: B1's key ABSENT at the cut" "$k1_v" 0
    [ "$GATE" = 1 ] && ck "cut 5: the gate the certificate rests on is in force (WE(1) held by A1's key)" "$resv1" "WE1:$(normkey "$PKEY")"
    # A witnessed reset's exclusion is a COMPLETED PAST OPERATION, so there is no
    # standing reservation state for the certificate to rest on and none to find
    # in force; what must hold is that nothing installed a single-holder gate.
    [ "$LURESET" = 1 ] && ck "cut 5: the all-registrants reservation stands (the certificate rests on a completed target operation, not on a gate)" "$resv1" WEAR ;;
6)  ck "cut 6: sealed (FENCED), kind $KINDPRED, prover A1, no execution owner" "${stage2:-none}/${kind2:-none}/${prover2:-none}/${owner2:-none}" "FENCED/$KINDPRED/$PNODE/none"
    ck "cut 6: B1's key ABSENT at the cut" "$k1_v" 0
    [ "$GATE" = 1 ] && ck "cut 6: the gate the certificate rests on is in force (WE(1) held by A1's key)" "$resv1" "WE1:$(normkey "$PKEY")"
    [ "$LURESET" = 1 ] && ck "cut 6: the all-registrants reservation stands (the certificate rests on a completed target operation, not on a gate)" "$resv1" WEAR ;;
7)  # The proof is finished and the REPLAY is half-applied.  Everything the
    # earlier cuts assert about the certificate must still hold — the cut is
    # downstream of all of it — and what is new is the three facts that make
    # this a partial replay rather than a slow one: a nonempty durable prefix,
    # a nonempty unissued suffix, and NO completion.  The prefix and suffix
    # come from the module's own cut line, so they are counted, not assumed.
    ck "cut 7: sealed (FENCED), kind $KINDPRED, prover A1" \
       "${stage2:-none}/${kind2:-none}/${prover2:-none}" "FENCED/$KINDPRED/$PNODE"
    ck "cut 7: the execution lease is held, so the replay was authorised before it ran" \
       "$([ "${owner2:-none}" != none ] && echo held || echo none)" held
    ck "cut 7: B1's key ABSENT at the cut (the P&A consumed it)" "$k1_v" 0
    ckge "cut 7: a NONEMPTY prefix of the replay is durable on home storage" "${PREFIX_N:-0}" 1
    ckge "cut 7: a NONEMPTY required suffix was never issued" "${SUFFIX_N:-0}" 1
    # The whole point.  If a completion had become durable the successor would
    # be entitled to skip the suffix and then retire the only copy of it, which
    # is the corruption this entry exists to look for.
    ck "cut 7: NO recovery completion became durable before the crash" \
       "$(cnt "$OUT/A_at_cut.txt" 'P163-RECOVERY-COMPLETE')" 0
    ck "cut 7: the victim's slot was NOT published, retired or zeroed" \
       "$(echo "$R2" | grep -ac 'flags=RECOVERY_GUARD')" 1 ;;
esac
if [ $fails != 0 ]; then
    echo "  the durable state at the cut is not the predicted one; the recovery outcome below is measured but attributed to THIS state, not to cut $CUT"
fi

# ---- 6. B mounts alone: keys before it registers (a PR IN changes
#         nothing), then the mount, then its journal and the table.
keys_into "$B" "$OUT/K2.txt" "READ KEYS from B's fresh boot before its mount"
k2_v=$(key_present "$OUT/K2.txt" "$(normkey "$VKEY")"); k2_p=$(key_present "$OUT/K2.txt" "$(normkey "$PKEY")")
resv2=$(resv_of "$OUT/K2.txt")
echo "STAGE B back: B1 key present=$k2_v A1 key present=$k2_p reservation=$resv2 (the target's registrations across the two session losses)"
# the observed loss, never the class label: on a purging target A's death
# takes its registration and, with it, any gate it held; on a persistent one
# A1's key stays as the fence target for B's successor
if [ "$PRCLASS" = purged ]; then
    ck "B back: A1's registration went with its session, and no reservation survives it" "$k2_p/$resv2" "0/none"
else
    ck "B back: A1's registration persists as the fence target" "$k2_p" 1
fi
BMARK=$(date +%s)
rsx $((JOIN_BOUND + 60)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/B_mount.txt"
capture_require "$OUT/B_mount.txt" '^(MOUNTED|NOT_MOUNTED)$' "the mount on $B's fresh boot"
echo "STAGE B mount rc=$(field "$OUT/B_mount.txt" MOUNT_RC) wall=$(field "$OUT/B_mount.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/B_mount.txt") at +$(el)s"
measure "$B" 60 "$OUT/B_journal.txt" '^JOURNAL_END$' "the kernel journal on $B since its boot" "dmesg | cut -c1-600; echo JOURNAL_END"
J=$OUT/B_journal.txt
echo "--- B: CERTIFIED(A1)=$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -ac "victim=$PNODE ") CERTIFIED(B1)=$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -ac "victim=$VNODE ") TAKEOVER=$(cnt "$J" 'P238-FENCE-TAKEOVER ') SELFSUCC=$(cnt "$J" 'P238-FENCE-SELF-SUCCESSION') BOOTSUCC=$(cnt "$J" 'BOOT_SUCCESSION_ABSENT') COMPLETE(B1)=$(grep -a 'P163-RECOVERY-COMPLETE' "$J" | grep -ac "node=$VNODE ") COMPLETE(A1)=$(grep -a 'P163-RECOVERY-COMPLETE' "$J" | grep -ac "node=$PNODE ") UNRECORDED=$(cnt "$J" 'P238-FENCE-UNRECORDED') BLOCKED=$(cnt "$J" 'P238-FENCE-BLOCKED')"
grep -ah 'P236-FENCE-CERTIFIED\|P238-FENCE-TAKEOVER\|P236-FENCE-ATTEMPT-TAKEOVER\|P238-FENCE-SELF-SUCCESSION\|BOOT_SUCCESSION\|P238-FENCE-UNRECORDED\|P238-FENCE-BLOCKED\|P238-FENCE-PENDING\|P304-FENCE-RETRY \|P239-GATE-REPROVE\|P163-RECOVERY-COMPLETE\|P-DEAD-INC\|P305-PR' "$J" | sed 's/.*mxfs: /    /; s/.*disklock: /    /' | cut -c1-200 | sort -u | head -18
b1kind=$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -a "victim=$VNODE " | grep -ao 'kind=[A-Z0-9_]*' | head -1 | cut -d= -f2)
ck   "B: the mount completed (this shape MUST recover)" "$(grep -ac '^MOUNTED' "$OUT/B_mount.txt")" 1
ckge "B: the dead prover A1 was certified fenced" "$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -ac "victim=$PNODE ")" 1
ckge "B: B1's recovery completed (P163-RECOVERY-COMPLETE for B1)" "$(grep -a 'P163-RECOVERY-COMPLETE' "$J" | grep -ac "node=$VNODE ")" 1
# A1's SLICE MUST BE RECOVERED, AND THERE ARE TWO ROUTES THAT DO IT.  Which
# one runs is a property of this harness's shape, not of the fence: on a live
# cluster a survivor foreign-replays the dead slot and logs
# P163-RECOVERY-COMPLETE for it, but every cut here destroys A while B is
# already down, so B's next mount finds a frozen table with two victims,
# declares a TOTAL OUTAGE and comes up as the whole-cluster bootstrap owner.
# That owner ADOPTS one certified victim's slot as its own log and replays it
# FULLY under authority evaluation (P-BOOT-ADOPT, P-BOOT-ADOPTED-LOG) rather
# than foreign-replaying it, so no P163-RECOVERY-COMPLETE is owed for that
# victim and demanding one fails a recovery that ran.
#
# ADOPTION ALONE IS NOT RECOVERY, so the bootstrap branch requires all three:
# the adoption of A1's slot, the adopted slice's replay having come back OK,
# and the bootstrap itself reaching completion.  A lap that adopted the slot
# and then did not replay it would be the exact hole this assertion exists to
# catch, and it still fails here.
a1_p163=$(grep -a 'P163-RECOVERY-COMPLETE' "$J" | grep -ac "node=$PNODE ")
a1_adopt=$(grep -a 'P-BOOT-ADOPT ' "$J" | grep -ac "slot=$ASLOT victim=$PNODE/")
a1_kreplay=$(cnt "$J" 'P-BOOT-ESCROW-K-REPLAY-OK')
boot_done=$(cnt "$J" 'P-BOOT-RECOVERY-COMPLETE')
echo "--- B: A1's recovery route: foreign-replay=$a1_p163 adopted-as-own-log=$a1_adopt adopted-replay-ok=$a1_kreplay bootstrap-complete=$boot_done"
if [ "$a1_p163" -ge 1 ]; then
    ckge "B: A1's recovery completed (P163-RECOVERY-COMPLETE for A1)" "$a1_p163" 1
else
    ck "B: A1's slice was recovered as the bootstrap owner's adopted log (adopt + replay OK + bootstrap complete, all three)" "$a1_adopt/$a1_kreplay/$boot_done" "1/1/1"
fi
# EVERY WITNESSED-LU-RESET CERTIFICATE MUST CARRY ITS WITNESS.  kind 24 is the
# only fence class in this harness whose validity rests on a command the
# successor issued rather than on state it read, so a certificate naming it is
# checked against the four things that command owes: the reset was issued at
# all, the target readmitted it afterwards with the PR generation continuous,
# the authority the replay would run under survived it, and the verdict came
# back certified on retire_basis=completed-target-op.  A certificate naming
# kind 24 with any of those missing would be the class asserting what it did
# not witness.
lur_certs=$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -ac 'kind=LU_RESET_WITNESSED_V1')
if [ "$lur_certs" -gt 0 ]; then
    echo "--- B: witnessed LU resets: certs=$lur_certs issued=$(cnt "$J" 'P305-LURESET-ISSUE') admitted=$(grep -a 'P306-LURESET-ADMIT' "$J" | grep -ac 'admitted=1') converged=$(grep -a 'P307-LURESET-CONVERGE' "$J" | grep -ac 'converged=1') barrier_held=$(grep -a 'P307-LURESET-BARRIER' "$J" | grep -ac 'held=1') certified=$(grep -a 'P308-LURESET-FENCE' "$J" | grep -ac 'certified=1 verdict=certified')"
    ckge "B: every LU_RESET_WITNESSED_V1 certificate had a reset actually issued (P305-LURESET-ISSUE)" "$(cnt "$J" 'P305-LURESET-ISSUE')" "$lur_certs"
    ckge "B: the target readmitted the reset with its PR generation continuous (P307-LURESET-CONVERGE converged=1)" "$(grep -a 'P307-LURESET-CONVERGE' "$J" | grep -ac 'converged=1')" "$lur_certs"
    ckge "B: the authority the replay runs under survived each reset (P307-LURESET-BARRIER held=1)" "$(grep -a 'P307-LURESET-BARRIER' "$J" | grep -ac 'held=1')" "$lur_certs"
    ckge "B: each reset's verdict was certified on a completed target operation (P308-LURESET-FENCE basis=completed-target-op)" "$(grep -a 'P308-LURESET-FENCE' "$J" | grep -ac 'certified=1 verdict=certified.*basis=completed-target-op')" "$lur_certs"
    ck   "B: no LU-reset leg was left unasked or refused after issuing (P238-FENCE-LURESET-UNASKED / -NOMEM)" "$(cnt "$J" 'P238-FENCE-LURESET-UNASKED')/$(cnt "$J" 'P238-FENCE-LURESET-NOMEM')" "0/0"
fi
# The successor's obligations by cut (design-consult ruling): at 1-4 no
# durable B1 certificate exists (cut 4's proof was volatile), so B2 must
# obtain and name a NEW proof of ITS term — on a purging target boot
# succession (B2 is B1's host's later boot) or the sole-survivor gate, never
# a relabelled absence; at 5-6 the durable certificate is taken over, and on
# a purging target the exclusion it rested on went with A's registration, so
# B2 must re-prove the gate under its own key (P239-GATE-REPROVED) before
# B1's recovery may proceed.  Cut 3 additionally shows that the dead term's
# arm did not strand the taken-over attempt: the P304-FENCE-RETRY count is
# printed for the record (the first prove may already succeed when no other
# gate is in force at that moment).
retries=$(grep -a 'P304-FENCE-RETRY ' "$J" | grep -ac "slot=$VSLOT ")
reproved=$(grep -a 'P239-GATE-REPROVED' "$J" | grep -ac "victim=$VNODE ")
echo "--- B: B1 attempt re-drives=$retries gate re-proofs for B1=$reproved"
case $CUT in
1|2|3|4)
    ckge "B: B1 was certified by the successor (no durable certificate stood at cut $CUT)" "$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -ac "victim=$VNODE ")" 1
    # LU_RESET_WITNESSED_V1 IS A PROOF OF THE SUCCESSOR'S OWN TERM, and the
    # strongest of the set: the successor issues ONE LOGICAL UNIT RESET itself,
    # under its own term, and the certificate rests on
    # retire_basis=completed-target-op — so unlike the other two it establishes
    # RETIREMENT and not only admission.  It is the leg a victim whose
    # registration the target already purged now reaches, because there is no
    # descriptor left for a PREEMPT AND ABORT to name.  Leaving it out of the
    # accepted set failed a fence that was working (measured at cut 1, s118a).
    # What the assertion is really refusing has not changed: a certificate that
    # relabels the ABSENCE of the victim's key as a proof.
    if [ "$PRCLASS" = purged ]; then
        ck "B: B1's certificate names a proof of the successor's own term — LU_RESET_WITNESSED_V1, BOOT_SUCCESSION_ABSENT or EXCLUSIVE_WRITE_GATE, never PREEMPT_ABORT_DONE on a key the target purged (kind=$b1kind)" "$(case $b1kind in LU_RESET_WITNESSED_V1|BOOT_SUCCESSION_ABSENT|EXCLUSIVE_WRITE_GATE) echo named;; *) echo "${b1kind:-none}";; esac)" named
    elif [ "$CUT" = 4 ] || [ "$k2_v" = 0 ]; then
        ck "B: B1's key was consumed before the successor's P&A, so the certificate names a NEW proof (LU_RESET_WITNESSED_V1, SELF_SUCCESSION_DONE or BOOT_SUCCESSION_ABSENT), never PREEMPT_ABORT_DONE (kind=$b1kind)" "$(case $b1kind in LU_RESET_WITNESSED_V1|SELF_SUCCESSION_DONE|BOOT_SUCCESSION_ABSENT) echo named;; *) echo "${b1kind:-none}";; esac)" named
    else
        ck "B: B1's certificate names a proving mechanism (kind=$b1kind)" "$(case $b1kind in PREEMPT_ABORT_DONE|SELF_SUCCESSION_DONE|BOOT_SUCCESSION_ABSENT) echo named;; *) echo "${b1kind:-none}";; esac)" named
    fi ;;
5|6)
    ck   "B: no NEW certificate for B1 — the durable one was taken over" "$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -ac "victim=$VNODE ")" 0
    # a PREEMPT_ABORT_DONE certificate stays usable while its exclusion
    # conditions hold (victim key absent, a Write Exclusive form held, our
    # key present); the mount re-establishes the reservation a purging
    # target dropped with A's registration, and the claim's own recheck is
    # the gate — a recorded lapse is the failure
    ck   "B: the taken-over certificate's exclusion was not found lapsed (P239-EXCL-LAPSED)" "$(cnt "$J" 'P239-EXCL-LAPSED')" 0
    if [ "$GATE" = 1 ]; then
        # The kind-20 certificate's gate went with A1's registration.  What
        # the module does (measured s71a cut 5): B2 is the sole survivor, so
        # it installs the exclusive-write gate under ITS key to fence A1
        # (P-PR-GATE) — or re-proves the lapsed one (P239-GATE-REPROVED) —
        # and only then claims B1's certified recovery; the gate is restored
        # to WE-AR only after B1's recovery completed (the gate dependency).
        # The order is the assertion, read from the journal's own stamps.
        t_gate=$(ts_first "$J" 'P-PR-GATE \|P239-GATE-REPROVED')
        t_claim=$(ts_first "$J" "P236-RECOV-CLAIMED slot=$VSLOT ")
        t_done=$(ts_first "$J" "P163-RECOVERY-COMPLETE.*node=$VNODE ")
        t_restore=$(ts_first "$J" 'P-PR-GATE-RESTORED')
        echo "--- B: gate under B2's key at ${t_gate:-never}s, B1 claimed at ${t_claim:-never}s, B1 complete at ${t_done:-never}s, gate restored at ${t_restore:-never}s"
        # the lease CAS (P236-RECOV-CLAIMED) may precede the gate by
        # milliseconds — cut 6 of s71a: claim at 154.899 s, gate at 154.914 s —
        # because the exclusion recheck runs at the execution site, not at the
        # claim; what must hold is that B2 held a gate under its own key
        # before B1's recovery EXECUTED, which the recheck (no P239-EXCL-LAPSED,
        # asserted above) plus this ordering against its completion establish
        ck "B: an exclusive-write gate under B2's own key was in force before B1's certified recovery completed (the lapsed gate is never the execution authority)" "$(ts_lt "$t_gate" "$t_done")" yes
        ck "B: the gate was restored to all-registrants only AFTER B1's recovery completed (the dependency held)" "$(ts_lt "$t_done" "$t_restore")" yes
    fi ;;
esac
ck   "B: no volatile-proof block (P238-FENCE-UNRECORDED)" "$(cnt "$J" 'P238-FENCE-UNRECORDED')" 0
ck   "B: no attempt series ended blocked (P238-FENCE-BLOCKED)" "$(cnt "$J" 'P238-FENCE-BLOCKED')" 0
ck   "B: zero shutdown / BUG / Oops" "$(bad_lines "$J")" 0
ck   "B: zero 'lock request failed after'" "$(cnt "$J" 'lock request failed after')" 0
# the dirty-death oracle
measure "$B" 60 "$OUT/B_files_after.txt" '^FILES_END$' "B1's fsynced files after recovery" \
    "cd $MNT/fcut_${LABEL}_$CUT 2>/dev/null && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files_after.txt" > "$OUT/B_files_after_sha.txt"
ck "B: every file B1 fsynced before its death is back with the same content" "$([ "$(cat "$OUT/B_files_sha.txt")" = "$(cat "$OUT/B_files_after_sha.txt")" ] && echo same || echo differ)" same
# ---- 6b. CUT 7 ONLY: the churn oracle.  The files above were sync -f'd long
# before the fence, so the replay owed nothing for them and they cannot tell a
# completed recovery from a skipped one.  What the recovery actually owes is
# the churn: every batch whose directory fsync returned is a result the
# filesystem promised, and the suffix the cut withheld is inside that set.
# The check is run here (on the recovering kernel) and again after the full
# unmount/remount below, because those two answers are not the same claim.
if [ "$CUT" = 7 ]; then
    CHURN_VERIFY_B64=$(base64 -w0 <<'PY'
import os, sys
d, m = sys.argv[1], int(sys.argv[2])
new, ren, dele = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
ok = bad = 0
miss = []
def want(path, text):
    global ok, bad
    try:
        v = open(path).read()
    except Exception:
        v = None
    if v == text:
        ok += 1
    else:
        bad += 1
        miss.append(os.path.basename(path))
for b in range(m + 1):
    for i in range(ren):
        want("%s/k%d_%d" % (d, b, i), "%d %d\n" % (b, i))
    for i in range(ren + dele, new):
        want("%s/c%d_%d" % (d, b, i), "%d %d\n" % (b, i))
    for i in range(ren + dele):
        if os.path.exists("%s/c%d_%d" % (d, b, i)):
            bad += 1
            miss.append("stale c%d_%d" % (b, i))
        else:
            ok += 1
print("CHURN_OK=%d" % ok)
print("CHURN_BAD=%d" % bad)
print("CHURN_MISS=" + ",".join(miss[:12]))
print("CHURN_END")
PY
)
    CHURN_LOG=$OUT/B_churn.txt
    CHURN_ACK=$(grep -ac ' rc=0$' "$CHURN_LOG" 2>/dev/null); CHURN_ACK=${CHURN_ACK:-0}
    CHURN_LAST=$(grep -a ' rc=0$' "$CHURN_LOG" 2>/dev/null | tail -1 | awk '{print $2}')
    CHURN_M=$(( CHURN_ACK - 1 ))
    CHURN_FAILED=$(grep -ac ' rc=1$' "$CHURN_LOG" 2>/dev/null); CHURN_FAILED=${CHURN_FAILED:-0}
    echo "STAGE churn: $CHURN_ACK batch(es) acknowledged (last=${CHURN_LAST:-none}), $CHURN_FAILED refused after the fence"
    ckge "cut 7: the victim acknowledged enough churn batches for the replay to owe real work" "$CHURN_ACK" "$CHURN_MIN"
    # A gap would mean a batch's fsync succeeded AFTER one failed, which is not
    # the fence behaviour this lap assumes and would make the oracle's prefix
    # argument false.  Grade it rather than paper over it.
    ck "cut 7: the acknowledged churn batches are a contiguous prefix 0..$CHURN_M" "${CHURN_LAST:-none}" "$CHURN_M"
    ckge "cut 7: the churn was cut off by the fence rather than running out on its own" "$CHURN_FAILED" 1
    measure "$B" 120 "$OUT/B_churn_after.txt" '^CHURN_END$' "the churn oracle after recovery" \
        "echo $CHURN_VERIFY_B64 | base64 -d > /run/fcut_churn_verify.py; python3 /run/fcut_churn_verify.py $MNT/fcut_${LABEL}_$CUT/churn $CHURN_M $CHURN_NEW $CHURN_REN $CHURN_DEL"
    echo "    $(grep -a '^CHURN_OK\|^CHURN_MISS' "$OUT/B_churn_after.txt" | tr '\n' ' ' | cut -c1-200)"
    # What this one claims and no more: every acknowledged effect is BACK.
    # That is the suffix the cut withheld having been applied.  It is NOT the
    # "repeating the prefix had no duplicate destructive effect" claim — a
    # doubled create is invisible to a content compare, and a doubled free or
    # link update shows up in accounting, not in file contents.  The offline
    # chk_mxfs below is what carries that half.
    ck "cut 7: every acknowledged churn effect is present after recovery, so the suffix the cut withheld was applied" \
       "$(field "$OUT/B_churn_after.txt" CHURN_BAD)" 0
fi
dump_into "$B" "$OUT/hb_3_after_B.txt" "the disklock table after B's mount"
echo "STAGE table after B's mount: $(cnt "$OUT/hb_3_after_B.txt" '^slot') record(s), $(cnt "$OUT/hb_3_after_B.txt" 'RECOVERY_GUARD') guarded"
grep -a '^slot\|desc v' "$OUT/hb_3_after_B.txt" | sed 's/^/    /' | cut -c1-200

# ---- 7. A's host returns and joins
$VIRSH start "$A" > /dev/null 2>&1
waitboot "$A"
deploy_ko "$A"
AMARK2=$(date +%s)
rsx $((JOIN_BOUND + 60)) "$A" "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/A_join.txt"
capture_require "$OUT/A_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the rejoin of $A"
echo "STAGE A join rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/A_join.txt") at +$(el)s"
measure "$A" 60 "$OUT/A_join_journal.txt" '^JOURNAL_END$' "the kernel journal on $A since its boot" "dmesg | cut -c1-600; echo JOURNAL_END"
measure "$B" 60 "$OUT/B_after_join_journal.txt" '^JOURNAL_END$' "the kernel journal on $B across A's rejoin" "dmesg | sed -n '/MXFS-MEMBERSHIP/,\$p' | tail -400 | cut -c1-600; echo JOURNAL_END"
ck "A rejoined (mounted)" "$(grep -ac '^MOUNTED' "$OUT/A_join.txt")" 1
ck "A: zero shutdown / BUG / Oops" "$(bad_lines "$OUT/A_join_journal.txt")" 0
ck "B: zero shutdown / BUG / Oops across A's join" "$(bad_lines "$OUT/B_after_join_journal.txt")" 0
value_now_into lsA "$A" 30 "$OUT/A_rootls.txt" '^[0-9a-f]{32}$' "the root listing digest on $A" "ls -A -l --time-style=+%s $MNT | md5sum | cut -c1-32"
value_now_into lsB "$B" 30 "$OUT/B_rootls.txt" '^[0-9a-f]{32}$' "the root listing digest on $B" "ls -A -l --time-style=+%s $MNT | md5sum | cut -c1-32"
ck "both nodes see the same root listing" "$([ "$lsA" = "$lsB" ] && echo same || echo differ)" same
dump_into "$A" "$OUT/hb_4_final.txt" "the disklock table after A's join"
ck "final: no recovery descriptor stands on the platter" "$(cnt "$OUT/hb_4_final.txt" 'RECOVERY_GUARD')" 0

# ---- 7b. CUT 7 ONLY: what a half-applied replay owes beyond "it mounted".
# A recovery that finished in the recovering kernel's caches and a recovery
# that is on the platter look identical from inside that kernel, and the
# oracle above reads the files through the same mount that recovered them.
# So the filesystem is made to accept NEW work, then taken all the way down
# and brought back through the ordinary path, and both sets are re-read; then
# it is checked offline, with nothing holding the device, because "mounted
# successfully" is not a consistency statement.
if [ "$CUT" = 7 ]; then
    # MEASURED 2026-09-20 (0.89.19): when B's recovering mount is REFUSED,
    # /mnt/shared is an ordinary empty directory on B's root filesystem, and
    # every check below happily writes into it and reads back what it wrote.
    # "new work accepted after the recovery" passed with 16 files on a node
    # that was not mounted at all.  So the mountpoint is the precondition for
    # this whole section, and a lap that lost it is reported as not measured
    # rather than graded against the local disk.
    # The probe prints the whole assignment — mounted=1 or mounted=0, which is
    # also what its capture regex requires — so the value held here is
    # "mounted=1", never the bare word.  Comparing against "mounted" could not
    # be satisfied by a mounted node either, and it took the whole section with
    # it: a lap that recovered cleanly and carried fails=0 was reported FAIL on
    # this line, and new work, the unmount/remount recycle, the churn oracle
    # through a second mount and the offline consistency check never ran.
    mounted_into bmnt "$B" "$OUT/B_mounted_7b.txt" "whether $B is still mounted"
    if [ "$bmnt" != mounted=1 ]; then
        echo "  cut 7: $B is NOT MOUNTED ($bmnt), so the post-recovery section measures nothing"
        echo "  (a refused mount leaves $MNT an empty local directory that accepts writes)"
        echo "RESULT: FAIL label=$LABEL cut=$CUT fails=$fails wall=$(el)s evidence=$OUT"
        exit 1
    fi
    measure "$B" 90 "$OUT/B_newwork.txt" '^NEW_END$' "new work accepted after the recovery" \
        "d=$MNT/fcut_post_${LABEL}_$CUT; mkdir -p \$d && for i in \$(seq 16); do printf 'post %s file %s\n' $LABEL \$i > \$d/n\$i; done; sync -f $MNT; cd \$d && sha256sum n* | sort; echo NEW_END"
    grep -av '^NEW_END' "$OUT/B_newwork.txt" > "$OUT/B_newwork_sha.txt"
    ck "cut 7: the filesystem accepts and persists new work after recovering" \
       "$(grep -ac '^[0-9a-f]\{64\}  n' "$OUT/B_newwork_sha.txt")" 16

    measure "$B" 260 "$OUT/B_recycle.txt" '^RECYCLE_END$' "B's unmount and remount through the ordinary path" \
        "umount $MNT; echo UMOUNT_RC=\$?; timeout 200 mount -t mxfs $MXFS_DEV $MNT; echo REMOUNT_RC=\$?; cd $MNT/fcut_${LABEL}_$CUT 2>/dev/null && sha256sum f* | sort; cd $MNT/fcut_post_${LABEL}_$CUT 2>/dev/null && sha256sum n* | sort; echo RECYCLE_END"
    ck "cut 7: B remounted through the ordinary path" "$(field "$OUT/B_recycle.txt" REMOUNT_RC)" 0
    grep -a '^[0-9a-f]\{64\}  f' "$OUT/B_recycle.txt" | sort > "$OUT/B_files_recycle_sha.txt"
    grep -a '^[0-9a-f]\{64\}  n' "$OUT/B_recycle.txt" | sort > "$OUT/B_newwork_recycle_sha.txt"
    ck "cut 7: the pre-crash files survive a full unmount/remount, so the recovery is on the platter and not in a cache" \
       "$([ "$(cat "$OUT/B_files_sha.txt")" = "$(cat "$OUT/B_files_recycle_sha.txt")" ] && echo same || echo differ)" same
    ck "cut 7: the post-recovery work survives it too" \
       "$([ "$(cat "$OUT/B_newwork_sha.txt")" = "$(cat "$OUT/B_newwork_recycle_sha.txt")" ] && echo same || echo differ)" same
    # The churn oracle again, through a mount that did NOT do the recovering.
    measure "$B" 120 "$OUT/B_churn_recycle.txt" '^CHURN_END$' "the churn oracle after the remount" \
        "python3 /run/fcut_churn_verify.py $MNT/fcut_${LABEL}_$CUT/churn $CHURN_M $CHURN_NEW $CHURN_REN $CHURN_DEL"
    ck "cut 7: every acknowledged churn effect survives a full unmount/remount, so the completed replay is on the platter" \
       "$(field "$OUT/B_churn_recycle.txt" CHURN_BAD)" 0

    # Offline: the checker takes the device O_EXCL, so every node must be off
    # it first.  A dirty exit here leaves the fleet unmounted, which the next
    # lap's prep handles — but say so, rather than leave it silent.
    measure "$A" 60 "$OUT/A_unmount_for_chk.txt" '^UMOUNT_RC=' "A's unmount before the offline check" \
        "umount $MNT 2>/dev/null; echo UMOUNT_RC=\$?"
    measure "$B" 60 "$OUT/B_unmount_for_chk.txt" '^UMOUNT_RC=' "B's unmount before the offline check" \
        "umount $MNT 2>/dev/null; echo UMOUNT_RC=\$?"
    measure "$B" 300 "$OUT/B_chk.txt" '^CHK_RC=[0-9]+$' "the offline consistency check" \
        "$CHK -v $MXFS_DEV > /tmp/fcut_chk.log 2>&1; echo CHK_RC=\$?; tail -25 /tmp/fcut_chk.log"
    ck "cut 7: the filesystem is consistent offline after the half-applied replay was completed" \
       "$(mxfs_chk_rc "$OUT/B_chk.txt")" 0
    echo "STAGE the fleet is left UNMOUNTED by the offline check; the next lap's prep remounts it"
fi

row="| $CUT $CNAME | at cut: stage=${stage2:-none} may_have_run=$armed2 kind=${kind2:-none} B1key=$k1_v | quiescent=$([ "$S1" = "$S2" ] && echo same || echo moved) | B back: B1key=$k2_v A1key=$k2_p mount=$(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/B_mount.txt") $(field "$OUT/B_mount.txt" WALL_MS)ms B1cert=${b1kind:-none} unrecorded=$(cnt "$J" 'P238-FENCE-UNRECORDED') blocked=$(cnt "$J" 'P238-FENCE-BLOCKED') | A join=$(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/A_join.txt") | files=$([ "$(cat "$OUT/B_files_sha.txt")" = "$(cat "$OUT/B_files_after_sha.txt")" ] && echo same || echo differ) |"
echo "$row" | tee "$OUT/row.txt"
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL cut=$CUT fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
