#!/bin/bash
# closure_footprint_shapes.sh — the last three Hazards-§7 fault shapes of the
# sess363 ruling for D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356, per the sess375
# RULE-5 review of this test's own design.
#
# The selective closure purge strips NINE fields of a dead victim's footprint
# from a CAW lock slot: holders_ex/pw/pr/cw/cr, waiters, waiters_ex, yield_to,
# open_holders.  Every shape verified so far was an EX-holder strip.  Two of
# the nine make a slot look empty of holders while still being unusable, and
# they are exactly the sess48 phantom-waiter wedge class:
#
#   waiter_only — the victim's ONLY state on the slot is waiters/waiters_ex.
#                 Missed, the dead node is a permanent phantom waiter and the
#                 live holder BAST/demote-cycles forever.
#   open_only   — the victim's ONLY state is open_holders (MXFS open tracking
#                 for deferred reap of open-unlinked inodes).  Missed, the
#                 deferred reap of those inodes never converges.
#
# The third shape is the tombstone/slot-reuse race:
#
#   reuse_race  — the batched candidacy HINT says "slot S carries the victim on
#                 resource A, which is OUT of closure", but before the CAS the
#                 slot changes underneath.  Stripping on the stale picture
#                 would revoke frozen evidence.  Two defenses cover it: the
#                 authoritative re-read + re-classify, and the full-image CAS.
#
#                 WHAT THIS ARM CAN AND CANNOT REACH, measured.  Slot binding
#                 is open-addressed: index = hash(resource) % 65536 with a
#                 linear probe past tombstones (dlm/dlm_caw.c:3126, 3187-3279).
#                 With a few dozen live slots the probe chains are length 1, so
#                 a specific freed index is re-bound only by a resource that
#                 hashes exactly to it — order 1/65536 per acquisition.  The
#                 full "tombstoned then re-bound to a DIFFERENT resource inside
#                 one strip attempt" transition is therefore NOT reachable
#                 through the filesystem at rig scale, and no amount of churn
#                 makes it reachable; it is a real long-run transition, not a
#                 testable one here.  Forging it would mean writing a false
#                 slot image, which fabricates evidence.
#
#                 So this arm forces the two antecedents that ARE reachable and
#                 that are what the defenses actually consume:
#                   bit_gone       another actor (a survivor's demand scrub)
#                                  removed the victim from the slot between the
#                                  hint and the authoritative re-read, so the
#                                  hint no longer describes the slot -> L1 fires
#                   cas_miscompare the image moved between the fresh gate and
#                                  the CAS, so the write is rejected and the
#                                  loop re-reads AND re-classifies -> L2 fires
#                 moved/flipped (a genuine resource change) are still counted
#                 and reported, so a run that ever does hit the rare transition
#                 is recognised instead of silently passing.
#
# EVIDENCE DISCIPLINE (sess375 ruling):
#   * Every arm proves its PRECONDITION from the platter, with caw_slotdump
#     (SCSI READ(16)+FUA, the same image read_slot sees), BEFORE it asserts
#     anything.  An arm whose precondition never occurred exits 2
#     (PRECONDITION-NOT-MET) and is NOT a pass.
#   * The kernel now logs vfoot=0x<9-bit footprint> on P299-CLOSURE-STRIP and
#     P299-SCRUB-STRIP, derived from the exact image the winning CAS consumed
#     — not from the batch hint, not from an earlier retry lap.
#       0x001 EX  0x002 PW  0x004 PR  0x008 CW  0x010 CR
#       0x020 WAIT  0x040 WAIT_EX  0x080 YIELD  0x100 OPEN
#   * reuse_race must PROVE the race fired, not merely survive it:
#     P299-CLOSURE-SHAPES reports hint vanished/moved/flipped separately from
#     ordinary cas_miscompare, which says nothing about reuse.
#   * Every arm ends with an INDEPENDENT on-disk audit — the victim's bit must
#     be gone from the audited slot regardless of what the logs claimed.
#   * waiter_only additionally requires FUNCTIONAL progress afterwards, paced
#     against a baseline measured on the same rig before the kill.  A strip
#     log alone does not prove the wedge cleared.
#
# Usage: tests/closure_footprint_shapes.sh <N> <victim> <arm>
#   arm = waiter_only | open_only | reuse_race
# Env: AUDIT_HOST (default test1, must differ from victim), RECOVERY_WAIT
#      (default 150), PROBE_BUDGET (default 20), OPEN_FILES (default 12),
#      RACE_FILES (default 60), PAUSE_N (default 12), PAUSE_MS (default 2000).
#
# Exit 0 PASS, 1 FAIL, 2 PRECONDITION-NOT-MET.
# Leaves a durable quarantine — re-prep before anything else.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
DUMP=/src/mxfs/tools/caw_slotdump
DEV=/dev/mapper/mpatha
MNT=/mnt/shared

N="${1:?usage: closure_footprint_shapes.sh <N> <victim> <arm>}"
VICTIM="${2:?usage: closure_footprint_shapes.sh <N> <victim> <arm>}"
ARM="${3:?usage: closure_footprint_shapes.sh <N> <victim> <arm>}"
AUDIT_HOST="${AUDIT_HOST:-test1}"
RECOVERY_WAIT="${RECOVERY_WAIT:-150}"
PROBE_BUDGET="${PROBE_BUDGET:-20}"
OPEN_FILES="${OPEN_FILES:-12}"
PAUSE_N="${PAUSE_N:-12}"
PAUSE_MS="${PAUSE_MS:-2000}"
# WHICH defense reuse_race forces.  Measured: with the pause at the gate->CAS
# boundary (2) only L2 fires — a slot the survivor scrub already stripped fails
# the batched candidacy filter and is skipped before a strip attempt exists, so
# L1 never sees it.  Widening the hint->authoritative-read window (1) is what
# puts the concurrent scrub INSIDE a strip attempt, which is where L1 lives.
# Both positions must be run to cover both defenses.
PAUSE_WHERE="${PAUSE_WHERE:-2}"

case "$ARM" in waiter_only|open_only|reuse_race) ;;
  *) echo "FAIL: unknown arm '$ARM'"; exit 1 ;; esac
[ "$VICTIM" = "$AUDIT_HOST" ] && { echo "FAIL: victim is the audit host — set AUDIT_HOST"; exit 1; }

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || survivors+=("$h")
done

T0=$(date -u +%FT%TZ)
echo "=== closure_footprint_shapes arm=$ARM N=$N victim=$VICTIM audit=$AUDIT_HOST @ $T0 ==="

VSLOT=$("$SSH" "$VICTIM" "dmesg | grep -oE 'node_slot=[0-9]+' | tail -1" 2>/dev/null |
        tr -d '[:space:]' | cut -d= -f2)
[ -n "${VSLOT:-}" ] || { echo "FAIL: could not resolve the victim's heartbeat slot"; exit 1; }
echo "victim $VICTIM holds heartbeat slot $VSLOT (CAW node bit $VSLOT)"

# The ino -> agno shift the CLOSURE CLASSIFIER uses (XFS_INO_TO_AGNO):
# agblklog + inopblog, read from the on-disk XFS superblock (xfs_dsb bytes
# 124 and 123).  Nothing else in this test may use the printed ag= field for
# an inode resource — see tests/closure_foot_parse.py for why.
CHK=$("$SSH" "$AUDIT_HOST" "/src/mxfs/tools/chk_mxfs -v $DEV 2>/dev/null" 2>/dev/null)
XOFF=$(echo "$CHK" | grep -oE 'xfs_data_offset=[0-9]+' | head -1 | cut -d= -f2)
AGCOUNT=$(echo "$CHK" | grep -oE 'agcount=[0-9]+' | head -1 | cut -d= -f2)
AGCOUNT=${AGCOUNT:-25}
[ -n "${XOFF:-}" ] || { echo "FAIL: could not read xfs_data_offset"; exit 1; }
LOGS=$("$SSH" "$AUDIT_HOST" "dd if=$DEV bs=1 skip=$(( XOFF + 123 )) count=2 2>/dev/null | od -An -tu1" 2>/dev/null |
       grep -vE 'known hosts|Unauthorized|authorized user' | tr -s ' ' | sed 's/^ //')
INOPBLOG=$(echo "$LOGS" | awk '{print $1}')
AGBLKLOG=$(echo "$LOGS" | awk '{print $2}')
[ -n "${INOPBLOG:-}" ] && [ -n "${AGBLKLOG:-}" ] || { echo "FAIL: could not read agblklog/inopblog"; exit 1; }
INOSHIFT=$(( INOPBLOG + AGBLKLOG ))
echo "XFS_INO_TO_AGNO shift = inopblog $INOPBLOG + agblklog $AGBLKLOG = $INOSHIFT"

PARSE="$REPO/tests/closure_foot_parse.py"

# AGMASK is NOT a constant.  Inode allocation picks the AG, and which AG the
# victim's files land in changes run to run (measured: ag16, ag6, ag1 on three
# consecutive laps).  A fixed 0x2 quarantined the very AG the victim occupied
# on the ag1 lap, so kept=64 purged=0 and the arm had nothing to measure.  The
# forged domain is therefore chosen AFTER the victim's real footprint is read
# off the platter — see "choose the forged domain" below.
AGMASK=0x2
RACE_FILES="${RACE_FILES:-60}"
RACE_DIRS="${RACE_DIRS:-12}"

# ── platter audit helpers ────────────────────────────────────────────────────
# One authoritative dump; every precondition and post-audit reads from a file,
# never from a second dump that could have moved.
dump_to() {   # dump_to <outfile>
    "$SSH" "$AUDIT_HOST" "$DUMP $DEV --all" 2>/dev/null |
        grep -vE 'known hosts|Unauthorized|authorized user' > "$1"
    grep -qc '^slot=' "$1"
}

# "slot ag ino foot" for every slot carrying the victim bit, with the AG the
# closure classifier would actually compute (NOT the printed ag= field).
victim_slots() {   # victim_slots <dumpfile>
    python3 "$PARSE" slots "$1" "$VSLOT" "$INOSHIFT"
}

disarm() {
    for h in "${survivors[@]}"; do
        "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                     echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                     echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
                     echo 0 > /sys/module/mxfs/parameters/closure_skip_publisher_purge;
                     echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_n;
                     echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_where" >/dev/null 2>&1 &
    done
    wait
}

arm_refusal() {   # arm_refusal [extra-shell]
    local extra="${1:-true}"
    echo "--- arming freplay_force_refusal=1 slot=$VSLOT ag_mask=$AGMASK on ${#survivors[@]} survivors"
    for h in "${survivors[@]}"; do
        "$SSH" "$h" "echo $AGMASK > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                     echo $VSLOT > /sys/module/mxfs/parameters/freplay_force_slot;
                     echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal;
                     $extra" >/dev/null 2>&1 &
    done
    wait
    local armed=0 v
    for h in "${survivors[@]}"; do
        v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal" 2>/dev/null | tail -1 | tr -d '[:space:]')
        [ "$v" = "1" ] && armed=$((armed+1))
    done
    [ "$armed" -eq "${#survivors[@]}" ] || {
        echo "FAIL: armed on $armed/${#survivors[@]} survivors"; disarm; exit 1; }
    echo "refusal CONFIRMED armed on all $armed survivors"
}

# Baseline pace for the functional progress assertion (RULE 0: the post-repair
# number is judged against a number measured on THIS rig, not a constant).
root_pace() {   # root_pace <host> <tag> ; echoes elapsed ms, or -1 on failure
    "$SSH" "$1" "s=\$(date +%s%N)
        for i in \$(seq 1 20); do
            timeout 30 touch $MNT/.cfs-$2.\$i || { echo -1; exit 0; }
        done
        for i in \$(seq 1 20); do rm -f $MNT/.cfs-$2.\$i; done
        echo \$(( (\$(date +%s%N) - s) / 1000000 ))" 2>/dev/null |
        grep -vE 'known hosts|Unauthorized|authorized user' | tail -1 | tr -d '[:space:]'
}

DD=$(mktemp -d)
pass=1
fail() { echo "FAIL: $*"; pass=0; }

# ── per-arm setup + kill ─────────────────────────────────────────────────────
BASE_MS=-1
case "$ARM" in
waiter_only)
    BASE_MS=$(root_pace "$AUDIT_HOST" base)
    echo "baseline root-dir pace on $AUDIT_HOST: ${BASE_MS}ms for 20 create+unlink"
    [ "${BASE_MS:-0}" -gt 0 ] || { echo "FAIL: baseline pace could not be measured"; exit 1; }

    # A PURE waiter cannot be built by contention: MXFS caches a grant once it
    # is given, so a node that churns a resource ends up holding a cached PR or
    # EX on it (measured — the victim came out of a 12s contention run as
    # pr=[31] on ino 128 and ex=[31] on three others, never a waiter).  The
    # deterministic construction is an UNANSWERABLE request:
    #
    #   HOLDER caches EX on a file the victim has NEVER touched, then is
    #   SUSPENDED so it cannot answer a BAST.  The victim's first and only
    #   request for that file therefore parks in caw_wait_for_grant, and its
    #   footprint on that slot is waiters/waiters_ex and nothing else.
    #
    # The suspension is short and bounded: the heartbeat death-confirm window
    # is ~62s, and this holds it under ~30s, so HOLDER is never itself fenced.
    HOLDER="${survivors[0]}"
    [ "$HOLDER" = "$AUDIT_HOST" ] && HOLDER="${survivors[1]}"
    echo "--- victim takes a hot root-dir EX (what the blocked prober contends for)"
    "$SSH" "$VICTIM" "nohup bash -c '
        end=\$((SECONDS + 200)); i=0
        while [ \$SECONDS -lt \$end ]; do
            i=\$((i+1)); echo x > $MNT/.cfs-v.\$i; rm -f $MNT/.cfs-v.\$((i-2))
        done' >/dev/null 2>&1 &" >/dev/null 2>&1
    sleep 6

    echo "--- $HOLDER caches EX on .cfs-wo-target, then is suspended so it cannot answer a BAST"
    "$SSH" "$HOLDER" "echo lock > $MNT/.cfs-wo-target; sync" >/dev/null 2>&1
    sleep 2
    sudo virsh -c qemu:///system suspend "$HOLDER" >/dev/null 2>&1 || {
        echo "FAIL: virsh suspend $HOLDER"; exit 1; }
    SUSPENDED_AT=$SECONDS

    echo "--- victim issues its FIRST request for that file — it can only wait"
    "$SSH" "$VICTIM" "nohup bash -c 'timeout 240 cat $MNT/.cfs-wo-target' >/dev/null 2>&1 &" >/dev/null 2>&1
    sleep 8

    date -u "+KILL $VICTIM @ %FT%TZ"
    sudo virsh -c qemu:///system destroy "$VICTIM" || {
        sudo virsh -c qemu:///system resume "$HOLDER" >/dev/null 2>&1
        echo "FAIL: virsh destroy"; exit 1; }
    sudo virsh -c qemu:///system resume "$HOLDER" >/dev/null 2>&1
    echo "$HOLDER resumed after $(( SECONDS - SUSPENDED_AT ))s suspended (death-confirm window ~62s)"
    ;;
open_only)
    # An OPEN alone is not enough: the open path also caches a read grant, so
    # the victim would show pr|open, not open alone.  Build the pure shape
    # deliberately —
    #   1. AUDIT_HOST creates the files (the victim never holds their EX),
    #   2. the victim opens them O_RDONLY and HOLDS the fds (open_holders set,
    #      plus a cached PR),
    #   3. AUDIT_HOST writes each one again.  That BASTs the victim's cached
    #      PR away while the fds stay open, which leaves open_holders as the
    #      victim's ONLY state on those slots.
    # Whether it worked is not assumed: the precondition is read back off the
    # platter below, and the arm exits 2 if the shape never formed.
    echo "--- victim takes a hot root-dir EX (what the blocked prober contends for)"
    "$SSH" "$VICTIM" "nohup bash -c '
        end=\$((SECONDS + 240)); i=0
        while [ \$SECONDS -lt \$end ]; do
            i=\$((i+1)); echo x > $MNT/.cfs-v.\$i; rm -f $MNT/.cfs-v.\$((i-2))
        done' >/dev/null 2>&1 &" >/dev/null 2>&1
    sleep 6

    echo "--- $AUDIT_HOST creates $OPEN_FILES files; victim opens and holds the fds"
    "$SSH" "$AUDIT_HOST" "for i in \$(seq 1 $OPEN_FILES); do echo oh > $MNT/.cfs-open.\$i; done; sync" >/dev/null 2>&1
    "$SSH" "$VICTIM" "nohup python3 -u -c \"
import time,glob
fds=[open(p) for p in sorted(glob.glob('$MNT/.cfs-open.*'))]
print(len(fds), flush=True)
time.sleep(400)
\" >/tmp/cfs_open.log 2>&1 &" >/dev/null 2>&1
    sleep 10
    held=$("$SSH" "$VICTIM" "cat /tmp/cfs_open.log 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -oE '^[0-9]+' | tail -1)
    [ "${held:-0}" -eq "$OPEN_FILES" ] || {
        echo "FAIL: victim holds ${held:-0}/$OPEN_FILES fds — cannot build the open-holder footprint"
        "$SSH" "$VICTIM" "cat /tmp/cfs_open.log" 2>/dev/null | tail -5
        exit 1; }
    echo "victim holds $held open fds"

    echo "--- $AUDIT_HOST re-writes each file to revoke the victim's cached read grant"
    "$SSH" "$AUDIT_HOST" "for i in \$(seq 1 $OPEN_FILES); do echo revoke >> $MNT/.cfs-open.\$i; done; sync" >/dev/null 2>&1
    sleep 8

    date -u "+KILL $VICTIM @ %FT%TZ"
    sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy"; exit 1; }
    ;;
reuse_race)
    # Give the publisher REAL work and give the survivors something to scrub:
    # the victim takes EX on many files, all out of closure under ag_mask 0x2.
    # After the kill, survivors read those same files, block on the victim's
    # frozen EX, and scrub those exact slots — which is the concurrent actor
    # the publisher's hint has to survive.
    # SPREAD the footprint.  Files created flat in the root dir all get inodes
    # from one AG (measured: 64 of 65 victim slots in ag5), which leaves no AG
    # that can be quarantined without swallowing the whole footprint.  XFS
    # rotates the AG for each new DIRECTORY, so one subdirectory per group puts
    # the victim's grants across many AGs.
    echo "--- victim takes EX on $RACE_FILES files spread over $RACE_DIRS dirs + a hot root-dir EX"
    "$SSH" "$VICTIM" "for d in \$(seq 1 $RACE_DIRS); do
            mkdir -p $MNT/cfs-rd\$d
            for i in \$(seq 1 \$(( $RACE_FILES / $RACE_DIRS ))); do echo r > $MNT/cfs-rd\$d/f\$i; done
        done; sync" >/dev/null 2>&1
    "$SSH" "$VICTIM" "nohup bash -c '
        end=\$((SECONDS + 240)); i=0
        while [ \$SECONDS -lt \$end ]; do
            i=\$((i+1)); echo x > $MNT/.cfs-v.\$i; rm -f $MNT/.cfs-v.\$((i-2))
        done' >/dev/null 2>&1 &" >/dev/null 2>&1
    sleep 6
    date -u "+KILL $VICTIM @ %FT%TZ"
    sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy"; exit 1; }
    ;;
esac

# ── precondition, proven from the platter, AFTER the kill ────────────────────
# A dead node's bits cannot change, so one authoritative dump settles it.
sleep 3
dump_to "$DD/pre.dump" || { echo "FAIL: pre-kill-state slotdump returned no slots"; disarm; exit 1; }
victim_slots "$DD/pre.dump" > "$DD/pre.foot"
echo "--- victim footprint on the platter (slot ag ino foot), $(wc -l < "$DD/pre.foot") slot(s)"
head -12 "$DD/pre.foot"

# ── choose the forged domain from the victim's REAL footprint ───────────────
# Quarantine the AG in which the victim holds the FEWEST resources (never ag0,
# which carries the root inode the blocked prober contends for).  That leaves
# the bulk of the victim's state out of closure, so the purge has real work,
# while still keeping the domain non-empty — otherwise "no strip landed inside
# the quarantined domain" would be a vacuous assertion.
# The arm's target shape must stay OUT of closure, so any AG that carries one
# is excluded from the choice — otherwise the least-occupied AG can be exactly
# the one holding the single waiter-shaped slot, and the arm would exit 2 for a
# reason it created itself.
case "$ARM" in
  waiter_only) SHAPE='and(f,0x060)>0 && and(f,0x11F)==0' ;;
  open_only)   SHAPE='f==0x100' ;;
  *)           SHAPE='0' ;;
esac
QAG=$(awk -v shape="$SHAPE" -v agcount="$AGCOUNT" '
        { ag=$2+0; f=strtonum($4); total++
          if (ag>0) c[ag]++
          keep=0
          if (shape=="and(f,0x060)>0 && and(f,0x11F)==0")
              keep = (and(f,0x060)>0 && and(f,0x11F)==0)
          else if (shape=="f==0x100")
              keep = (f==0x100)
          if (keep) protect[ag]=1 }
        END{
          need = total/2; if (need < 5) need = 5
          # Prefer an AG the victim DOES occupy (so "no strip landed inside the
          # quarantined domain" is a real assertion), but only if quarantining
          # it still leaves most of the footprint out of closure for the purge
          # to work on.  Among those, take the largest occupancy.
          best = -1; bo = -1
          for (a in c) {
              if (a in protect) continue
              if (total - c[a] < need) continue
              if (c[a] > bo) { bo = c[a]; best = a }
          }
          if (best >= 0) { print best; exit }
          # Fallback: an AG the victim does not occupy at all.  Valid domain,
          # but then nothing of the victim is in closure — the caller says so.
          for (a = 1; a < agcount; a++)
              if (!(a in c) && !(a in protect)) { print a; exit }
          print 1
        }' "$DD/pre.foot")
AGMASK=$(printf '0x%x' $(( 1 << QAG )))
QIN=$(awk -v q=$QAG '{if ($2+0==q) n++} END{print n+0}' "$DD/pre.foot")
QOUT=$(awk -v q=$QAG '{if ($2+0!=q) n++} END{print n+0}' "$DD/pre.foot")
echo "forged refused domain: ag$QAG (ag_mask=$AGMASK) — $QIN victim slot(s) IN closure, $QOUT OUT"
[ "$QIN" -gt 0 ] || echo "  NOTE: the victim occupies nothing in ag$QAG, so the in-closure"
[ "$QIN" -gt 0 ] || echo "  assertion below is vacuous on this lap (reported, not hidden)"

TARGET_SLOT=""
case "$ARM" in
waiter_only)
    # Waiter-shaped: at least one of WAIT|WAIT_EX (0x060) and NO holder bit
    # (0x01F) and no open_holder (0x100), on an AG the forged mask leaves out
    # of closure.  yield_to (0x080) is allowed alongside — measured, a parked
    # waiter routinely carries it, and dlm_caw.c names "a waiters_ex or
    # yield_to bit" as exactly this frozen-grant shape.  What the hazard is
    # about is the absence of a HOLDER bit: such a slot looks unheld while
    # being permanently unusable.
    TARGET_SLOT=$(awk -v m=$(( AGMASK )) '{f=strtonum($4); ag=$2+0;
        if (and(f,0x060)>0 && and(f,0x11F)==0 && ag>=0 &&
            and(m, lshift(1,ag))==0) { print $1" "$2" "$3" "$4; exit }}' "$DD/pre.foot")
    ;;
open_only)
    TARGET_SLOT=$(awk -v m=$(( AGMASK )) '{f=strtonum($4); ag=$2+0;
        if (f==0x100 && ag>=0 && and(m, lshift(1,ag))==0) { print $1" "$2" "$3" "$4; exit }}' "$DD/pre.foot")
    ;;
reuse_race)
    TARGET_SLOT="n/a"
    ;;
esac

if [ -z "$TARGET_SLOT" ]; then
    echo "PRECONDITION-NOT-MET: no slot carries a $ARM footprint for bit $VSLOT"
    echo "  (a run that never built the shape proves nothing about it)"
    disarm
    exit 2
fi
[ "$ARM" = "reuse_race" ] || echo "precondition PROVEN on the platter: target slot -> $TARGET_SLOT"
TSLOT=$(echo "$TARGET_SLOT" | awk '{print $1}')

# ── arm the refusal (and, for reuse_race, the timing hooks) ──────────────────
for h in "${survivors[@]}"; do "$SSH" "$h" "dmesg --clear" >/dev/null 2>&1 & done
wait
if [ "$ARM" = "reuse_race" ]; then
    arm_refusal "echo $PAUSE_WHERE > /sys/module/mxfs/parameters/caw_inject_closure_pause_where;
                 echo $PAUSE_MS > /sys/module/mxfs/parameters/caw_inject_closure_pause_ms;
                 echo $PAUSE_N > /sys/module/mxfs/parameters/caw_inject_closure_pause_n"
    if [ "$PAUSE_WHERE" = 1 ]; then WD="hint -> authoritative read (forces L1)"
    else WD="gate -> CAS (forces L2)"; fi
    echo "timing hook armed: pause_where=$PAUSE_WHERE n=$PAUSE_N ms=$PAUSE_MS ($WD)"
else
    arm_refusal
fi

# The blocked prober: an operation genuinely waiting on victim-owned
# out-of-closure state across the whole recovery window.
BLOCK_BUDGET=$(( RECOVERY_WAIT + 60 ))
"$SSH" "$AUDIT_HOST" "nohup bash -c '
    s=\$(date +%s)
    timeout $BLOCK_BUDGET touch $MNT/.cfs-blocked; rc=\$?
    echo \"BLOCKED_PROBE rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/cfsprobe.out
' >/dev/null 2>&1 &" >/dev/null 2>&1

# reuse_race only: real churn across the whole FS during the window, so slots
# freed by the survivor scrub are genuinely re-bound to other resources.
if [ "$ARM" = "reuse_race" ]; then
    echo "--- 12 survivors read the victim's $RACE_FILES frozen files: each blocks"
    echo "    on victim-owned out-of-closure EX and scrubs those exact slots"
    for h in "${survivors[@]:1:12}"; do
        "$SSH" "$h" "rm -f /tmp/cfs_churn_stop; nohup bash -c '
            end=\$((SECONDS + $RECOVERY_WAIT + 40))
            while [ \$SECONDS -lt \$end ] && [ ! -e /tmp/cfs_churn_stop ]; do
                for d in \$(seq 1 $RACE_DIRS); do
                    for i in \$(seq 1 \$(( $RACE_FILES / $RACE_DIRS ))); do
                        timeout 25 cat $MNT/cfs-rd\$d/f\$i >/dev/null 2>&1
                    done
                done
            done' >/dev/null 2>&1 &" >/dev/null 2>&1 &
    done
    wait
fi

echo "waiting ${RECOVERY_WAIT}s for fence+refusal+publish+purge..."
sleep "$RECOVERY_WAIT"

# reuse_race: quiesce the churn before demanding a terminal verdict — retry
# exhaustion under unbounded contention is legitimate, not a defect.
if [ "$ARM" = "reuse_race" ]; then
    echo "--- quiescing the churn (retry exhaustion under unbounded contention"
    echo "    would be legitimate, so the terminal verdict is demanded quiet)"
    for h in "${survivors[@]:1:12}"; do
        "$SSH" "$h" "touch /tmp/cfs_churn_stop" >/dev/null 2>&1 &
    done
    wait
    sleep 25
fi

# ── harvest ─────────────────────────────────────────────────────────────────
bp=$("$SSH" "$AUDIT_HOST" "cat /tmp/cfsprobe.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep BLOCKED_PROBE | tail -1)
bp_rc=$(echo "$bp" | grep -o 'rc=[0-9]*' | cut -d= -f2)
bp_s=$(echo "$bp" | grep -o 'elapsed=[0-9]*' | cut -d= -f2)
echo "--- blocked prober: ${bp:-<still running>}"

for h in "${survivors[@]}"; do "$SSH" "$h" "dmesg" > "$DD/$h.dmesg" 2>/dev/null & done
wait
disarm

STRIPS="$DD/strips.txt"
grep -h "P299-CLOSURE-STRIP\|P299-SCRUB-STRIP" "$DD"/*.dmesg 2>/dev/null > "$STRIPS" || true
grep -h "P299-CLOSURE-PURGE\|P299-CLOSURE-SHAPES\|P299-CLOSURE-INCOMPLETE\|P299-CLOSURE-REFROZE" \
    "$DD"/*.dmesg 2>/dev/null > "$DD/summary.txt" || true
echo "--- purge summary"
cat "$DD/summary.txt" | sed 's/^\[[^]]*\] *//' | head -8
echo "--- strips ($(wc -l < "$STRIPS"))"
head -6 "$STRIPS" | sed 's/^\[[^]]*\] *//'

# ── did the FORGED domain actually take? ────────────────────────────────────
# Measured sess375: a replay can refuse GENUINELY (defect #1, unauthorized
# images) before the one-shot knob is even reached, and then the published
# domain is the replay's own refused AG set — which included ag0.  With ag0 IN
# closure the victim's root grant is SUPPOSED to stay frozen, so the purge
# correctly does nothing and the blocked prober correctly never returns.
# Reporting that as FAIL blames the filesystem for the harness not getting the
# scenario it asked for.  Check both halves: the injection fired, and the
# domain that got published is the one that was armed.
INJ=$(grep -h "P227-FR-INJECT-ARMED" "$DD"/*.dmesg 2>/dev/null | head -1)
PUBMASK=$(grep -h "slice replay refused" "$DD"/*.dmesg 2>/dev/null |
          grep -oE 'ag_mask=0x[0-9a-f]+' | head -1 | cut -d= -f2)
echo "--- forged-domain check: injection=$( [ -n "$INJ" ] && echo fired || echo NOT-FIRED ) published ag_mask=${PUBMASK:-<none>} (armed $AGMASK)"
if [ -z "$INJ" ] || [ -z "${PUBMASK:-}" ] || [ $(( PUBMASK )) -ne $(( AGMASK )) ]; then
    echo "PRECONDITION-NOT-MET: the run did not get the domain it armed."
    echo "  armed ag_mask=$AGMASK, published ag_mask=${PUBMASK:-<none>},"
    echo "  one-shot injection $( [ -n "$INJ" ] && echo consumed || echo NEVER CONSUMED )."
    echo "  A genuine refusal (defect #1) preempting the forged one publishes"
    echo "  its OWN refused AG set; if that set contains the probe's AG then"
    echo "  the frozen grant is CORRECT and there is nothing here to measure."
    echo "  This is a harness precondition, NOT an MXFS defect — do not ledger it."
    disarm 2>/dev/null || true
    exit 2
fi

shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$DD"/*.dmesg 2>/dev/null | wc -l)
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
[ "$shutdowns" -eq 0 ] || fail "survivor withdrew"

# ── per-arm assertions ──────────────────────────────────────────────────────
echo "--- assertions ($ARM)"
case "$ARM" in
waiter_only|open_only)
    if [ "$ARM" = waiter_only ]; then
        WANT="a WAIT/WAIT_EX bit set and no holder (0x01F) or open (0x100) bit"
    else
        WANT="exactly 0x100 (open_holders only)"
    fi
    hit=$(grep -E "slot=$TSLOT " "$STRIPS" | grep -oE 'vfoot=0x[0-9a-f]+' | tail -1 | cut -d= -f2)
    echo "strip on target slot $TSLOT: vfoot=${hit:-<none>} (want: $WANT)"
    if [ -z "${hit:-}" ]; then
        fail "the $ARM slot was never stripped — that footprint is not covered"
    elif [ "$ARM" = waiter_only ]; then
        h=$(( hit ))
        if [ $(( h & 0x060 )) -eq 0 ] || [ $(( h & 0x11F )) -ne 0 ]; then
            fail "slot $TSLOT stripped with vfoot=$hit — not the waiter-shaped footprint the precondition proved"
        fi
    else
        [ "$(( hit ))" -eq $(( 0x100 )) ] || \
            fail "slot $TSLOT stripped with vfoot=$hit — not a pure open_holders footprint"
    fi
    ;;
reuse_race)
    sh_line=$(grep -h "P299-CLOSURE-SHAPES" "$DD"/*.dmesg | tail -1)
    van=$(echo "$sh_line" | grep -o ' vanished=[0-9]*' | cut -d= -f2)
    bgo=$(echo "$sh_line" | grep -o 'bit_gone=[0-9]*' | cut -d= -f2)
    mov=$(echo "$sh_line" | grep -o 'moved=[0-9]*' | cut -d= -f2)
    flp=$(echo "$sh_line" | grep -o 'flipped=[0-9]*' | cut -d= -f2)
    mis=$(echo "$sh_line" | grep -o 'cas_miscompare=[0-9]*' | cut -d= -f2)
    echo "hint staleness: vanished=${van:-?} bit_gone=${bgo:-?} moved=${mov:-?} flipped=${flp:-?}"
    echo "image moved under the CAS: cas_miscompare=${mis:-?}"
    l1=$(( ${van:-0} + ${bgo:-0} + ${mov:-0} + ${flp:-0} ))
    # The pause position decides which defense this lap is responsible for.
    # Reporting the other one is welcome but not a substitute.
    if [ "$PAUSE_WHERE" = 1 ]; then need=$l1; nm="L1 (authoritative re-read + re-classify)"
    else need=${mis:-0}; nm="L2 (full-image CAS)"; fi
    if [ "$need" -eq 0 ]; then
        echo "PRECONDITION-NOT-MET: $nm was never exercised on this lap."
        echo "  Surviving a race that never fired is not evidence; re-run with"
        echo "  more RACE_FILES, a longer PAUSE_MS, or a larger PAUSE_N."
        exit 2
    fi
    [ "$l1" -gt 0 ] && echo "L1 EXERCISED: the authoritative re-read saw a slot the hint no longer described"
    [ "${mis:-0}" -gt 0 ] && echo "L2 EXERCISED: a full-image CAS was rejected and the attempt re-read + re-classified"
    ;;
esac

# Every arm: nothing IN the quarantined domain may have been stripped.
cat "$DD"/*.dmesg > "$DD/all.dmesg" 2>/dev/null
python3 "$PARSE" strips "$DD/all.dmesg" "$INOSHIFT" > "$DD/strips.parsed"
badstrip=$(awk -v m=$(( AGMASK )) '{ag=$2+0; if (ag>=0 && and(m, lshift(1,ag))!=0) print}' \
           "$DD/strips.parsed" | wc -l)
echo "strips inside the quarantined domain (want 0): $badstrip"
[ "$badstrip" -eq 0 ] || fail "an IN-closure resource was force-revoked — frozen evidence destroyed"

# Every arm: the purge must never call itself complete with unresolved slots.
inc=$(grep -c "P299-CLOSURE-INCOMPLETE" "$DD/summary.txt" 2>/dev/null); inc=${inc:-0}
for s in $(grep -o 'unread=[0-9-]*' "$DD/summary.txt" | cut -d= -f2) \
         $(grep -o 'wfail=[0-9-]*' "$DD/summary.txt" | cut -d= -f2); do
    if [ "${s:-0}" -ne 0 ] && [ "$inc" -eq 0 ]; then
        fail "purge reported unread/wfail=$s but no P299-CLOSURE-INCOMPLETE"
    fi
done
echo "completion accounting: INCOMPLETE lines=$inc (only required when unread/wfail>0)"

# ── independent on-disk post-audit ──────────────────────────────────────────
dump_to "$DD/post.dump" || fail "post-audit slotdump returned no slots"
victim_slots "$DD/post.dump" > "$DD/post.foot"
echo "--- post-audit: victim bit $VSLOT still present on $(wc -l < "$DD/post.foot") slot(s)"
head -8 "$DD/post.foot"
if [ "$ARM" != reuse_race ]; then
    still=$(awk -v s="$TSLOT" '$1==s' "$DD/post.foot")
    echo "target slot $TSLOT after repair: ${still:-<victim bit gone>}"
    [ -z "$still" ] || fail "the victim's footprint is STILL on slot $TSLOT on the platter"
fi
# No out-of-closure slot may retain the victim, whatever the logs said.
ooc=$(awk -v m=$(( AGMASK )) '{ag=$2+0; if (and(m, lshift(1,ag))==0) print}' "$DD/post.foot" | wc -l)
echo "out-of-closure slots still carrying the victim (want 0): $ooc"
[ "$ooc" -eq 0 ] || { awk -v m=$(( AGMASK )) '{ag=$2+0; if (and(m, lshift(1,ag))==0) print}' "$DD/post.foot" | head -5
                      fail "out-of-closure victim state survived the purge"; }

# ── functional progress (waiter_only) ───────────────────────────────────────
if [ "$ARM" = waiter_only ]; then
    POST_MS=$(root_pace "$AUDIT_HOST" post)
    CEIL=$(( BASE_MS * 3 + 5000 ))
    echo "root-dir pace after repair: ${POST_MS}ms (baseline ${BASE_MS}ms, ceiling ${CEIL}ms)"
    if [ "${POST_MS:-0}" -le 0 ]; then
        fail "root-dir operations still do not complete after the repair"
    elif [ "$POST_MS" -gt "$CEIL" ]; then
        fail "root-dir pace ${POST_MS}ms exceeds 3x baseline + 5s — the holder is still cycling"
    fi
    bast=$(grep -h "P7B-BASTNOTIFY" "$DD"/*.dmesg 2>/dev/null | grep -c "ino=128" || true)
    echo "P7B-BASTNOTIFY on ino=128 across the window: $bast (reported, not asserted)"
fi

echo "blocked prober: rc=${bp_rc:-<hung>} elapsed=${bp_s:-?}s"
[ "${bp_rc:-1}" -eq 0 ] || fail "blocked prober was never released"

mounted=0
for h in "${survivors[@]}"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "survivors still mounted (want ${#survivors[@]}): $mounted"
[ "$mounted" -eq "${#survivors[@]}" ] || fail "survivor lost its mount"

echo "evidence kept in $DD"
if [ "$pass" -eq 1 ]; then
    echo "=== closure_footprint_shapes[$ARM] PASS @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== closure_footprint_shapes[$ARM] FAIL @ $(date -u +%FT%TZ) ==="
exit 1
