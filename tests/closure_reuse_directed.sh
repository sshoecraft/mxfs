#!/bin/bash
# closure_reuse_directed.sh — the tombstone/slot-reuse hazard of the sess363
# ruling's Hazards §7, INJECTED, for D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356.
#
# THE HAZARD.  The publisher's selective closure purge reads the CAW slot table
# in 32-slot batches; each batch entry is a candidacy HINT ("slot S carries the
# victim, on resource A, which is OUT of closure").  Between that hint and the
# destructive CAS the slot can be tombstoned and RE-BOUND to a different
# resource.  Acting on the stale hint would mutate a slot the verdict says
# nothing about.  Two defenses cover it: the authoritative re-read + re-classify
# inside caw_closure_strip_one, and the full-image CAS.
#
# WHY THIS IS A DIRECTED TEST AND NOT A CHURN TEST.  Slot binding is
# open-addressed: index = hash(resource) % 65536, linear probe past tombstones
# (dlm/dlm_caw.c:3126, 3187-3279).  Waiting for random filesystem churn to
# re-bind one specific freed index is hopeless.  sess375 first concluded from
# that the transition was unreachable and tried to substitute "both defenses
# exercised separately"; the RULE-5 review refuted it — resource_hash_raw
# (dlm/dlm_shared.c:34) is seedless FNV-1a over the raw resource bytes, so the
# home slot of any resource is COMPUTABLE OUTSIDE THE KERNEL, and a colliding
# pair can simply be looked up.  tools/caw_slot_hash.py does that;
# `verify` replicated 788 live slots at their computed home with ZERO
# mismatches, and `collide` found 2478 cross-AG pairs among 18669 real inodes.
# Nothing here is forged: A and B are ordinary files, bound and released through
# the filesystem's normal paths.
#
# THE CONSTRUCTION.
#   A (in agA) and B (in agB) are two real inodes whose home slot is the SAME S.
#   The forged refused domain is a THIRD AG, so both are out of closure and both
#   stay usable.
#     1. S is free, and neither inode is bound anywhere (checked on the platter).
#     2. The victim writes A  -> A binds at S, victim holds EX.  Verified on the
#        platter before anything is killed.
#     3. Survivor P starts reading A and BLOCKS on the victim's EX.
#     4. The victim is killed and the replay is forced to refuse.
#     5. The publisher's strip attempt for S pauses at the hint->read boundary
#        (caw_inject_closure_pause_where=1 — timing only, no image written).
#     6. Inside that pause, real code empties S: P's demand scrub strips the
#        dead victim, P is granted, P reads and then EVICTS the inode, which
#        releases the grant and tombstones S.  (Eviction really does release:
#        measured, a fleet-wide drop_caches took LIVE slots 1454 -> 923.)
#     7. Survivor Q is polling S's magic directly off the platter; the moment S
#        stops being LIVE it reads B, which binds B AT S — S is the first
#        recyclable tombstone on B's own probe chain.
#     8. The publisher wakes, does its authoritative re-read, and finds resource
#        B where its hint said A.
#   REQUIRED: hint moved>=1, and slot S holding B, unmutated.
#
# WHAT THIS CANNOT PRODUCE, and why that is a property and not a gap.  The
# `flipped` counter (hint said out-of-closure, the re-read says in-closure)
# cannot fire on a REUSED slot: whatever re-binds a freed slot is bound by a
# LIVE node, so it cannot carry the dead victim's bit, and strip_one returns at
# the victim-bit check before classification is ever reached.  The in-closure
# keep path is exercised on its own by the kept>0 arms of
# closure_purge_scrub.sh and closure_footprint_shapes.sh.
#
# Usage: tests/closure_reuse_directed.sh <N> <victim>
# Env: AUDIT_HOST (default test1), RECOVERY_WAIT (default 200),
#      PAUSE_MS (default 20000), PAUSE_N (default 64),
#      POP_DIRS (default 40), POP_FILES (default 200).
#
# Exit 0 PASS, 1 FAIL, 2 PRECONDITION-NOT-MET.
# Leaves a durable quarantine — re-prep before anything else.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
DUMP=/src/mxfs/tools/caw_slotdump
HASH="$REPO/tools/caw_slot_hash.py"
PARSE="$REPO/tests/closure_foot_parse.py"
DEV=/dev/mapper/mpatha
MNT=/mnt/shared
CAW_LIVE_MAGIC=0x4d584357

N="${1:?usage: closure_reuse_directed.sh <N> <victim>}"
VICTIM="${2:?usage: closure_reuse_directed.sh <N> <victim>}"
AUDIT_HOST="${AUDIT_HOST:-test1}"
RECOVERY_WAIT="${RECOVERY_WAIT:-200}"
PAUSE_MS="${PAUSE_MS:-75000}"
PAUSE_N="${PAUSE_N:-4}"
# sess376: the pause countdown is a single global consumed by whichever
# thread reaches caw_closure_strip_one first, and BOTH the publisher scan
# and a blocked waiter's demand scrub pass through it.  Unfiltered (who=0)
# the scrub that step 6 depends on is itself parked for PAUSE_MS, which is
# what sess375 misread as "the demand scrub never fired".  1 = scan only.
PAUSE_WHO="${PAUSE_WHO:-1}"
# ABA ARM (sess376 RULE-5 review, question 3).  The default arm proves the
# hint->authoritative-read window: the re-read finds a DIFFERENT resource.  The
# ABA arm proves the authoritative-read->CAS window with the HARDEST shape the
# review named — the slot goes A -> tombstone -> A, so resource comparison
# cannot save the stale attempt and the full-image CAS has to.  where=2 pauses
# between the per-CAS gate and the CAS itself; REUSE_TO=A makes Q re-bind the
# SAME resource instead of a colliding one.
ABA="${ABA:-0}"
if [ "$ABA" = "1" ]; then
    PAUSE_WHERE="${PAUSE_WHERE:-2}"; REUSE_TO="${REUSE_TO:-A}"
else
    PAUSE_WHERE="${PAUSE_WHERE:-1}"; REUSE_TO="${REUSE_TO:-B}"
fi
POP_DIRS="${POP_DIRS:-40}"
POP_FILES="${POP_FILES:-200}"

[ "$VICTIM" = "$AUDIT_HOST" ] && { echo "FAIL: victim is the audit host"; exit 1; }

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || survivors+=("$h")
done
# Q watches slot S and binds B.  The EX waiter that empties S is NOT chosen
# here: it has to run on the recovery-lease owner, which is only known once the
# lease is claimed (see step 6).
Q_HOST="${survivors[3]}"; [ "$Q_HOST" = "$AUDIT_HOST" ] && Q_HOST="${survivors[4]}"

DD=$(mktemp -d)
pass=1
fail() { echo "FAIL: $*"; pass=0; }

echo "=== closure_reuse_directed: N=$N victim=$VICTIM Q=$Q_HOST @ $(date -u +%FT%TZ) ==="

VSLOT=$("$SSH" "$VICTIM" "dmesg | grep -oE 'node_slot=[0-9]+' | tail -1" 2>/dev/null |
        tr -d '[:space:]' | cut -d= -f2)
[ -n "${VSLOT:-}" ] || { echo "FAIL: could not resolve the victim's heartbeat slot"; exit 1; }

CHK=$("$SSH" "$AUDIT_HOST" "/src/mxfs/tools/chk_mxfs -v $DEV 2>/dev/null" 2>/dev/null)
XOFF=$(echo "$CHK" | grep -oE 'xfs_data_offset=[0-9]+' | head -1 | cut -d= -f2)
DLOFF=$(echo "$CHK" | grep -oE 'disklock_offset=[0-9]+' | head -1 | cut -d= -f2)
AGCOUNT=$(echo "$CHK" | grep -oE 'agcount=[0-9]+' | head -1 | cut -d= -f2)
[ -n "${XOFF:-}" ] && [ -n "${DLOFF:-}" ] || { echo "FAIL: could not read the MXFS envelope offsets"; exit 1; }
TABOFF=$(( DLOFF + 64 * 512 ))
LOGS=$("$SSH" "$AUDIT_HOST" "dd if=$DEV bs=1 skip=$(( XOFF + 123 )) count=2 2>/dev/null | od -An -tu1" 2>/dev/null |
       grep -vE 'known hosts|Unauthorized|authorized user' | tr -s ' ' | sed 's/^ //')
INOSHIFT=$(( $(echo "$LOGS" | awk '{print $1}') + $(echo "$LOGS" | awk '{print $2}') ))
echo "victim slot=$VSLOT  slot_table_offset=$TABOFF  ino>>agno shift=$INOSHIFT  agcount=$AGCOUNT"

# ── 1. populate, so there are enough real inodes to collide ─────────────────
have=$("$SSH" "$AUDIT_HOST" "find $MNT -xdev -type f 2>/dev/null | head -20000 | wc -l" 2>/dev/null |
       tail -1 | tr -d '[:space:]')
if [ "${have:-0}" -lt 6000 ]; then
    echo "--- populating: $POP_DIRS dirs x $POP_FILES files over 8 survivors (have ${have:-0})"
    n=0
    for h in "${survivors[@]:0:8}"; do
        n=$((n+1))
        "$SSH" "$h" "for d in \$(seq 1 $(( POP_DIRS / 8 )) ); do
                dd=$MNT/reuse-$n-\$d; mkdir -p \$dd
                for i in \$(seq 1 $POP_FILES); do echo p > \$dd/f\$i; done
            done; sync" >/dev/null 2>&1 &
    done
    wait
    have=$("$SSH" "$AUDIT_HOST" "find $MNT -xdev -type f 2>/dev/null | head -20000 | wc -l" 2>/dev/null |
           tail -1 | tr -d '[:space:]')
fi
echo "inode population: ${have:-0} files"
[ "${have:-0}" -ge 2000 ] || { echo "PRECONDITION-NOT-MET: too few inodes to find a collision"; exit 2; }

# ── 2. enumerate inodes FIRST, then quiesce ────────────────────────────────
# Order matters and cost sess375 two runs.  `find -printf '%i'` stats every
# file, which ACQUIRES a lock on every inode and binds all of them into slots.
# Run with the enumeration last, A took its home slot and B — whose home is the
# same slot — was pushed one probe past it and could never move back; the giveaway
# was B's slot carrying an EARLIER lmod than A's.  So: enumerate, THEN evict, so
# the platter the pair is chosen against is the quiesced one both will bind into.
"$SSH" "$AUDIT_HOST" "find $MNT -xdev -type f -printf '%i %p\\n' 2>/dev/null | head -40000" 2>/dev/null |
    grep -vE 'known hosts|Unauthorized|authorized user' > "$DD/inos.txt"
echo "enumerated $(wc -l < "$DD/inos.txt") inodes"

echo "--- fleet-wide sync + evict, so cached grants release and slots tombstone"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "sync; echo 3 > /proc/sys/vm/drop_caches" >/dev/null 2>&1 &
done
wait
sleep 15

# ── 3. choose the colliding pair off the QUIESCED platter ──────────────────
"$SSH" "$AUDIT_HOST" "$DUMP $DEV --all" 2>/dev/null |
    grep -vE 'known hosts|Unauthorized|authorized user' > "$DD/pre.dump"
echo "--- replicating the kernel's slot hash against the live platter"
python3 "$HASH" verify "$DD/pre.dump" | tail -1
PAIR=$(python3 "$HASH" pick "$DD/pre.dump" "$DD/inos.txt" "$INOSHIFT")
[ -n "${PAIR:-}" ] || { echo "PRECONDITION-NOT-MET: no usable colliding pair"; exit 2; }
S=$(echo "$PAIR" | awk '{print $1}')
INO_A=$(echo "$PAIR" | awk '{print $2}'); AG_A=$(echo "$PAIR" | awk '{print $3}'); PATH_A=$(echo "$PAIR" | awk '{print $4}')
INO_B=$(echo "$PAIR" | awk '{print $5}'); AG_B=$(echo "$PAIR" | awk '{print $6}'); PATH_B=$(echo "$PAIR" | awk '{print $7}')
echo "collision: home slot S=$S"
echo "  A ino=$INO_A ag=$AG_A $PATH_A   (will be the victim's frozen grant, OUT of closure)"
echo "  B ino=$INO_B ag=$AG_B $PATH_B   (will re-bind at S inside the strip attempt)"
if [ "$REUSE_TO" = "A" ]; then
    REBIND_INO="$INO_A"; REBIND_PATH="$PATH_A"
else
    REBIND_INO="$INO_B"; REBIND_PATH="$PATH_B"
fi
echo "arm: pause_where=$PAUSE_WHERE pause_who=$PAUSE_WHO rebind_to=$REUSE_TO (ino=$REBIND_INO)"

# Forged domain: a third AG, so A and B both stay OUT of closure and usable.
QAG=""
for a in $(seq 1 $(( AGCOUNT - 1 ))); do
    [ "$a" = "$AG_A" ] || [ "$a" = "$AG_B" ] || { QAG=$a; break; }
done
[ -n "$QAG" ] || { echo "PRECONDITION-NOT-MET: no third AG available"; exit 2; }
AGMASK=$(printf '0x%x' $(( 1 << QAG )))
echo "forged refused domain: ag$QAG (ag_mask=$AGMASK) — ag0, ag$AG_A and ag$AG_B all stay OUT of closure"

# ── 4. bind A at S from the victim, and PROVE it landed there ───────────────
# A plain direct read of the sector is NOT equivalent and cost sess375 a run:
# this target stack drops the SCSI FUA bit, so `dd iflag=direct` returned a
# SUPERSEDED tombstone image, the poller fired early, and B bound one probe
# slot past its home while A was still live there (slot 47 lmod EARLIER than
# slot 46's, which is how it was caught).  caw_slotdump --slot issues the same
# READ(16)+FUA the kernel's read_slot uses.
slot_magic() {   # slot_magic <host> <slot>  -> hex magic
    "$SSH" "$1" "$DUMP $DEV --slot $2" 2>/dev/null |
        grep -oE 'magic=0x[0-9a-f]+' | cut -d= -f2
}
echo "--- victim writes A, taking EX; and churns the root dir for the blocked prober"
"$SSH" "$VICTIM" "echo directed >> $PATH_A; sync" >/dev/null 2>&1
"$SSH" "$VICTIM" "nohup bash -c '
    end=\$((SECONDS + 300)); i=0
    while [ \$SECONDS -lt \$end ]; do
        i=\$((i+1)); echo x > $MNT/.crd-v.\$i; rm -f $MNT/.crd-v.\$((i-2))
    done' >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 5
"$SSH" "$AUDIT_HOST" "$DUMP $DEV --all" 2>/dev/null |
    grep -vE 'known hosts|Unauthorized|authorized user' > "$DD/bound.dump"
BOUND=$(awk -v s="$S" '$0 ~ "^slot="s" " {print}' "$DD/bound.dump")
echo "slot $S after the victim's write: ${BOUND:-<empty>}"
case "$BOUND" in
    *"ino=$INO_A"*) ;;
    *) echo "PRECONDITION-NOT-MET: A did not bind at its home slot $S (probe collision or a"
       echo "  racing acquire took it).  Nothing to measure; re-run."
       exit 2 ;;
esac
echo "$BOUND" | grep -qE "ex=0x[0-9a-f]+\[[0-9,]*\b$VSLOT\b" || {
    echo "PRECONDITION-NOT-MET: the victim does not hold EX on A at slot $S"; exit 2; }
echo "PROVEN on the platter: A is bound at S=$S with the victim's EX"

# ── 5. kill FIRST, so the victim dies still holding A ──────────────────────
for h in "${survivors[@]}"; do "$SSH" "$h" "dmesg --clear" >/dev/null 2>&1 & done
wait
date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy"; exit 1; }

echo "--- arming refusal ag_mask=$AGMASK slot=$VSLOT + hint->read pause ${PAUSE_MS}ms x$PAUSE_N AT SLOT $S (who=$PAUSE_WHO)"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo $AGMASK > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo $VSLOT > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo $PAUSE_WHERE > /sys/module/mxfs/parameters/caw_inject_closure_pause_where;
                 echo $PAUSE_MS > /sys/module/mxfs/parameters/caw_inject_closure_pause_ms;
                 echo $S > /sys/module/mxfs/parameters/caw_inject_closure_pause_slot;
                 echo $PAUSE_WHO > /sys/module/mxfs/parameters/caw_inject_closure_pause_who;
                 echo $PAUSE_N > /sys/module/mxfs/parameters/caw_inject_closure_pause_n" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = "1" ] && armed=$((armed+1))
done
[ "$armed" -eq "${#survivors[@]}" ] || { echo "FAIL: armed on $armed/${#survivors[@]}"; exit 1; }

# Q watches slot S's magic straight off the platter and binds B the instant the
# slot stops being LIVE.  Touching B any earlier would bind it at S+1 (S is
# still occupied by A) and it could never move.
echo "--- $Q_HOST polling slot $S; it reads B the instant S stops being LIVE"
"$SSH" "$Q_HOST" "nohup bash -c '
    end=\$((SECONDS + $(( RECOVERY_WAIT + 20 ))))
    seen_live=0
    while [ \$SECONDS -lt \$end ]; do
        m=\$($DUMP $DEV --slot $S 2>/dev/null | grep -oE \"magic=0x[0-9a-f]+\" | cut -d= -f2)
        if [ \"\$m\" = \"$CAW_LIVE_MAGIC\" ]; then seen_live=1; sleep 0.3; continue; fi
        if [ \$seen_live -eq 1 ]; then
            echo \"S_FREED magic=\$m at \$SECONDS\" > /tmp/crd_q.out
            $DUMP $DEV --slot $S >> /tmp/crd_q.out 2>&1
            cat $REBIND_PATH > /dev/null 2>&1
            echo \"B_READ rc=\$?\" >> /tmp/crd_q.out
            $DUMP $DEV --slot $S >> /tmp/crd_q.out 2>&1
            # HOLD B LIVE AT S until the publisher wakes from its pause.  A
            # single read binds S and then releases within milliseconds
            # (measured sess376: LIVE -> TOMB inside one dump interval), and a
            # tombstoned slot short-circuits caw_closure_strip_one at the magic
            # check (hint_vanished) BEFORE the resource comparison that scores
            # moved.  Real work on B keeps the grant, and therefore the
            # binding, alive across the whole window.
            live=0; dead=0
            while [ \$SECONDS -lt \$end ]; do
                echo x >> $REBIND_PATH 2>/dev/null
                mm=\$($DUMP $DEV --slot $S 2>/dev/null | grep -oE \"magic=0x[0-9a-f]+\" | cut -d= -f2)
                if [ \"\$mm\" = \"$CAW_LIVE_MAGIC\" ]; then live=\$((live+1)); else dead=\$((dead+1)); fi
                echo \"B_HELD live_samples=\$live non_live_samples=\$dead at \$SECONDS\" > /tmp/crd_q_hold.out
                sleep 0.3
            done
            echo \"B_HELD live_samples=\$live non_live_samples=\$dead\" >> /tmp/crd_q.out
            $DUMP $DEV --slot $S >> /tmp/crd_q.out 2>&1
            echo Q_DONE >> /tmp/crd_q.out
            exit 0
        fi
        sleep 0.3
    done
    echo S_NEVER_FREED > /tmp/crd_q.out
' >/dev/null 2>&1 &" >/dev/null 2>&1

# ── 6. find the PUBLISHER, and put the EX waiter on IT ─────────────────────
# The waiter that empties S must live on the publisher, but NOT for the reason
# sess375 recorded.  CORRECTED sess376: "the publisher purges before it
# publishes" was a misreading of log ordering.  The DURABLE publication is
# mxfs_v5_dlm_recovery_publish_refusal (xfs/xfs_mxfs_dlm.c:46711); the purge
# scan runs after it (:46759); the "terminal outcome PUBLISHED" line is just
# the summary emitted at the end (:46791).  Proven on the rig: a publisher
# destroyed mid-scan, which never emitted that line at all, still had its
# verdict imported by ALL 30 remote survivors (P240-QUAR-IMPORT victim_slot=31
# ag_mask=0x2), ~2.1s after their own fence-done.
# The real reason is TIMING, and it is why this test puts the waiter on the
# publisher: the publisher seeds its own candidate hint locally and its blocked
# waiter scrubs within ~1ms (measured, P299-SCRUB-TRY el_ms=1), while a remote
# node has to wait for its monitor import lap — ~2.1s — by which time the
# publisher's 418ms scan (measured un-injected) has already passed S.
echo "--- waiting for the recovery lease so the publisher can be identified"
PUB=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    sleep 8
    for h in "${survivors[@]}"; do
        ( "$SSH" "$h" "dmesg | grep -cE 'P236-RECOV-CLAIMED|P238-RECOV-LEASE.*execution lease acquired'" \
            2>/dev/null | tr -d '[:space:]' > "$DD/lease.$h" ) &
    done
    wait
    for h in "${survivors[@]}"; do
        c=$(cat "$DD/lease.$h" 2>/dev/null)
        [ "${c:-0}" -ge 1 ] && { PUB="$h"; break; }
    done
    [ -n "$PUB" ] && break
done
if [ -z "$PUB" ]; then
    echo "PRECONDITION-NOT-MET: no node claimed the recovery lease — nothing purged"
    exit 2
fi
echo "publisher = $PUB (recovery-lease owner)"

echo "--- $PUB requests EX on A: its LOCAL demand scrub is what empties S"
"$SSH" "$PUB" "nohup bash -c '
    s=\$(date +%s)
    timeout $(( RECOVERY_WAIT )) bash -c \"echo probe >> $PATH_A\"; rc=\$?
    echo \"P_EX rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/crd_p.out
    sync; echo 3 > /proc/sys/vm/drop_caches
    echo EVICTED >> /tmp/crd_p.out
' >/dev/null 2>&1 &" >/dev/null 2>&1

BLOCK_BUDGET=$(( RECOVERY_WAIT + 40 ))
"$SSH" "$AUDIT_HOST" "nohup bash -c '
    s=\$(date +%s)
    timeout $BLOCK_BUDGET touch $MNT/.crd-blocked; rc=\$?
    echo \"BLOCKED_PROBE rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/crd_probe.out
' >/dev/null 2>&1 &" >/dev/null 2>&1

echo "waiting ${RECOVERY_WAIT}s for fence+refusal+publish+purge..."
sleep "$RECOVERY_WAIT"

# ── 7. harvest ─────────────────────────────────────────────────────────────
for h in "${survivors[@]}"; do "$SSH" "$h" "dmesg" > "$DD/$h.dmesg" 2>/dev/null & done
wait
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_n;
                 echo -1 > /sys/module/mxfs/parameters/caw_inject_closure_pause_slot;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_who;
                 echo 0 > /sys/module/mxfs/parameters/caw_inject_closure_pause_where" >/dev/null 2>&1 &
done
wait

echo "--- P(on $PUB): $("$SSH" "$PUB" "cat /tmp/crd_p.out 2>/dev/null" 2>/dev/null | tr -d '\r' | tr '\n' ' ')"
QOUT=$("$SSH" "$Q_HOST" "cat /tmp/crd_q.out 2>/dev/null" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
echo "--- Q: $QOUT"
echo "--- Q hold: $("$SSH" "$Q_HOST" "cat /tmp/crd_q_hold.out 2>/dev/null" 2>/dev/null | tr -d '\r' | tr '\n' ' ')"
bp=$("$SSH" "$AUDIT_HOST" "cat /tmp/crd_probe.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep BLOCKED_PROBE | tail -1)
echo "--- blocked prober: ${bp:-<still running>}"

cat "$DD"/*.dmesg > "$DD/all.dmesg" 2>/dev/null
echo "--- demand-scrub census (sess376 P299-SCRUB-TRY) + injected pauses"
grep -h "P299-SCRUB-TRY\|P299-INJECT-PAUSE\|P299-SCRUB-STRIP\|P299-HINT-MOVED\|P299-HINT-FLIPPED\|P299-STRIP-CASMISS" "$DD/all.dmesg" |
    sed 's/^\[[^]]*\] *//' | head -16

echo "--- purge summary"
grep -h "P299-CLOSURE-PURGE\|P299-CLOSURE-SHAPES\|P299-CLOSURE-INCOMPLETE" "$DD/all.dmesg" |
    sed 's/^\[[^]]*\] *//' | head -4

INJ=$(grep -h "P227-FR-INJECT-ARMED" "$DD/all.dmesg" | head -1)
PUBMASK=$(grep -h "slice replay refused" "$DD/all.dmesg" | grep -oE 'ag_mask=0x[0-9a-f]+' | head -1 | cut -d= -f2)
echo "--- forged-domain check: injection=$( [ -n "$INJ" ] && echo fired || echo NOT-FIRED ) published=${PUBMASK:-<none>} armed=$AGMASK"
if [ -z "$INJ" ] || [ -z "${PUBMASK:-}" ] || [ $(( PUBMASK )) -ne $(( AGMASK )) ]; then
    echo "PRECONDITION-NOT-MET: the run did not get the domain it armed (a genuine"
    echo "  refusal publishes its OWN refused AG set).  Harness precondition, not"
    echo "  an MXFS defect — do not ledger it."
    exit 2
fi

# ── 8. assertions ──────────────────────────────────────────────────────────
sh=$(grep -h "P299-CLOSURE-SHAPES" "$DD/all.dmesg" | tail -1)
mov=$(echo "$sh" | grep -o 'moved=[0-9]*' | cut -d= -f2)
bgo=$(echo "$sh" | grep -o 'bit_gone=[0-9]*' | cut -d= -f2)
van=$(echo "$sh" | grep -o ' vanished=[0-9]*' | cut -d= -f2)
mis=$(echo "$sh" | grep -o 'cas_miscompare=[0-9]*' | cut -d= -f2)

"$SSH" "$AUDIT_HOST" "$DUMP $DEV --all" 2>/dev/null |
    grep -vE 'known hosts|Unauthorized|authorized user' > "$DD/post.dump"
AFTER=$(awk -v s="$S" '$0 ~ "^slot="s" " {print}' "$DD/post.dump")
echo "--- assertions"
echo "slot $S after the run: ${AFTER:-<empty>}"
case "$AFTER" in
    *"ino=$REBIND_INO"*) ;;
    *) echo "PRECONDITION-NOT-MET: slot $S does not hold the rebind target"
       echo "  (want ino=$REBIND_INO, got: ${AFTER:-empty})"; exit 2 ;;
esac
# The tombstone transition itself is proven by Q, which polls S's magic straight
# off the platter and only acts once it stops being LIVE.  In the ABA arm the
# rebind target IS A, so the post-run image alone cannot distinguish "freed and
# re-bound" from "never freed" — Q's observation is what does.
case "$QOUT" in
    *S_FREED*) echo "REUSE HAPPENED: slot $S went A(ino=$INO_A) -> tombstone -> $REUSE_TO(ino=$REBIND_INO)" ;;
    *) echo "PRECONDITION-NOT-MET: slot $S was never observed non-LIVE by $Q_HOST —"
       echo "  the tombstone transition did not occur on this run."; exit 2 ;;
esac
echo "hint staleness: vanished=${van:-?} bit_gone=${bgo:-?} moved=${mov:-?} cas_miscompare=${mis:-?}"

if [ "$REUSE_TO" = "A" ]; then
    # ── ABA arm: the authoritative-read -> CAS window, same resource ───────
    ip=$(grep -h "P299-INJECT-PAUSE slot=$S " "$DD/all.dmesg" | grep "where=2" | tail -1)
    [ -n "$ip" ] || fail "the scan never paused between the per-CAS gate and the CAS on slot $S"
    inv=$(echo "$ip" | grep -o 'inv=[0-9]*' | cut -d= -f2)
    cmline=$(grep -h "P299-STRIP-CASMISS slot=$S " "$DD/all.dmesg" | grep "inv=${inv:-none}" | tail -1)
    cm=$(grep -h "P299-STRIP-CASMISS slot=$S " "$DD/all.dmesg" | grep -c "inv=${inv:-none}" || true)
    echo "paused strip attempt inv=${inv:-?} on slot $S: CAS miscompares=$cm"
    echo "expected image of that attempt: $(echo "$cmline" | sed 's/^\[[^]]*\] *//')"
    [ "${cm:-0}" -ge 1 ] || fail "the stale CAS did NOT miscompare after S was re-bound to the SAME resource — an ABA success"
    cs=$(grep -h "P299-CLOSURE-STRIP slot=$S " "$DD/all.dmesg" | wc -l)
    echo "publisher strips completed on slot $S (want 0 — the demand scrub got there first): $cs"
    [ "$cs" -eq 0 ] || fail "the publisher completed a strip on slot $S after the re-bind"
else
    [ "${mov:-0}" -ge 1 ] || fail "the publisher's authoritative re-read never saw a CHANGED resource (moved=0) — the race did not land inside a strip attempt"
    mvline=$(grep -h "P299-HINT-MOVED slot=$S " "$DD/all.dmesg" | tail -1)
    echo "attributed moved event: $(echo "$mvline" | sed 's/^\[[^]]*\] *//')"
    # The aggregate SHAPES counters accumulate over the WHOLE 65536-slot scan,
    # so moved>=1 on its own names no slot.  Require the per-attempt line, on
    # THIS slot, naming A as the hint and B as what was actually found.
    [ -n "$mvline" ] || fail "no P299-HINT-MOVED line for slot $S — moved>=1 came from some other slot"
    case "$mvline" in
        *"hint_ino=$INO_A"*) ;;
        *) fail "the moved event on slot $S did not name A ($INO_A) as the hint" ;;
    esac
    case "$mvline" in
        *"found_ino=$INO_B"*) ;;
        *) fail "the moved event on slot $S did not find B ($INO_B)" ;;
    esac
fi

# The rebound resource must be untouched by the stale attempt: no victim bit,
# and (default arm) no strip logged against B'"'"'s inode.
python3 "$PARSE" slots "$DD/post.dump" "$VSLOT" "$INOSHIFT" > "$DD/post.foot"
bvic=$(awk -v s="$S" '$1==s' "$DD/post.foot")
echo "victim footprint on slot $S after the run (want none): ${bvic:-<none>}"
[ -z "$bvic" ] || fail "the re-bound resource B carries the dead victim's bit"
if [ "$REUSE_TO" != "A" ]; then
    bstrip=$(grep -h "P299-CLOSURE-STRIP\|P299-SCRUB-STRIP" "$DD/all.dmesg" | grep -c "ino=$INO_B" || true)
    echo "strips logged against B (ino=$INO_B) (want 0): $bstrip"
    [ "$bstrip" -eq 0 ] || fail "the publisher acted on B — the stale hint was applied to the re-bound resource"
fi

python3 "$PARSE" strips "$DD/all.dmesg" "$INOSHIFT" > "$DD/strips.parsed"
badstrip=$(awk -v m=$(( AGMASK )) '{ag=$2+0; if (ag>=0 && and(m, lshift(1,ag))!=0) print}' "$DD/strips.parsed" | wc -l)
echo "strips inside the quarantined domain (want 0): $badstrip"
[ "$badstrip" -eq 0 ] || fail "an IN-closure resource was force-revoked"

ooc=$(awk -v m=$(( AGMASK )) '{ag=$2+0; if (ag>=0 && and(m, lshift(1,ag))==0) print}' "$DD/post.foot" | wc -l)
echo "out-of-closure slots still carrying the victim (want 0): $ooc"
[ "$ooc" -eq 0 ] || fail "out-of-closure victim state survived the purge"

shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$DD"/test*.dmesg 2>/dev/null | wc -l)
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
[ "$shutdowns" -eq 0 ] || fail "survivor withdrew"

bp_rc=$(echo "$bp" | grep -o 'rc=[0-9]*' | cut -d= -f2)
echo "blocked prober: rc=${bp_rc:-<hung>}"
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
    echo "=== closure_reuse_directed PASS @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== closure_reuse_directed FAIL @ $(date -u +%FT%TZ) ==="
exit 1
