#!/bin/bash
# creator_stale_base.sh — DETERMINISTIC reproducer for the silent mkdir loss.
#
# WHY THIS EXISTS
#   sf_mkdir_storm.sh reproduces the loss statistically: 32 nodes race into one
#   shortform parent and *sometimes* one of them ends up mutating a superseded
#   base.  On builds where the deterministic precursor (P195) fires 0-1 times a
#   run, the storm passes on luck and neither a fix nor a regression can be
#   measured.  RULE 6 is explicit that "cannot reproduce" is not a disposition,
#   so the answer is a harness that CONSTRUCTS the state instead of waiting for
#   it.
#
# THE STATE THIS BUILDS, step by step (from the ROUND-29 capture,
# sfstorm_20260728_201959, pino=46137485, test24):
#
#   1. ONE designated node creates dK.  It now holds an in-core image that is
#      dirty (it just created the object this tenure) and whose dir epoch is 0
#      (it created the object, so it has never ADOPTED anything).
#   2. The creator then goes quiet.  Every other node piles children into dK,
#      which BASTs the grant away from the creator and drives dK through the
#      SHORTFORM -> BLOCK conversion on the platter.
#   3. The creator re-acquires dK and adds ONE child of its own.  Every
#      keep-stale guard (P6, P34F, P184) legitimately protects its dirty
#      self-created image, so the child is added to the superseded base, and
#      the write-side backstop (P189) then refuses to publish a behind-disk
#      image.  mkdir(2) returned 0 and the entry exists nowhere.
#
#   Step 2 is what the storm only gets by luck.  Here it is a wall-clock fact:
#   the creator is given an explicit quiet window while the peers work.
#
# THE ORACLE
#   Same as the storm and equally authoritative: nlink == 2 + subdirectories,
#   every expected name present.  But the name under test is named CREATOR_K
#   and is created by a KNOWN node at a KNOWN time, so a loss is attributable
#   to a specific node's tenure instead of being one of 32 candidates.
#
# USAGE
#   tests/creator_stale_base.sh <rounds> [nodes] [slot_seconds] [peer_children] [quiet_ms]
#     rounds        — fresh parent directories, one per round.
#     nodes         — node count, default 32 (test1..testN).
#     slot          — seconds per round, default 4.  Must comfortably exceed
#                     quiet_ms + the time peers need to land their children.
#     peer_children — subdirs each PEER creates per round, default 2.  31x2=62
#                     entries forces the shortform->block conversion, which is
#                     the LOCAL-vs-non-LOCAL disjunct of the P189 drop.
#     quiet_ms      — how long the creator waits between creating dK and adding
#                     its own child, default 1500.  Sized from the measured
#                     32-way contention profile (p50 810ms, p90 1382ms per
#                     serialized tenure) so the peers are mid-conversion.
#
#   MXFS_CSB_NOSLEEP=1 removes the quiet window (creator adds its child
#   immediately).  That is the control arm: same workload, but the creator
#   never sits on a stale base, so a loss there is a DIFFERENT defect.
#
# EXIT: 0 = every round consistent on every node.  1 = loss reproduced.
#       2 = INFRASTRUCTURE failure (a node did not complete) — never a loss.
#
# RULE 0 budget: a round is 63 mkdirs spread over N nodes into one directory;
# native XFS does that in milliseconds.  The slot is dominated by the
# deliberate quiet window, not by filesystem time.  Total wall =
# 12s setup + rounds*slot + ~25s settle/census.
#
# HARNESS RULES OBSERVED (each of these cost a full run to learn — see state.md
# "Four traps found while building these"):
#   * NO coordinator barriers.  One barrier per round costs a broker round-trip
#     per node per round AND serialises the tenures, destroying the race under
#     test.  Rounds start on a shared wall-clock slot instead.
#   * NO inline `rm -rf` of a leftover tree before a rendezvous.
#   * Per-run base directory; prep_cluster wipes the mount.
#   * NO teardown at all.  This harness trades inode-reuse pressure (which the
#     storm covers) for an unambiguous verdict: nothing is ever removed, so
#     "missing" can never be a partially-completed rm.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

ROUNDS="${1:?usage: creator_stale_base.sh <rounds> [nodes] [slot_s] [peer_children] [quiet_ms]}"
N="${2:-32}"
SLOT="${3:-4}"
KIDS="${4:-2}"
QUIET_MS="${5:-1500}"
NOSLEEP="${MXFS_CSB_NOSLEEP:-0}"
[ "$NOSLEEP" = 1 ] && QUIET_MS=0
MNT="${MXFS_MNT:-/mnt/shared}"
BASE="$MNT/.csb_$(date -u +%H%M%S)"

STAMP=$(date -u +%Y%m%d_%H%M%S)
OUT="$REPO/tests/logs/csb_$STAMP"
mkdir -p "$OUT"

timeout 120 "$SSH" test1 "mkdir -p '$BASE'; sync" > "$OUT/setup.log" 2>&1 \
    || { echo "BASE CREATE FAILED — see $OUT/setup.log"; exit 2; }

# One run per kernel ring: inode numbers are reused heavily across tests, so a
# ring carrying an earlier run makes the publish ledger ambiguous.
for r in $(seq 1 "$N"); do
    ( timeout 30 "$SSH" "test$r" "dmesg -C" >/dev/null 2>&1 ) &
done
wait

START=$(( $(date +%s) + 12 ))
{
    echo "start=$START"; echo "slot=$SLOT"; echo "rounds=$ROUNDS"
    echo "nodes=$N"; echo "peer_children=$KIDS"; echo "quiet_ms=$QUIET_MS"
    echo "base=$BASE"
} > "$OUT/meta.txt"

echo "=== creator_stale_base: rounds=$ROUNDS nodes=$N slot=${SLOT}s peer_children=$KIDS quiet=${QUIET_MS}ms out=$OUT ==="

body() {
    cat <<EOF
set -u
R=\$1
# Expected entries per round: one CREATOR_K plus KIDS from each of the N-1
# peers.  The creator does NOT also act as a peer — its single child is the
# name under test and must not be confounded with bulk peer traffic.
EXP=\$(( 1 + ($N - 1) * $KIDS ))

for K in \$(seq 1 $ROUNDS); do
    target=\$(( $START + (K - 1) * $SLOT ))
    while [ "\$(date +%s)" -lt "\$target" ]; do sleep 0.02; done
    creator=\$(( (K - 1) % $N + 1 ))
    d="$BASE/d\$K"

    if [ "\$R" = "\$creator" ]; then
        # Step 1 — create the parent.  We are now the only node with an
        # in-core image of it, that image is dirty, and its dir epoch is 0.
        mkdir "\$d" 2>/dev/null
        rc=\$?
        [ "\$rc" -ne 0 ] && echo "CREATE-RC K=\$K rc=\$rc"
        # Step 2 — go quiet.  Touching \$d here (even a stat) would give us a
        # fresh base and defeat the reproducer.
        if [ "$QUIET_MS" -gt 0 ]; then
            sleep \$(awk "BEGIN{print $QUIET_MS/1000}")
        fi
        # Step 3 — add our child to what may now be a superseded base.
        mkdir "\$d/CREATOR_\$K" 2>/dev/null
        rc=\$?
        # A NONZERO rc is not the defect under test — it is the honest failure
        # this harness would rather see.  Record it so a run that starts
        # returning errors instead of losing entries is not mistaken for a fix.
        [ "\$rc" -ne 0 ] && echo "CREATOR-MKDIR-RC K=\$K rc=\$rc"
    else
        # Peers: wait for the parent to become visible, then pile in.  The
        # spin is bounded; a peer that never sees the parent reports it rather
        # than silently contributing nothing (which would read as loss).
        w=0
        while [ ! -d "\$d" ] && [ "\$w" -lt 200 ]; do sleep 0.02; w=\$(( w + 1 )); done
        if [ ! -d "\$d" ]; then
            echo "PEER-NOPARENT K=\$K"
            continue
        fi
        for m in \$(seq 1 $KIDS); do
            mkdir "\$d/node\${R}_\$m" 2>/dev/null
            rc=\$?
            [ "\$rc" -ne 0 ] && echo "PEER-MKDIR-RC K=\$K m=\$m rc=\$rc"
        done
    fi
done

# Settle.  Nothing is ever torn down here, so every round is still present and
# every "missing" verdict below is unambiguous.
sync
sleep 5
sync

for K in \$(seq 1 $ROUNDS); do
    d="$BASE/d\$K"
    if [ ! -d "\$d" ]; then echo "ROUND \$K ABSENT"; continue; fi
    nl=\$(stat -c %h "\$d" 2>/dev/null)
    pino=\$(stat -c %i "\$d" 2>/dev/null)
    names=" \$(ls -1 "\$d" 2>/dev/null | tr '\n' ' ')"
    subs=\$(echo \$names | wc -w)
    creator=\$(( (K - 1) % $N + 1 ))
    miss=""
    case "\$names" in *" CREATOR_\$K "*) ;; *) miss="\$miss CREATOR_\$K" ;; esac
    for r in \$(seq 1 $N); do
        [ "\$r" = "\$creator" ] && continue
        for m in \$(seq 1 $KIDS); do
            case "\$names" in
                *" node\${r}_\$m "*) ;;
                *) miss="\$miss node\${r}_\$m" ;;
            esac
        done
    done
    if [ -n "\$miss" ] || [ "\$subs" != "\$EXP" ] || [ "\$subs" != "\$(( nl - 2 ))" ]; then
        echo "ROUND \$K FAIL creator=\$creator pino=\$pino nlink=\$nl visible=\$subs expected=\$EXP missing=[\$miss ]"
        echo "mxfs-CSB-LOSS rank=\$R round=\$K creator=\$creator pino=\$pino nlink=\$nl visible=\$subs expected=\$EXP missing=[\$miss ]" > /dev/kmsg 2>/dev/null
    else
        echo "ROUND \$K OK creator=\$creator pino=\$pino nlink=\$nl subs=\$subs"
    fi
done
echo CSB_DONE
EOF
}

pids=()
for r in $(seq 1 "$N"); do
    ( timeout $(( ROUNDS * SLOT + 300 )) "$SSH" "test$r" \
        "bash -s $r" <<<"$(body)" > "$OUT/csb_test$r.log" 2>&1 ) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done

absent=""
for r in $(seq 1 "$N"); do
    grep -q CSB_DONE "$OUT/csb_test$r.log" 2>/dev/null || absent="$absent test$r"
done
if [ -n "$absent" ]; then
    echo "=== creator_stale_base INFRA-FAIL: did not complete on:$absent ==="
    echo "    (not a loss verdict — these nodes never ran their mkdirs)"
    echo "    logs: $OUT"
    exit 2
fi

echo "--- per-node verdicts ---"
grep -h "MKDIR-RC\|CREATE-RC\|PEER-NOPARENT" "$OUT"/csb_test*.log | sort | uniq -c | sed 's/^/  /'
fails=$(grep -hc "^ROUND .* FAIL" "$OUT"/csb_test*.log | paste -sd+ | bc)
oks=$(grep -hc "^ROUND .* OK" "$OUT"/csb_test*.log | paste -sd+ | bc)
echo "  node-checks OK=$oks FAIL=${fails:-0}"

# Which names went missing, and was the creator's own child among them?  A loss
# confined to CREATOR_K is the mechanism this harness targets; a loss of peer
# names is a different (also real) shape and must not be conflated.
echo "--- missing-name census ---"
grep -h "^ROUND .* FAIL" "$OUT"/csb_test*.log \
  | sed 's/.*missing=\[//; s/ \]$//' | tr ' ' '\n' | grep -v '^$' \
  | sort | uniq -c | sort -rn | head -20 | sed 's/^/  /'
creator_lost=$(grep -h "^ROUND .* FAIL" "$OUT"/csb_test*.log | grep -c "CREATOR_")
echo "  round-checks whose missing set includes the CREATOR's own child: $creator_lost"

if [ "${fails:-0}" != 0 ]; then
    echo "=== creator_stale_base FAIL: $fails node-round checks inconsistent ==="
    for r in $(seq 1 "$N"); do
        ( timeout 40 "$SSH" "test$r" "dmesg" > "$OUT/dmesg_test$r.log" 2>&1 ) &
    done
    wait
    echo "    logs: $OUT"
    exit 1
fi

echo "=== creator_stale_base PASS: $ROUNDS rounds consistent on all $N nodes ==="
echo "    logs: $OUT"
exit 0
