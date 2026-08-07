#!/bin/bash
# sf_mkdir_storm.sh — concurrent SHORTFORM-directory mkdir storm reproducer.
#
# WHAT IT REPRODUCES
#   N nodes concurrently mkdir inside ONE shared parent while that parent is
#   still in SHORTFORM (LOCAL) format, so every node's create is a read-modify-
#   write of the parent's inline data fork AND of its core link count.  A node
#   that starts an RMW from a base a peer has already advanced past publishes a
#   parent that has lost the peer's work — either a dirent (the name is gone
#   cluster-wide) or a link-count increment (nlink under-counts the children).
#   Both were captured byte-exact in ccloop c7ee71c6 sess19; see
#   tests/logs/fdw_32caw_20260728_120403 (3 of 33 names erased, parent ino
#   56623232) and tests/logs/sfstorm_20260728_122652 (nlink 29 vs 32 subdirs).
#
# THE ORACLE
#   A directory's link count is authoritative: nlink == 2 + <subdirectories>.
#   Every mkdir bumps the parent's nlink in the SAME transaction that adds the
#   dirent, so the two can never legitimately disagree once the round is
#   quiesced.  Each node checks BOTH (count agrees with nlink, and every peer's
#   name is present) so a name visible on one node and absent on another is
#   caught as well as a name absent everywhere.
#
#   The vulnerable window is the SHORTFORM phase — the first handful of entries
#   before the dir converts to block format — so pressure comes from many
#   FRESH parents (rounds), not from many entries per parent.
#
# USAGE
#   tests/sf_mkdir_storm.sh <rounds> [nodes] [slot_seconds] [per_node]
#     rounds — fresh parent directories to storm, one per round.
#     nodes  — node count, default 32 (test1..testN).
#     slot   — seconds per round, default 2.  Rounds start on a shared
#              wall-clock slot so all N creates land in the same window.
#     per_node — subdirs each node creates per round, default 1.  Keep this
#              at 1 to stay in the shortform window; raise it only to study
#              the block-format path.
#
#   Every node verifies round K-2 at the top of round K — BEFORE any teardown
#   can remove it — so a loss is caught in the round it happened rather than
#   only in the two rounds that survive to the end.  Rank 1 tears down round
#   K-4 in the background (never on the critical path: a foreground rm -rf of
#   a 32-child tree outlasted a slot and silently dropped rank 1 out of the
#   storm, which then looked exactly like real dirent loss).  The teardown is
#   what drives the inode/daddr REUSE this defect family needs.
#
# EXIT: 0 = every round consistent on every node.  1 = defect reproduced (per
#       round/node detail printed, dmesg harvested).  2 = INFRASTRUCTURE
#       failure (a node did not complete its storm) — never reported as loss.
#
# RULE 0 budget: a round is N concurrent mkdirs in one directory; native XFS
# does that in milliseconds, so a 2s slot is ~1000x headroom.  Total wall =
# 10s setup + rounds*slot + ~20s verify/census.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

ROUNDS="${1:?usage: sf_mkdir_storm.sh <rounds> [nodes] [slot_seconds] [per_node]}"
N="${2:-32}"
SLOT="${3:-2}"
M="${4:-1}"
MNT="${MXFS_MNT:-/mnt/shared}"
# MXFS_STORM_NOTEARDOWN=1 keeps every round directory alive to the end of the
# run.  The teardown exists to drive inode/daddr REUSE, so a no-teardown run is
# a weaker reproducer — but it is the only way to ask the one question the
# in-run oracle cannot answer: is a "missing" name DURABLY lost, or merely not
# visible yet in the two-slot verification window?  The settled census below
# re-checks every round on every node after a sync, long after the storm ends.
NOTEARDOWN="${MXFS_STORM_NOTEARDOWN:-0}"
# Per-run base.  A previous run's rounds must never land in this run's round
# directories (creates EEXIST and the verifier sees more children than anyone
# created), and a run that reproduced the defect leaves behind directories that
# CANNOT be removed: a lost nlink bump makes the later rmdirs underflow the
# count, so the parent settles at nlink=1 or wraps to 4294967295 and rmdir
# returns ENOTEMPTY forever on an empty directory (captured 2026-07-28: d4
# nlink=4294967295, d10 nlink=1, both listing only "." and "..").  A unique
# base per run keeps that wreckage out of the next run's way.
BASE="$MNT/.sfstorm_$(date -u +%H%M%S)"

STAMP=$(date -u +%Y%m%d_%H%M%S)
OUT="$REPO/tests/logs/sfstorm_$STAMP"
mkdir -p "$OUT"

timeout 120 "$SSH" test1 "mkdir -p '$BASE'; sync" > "$OUT/wipe.log" 2>&1 \
    || { echo "BASE CREATE FAILED — see $OUT/wipe.log"; exit 2; }

# Clear each node's kernel ring first.  Inode numbers are reused heavily across
# tests, so a ring carrying earlier runs makes the publish ledger ambiguous:
# the same ino shows dirents from a previous test's incarnation and the
# analyzer cannot tell them apart.  One run per ring.
for r in $(seq 1 "$N"); do
    ( timeout 30 "$SSH" "test$r" "dmesg -C" >/dev/null 2>&1 ) &
done
wait

START=$(( $(date +%s) + 10 ))
{
    echo "start=$START"
    echo "slot=$SLOT"
    echo "rounds=$ROUNDS"
    echo "nodes=$N"
    echo "per_node=$M"
    echo "base=$BASE"
} > "$OUT/meta.txt"

echo "=== sf_mkdir_storm: rounds=$ROUNDS nodes=$N slot=${SLOT}s per_node=$M out=$OUT ==="

storm_body() {
    cat <<EOF
set -u
R=\$1
EXP=\$(( $N * $M ))
PENDING=""

verify_round() {
    K=\$1
    d="$BASE/d\$K"
    [ -d "\$d" ] || { echo "ROUND \$K ABSENT"; return; }
    # ONE readdir + one stat.  Per-name [ -d ] lookups cost a cluster lookup
    # each; at 32 names/round that ran ~25s per round, so nodes fell behind
    # their wall-clock slots and the storm stopped being concurrent (the whole
    # point).  Read the names once and compare in the shell.
    nl=\$(stat -c %h "\$d" 2>/dev/null)
    names=" \$(ls -1 "\$d" 2>/dev/null | tr '\n' ' ')"
    subs=\$(echo \$names | wc -w)
    miss=""
    for r in \$(seq 1 $N); do
        for m in \$(seq 1 $M); do
            case "\$names" in
                *" node\${r}_\$m "*) ;;
                *) miss="\$miss node\${r}_\$m" ;;
            esac
        done
    done
    implies=\$(( nl - 2 ))
    pino=\$(stat -c %i "\$d" 2>/dev/null)
    if [ "\$subs" != "\$implies" ] || [ -n "\$miss" ] || [ "\$subs" != "\$EXP" ]; then
        echo "ROUND \$K FAIL pino=\$pino nlink=\$nl implies=\$implies visible=\$subs expected=\$EXP missing=[\$miss ]"
        echo "mxfs-SFSTORM-LOSS rank=\$R round=\$K pino=\$pino nlink=\$nl visible=\$subs expected=\$EXP missing=[\$miss ]" > /dev/kmsg 2>/dev/null
        case " \$PENDING " in *" \$K "*) ;; *) PENDING="\$PENDING \$K" ;; esac
        return 1
    else
        echo "ROUND \$K OK pino=\$pino nlink=\$nl subs=\$subs"
        return 0
    fi
}

# ── DURABLE vs TRANSIENT ──────────────────────────────────────────────────────
# verify_round runs two slots after the round it checks.  That is deliberate
# (catch a loss in the round it happened, before teardown removes the evidence)
# but it is NOT proof of durable loss: a name that has not propagated to this
# node yet looks identical to one that is gone.  Measured 2026-07-28: a
# no-teardown run flagged 70 round-checks in-run and the post-settle census
# found 0 of them still wrong on any of the 32 nodes — every one was
# visibility lag.  So a first FAIL only makes the round PENDING; it is
# re-checked on every later round until it either comes good (LATE-OK, dropped)
# or dies still wrong (DURABLE-FAIL).  Only DURABLE-FAIL is a data-loss verdict.
# \$1 = the round we are currently in (ROUNDS+1 for the final pass).  Any round
# the teardown has already been ASKED to remove is off-limits for a verdict: a
# concurrent `rm -rf` walks the link count down (captured: "nlink=4 visible=2
# expected=32" on 24 nodes, which is the teardown mid-flight, not a loss).
recheck_pending() {
    [ -n "\$PENDING" ] || return
    C=\$1
    keep=""
    for K in \$PENDING; do
        d="$BASE/d\$K"
        if [ "$NOTEARDOWN" != 1 ] && [ "\$K" -le "\$(( C - 10 ))" ]; then
            echo "ROUND \$K UNRESOLVED (teardown target; no verdict possible)"
            continue
        fi
        if [ ! -d "\$d" ]; then
            # Removed by the teardown while still pending.  We CANNOT tell a
            # durable loss from a slow propagation here — the evidence is gone.
            # Say so; do not count it either way.  (The teardown lag above is
            # sized so this should be rare.)
            echo "ROUND \$K UNRESOLVED (torn down while still pending)"
            continue
        fi
        nl=\$(stat -c %h "\$d" 2>/dev/null)
        names=" \$(ls -1 "\$d" 2>/dev/null | tr '\n' ' ')"
        subs=\$(echo \$names | wc -w)
        miss=""
        for r in \$(seq 1 $N); do
            for m in \$(seq 1 $M); do
                case "\$names" in
                    *" node\${r}_\$m "*) ;;
                    *) miss="\$miss node\${r}_\$m" ;;
                esac
            done
        done
        if [ "\$subs" = "\$(( nl - 2 ))" ] && [ -z "\$miss" ] && [ "\$subs" = "\$EXP" ]; then
            echo "ROUND \$K LATE-OK nlink=\$nl subs=\$subs (was a visibility lag, not a loss)"
        else
            keep="\$keep \$K"
        fi
    done
    PENDING="\$keep"
}

for K in \$(seq 1 $ROUNDS); do
    target=\$(( $START + (K - 1) * $SLOT ))
    while [ "\$(date +%s)" -lt "\$target" ]; do sleep 0.05; done
    mkdir -p "$BASE/d\$K" 2>/dev/null
    for m in \$(seq 1 $M); do
        mkdir "$BASE/d\$K/node\${R}_\$m" 2>/dev/null
        rc=\$?
        [ "\$rc" -ne 0 ] && echo "MKDIR-RC K=\$K m=\$m rc=\$rc"
    done
    # Verify the round that finished two slots ago (quiesced, not yet torn
    # down), so a loss is caught in the round it happened.
    [ "\$K" -gt 2 ] && verify_round \$(( K - 2 ))
    # ...then re-ask about every round still flagged, so a name that was merely
    # slow to become visible is retired as LATE-OK instead of counted as loss.
    recheck_pending \$K
    # Teardown drives inode/daddr reuse; detached so it never eats a slot.
    # Teardown lag is 10, not 4.  A round flagged at J+2 must survive long
    # enough to be RE-CHECKED several times, otherwise it is removed while
    # still pending and the harness cannot tell a durable loss from a name that
    # had not propagated yet.  Reuse pressure is preserved — it just arrives 6
    # slots later.
    #
    # sess22: tear down only EVERY THIRD round, and SAY WHICH.
    #
    # Two problems with tearing down every round.  (1) It leaves almost
    # nothing convictable: with lag 10 and 60 rounds, rounds 1..50 were all
    # "teardown targets" and the node side abstained on every one of them --
    # which is how a run that lost four dirents exited 0.  (2) A STALLED
    # teardown is stable, so the host-side two-pass stability test cannot
    # exclude it by shape: run sfstorm_20260729_031835 produced 8 rounds
    # reading "nlink=3 visible=1 missing=[31 names]", identical 8s apart.
    # That is `rm -rf` having removed 31 of 32 children and then failing on
    # the last (the ENOTEMPTY loop this file's header describes), NOT a loss.
    #
    # Tearing down a third of the rounds keeps the inode/daddr REUSE pressure
    # this defect family needs (the captures show P128-REARM-UNPUB "cache-hit
    # CREATE on reused inode") while leaving two thirds of the rounds never
    # touched and therefore fully convictable.  The round number is logged so
    # the host excludes EXACTLY the rounds it removed, instead of guessing
    # from the damage shape.
    if [ "\$R" = 1 ] && [ "\$K" -gt 10 ] && [ "$NOTEARDOWN" != 1 ] &&
       [ \$(( (K - 10) % 3 )) -eq 0 ]; then
        echo "TEARDOWN \$(( K - 10 ))"
        ( rm -rf "$BASE/d\$((K - 10))" 2>/dev/null ) &
    fi
done
sync
sleep 2
verify_round $ROUNDS
[ $ROUNDS -gt 1 ] && verify_round \$(( $ROUNDS - 1 ))
# Final settle, then one last pass: anything still inconsistent after a sync and
# a quiet interval is durable.
sleep 3
sync
# Re-verify EVERY surviving round, not just the ones already flagged.  A round
# that was correct when it was checked can still be reverted afterwards by a
# peer publishing a stale image over it — that is precisely the shape of the
# fence_during_write capture (parent nlink=35 with only 30 names, identical on
# all 32 nodes, permanent).  Checking only the flagged set would step straight
# past it.
for K in \$(seq 1 $ROUNDS); do
    [ -d "$BASE/d\$K" ] || continue
    case " \$PENDING " in *" \$K "*) continue ;; esac
    verify_round \$K > /dev/null 2>&1 || true
done
recheck_pending \$(( $ROUNDS + 1 ))
for K in \$PENDING; do
    d="$BASE/d\$K"
    # The teardown may have removed it between recheck_pending and here; a
    # missing directory is UNRESOLVED, not a loss (stat would report nlink=""
    # and visible=0, i.e. a fabricated 32-name loss on every node).
    [ -d "\$d" ] || { echo "ROUND \$K UNRESOLVED (torn down before final check)"; continue; }
    if [ "$NOTEARDOWN" != 1 ] && [ "\$K" -le "\$(( $ROUNDS + 1 - 10 ))" ]; then
        echo "ROUND \$K UNRESOLVED (teardown target; no verdict possible)"
        continue
    fi
    nl=\$(stat -c %h "\$d" 2>/dev/null)
    names=" \$(ls -1 "\$d" 2>/dev/null | tr '\n' ' ')"
    subs=\$(echo \$names | wc -w)
    miss=""
    for r in \$(seq 1 $N); do
        for m in \$(seq 1 $M); do
            case "\$names" in *" node\${r}_\$m "*) ;; *) miss="\$miss node\${r}_\$m" ;; esac
        done
    done
    echo "ROUND \$K DURABLE-FAIL nlink=\$nl visible=\$subs expected=\$EXP missing=[\$miss ]"
done
wait
echo STORM_DONE
EOF
}

pids=()
for r in $(seq 1 "$N"); do
    ( timeout $(( ROUNDS * SLOT + 240 )) "$SSH" "test$r" \
        "mkdir -p '$BASE'; bash -s $r" <<<"$(storm_body)" \
        > "$OUT/storm_test$r.log" 2>&1 ) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done

# A node whose storm did not COMPLETE never created its subdirectories, and no
# verifier can tell that from a durably lost dirent.  Assert it here so an
# infrastructure failure is never reported as data loss.
absent=""
for r in $(seq 1 "$N"); do
    grep -q STORM_DONE "$OUT/storm_test$r.log" 2>/dev/null || absent="$absent test$r"
done
if [ -n "$absent" ]; then
    echo "=== sf_mkdir_storm INFRA-FAIL: storm did not complete on:$absent ==="
    echo "    (not a data-loss verdict — these nodes never ran their mkdirs)"
    echo "    logs: $OUT"
    exit 2
fi

# ── SETTLED CENSUS ────────────────────────────────────────────────────────────
# The in-run oracle checks round K-2 at the top of round K.  That is deliberate
# (it catches a loss in the round it happened, before teardown can remove the
# evidence) but it CANNOT distinguish a durable loss from a name that simply has
# not become visible on this node yet.  Re-ask, on every node, after everything
# has quiesced: which of the flagged rounds are still wrong?  Anything still
# wrong here is durable; anything now correct was a visibility lag, not a loss.
#
# ccloop c7ee71c6 sess22 — THIS CENSUS NOW CARRIES THE VERDICT.
#
# It did not, and that produced a FALSE PASS on a run that had really lost
# four dirents: run sfstorm_20260729_003736 printed
#     32 SETTLED 32 STILL-WRONG nlink=33 visible=31 missing=[ node31_1 ]
#     32 SETTLED 46 STILL-WRONG nlink=33 visible=31 missing=[ node29_1 ]
#     32 SETTLED 48 STILL-WRONG nlink=33 visible=31 missing=[ node14_1 ]
#     32 SETTLED 51 STILL-WRONG nlink=33 visible=31 missing=[ node16_1 ]
# on ALL 32 nodes and then exited 0, because the verdict read only the
# node-side DURABLE-FAIL lines — and every one of those rounds had been
# classified "UNRESOLVED (teardown target)" node-side, so none of them existed.
# A board that can print the loss and still say PASS is worse than no board.
#
# The reason the node side abstains is real: a concurrent `rm -rf` walks
# children and nlink down together, so mid-teardown a round is indistinguishable
# from a loss by a single snapshot.  The fix is not to abstain, it is to take
# TWO snapshots separated by a quiet interval and convict only on a signature
# that is IDENTICAL in both.  A teardown in flight cannot be stable — it is
# actively removing entries, so the second look differs (or the directory is
# gone).  A durable loss does not move.  That discriminates the two without
# throwing away half the rounds, and it needs no heuristic about how many names
# "look like" a teardown.
census_pass() {   # $1 = output suffix
    local sfx="$1" r
    for r in $(seq 1 "$N"); do
        ( timeout 90 "$SSH" "test$r" "
            sync
            for K in $flagged; do
                d='$BASE'/d\$K
                [ -d \"\$d\" ] || { echo \"ROUND \$K GONE\"; continue; }
                nl=\$(stat -c %h \"\$d\" 2>/dev/null)
                names=\" \$(ls -1 \"\$d\" 2>/dev/null | tr '\n' ' ')\"
                subs=\$(echo \$names | wc -w)
                miss=''
                for i in \$(seq 1 $N); do
                  for m in \$(seq 1 $M); do
                    case \"\$names\" in *\" node\${i}_\$m \"*) ;; *) miss=\"\$miss node\${i}_\$m\" ;; esac
                  done
                done
                if [ \"\$subs\" != \"\$(( nl - 2 ))\" ] || [ -n \"\$miss\" ]; then
                    echo \"SETTLED \$K STILL-WRONG nlink=\$nl visible=\$subs missing=[\$miss ]\"
                else
                    echo \"SETTLED \$K OK nlink=\$nl visible=\$subs\"
                fi
            done" > "$OUT/${sfx}_test$r.log" 2>&1 ) &
    done
    wait
}

stable_bad=""
flagged=$(grep -h "FAIL" "$OUT"/storm_test*.log 2>/dev/null | \
          sed -n 's/^ROUND \([0-9]*\) FAIL.*/\1/p' | sort -un | tr '\n' ' ')
if [ -n "$flagged" ]; then
    echo "--- settled census (rounds flagged in-run: $flagged) ---"
    census_pass settled
    sleep 8
    census_pass settled2
    sc_bad=$(grep -h "STILL-WRONG" "$OUT"/settled_test*.log 2>/dev/null | \
             sed -n 's/^SETTLED \([0-9]*\) .*/\1/p' | sort -un | tr '\n' ' ')
    sc_gone=$(grep -hc "GONE" "$OUT"/settled_test*.log 2>/dev/null | awk '{s+=$1} END{print s+0}')
    echo "  WRONG AFTER SETTLING (pass 1): ${sc_bad:-<none>}"
    echo "  (rounds already torn down / not present: $sc_gone node-checks)"
    grep -h "STILL-WRONG" "$OUT"/settled_test*.log 2>/dev/null | sort | uniq -c | sort -rn | head -6

    # Convict only signatures present and IDENTICAL in both passes.  Comparing
    # the whole line (nlink, visible count AND the exact missing set) is what
    # makes this a stability test rather than a second coin toss.
    #
    # ...and never convict a round rank 1 actually removed.  Stability alone is
    # not enough: a `rm -rf` that STALLED (the lost-nlink ENOTEMPTY loop) leaves
    # a stable, partially-emptied directory that looks exactly like a mass loss.
    # rank 1 logs the round number of every teardown it started, so the
    # exclusion is the exact set rather than an inference from the damage.
    torn=$(sed -n 's/^TEARDOWN \([0-9]*\)$/\1/p' "$OUT/storm_test1.log" 2>/dev/null | sort -un | tr '\n' ' ')
    echo "  rounds rank1 tore down (never convictable): ${torn:-<none>}"

    #
    # sess22: A REPORTED mkdir FAILURE IS NOT SILENT LOSS.
    #
    # The entire defect class this harness exists for is defined by mkdir(2)
    # returning SUCCESS while the entry exists nowhere.  A name whose creator
    # got a nonzero rc is the honest failure mode — a different (possibly also
    # real) problem, but never this one, and counting it here manufactures a red
    # that sends the next session chasing a phantom.
    #
    # It bit immediately: run sfstorm_20260729_034002 reported 27 "durable"
    # rounds with EVERY mechanism marker clean (p32e=0 p177=0 p188=0).  The
    # missing names were just node20_1 (690 checks) and node31_1 (630) — two
    # nodes that had logged 55 `MKDIR-RC rc=1` lines between them after a peer
    # was power-cycled mid-series.  Not loss; reported failure.
    #
    # So: build the set of names whose own creator reported a failure, and
    # refuse to convict a round whose missing set is covered by it.  The rc
    # lines are still surfaced below, because a run that starts returning
    # errors is itself a finding.
    nerr=$(grep -hc '^MKDIR-RC' "$OUT"/storm_test*.log 2>/dev/null | awk '{s+=$1} END{print s+0}')
    if [ "$nerr" -gt 0 ]; then
        echo "  !! $nerr mkdir(2) calls RETURNED AN ERROR this run — those are reported"
        echo "     failures, not silent loss.  Rounds whose missing names are all"
        echo "     error-reported are excluded from conviction:"
        grep -h '^MKDIR-RC' "$OUT"/storm_test*.log 2>/dev/null | sort | uniq -c |
            sort -rn | head -5 | sed 's/^/       /'
    fi
    # Per-name exclusion: nodeR_m is excluded for round K iff test$R logged a
    # failure for exactly that (K, m).
    errpairs=""
    for r in $(seq 1 "$N"); do
        [ -s "$OUT/storm_test$r.log" ] || continue
        while IFS= read -r el; do
            ek=$(printf '%s\n' "$el" | sed -n 's/^MKDIR-RC K=\([0-9]*\) m=\([0-9]*\) .*/\1/p')
            em=$(printf '%s\n' "$el" | sed -n 's/^MKDIR-RC K=\([0-9]*\) m=\([0-9]*\) .*/\2/p')
            [ -n "$ek" ] && errpairs="$errpairs ${ek}:node${r}_${em}"
        done < <(grep '^MKDIR-RC' "$OUT/storm_test$r.log" 2>/dev/null)
    done
    for r in $(seq 1 "$N"); do
        [ -s "$OUT/settled_test$r.log" ] || continue
        [ -s "$OUT/settled2_test$r.log" ] || continue
        while IFS= read -r line; do
            case "$line" in *STILL-WRONG*) ;; *) continue ;; esac
            if grep -qxF "$line" "$OUT/settled2_test$r.log"; then
                k=$(printf '%s\n' "$line" | sed -n 's/^SETTLED \([0-9]*\) .*/\1/p')
                case " $torn " in *" $k "*) continue ;; esac
                # Every missing name whose own creator reported a failure is
                # not evidence of silent loss.  If that accounts for ALL of
                # them, the round is not convictable.
                mset=$(printf '%s\n' "$line" | sed 's/.*missing=\[//; s/ \]$//')
                # No missing names but still STILL-WRONG == the link count
                # disagrees with the entries.  That is a defect in its own
                # right (a lost or double-counted nlink bump) and has no
                # mkdir-rc explanation, so it always convicts.
                real=0
                [ -z "$(printf '%s' "$mset" | tr -d ' ')" ] && real=1
                for nm in $mset; do
                    case " $errpairs " in
                        *" ${k}:${nm} "*) ;;
                        *) real=1 ;;
                    esac
                done
                [ "$real" = 1 ] || continue
                case " $stable_bad " in *" $k "*) ;; *) stable_bad="$stable_bad $k" ;; esac
            fi
        done < "$OUT/settled_test$r.log"
    done
    stable_bad=$(printf '%s\n' $stable_bad | sort -un | tr '\n' ' ')
    echo "  DURABLE (identical in both census passes, ${SETTLE_GAP:-8}s apart): ${stable_bad:-<none>}"
    if [ -n "$stable_bad" ]; then
        grep -h "STILL-WRONG" "$OUT"/settled2_test*.log 2>/dev/null | sort | uniq -c | sort -rn | head -8
    fi
fi

# The verdict is DURABLE-FAIL only.  A bare "ROUND n FAIL" is the first sighting
# and is frequently just visibility lag (measured: 70 in-run flags, 0 durable);
# recheck_pending retires those as LATE-OK.  Report both so the leading
# indicator stays visible, but fail the run on durable loss.
badrounds=$(grep -h "DURABLE-FAIL" "$OUT"/storm_test*.log 2>/dev/null | \
            sed -n 's/^ROUND \([0-9]*\) DURABLE-FAIL.*/\1/p' | sort -un | tr '\n' ' ')
# sess22: the host-side settled census OUTRANKS the node side, in BOTH
# directions.  It runs after everything has quiesced, twice, 8 s apart, on every
# node — strictly better evidence than a single in-run snapshot.
#
#   * A round the node side DECLINED to judge (teardown target) but which the
#     census finds still short a name, identically in both passes, IS a durable
#     loss.  Without this the harness printed four losses and exited 0.
#   * A round the node side convicted but which the census finds CLEAN on every
#     node is NOT a loss.  The node side re-checks a flagged round on each later
#     round, so the LAST round gets almost no re-checks and dies DURABLE-FAIL on
#     mere visibility lag.  Measured: sfstorm_20260729_132342 reported "ROUND 20
#     DURABLE-FAIL ... missing=[ node20_1 ]" on 4 nodes while the settled census
#     found ZERO rounds wrong — the entry had landed, the final check was just
#     too early.  Convicting on that sends the next session chasing a phantom.
if [ -n "$flagged" ]; then
    kept=""
    for k in $badrounds; do
        # Clean in census pass 2 on every node that reported => not a loss.
        if grep -h "^SETTLED $k " "$OUT"/settled2_test*.log 2>/dev/null | grep -q "STILL-WRONG"; then
            kept="$kept $k"
        else
            echo "  round $k: node-side DURABLE-FAIL but the settled census finds it CLEAN on every node — visibility lag at the final check, not a loss"
        fi
    done
    badrounds="$kept"
fi
badrounds=$(printf '%s\n' $badrounds $stable_bad | sed '/^$/d' | sort -un | tr '\n' ' ')
nfail=$(grep -hc "DURABLE-FAIL" "$OUT"/storm_test*.log 2>/dev/null | awk '{s+=$1} END{print s+0}')
seen=$(grep -h "^ROUND [0-9]* FAIL" "$OUT"/storm_test*.log 2>/dev/null | \
       sed -n 's/^ROUND \([0-9]*\) FAIL.*/\1/p' | sort -un | tr '\n' ' ')
lateok=$(grep -hc "LATE-OK" "$OUT"/storm_test*.log 2>/dev/null | awk '{s+=$1} END{print s+0}')
echo "--- storm complete on all $N nodes ---"
echo "  first-sighting flags (may be visibility lag): ${seen:-<none>}"
echo "  retired as LATE-OK: $lateok node-checks"
if [ -n "$badrounds" ]; then
    echo "  DURABLY FAILING ROUNDS: $badrounds"
    grep -h "DURABLE-FAIL" "$OUT"/storm_test*.log 2>/dev/null | sort | uniq -c | sort -rn | head -12
fi

echo "--- marker census ---"
MARKERS="P178-REBASE-OLDER-DISK P179-REBASE-CORE-TEAR P3-REFUSE-OLDER-DISK P-SFDIR-REVERT P174-STALEGEN-ADOPT P21-RB"
for r in $(seq 1 "$N"); do
    ( timeout 40 "$SSH" "test$r" \
        "for m in $MARKERS; do echo \"\$m \$(dmesg | grep -c -- \"\$m\")\"; done" \
        > "$OUT/markers_test$r.log" 2>&1 ) &
done
wait
for m in $MARKERS; do
    tot=$(grep -h "^$m " "$OUT"/markers_test*.log 2>/dev/null | awk '{s+=$2} END{print s+0}')
    echo "  $m: $tot"
done

if [ -n "$badrounds" ]; then
    ncensus=$(grep -hc "STILL-WRONG" "$OUT"/settled2_test*.log 2>/dev/null | awk '{s+=$1} END{print s+0}')
    echo "=== sf_mkdir_storm FAIL: node-side DURABLE-FAIL=$nfail, settled-census stable losses=$ncensus (rounds: $badrounds) ==="
    for r in $(seq 1 "$N"); do
        ( timeout 60 "$SSH" "test$r" "dmesg" > "$OUT/dmesg_test$r.log" 2>&1 ) &
    done
    wait
    echo "    evidence: $OUT"
    exit 1
fi
echo "=== sf_mkdir_storm PASS: $ROUNDS rounds consistent on all $N nodes ==="
echo "    logs: $OUT"
exit 0
