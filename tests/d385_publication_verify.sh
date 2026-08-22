#!/bin/bash
# d385_publication_verify.sh — the CLOSING RUN for
#   D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN  (and its symptom #361,
#   D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361)
#
# sess385 proved the root cause and landed the fix, but did NOT close the
# defect: the fixed arm published only 8 unlinked-list heads against the
# control arm's 167, which is nowhere near enough exposure to satisfy RULE 6
# ("testing that exercises the cause passes cleanly").  This script is that
# missing run, so nobody has to re-derive the protocol.
#
# WHAT IT DOES
#   Runs the same unlink-heavy chunk N times per arm, with the fix OFF
#   (control) and ON (treatment), on ONE build, using the module param —
#   no rebuild, no srcversion skew between arms.  Then it counts, per arm:
#     heads      published AGI unlinked-list heads   (the EXPOSURE)
#     joint_ok   head whose home dinode reads UNLINKED  (correct)
#     REPAIRED   split caught and fixed before unlock   (P87 Part D)
#     SPLIT      split we knew about and could NOT fix  (OUR BUG)
#     BADHEAD    head reading LINKED that we never had in core
#
# THE BAR (all must hold on the treatment arm):
#   * heads >= MIN_HEADS                    -- the cause was actually exercised
#   * SPLIT == 0
#   * no P217-RENAME-DIRTYCANCEL, no "Corruption of in-memory data (0x8)"
#   * every test row PASS
# BADHEAD is NOT part of the bar: by construction we cannot repair a head
# another node published, so it only reaches zero once the fix is fleet-wide.
#
# RULE 0: budgets are derived from MEASURED walls, never padded.  Re-derive
# them from `./showstat.sh 32 caw` if the rig's numbers move; do not pad.
#
# RULE 2c: no `pgrep -f`, no unbounded ssh; every remote call is bounded and
# captures its own per-node rc and output.
#
# Usage: tests/d385_publication_verify.sh [laps_per_arm] [nodes]
#
# STEPWISE MODE (for callers bounded to <10min foreground calls, e.g. a
# ccloop session obeying the sess47 foreground directive): set D385_OUT to a
# persistent dir and D385_STEP to one of
#     arm_prep <CONTROL|TREATMENT>     (~120s: re-prep + knobs + dmesg -C)
#     arm_lap  <CONTROL|TREATMENT> <n> (~CHUNK_TIMEOUT s: one chunk lap)
#     arm_collect <CONTROL|TREATMENT>  (~30s: fleet dmesg harvest + tally)
#     verdict                          (instant: reads TREATMENT harvest)
# Run the steps in order; state lives only in $D385_OUT. With D385_STEP unset
# the script runs the whole protocol in one invocation, exactly as before.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

LAPS="${1:-3}"
N="${2:-32}"
DLM=caw
MIN_HEADS="${MIN_HEADS:-100}"
SSH=tools/mxfs_sshpass.sh

# Unlink-heavy rows: rename-over-existing (rsync_paired) + open-unlink
# (posix_multi) + directory churn (dir_reuse_coherency, dirent_durability).
# Measured walls 2026-08-20: 9 + 23 + 103 + 66 = 201s.
# budget = 201 + 12s*4 rows + 15s startup = 264 -> 280s of headroom for jitter
# in the ROW walls only (never widen this to make a run pass; a row that
# overruns its own manifest budget is already a FAIL inside run.sh).
CHUNK=(posix_multi rsync_paired dir_reuse_coherency dirent_durability)
CHUNK_TIMEOUT="${CHUNK_TIMEOUT:-280}"
PREP_TIMEOUT="${PREP_TIMEOUT:-320}"

OUT="${D385_OUT:-$(mktemp -d)}"
mkdir -p "$OUT"
echo "=== d385 publication verify: ${LAPS} lap(s)/arm, ${N}/${DLM}, out=$OUT ==="

fleet() {   # fleet <bounded_secs> <remote command>   -- per-node rc + output
    local tt="$1"; shift
    local d; d=$(mktemp -d)
    local i
    for i in $(seq 1 "$N"); do
        (
            rc=0
            timeout "$tt" "$SSH" "test$i" "$*" > "$d/n$i.raw" 2>&1 || rc=$?
            printf '%s\n' "$rc" > "$d/n$i.rc"
            grep -avE '^Warning:|^Unauthorized|^If you' "$d/n$i.raw" \
                | sed "s/^/test$i /" > "$d/n$i.out"
        ) &
    done
    wait
    cat "$d"/n*.out 2>/dev/null
    local bad=0
    for i in $(seq 1 "$N"); do
        [ "$(cat "$d/n$i.rc" 2>/dev/null)" = "0" ] || bad=$((bad+1))
    done
    [ "$bad" -gt 0 ] && echo "  (WARN: $bad/$N node(s) returned non-zero)" >&2
    return 0
}

tally() {   # tally <dmesg-file> <arm-label>
    python3 - "$1" "$2" <<'PY'
import re, sys
f, arm = sys.argv[1], sys.argv[2]
tot = {}
# P86-AGI-PUBLISH-TOTALS is a per-node RUNNING total, rate-limited to 1/30s.
# Take the LAST line per node -- summing successive totals would double count.
last = {}
for L in open(f, errors='replace'):
    if 'P86-AGI-PUBLISH-TOTALS' in L:
        node = L.split()[0]
        last[node] = {k: int(v) for k, v in re.findall(
            r'(heads|joint_ok|REPAIRED|SPLIT|BADHEAD)=(\d+)', L)}
for d in last.values():
    for k, v in d.items():
        tot[k] = tot.get(k, 0) + v
def count(pat):
    return sum(1 for L in open(f, errors='replace') if pat in L)
print("ARM %s: %s" % (arm, tot if tot else "(no P86 totals -- was mxfs.agi_publish_audit=1?)"))
print("  per-head SPLIT warns : %d" % count('P86-AGI-UNLINKED-PUBLISH'))
print("  BADHEAD warns        : %d" % count('P86-AGI-UNLINKED-BADHEAD'))
print("  P87 repairs          : %d" % count('P87-PUBLISH-REPAIRED'))
print("  P87 refusals         : %d" % count('P87-PUBLISH-REFUSED'))
print("  rename dirty-cancels : %d" % count('P217-RENAME-DIRTYCANCEL'))
print("  in-memory corruption : %d" % count('Corruption of in-memory data'))
print("  fs shutdowns         : %d" % count('Shutting down filesystem'))
PY
}

arm_knob() {  # CONTROL -> 0, TREATMENT -> 1
    case "$1" in
        CONTROL) echo 0 ;;
        TREATMENT) echo 1 ;;
        *) echo "unknown arm '$1' (want CONTROL|TREATMENT)" >&2; return 2 ;;
    esac
}

arm_prep() {  # arm_prep <label> -- re-prep + probes + knob + dmesg -C
    local arm="$1" knob
    knob=$(arm_knob "$arm") || exit 2
    echo
    echo "--- ARM $arm (publish_inodes=$knob) ---"
    timeout "$PREP_TIMEOUT" ./run.sh "$N" "$DLM" prep_cluster \
        > "$OUT/prep.$arm.log" 2>&1
    echo "  prep rc=$? : $(tail -1 "$OUT/prep.$arm.log")"

    # Probes ON, fix knob per arm, dmesg cleared so the tally sees THIS arm only
    # (prep_cluster does NOT clear it -- mixing arms silently corrupts the counts).
    fleet 20 "echo $knob > /sys/module/mxfs/parameters/publish_inodes;
              echo 1 > /sys/module/mxfs/parameters/agi_publish_audit;
              echo 1 > /sys/module/mxfs/parameters/inode_drain_probe;
              dmesg -C" > /dev/null
}

arm_lap() {  # arm_lap <label> <lapno>
    local arm="$1" lap="$2"
    timeout "$CHUNK_TIMEOUT" ./run.sh "$N" "$DLM" "${CHUNK[@]}" \
        > "$OUT/lap.$arm.$lap.log" 2>&1
    echo "  lap $lap rc=$? : $(grep -cE '^  PASS' "$OUT/lap.$arm.$lap.log") PASS, $(grep -cE '^  FAIL' "$OUT/lap.$arm.$lap.log") FAIL"
    grep -E '^  FAIL' "$OUT/lap.$arm.$lap.log" | sed 's/^/      /'
}

arm_collect() {  # arm_collect <label>
    local arm="$1"
    fleet 25 "dmesg | grep -aE 'P86-AGI|P87-|P217-RENAME|Corruption of in-memory|Shutting down filesystem'" \
        > "$OUT/dmesg.$arm.txt"
    tally "$OUT/dmesg.$arm.txt" "$arm"
}

run_arm() {  # run_arm <label>
    local arm="$1" lap
    arm_prep "$arm"
    for lap in $(seq 1 "$LAPS"); do arm_lap "$arm" "$lap"; done
    arm_collect "$arm"
}

verdict_step() {
echo
echo "=== VERDICT ==="
python3 - "$OUT/dmesg.TREATMENT.txt" "$MIN_HEADS" <<'PY'
import re, sys
f, min_heads = sys.argv[1], int(sys.argv[2])
last = {}
for L in open(f, errors='replace'):
    if 'P86-AGI-PUBLISH-TOTALS' in L:
        last[L.split()[0]] = {k: int(v) for k, v in re.findall(
            r'(heads|joint_ok|REPAIRED|SPLIT|BADHEAD)=(\d+)', L)}
tot = {}
for d in last.values():
    for k, v in d.items():
        tot[k] = tot.get(k, 0) + v
heads = tot.get('heads', 0)
split = tot.get('SPLIT', 0)
dirty = sum(1 for L in open(f, errors='replace') if 'P217-RENAME-DIRTYCANCEL' in L)
corr  = sum(1 for L in open(f, errors='replace') if 'Corruption of in-memory data' in L)
fails = []
if heads < min_heads:
    fails.append("EXPOSURE TOO LOW: %d heads < %d -- the cause was not exercised "
                 "enough to conclude anything. Raise laps or pick a heavier "
                 "workload; do NOT lower the bar." % (heads, min_heads))
if split:  fails.append("SPLIT=%d -- unrepaired split publications remain" % split)
if dirty:  fails.append("P217-RENAME-DIRTYCANCEL x%d" % dirty)
if corr:   fails.append("in-memory corruption shutdown x%d" % corr)
if fails:
    print("NOT CLOSED. RULE 6 keeps this defect OPEN:")
    for x in fails: print("  - " + x)
    sys.exit(1)
print("Treatment arm: heads=%d joint_ok=%d REPAIRED=%d SPLIT=0 BADHEAD=%d"
      % (heads, tot.get('joint_ok', 0), tot.get('REPAIRED', 0), tot.get('BADHEAD', 0)))
print("Cause exercised at %d heads with zero unrepaired splits." % heads)
print("BADHEAD is informational: a head another node published cannot be "
      "repaired here, so it only reaches 0 once the fix is fleet-wide.")
print("STILL REQUIRED before closing: a full 28-row board at 32/caw.")
PY
}

if [ -n "${D385_STEP:-}" ]; then
    # Stepwise mode: one bounded step per invocation, state in $D385_OUT.
    [ -n "${D385_OUT:-}" ] || { echo "D385_STEP requires D385_OUT (persistent dir)" >&2; exit 2; }
    # shellcheck disable=SC2086 -- word-split the step spec deliberately
    set -- $D385_STEP
    case "$1" in
        arm_prep)    arm_prep "$2" ;;
        arm_lap)     arm_lap "$2" "$3" ;;
        arm_collect) arm_collect "$2" ;;
        verdict)     verdict_step ;;
        *) echo "unknown D385_STEP '$D385_STEP'" >&2; exit 2 ;;
    esac
    exit $?
fi

run_arm CONTROL
run_arm TREATMENT
verdict_step
echo
echo "evidence: $OUT"
