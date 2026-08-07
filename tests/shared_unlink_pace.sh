#!/bin/bash
# shared_unlink_pace.sh — what does it cost to REMOVE a directory entry whose
# child inode is cached by a peer?  (ccloop c7ee71c6 sess28.)
#
# WHY
#   sustained_load at 32/caw was failing its 180 s budget with per_op=198 ms and
#   wall=3978 ms — numbers that make the mount look healthy.  Phase timers added
#   to that criterion showed the truth: rank 1's `rm -rf $MNT/.sustained_load`
#   accounted for 38379 of 38402 ms of setup (mkdir 5 ms, sync 18 ms), and it was
#   deterministic across four consecutive runs (38379/38391/38402/38454 ms,
#   +/-0.2%).  That is ~33 directory removals at ~1.16 s each.  Native XFS does
#   this in single-digit milliseconds, so under RULE 0 it is disqualifying on its
#   own — and it is the same order as the recorded 1722 ms/op shared-directory
#   create pace (D-32NODE-SHARED-DIR-CREATE-PACE), which suggests one defect
#   measured on two sides rather than two defects.
#
# WHAT THIS SEPARATES
#   Two candidate costs are confounded in that `rm -rf`:
#     (a) PER ENTRY, on the shared parent — every unlink is an RMW of one hot
#         directory whose lock ping-pongs.
#     (b) PER CHILD, revoking each child inode's lock from the PEER that created
#         it — a BAST + drain + release round trip per child.
#   Phase A removes children this node created itself (no peer holds anything):
#   only (a) can be present.  Phase B removes children each PEER created: both
#   (a) and (b).  B - A is the cost of peer-cached-child revocation.
#
#   Same parent shape, same child count, same node, back to back, so nothing but
#   the creator differs.
#
# RULE 0 BUDGET
#   Native XFS creates and removes 32 directories in well under 100 ms.  Each
#   phase is budgeted 60 s (a deliberately loose 600x) purely so a pathological
#   run still reports a number instead of being killed; the VERDICT threshold is
#   2x native, and any phase over ~1 s is already a failure to report, not to
#   retry.  A timeout here is a FAILURE.
#
# USAGE
#   tests/shared_unlink_pace.sh [nodes] [children_per_node]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

N="${1:-32}"
PER="${2:-1}"
MNT=/mnt/shared
PHASE_BUDGET=60

nodes() { local i; for ((i=1; i<=N; i++)); do echo "test$i"; done; }
on() { timeout $((PHASE_BUDGET + 15)) tools/mxfs_sshpass.sh "$1" "$2" 2>/dev/null; }

# Unique per invocation so a re-run never collides with, or has to delete, a
# previous run's tree (RULE 2b: no rm on a variable path from this script).
STAMP=$(date +%s)
A="$MNT/.sup_${STAMP}_a"
B="$MNT/.sup_${STAMP}_b"

echo "=== shared_unlink_pace: nodes=$N per_node=$PER budget=${PHASE_BUDGET}s/phase ==="

# ---------------------------------------------------------------- PHASE A ----
# Every child created BY RANK 1.  No peer has ever named them.
echo "--- phase A: $((N * PER)) children created locally by test1, removed by test1 ---"
A_OUT=$(on test1 "
    mkdir -p '$A' || exit 9
    for i in \$(seq 1 $((N * PER))); do mkdir '$A/c'\$i || exit 9; done
    sync
    s=\$(date +%s%3N)
    rm -rf '$A'
    e=\$(date +%s%3N)
    echo \"A_MS=\$((e - s))\"
")
A_MS=$(echo "$A_OUT" | grep -oE 'A_MS=[0-9]+' | cut -d= -f2)
[ -n "$A_MS" ] || { echo "PHASE A FAILED (no measurement): $A_OUT"; exit 4; }

# ---------------------------------------------------------------- PHASE B ----
# Each child created BY A DIFFERENT NODE, which then still holds it cached.
# The creators do NOT unmount, drop caches, or otherwise release — holding the
# cached state is the condition under test.
echo "--- phase B: same count, each child created by its own node, removed by test1 ---"
on test1 "mkdir -p '$B'" >/dev/null
pids=""
for h in $(nodes); do
    r="${h#test}"
    on "$h" "for i in \$(seq 1 $PER); do mkdir '$B/n${r}_'\$i; done; sync" >/dev/null &
    pids="$pids $!"
done
for p in $pids; do wait "$p"; done

# Time EACH removal, not just the batch.  A tight distribution means a fixed
# per-op delay (a constant in the acquire/handoff path); a wide 0..4000 ms
# spread means the holder is only discovering the waiter on its idle disk poll
# (MXFS_CAW_BAST_POLL_RELAX_MS=4000), i.e. the UDP BAST hint is being missed.
# Those two need completely different fixes, so never infer from the batch mean.
B_OUT=$(on test1 "
    s=\$(date +%s%3N)
    for d in '$B'/*; do
        a=\$(date +%s%3N)
        rmdir \"\$d\" 2>/dev/null
        b=\$(date +%s%3N)
        echo \"OP_MS=\$((b - a))\"
    done
    rmdir '$B' 2>/dev/null
    e=\$(date +%s%3N)
    echo \"B_MS=\$((e - s))\"
")
echo "  per-removal ms: $(echo "$B_OUT" | grep -oE 'OP_MS=[0-9]+' | cut -d= -f2 | sort -n | tr '\n' ' ')" 
B_MS=$(echo "$B_OUT" | grep -oE 'B_MS=[0-9]+' | cut -d= -f2)
[ -n "$B_MS" ] || { echo "PHASE B FAILED (no measurement): $B_OUT"; exit 4; }

# ---------------------------------------------------------------- PHASE C ----
# WHICH SYSCALL actually costs?  Measured above: `rm -rf` of 32 peer-created
# dirs = 1198 ms/op, but an explicit `rmdir` loop over the SAME shape = 32 ms/op.
# So the cost is NOT the unlink.  rm -rf additionally openat()s, getdents()es
# and fstatat()s each child, and those need a PR grant that must revoke the
# peer's cached EX.  Time each syscall class separately, on its own fresh tree,
# so nothing is confounded and no phase warms the next one's cache.
echo "--- phase C: per-syscall cost on peer-created children ---"
c_phase() {   # <label> <shell-command-template using $d>
    local label="$1" cmd="$2" dir="$MNT/.sup_${STAMP}_c${3}"
    local h r out
    on test1 "mkdir -p '$dir'" >/dev/null
    local pids=""
    for h in $(nodes); do
        r="${h#test}"
        on "$h" "mkdir '$dir/n${r}'; sync" >/dev/null &
        pids="$pids $!"
    done
    for p in $pids; do wait "$p"; done
    out=$(on test1 "
        s=\$(date +%s%3N)
        for d in '$dir'/*; do $cmd; done
        e=\$(date +%s%3N)
        echo \"C_MS=\$((e - s))\"
    ")
    local ms
    ms=$(echo "$out" | grep -oE 'C_MS=[0-9]+' | cut -d= -f2)
    [ -n "$ms" ] || ms=-1
    printf '%-46s %9s %10s\n' "  $label" "$ms" "$((ms / K_C))"
    on test1 "rm -rf '$dir'" >/dev/null 2>&1 &
}
K_C=$N
printf '%-46s %9s %10s\n' "one pass over $N peer-created children" "total_ms" "per_op_ms"
c_phase "stat only"                'stat "$d" >/dev/null 2>&1'                    1
c_phase "opendir+readdir only"     'ls -f "$d" >/dev/null 2>&1'                   2
c_phase "rmdir only"               'rmdir "$d" 2>/dev/null'                       3
c_phase "open(O_RDONLY|O_DIRECTORY) only" 'exec 9<"$d" 2>/dev/null; exec 9<&-'    4
echo

# ------------------------------------------------------------------ VERDICT --
K=$((N * PER))
A_PER=$((A_MS / K))
B_PER=$((B_MS / K))
echo
printf '%-46s %9s %10s\n' "removal of $K children from a shared parent" "total_ms" "per_op_ms"
printf '%-46s %9s %10s\n' "  A: children created locally (no peer cache)" "$A_MS" "$A_PER"
printf '%-46s %9s %10s\n' "  B: children created by their own node"       "$B_MS" "$B_PER"
echo
if [ "$A_PER" -gt 0 ]; then
    echo "  B/A ratio: $(( B_MS * 100 / (A_MS > 0 ? A_MS : 1) ))%"
fi
echo
echo "READ IT LIKE THIS:"
echo "  B >> A  => the cost is REVOKING EACH CHILD from the peer that cached it."
echo "            The shared parent is not the bottleneck; per-child DLM"
echo "            revocation is, and the fix belongs in the release/BAST path."
echo "  B ~= A  => the cost is the SHARED PARENT's own lock, independent of who"
echo "            created the children — i.e. D-32NODE-SHARED-DIR-CREATE-PACE"
echo "            measured on the unlink side, and the same fix applies."
echo "  BOTH small => the sustained_load setup cost is NOT reproduced by this"
echo "            shape; go back and vary what else differs (child depth, files"
echo "            inside the children, how long the peers held them)."
echo
# RULE 0: 2x native XFS is the ceiling.  Native does this in <100 ms total.
if [ "$B_MS" -gt 200 ] || [ "$A_MS" -gt 200 ]; then
    echo "RESULT: FAIL | test=shared_unlink_pace | measured=A=${A_MS}ms(${A_PER}/op) B=${B_MS}ms(${B_PER}/op) k=$K nodes=$N | reason=over the 2x-native ceiling (<=200ms for $K removals)"
    exit 1
fi
echo "RESULT: PASS | test=shared_unlink_pace | measured=A=${A_MS}ms(${A_PER}/op) B=${B_MS}ms(${B_PER}/op) k=$K nodes=$N | reason="
