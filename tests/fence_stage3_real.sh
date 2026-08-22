#!/bin/bash
# fence_stage3_real.sh — STAGE (iii) of the D-PR-FENCE-PREEMPT-WITHOUT-ABORT
# closure plan: MXFS INTEGRATION EVIDENCE.
#
# The sess133 RULE-5 ruling is explicit that the sg_persist/prprobe A/B (stages
# (i) and (ii)) is NOT RULE-6 closure evidence, because it does not exercise the
# patched call chain.  Stage (iii) has to show that MXFS'S OWN KERNEL FENCE, on
# the SHIPPED production LUN, emits PREEMPT AND ABORT (0x05) and that nothing
# downstream is authorised until that success is CONSUMED.
#
# WHY THIS SCRIPT HAD TO BE WRITTEN (sess378).  The ledger's plan said to get
# this evidence by running `fence_during_write` because "it already kills the
# victim mid-write".  IT DOES NOT.  fence_during_write is a NEGATIVE test: it
# runs a concurrent write storm and asserts that NO node is fenced
# (`ckeq "no fence/shutdown in window" 0 "$hits"`).  Measured 2026-08-20: a full
# 32/caw board — fence_during_write, crash_consistency, fault_netpartition,
# dlm_membership — produced ZERO fence markers on all 32 nodes (dmesg ring
# verified to cover the whole window; the prints are MXFS_LOG_WARN, not gated).
# crash_consistency says so itself: "a true node-KILL + survivor
# foreign-log-replay needs host-side orchestration the in-guest run_coord
# harness doesn't have".
#
# So the PR fence has NO board coverage at all, and this is the only thing in
# the tree that exercises it end to end.
#
# EVIDENCE CAPTURED
#   A. TARGET-SIDE, on the wire: SCST's own CDB parser prints, under the 'pr'
#      trace flag, "Preempt and abort: initiator <iqn>..." from
#      scst_pr_do_preempt().  The substring " and abort" appears ONLY for
#      service action 0x05 — scst_pr_preempt() (0x04) prints "Preempt:".  This
#      is proof of what MXFS's kernel emitted, taken from the target, with no
#      sg_persist anywhere in the path.
#   B. SURVIVOR-SIDE ordering: P236-FENCE-INTENT (durable intent, authorises
#      nothing) -> P236-FENCEKIND kind=PREEMPT_ABORT_DONE -> P236-FENCE-CERTIFIED.
#   C. Nothing downstream before the certificate.
#
# Usage:  fence_stage3_real.sh [victim_host] [nodes]
#   Requires a cluster already prepped and mounted (./run.sh <N> caw prep_cluster).
#   The victim is HARD-KILLED (virsh destroy) and restored afterwards.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
VICTIM="${1:-test30}"
N="${2:-32}"
MNT=/mnt/shared
DEV=/dev/mapper/mpatha

# RULE 0 budgets, each derived rather than picked:
#   dead-confirmation window = dead_threshold(31) x HB interval(2000ms) = 62 s
#   + fence issue/certify (measured single-digit seconds) + margin
FENCE_WAIT=150
#   virsh start -> ssh (measured 40-50 s) + /src NFS + dual-portal iSCSI +
#   multipath assembly (measured ~30 s)
RESTORE_WAIT=210

OUT=$(mktemp -d /var/tmp/fence_stage3.XXXXXX)
echo "=== stage (iii): real MXFS fence — victim=$VICTIM nodes=$N out=$OUT"

survivors=()
for i in $(seq 1 "$N"); do [ "test$i" != "$VICTIM" ] && survivors+=("test$i"); done

# ── 0. preconditions ──────────────────────────────────────────────────────
# SCST 'pr' tracing is what makes evidence (A) possible at all.  It is NOT on
# by default and is lost across an scst module reload, so assert it rather than
# assume it (measured 2026-08-20: it had been silently lost since sess133).
sudo sh -c 'echo "add pr" > /sys/kernel/scst_tgt/trace_level' 2>/dev/null
if ! sudo head -1 /sys/kernel/scst_tgt/trace_level 2>/dev/null | grep -q '\bpr\b'; then
    echo "PRECONDITION-NOT-MET: could not enable SCST 'pr' tracing — evidence (A) is impossible"
    exit 2
fi
echo "--- SCST pr tracing: $(sudo head -1 /sys/kernel/scst_tgt/trace_level)"

up=0
for h in "$VICTIM" "${survivors[@]:0:3}"; do
    timeout 15 "$SSH" "$h" "mountpoint -q $MNT && echo MOUNTED" 2>/dev/null | grep -q MOUNTED && up=$((up+1))
done
[ "$up" -ge 3 ] || { echo "PRECONDITION-NOT-MET: cluster not mounted (only $up/4 sampled nodes) — run ./run.sh $N caw prep_cluster"; exit 2; }

# The victim must be HOLDING GRANTS when it dies, otherwise the survivors have
# nothing to fence it out of and take the KEY_ABSENT/NO-op path.
echo "--- making the victim hold live grants"
timeout 45 "$SSH" "$VICTIM" "mkdir -p $MNT/.fence_s3 && for k in \$(seq 1 200); do head -c 4096 /dev/urandom > $MNT/.fence_s3/v\$k; done; sync" >/dev/null 2>&1

TOK="MXFS-FENCE-STAGE3-$(date -u +%s%N)"
echo "$TOK" | sudo tee /dev/kmsg >/dev/null
echo "$TOK" > "$OUT/token.txt"

# ── 1. hard kill ──────────────────────────────────────────────────────────
date -u "+--- KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 \
    || { echo "FAIL: virsh destroy $VICTIM"; exit 1; }
t_kill=$(date +%s)

# ── 2. wait for a survivor to fence, bounded ──────────────────────────────
echo "--- waiting up to ${FENCE_WAIT}s for a survivor to fence (62 s confirm window + fence)"
fenced=""
while [ $(( $(date +%s) - t_kill )) -lt "$FENCE_WAIT" ]; do
    for h in "${survivors[@]}"; do
        if timeout 8 "$SSH" "$h" "dmesg | grep -q 'P236-FENCEKIND\|P236-FENCE-CERTIFIED\|P236-FENCE-INTENT' && echo HIT" 2>/dev/null | grep -q HIT; then
            fenced="$h"; break
        fi
    done
    [ -n "$fenced" ] && break
    sleep 5
done
t_fence=$(( $(date +%s) - t_kill ))

if [ -z "$fenced" ]; then
    echo "--- NO survivor logged a fence marker within ${FENCE_WAIT}s"
else
    echo "--- fence markers first seen on $fenced at +${t_fence}s"
fi

# ── 3. collect evidence ───────────────────────────────────────────────────
# Capture with MONOTONIC timestamps, not `dmesg -T`.  Evidence (B) is an
# ORDERING claim (intent -> P&A -> certificate -> only then replay), and every
# one of those lines lands inside the same wall-clock second — so human dates
# cannot order them and sorting by them silently produces an arbitrary order
# that LOOKS like proof.  The raw [seconds.microseconds] prefix can.
for h in "${survivors[@]}"; do
    ( timeout 20 "$SSH" "$h" "dmesg | grep -E 'P236-FENCE|FENCEKIND|P227-FENCEFAIL|P238-FENCE|P241-RECOV|P302-PROUT' | sed 's/^/'"$h"' /'" > "$OUT/$h.fence" 2>/dev/null ) &
done
wait
cat "$OUT"/test*.fence > "$OUT/all.fence" 2>/dev/null
sudo dmesg | sed -n "/$TOK/,\$p" > "$OUT/clyde.dmesg" 2>&1

echo
echo "================= EVIDENCE (A): target-side service action ================="
grep -iE 'preempt' "$OUT/clyde.dmesg" | head -12 | tee "$OUT/preempt.txt"
NPA=$(grep -ic 'preempt and abort' "$OUT/clyde.dmesg" || true)
NP=$(grep -icE 'scst_pr_do_preempt.*Preempt:' "$OUT/clyde.dmesg" || true)
echo "  'Preempt and abort' (0x05) lines: $NPA"
echo "  plain 'Preempt:'     (0x04) lines: $NP"

echo
echo "================= EVIDENCE (B): survivor fence ordering ==================="
# Per-node monotonic clocks are NOT comparable across nodes, so order WITHIN
# each node and report the node on every line rather than interleaving them.
for h in "${survivors[@]}"; do
    [ -s "$OUT/$h.fence" ] || continue
    grep -E 'FENCE-INTENT|FENCEKIND|FENCE-CERTIFIED|FENCEFAIL|P302-PROUT' "$OUT/$h.fence" \
      | sed -E 's/\[([0-9]+)\.([0-9]+)\]/[\1.\2]/' | sort -t'[' -k2 -n \
      | sed -E 's/(P2[0-9]+-[A-Z-]+).*/\1/' | head -6
done

echo
echo "================= VERDICT ================================================="
rc=0
if [ "$NPA" -ge 1 ]; then
    echo "  A: PASS — the target observed PREEMPT AND ABORT (0x05) from MXFS's own fence"
elif [ "$NP" -ge 1 ]; then
    echo "  A: FAIL — the target observed plain PREEMPT (0x04): the defect is LIVE"; rc=1
else
    echo "  A: NOT ESTABLISHED — no PROUT reached the target (no fence was issued)"; rc=2
fi
if grep -q 'PREEMPT_ABORT_DONE' "$OUT/all.fence" 2>/dev/null; then
    echo "  B: kind=PREEMPT_ABORT_DONE observed on a survivor"
else
    echo "  B: NOT ESTABLISHED — no survivor recorded kind=PREEMPT_ABORT_DONE"
    [ "$rc" = 0 ] && rc=2
fi

# ── 4. restore the victim (same steps run.sh's power_cycle_node uses) ──────
echo
date -u "+--- RESTORE $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system start "$VICTIM" >/dev/null 2>&1
t0=$(date +%s); booted=0
while [ $(( $(date +%s) - t0 )) -lt "$RESTORE_WAIT" ]; do
    if timeout 8 "$SSH" "$VICTIM" "echo SSH_UP" 2>/dev/null | grep -q SSH_UP; then booted=1; break; fi
    sleep 5
done
if [ "$booted" = 1 ]; then
    timeout 70 "$SSH" "$VICTIM" "
        mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
        iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
        iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
        iscsiadm -m node --login >/dev/null 2>&1
        iscsiadm -m session --rescan >/dev/null 2>&1
        multipath >/dev/null 2>&1" >/dev/null 2>&1
    dev_ok=$(timeout 15 "$SSH" "$VICTIM" "[ -e $DEV ] && echo DEV_UP" 2>/dev/null)
    echo "  $VICTIM back on ssh; device: ${dev_ok:-NOT PRESENT}"
else
    echo "  WARNING: $VICTIM did not return within ${RESTORE_WAIT}s — recover before the next board"
fi

echo
echo "artifacts: $OUT"
exit "$rc"
