#!/bin/bash
# dir_reuse_coherency — concurrent same-directory create coherency under
# inode/daddr REUSE churn, with a LEAF-HASH-index integrity check.
#
# This is the harsher sibling of crash_consistency.  crash_consistency does ONE
# wave of concurrent same-dir creates from every node and checks file content
# survives a cold reload — but it never removes+recreates the directory, so it
# never reuses the dir inode / dir-block daddrs across iterations.  That left a
# real, durable bug uncovered (sess20): under rm-rf + recreate churn (which
# frees and reuses the dir inode and its leaf/data block daddrs), a concurrent
# create RMWs a STALE dir base and durably drops a peer's hash entry from the
# directory LEAF index — readdir still lists the name (it is in the data block)
# but lookup/statx ENOENTs (its hash is gone from the leaf).  A pure count check
# misses the leaf-hash variant entirely; this test adds a per-entry lookup.
#
# Each round, every node writes NF data files + NF .md5 sidecars into ONE shared
# directory, barriers, then EVERY node (cold cache) asserts BOTH:
#   (a) every expected entry is present (readdir count == 2*T*NF), AND
#   (b) every entry readdir lists is actually lookup-able (no leaf-hash hole).
# Then rank 1 rm-rf's + recreates the directory (the reuse stressor) and the
# next round runs on the reused inode/daddrs.
#
# coord=barrier, min_nodes=2.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.dir_reuse_coherency"

# sess69 DIAGNOSTIC: stream the kernel ring to a file (immune to ring rotation
# under the always-on probe flood) so per-round EVDECIDE/handoff events at the
# failure survive.  Enabled only when DRC_STREAM is set.
if [ -n "${DRC_STREAM:-}" ]; then
    pkill -f 'dmesg --follow' 2>/dev/null || true
    # sess304: stream lands on /dev/shm (tmpfs), NOT /root.  Writing it to the
    # root fs forced ~17MB/round/node through vda→qcow2→the same host NVMe that
    # backs the LUN; at 32 nodes that is 540MB/round of harness-only IO, and the
    # sess303 null-mxfs repro (tests/drc_synth_sync.sh) proved it alone collapses
    # host NVMe write latency enough to fail a back-to-back run.  The stream is
    # harvested post-run over ssh, so tmpfs is equivalent for diagnostics.
    rm -f "/dev/shm/drc_stream_rank${R}.log"
    ( dmesg --follow > "/dev/shm/drc_stream_rank${R}.log" 2>&1 & )
fi
# sess17(ccloop): persistent NFS capture — survives a node panic/reboot (the
# fatal round's trace was lost when rank1 rebooted).  /src is clyde's NFS export
# (rw), so the stream lands on the dev host.  Opt-in (DRC_STREAM) so it never
# perturbs a full-suite criterion run.
if [ -n "${DRC_STREAM:-}" ] && [ -d /src/mxfs ] && \
   touch "/src/mxfs/tests/tcp/drc_cap/.w" 2>/dev/null; then
    pkill -f 'dmesg --follow' 2>/dev/null || true
    rm -f "/src/mxfs/tests/tcp/drc_cap/stream_rank${R}.log"
    ( dmesg --follow > "/src/mxfs/tests/tcp/drc_cap/stream_rank${R}.log" 2>&1 & )
fi

# sess14(a9a03929): /root persists across VM reboots, so per-round forensic
# snapshots from PREVIOUS runs survive and get pulled into the NEXT failing
# run's artifact as if they were current (r4 post-mortem chased a "divergent
# DIRID incarnation" for an hour that was really iter-r3's files from an
# earlier boot).  Start every run with a clean forensic slate.
rm -f /root/drc_create_r*.dmesg /dev/shm/drc_create_r*.dmesg /root/drc_fail_r*.dmesg \
      /root/drc_failverify_r*.dmesg /root/drc_failrounds.txt 2>/dev/null
rm -rf /root/drc_blkdump_r* 2>/dev/null
# ccloop c7ee71c6 sess6: the newer capture families were MISSING from this
# clean-slate rm — run 155524Z's artifact contained drc_dchang_r14 /
# drc_hang_rm_r{1,3,4} snapshots whose in-file uptimes (134s..5329s) span
# FIVE different boots; they read as "this run reached round 14 and hung rm
# three times" when the run actually died in round 1.  Every /root capture
# family this script can emit must be cleared here.
rm -f /root/drc_dchang_r*.dmesg /root/drc_hang_rm_r*.dmesg \
      /root/drc_hang_mkdir_r*.dmesg 2>/dev/null

# sess8 (ccloop 72513a13) TEST REARCHITECTURE — user directive: 1380s for one
# test is itself the failure; a debug loop that takes 20+ minutes per attempt
# is unusable.  The coherency SIGNALS this test exists for are kept intact:
#   (1) concurrent same-dir create waves from every node (dirent/leaf RMW),
#   (2) cold cross-node verify: readdir count + per-listed-name lookup
#       (the leaf-hash-hole check),
#   (3) rm-rf + recreate cycling that reuses the dir inode + block daddrs,
#   (4) content integrity spot-check.
# What changes is the COST model:
#   - No .md5 sidecar FILES (they doubled every dirent/create/unlink/lookup).
#     Content is a deterministic pattern of (name, round) — verified by read,
#     no md5sum forks, no second file.
#   - Total files per round is N-INVARIANT (DRC_TOTAL, default 128, split
#     across nodes, min 4/node): the dir-EX rotation serializes the TOTAL, so
#     round wall no longer grows with N.  The old 50/node meant 3200
#     files/round at 32 nodes = a 1380s wedge-burn when anything went wrong.
#   - Rounds are TIME-BOXED: run up to DRC_ROUNDS rounds but stop cleanly
#     once DRC_TIME_BUDGET_S (default 100s) is spent.  A hard pace assertion
#     stays: fewer than DRC_MIN_ROUNDS (default 8) completed rounds inside
#     the window = FAIL SLOW_ROUNDS — slowness is a first-class failure
#     (RULE 0), it just fails FAST now instead of after 24 slow rounds.
#   - FAIL-FAST: a failed round ends the test immediately (the old loop ran
#     all remaining rounds after a failure, multiplying a wedge into 1380s).
# Diagnosis-mode heavy shapes remain available via the env knobs.
DRC_TOTAL="${DRC_TOTAL:-128}"
NFILES="${DRC_NFILES:-$(( DRC_TOTAL / T > 4 ? DRC_TOTAL / T : 4 ))}"
ROUNDS="${DRC_ROUNDS:-24}"
MIN_ROUNDS="${DRC_MIN_ROUNDS:-8}"
TIME_BUDGET_S="${DRC_TIME_BUDGET_S:-100}"
EXP=$(( T * NFILES ))         # data files only, every node
# The flat 20s this used to be assumed "native mkdir/rm-rf is well under 1s"
# — true for a SINGLE node, false for T-node coherent rm-rf: every removed
# dirent needs a durable per-inode owner-scan flush (CAW/DLM round trips),
# and that cost is O(T)-ish, not constant.  run.sh already measured rm-rf
# ~21s at just 8 nodes (see its dir_reuse_coherency case-arm comments); live
# 2026-07-11 measurement at 32 nodes (build 1BAFC14435BA2FFEBEF0742, 2
# rounds): rm-rf 32s/38s, mkdir/verify comparable.  A flat 20s false-
# positives "SYSCALL_HANG" on this legitimate cost at T>=8 — confirmed via
# nanosecond-precision realns fields showing the "hung" rm PID continuing to
# make forward progress for 9+ seconds after the threshold tripped — which
# then cascades (coord_signal_abort) into every peer reporting
# ABORTED_BY_PEER even though nothing was stuck.  Scale with T instead;
# floor of 20 keeps small-T behavior unchanged.  Stay comfortably under
# run.sh's per-test COORD_TIMEOUT override for this test (see its
# dir_reuse_coherency case-arm) so a GENUINE forever-hang still self-reports
# via finish_hang before peers hit the less-specific BARRIER_TIMEOUT.
drc_hang_floor=$(( T * 10 ))
[ "$drc_hang_floor" -lt 20 ] && drc_hang_floor=20
DRC_HANG_THRESHOLD_S="${DRC_HANG_THRESHOLD_S:-$drc_hang_floor}"

# drc_barrier <tag> — abort-aware barrier for this test's round loop.  A
# genuine timeout OR a peer-broadcast abort ends the test IMMEDIATELY with
# a specific structured RESULT, instead of recording one more FAIL (via ck)
# and cascading through every remaining round/barrier.  Proven costly
# 2026-07-11 (run61b): one node's hung rm cost ~2h of repeated 120s
# timeouts across 31 peers — itself a RULE 0 violation — before the outer
# per-run timeout killed everything with zero RESULT lines anywhere (see
# ccmemory gpt-consult-dir_reuse32-architectural-review).
drc_barrier() {
    local tag="$1" out rc
    out=$(coord_barrier_or_abort "$tag"); rc=$?
    case "$rc" in
        0) PASS_N=$((PASS_N + 1)); return 0 ;;
        2) FAIL_N=$((FAIL_N + 1))
           finish_aborted "round=${round:-?} barrier=${tag} peer_reason=[$out]"
           exit 1 ;;
        *) FAIL_N=$((FAIL_N + 1))
           finish_state BARRIER_TIMEOUT "round=${round:-?} barrier=${tag}"
           exit 1 ;;
    esac
}

# Deterministic per-file content: verifiable by read alone (no sidecar, no
# md5 fork).  Size still varies 1-8 4k blocks by round (the multi-block dir
# data/extent shapes the old test exercised).
#
# sess9 (16/tcp pace RULE-4): the original `yes | head -c` spawned a 2-fork
# pipeline PER CREATE; that 20-50ms client-side gap exceeds the DLM's 40ms
# tenure grace, so every create forfeited the shared-dir EX tenure and
# re-queued behind N-1 peers (~35ms/create × 128 = the 4.5-5.1s create wave
# measured at 16/tcp; the sess8 cc@32 "burst fragmentation" anatomy, exact).
# Pure-bash string doubling emits identical bytes (repeated "line\n"
# truncated) with ZERO forks, so back-to-back creates stay inside the grace
# window and tenure batching serves a node's whole wave in one rotation.
drc_pat_str() {  # name round -> $DRC_PAT
    local line="DRC $1 r$2"$'\n'
    local need=$(( (($2 % 8) + 1) * 4096 ))
    local s="$line"
    while [ "${#s}" -lt "$need" ]; do s="$s$s"; done
    DRC_PAT="${s:0:need}"
}
drc_pat() {  # name round -> stdout (kept for the verify-side cmp)
    drc_pat_str "$1" "$2"
    printf '%s' "$DRC_PAT"
}

drc_t0=$(date +%s)
rounds_done=0

drc_barrier "drc_ready"

for round in $(seq 1 "$ROUNDS"); do
    # Time box, COORDINATED: rank 1 alone decides whether this round starts
    # (peers' clocks/skew must not desynchronize the barrier sequence — an
    # uncoordinated per-node break would deadlock the round barriers).  The
    # coord kv is retained, so late getters still see it.
    if [ "$R" = 1 ]; then
        if [ $(( $(date +%s) - drc_t0 )) -ge "$TIME_BUDGET_S" ]; then
            coord_put "drc_go_r${round}" 0
        else
            coord_put "drc_go_r${round}" 1
        fi
    fi
    drc_go=$(coord_get "drc_go_r${round}" 60) || drc_go=0
    [ "$drc_go" = 1 ] || break
    # rank 1 owns the dir lifecycle; everyone waits until it (re)exists.
    if [ "$R" = 1 ]; then
        # sess9: no sync after mkdir — peers reach the new dir through the
        # DLM-coordinated path (that coherency IS the assertion under test);
        # the sync was sidecar-era belt-and-braces costing ~1-1.5s/round of
        # log-force against the pace budget.
        if run_bounded "drc-mkdir-r${round}" "$DRC_HANG_THRESHOLD_S" mkdir -p "$D"; then
            :
        else
            dmesg > "/root/drc_hang_mkdir_r${round}_rank${R}.dmesg" 2>/dev/null || true
            coord_signal_abort "SYSCALL_HANG rank=${R} op=mkdir round=${round}"
            finish_hang mkdir "round=${round} dir=${D}"
            exit 1
        fi
    fi
    drc_barrier "drc_r${round}_mk"
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=create-start" > /dev/kmsg 2>/dev/null || true

    # sess10(a9a03929): arm the kernel storm-dir probe family (P9-LFREE,
    # P13-LADD, P11-DATALOG, P49-STALEBASE, P10-RDBLK, P-DIRWR) on THIS
    # round's dir inode.  In-suite the dir allocates high (r8: ino=2529) and
    # the legacy ino<=256 scope left every probe blind exactly when the flake
    # reproduces.  Per-node, per-round; harmless if the param is absent.
    # MXFS_WATCH_ARM=0 (harness env) = unarmed r8-parity iteration: the
    # per-op probe I/O also perturbs (possibly protects) the race.
    if [ "${MXFS_WATCH_ARM:-1}" = 1 ]; then
        drc_watch=$(stat -c '%i' "$D" 2>/dev/null)
        [ -n "$drc_watch" ] && echo "$drc_watch" > /sys/module/mxfs/parameters/watch_ino 2>/dev/null || true
    fi

    # Concurrent same-dir create wave in TWO half-waves with a sync between
    # (the old data-then-sidecar shape's mid-wave sync is preserved — the RMW
    # stale-base window it opens is part of the signal).  One sync per wave,
    # not per file: the bug family is dir leaf/data coherency, not per-file
    # fsync durability.
    half=$(( NFILES / 2 )); [ "$half" -lt 1 ] && half=1
    for i in $(seq 1 "$half"); do
        drc_pat_str "node${R}_f${i}" "$round"
        printf '%s' "$DRC_PAT" > "$D/node${R}_f${i}"
    done
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=wave1-done" > /dev/kmsg 2>/dev/null || true
    sync
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=sync1-done" > /dev/kmsg 2>/dev/null || true
    for i in $(seq $(( half + 1 )) "$NFILES"); do
        drc_pat_str "node${R}_f${i}" "$round"
        printf '%s' "$DRC_PAT" > "$D/node${R}_f${i}"
    done
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=wave2-done" > /dev/kmsg 2>/dev/null || true
    sync

    echo "mxfs-DRCph r=${round} rank=${R} PHASE=create-done" > /dev/kmsg 2>/dev/null || true
    # sess62: snapshot the create-phase ring NOW (before verify-phase reads +
    # the next round flood it out).  Per-round so a node1_f1-losing round's
    # create snapshot (holding the clobber) can be correlated after the fact.
    # sess304: target is /dev/shm (tmpfs), NOT /root.  The full 16.9MB ring
    # dumped to the root fs every round on every node (540MB/round fleet-wide,
    # forced out by this test's own syncs) saturates the shared host NVMe and
    # was the proven but-for cause of the back-to-back-run FAIL (D-503 residual,
    # sess303 null-mxfs repro tests/drc_synth_sync.sh).  tmpfs also can't leak
    # stale snapshots across reboots (the sess14 contamination above).
    dmesg > "/dev/shm/drc_create_r${round}_rank${R}.dmesg" 2>/dev/null || true
    drc_barrier "drc_r${round}_wr"
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=wrbar-done" > /dev/kmsg 2>/dev/null || true

    # Cold reload so reads come coherently from the shared LUN (as a peer sees
    # them), then verify count AND per-entry lookup-ability.  drop_caches is
    # synchronous and mxfs reload-on-acquire is prompt, so no settle sleep is
    # needed (RULE 0: a masking delay is debt — removed sess18 after the
    # reliable-handoff + release-fast-path fixes made coherency immediate).
    #
    # sess14(a9a03929): r4/test7 and r6/test5 both died SILENTLY here —
    # drop_caches' inode eviction (800 per round) interlocks with a peer's
    # concurrent rm-storm DLM releases in an INTERRUPTIBLE wait (no hung-task
    # warning, no P73), the node stops participating, and every subsequent
    # barrier times out 120s — the "whole-blob 700/800 miss" + 62s/round
    # death spiral (the victim's blob is missing because it never CREATED
    # it).  Run drop_caches bounded in a subshell: on a hang, capture the
    # hung task's kernel stack to kmsg (the RULE-4 instrument for the
    # eviction interlock) and PROCEED with a warm verify — the loud
    # DROPCACHES-HUNG marker disqualifies the round from coherency claims,
    # but the cluster stays in lockstep instead of cascading timeouts.
    sync
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=presync-done" > /dev/kmsg 2>/dev/null || true
    rm -f "/tmp/.drc_dc_done.$$"
    ( echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; echo "mxfs-DRCph r=${round} rank=${R} PHASE=dc-real-done" > /dev/kmsg 2>/dev/null; : > "/tmp/.drc_dc_done.$$" ) &
    dc_pid=$!
    dc_ok=0
    # sess1 (ccloop 0220f43f) RULE-4: TRIED a 0.05s poll granularity here
    # (matching the coord_check_abort fix's reasoning) -- REVERTED, not a
    # proven win: live A/B on 32/cawp showed verify-phase time went UP
    # (~7.3s avg with only the coord.sh fix -> ~8.7s avg with this added),
    # consistent with 32 concurrent VMs' 20Hz busy-poll adding real CPU/
    # scheduling contention on constrained vCPU allocations rather than
    # saving wall-clock.  Back to the original 1s granularity pending a
    # proper measurement of what's actually dominating verify-phase time.
    for _dci in $(seq 1 120); do
        [ -e "/tmp/.drc_dc_done.$$" ] && { dc_ok=1; break; }
        # sess37: while dc is in flight, sample the dc writer's kernel wait
        # site — the 5-9s "dc" phase is the round-dominant cost and the
        # blocking stack names the mechanism directly (bounded: <=8 lines/s).
        while IFS= read -r dcln; do
            echo "mxfs-drc-DCSTK r=${round} rank=${R} i=${_dci} $dcln" > /dev/kmsg 2>/dev/null
        done < <(head -14 "/proc/$dc_pid/stack" 2>/dev/null)
        sleep 1
    done
    if [ "$dc_ok" != 1 ]; then
        echo "mxfs-drc-DROPCACHES-HUNG round=$round rank=$R pid=$dc_pid wchan=[$(cat /proc/$dc_pid/wchan 2>/dev/null)] comm=[$(cat /proc/$dc_pid/comm 2>/dev/null)]" > /dev/kmsg 2>/dev/null
        while IFS= read -r dcln; do
            echo "mxfs-drc-DCSTACK r=$round rank=$R $dcln" > /dev/kmsg 2>/dev/null
        done < "/proc/$dc_pid/stack" 2>/dev/null
        dmesg > "/root/drc_dchang_r${round}_rank${R}.dmesg" 2>/dev/null || true
    fi
    rm -f "/tmp/.drc_dc_done.$$"
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=dc-done" > /dev/kmsg 2>/dev/null || true

    # sess63 DECISIVE (zero-kernel-build): log the dir INODE NUMBER this node
    # resolves "$D" to, every round.  If on a readdir-miss the failing peers'
    # dirino DIFFERS from rank1's, the dir path resolves to a DIFFERENT inode
    # incarnation (dentry/iget reuse-coherence bug); if it MATCHES, the loss is
    # an intra-inode dir-block lost-update.  Settles the ambiguity.
    drc_dirino=$(stat -c '%i' "$D" 2>/dev/null)
    echo "mxfs-drc-DIRID round=$round rank=$R dirino=$drc_dirino" > /dev/kmsg 2>/dev/null || true

    # sess6(ccloop): capture the FIRST readdir view to a file — the transient
    # rank1 shortfall heals before the diagnostic re-ls below, erasing the
    # victim names (run82: RDMISS printed missing=[] with count 764/800).
    ls "$D" 2>/dev/null | sort > "/tmp/drc_ls1.$$"
    readdir_cnt=$(grep -c . "/tmp/drc_ls1.$$")
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=ls-done" > /dev/kmsg 2>/dev/null || true
    lookup_fail=0
    missing=""
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        if [ ! -e "$D/$name" ]; then
            lookup_fail=$((lookup_fail + 1))
            [ "${#missing}" -lt 200 ] && missing="$missing $name"
        fi
    done < "/tmp/drc_ls1.$$"
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=lookups-done" > /dev/kmsg 2>/dev/null || true

    # (a) every expected entry present in readdir
    ckeq "drc r${round} r${R} readdir count" "$EXP" "$readdir_cnt"
    # (b) no leaf-hash hole: every listed name is lookup-able
    ckeq "drc r${round} r${R} leaf-hash lookup_fail" "0" "$lookup_fail"
    # (c) content spot-check: own first file + one peer file per node, read
    # cold and compared against the deterministic pattern (no md5 forks).
    content_bad=0
    for nm in "node${R}_f1" "node$(( (R % T) + 1 ))_f1"; do
        if [ -e "$D/$nm" ]; then
            if ! cmp -s <(drc_pat "$nm" "$round") "$D/$nm"; then
                content_bad=$((content_bad + 1))
                echo "mxfs-drc-CONTENT round=$round rank=$R name=$nm MISMATCH" > /dev/kmsg 2>/dev/null
            fi
        fi
    done
    ckeq "drc r${round} r${R} content sample" "0" "$content_bad"

    # sess28: on a readdir SHORTFALL, log exactly which expected names are
    # absent from readdir (the dir-DATA-block content loss) — distinguishes
    # which node's entries were dropped and the contiguity pattern.
    if [ "$readdir_cnt" != "$EXP" ]; then
        for rr in $(seq 1 "$T"); do for ii in $(seq 1 "$NFILES"); do
            echo "node${rr}_f${ii}"; done; done | sort > "/tmp/drc_exp.$$"
        # sess6: FIRST-view missing set (the transient's true victims), plus
        # a re-ls diff to show whether/what healed in the interim.
        rdmiss0=$(comm -13 "/tmp/drc_ls1.$$" "/tmp/drc_exp.$$" | tr '\n' ' ')
        echo "mxfs-drc-RDMISS0 round=$round rank=$R readdir=$readdir_cnt missing_first_view=[$rdmiss0]" > /dev/kmsg 2>/dev/null
        # sess10(a9a03929): P10-DIRDUMP — magic-name lookup makes the kernel
        # dump every data block of $D (in-core cached image vs coherent
        # platter read, active counts + buffer/DLM state) WITHOUT touching
        # the dir's coherency state.  Fired at the miss, before the re-ls.
        [ -e "$D/.mxfs_dirdump1" ] 2>/dev/null || true
        # sess12(a9a03929): raw platter capture of every data block the dump
        # just enumerated (P10-DIRDUMP-BLK prints lba= = envelope-adjusted
        # device sector).  The r7 node1_f17.md5 loss proved the final durable
        # image is INTERNALLY inconsistent (walk misses the entry, exact-offset
        # lookup finds it) — only the raw bytes name which prior entry/unused
        # header swallowed it.  O_DIRECT so we read the platter, not the cache.
        drc_dino=$(stat -c %i "$D" 2>/dev/null)
        drc_bd="/root/drc_blkdump_r${round}_rank${R}"
        mkdir -p "$drc_bd" 2>/dev/null
        dmesg | grep "P10-DIRDUMP-BLK ino=${drc_dino} " | tail -32 | \
          grep -oE "daddr=[0-9]+ lba=[0-9]+" | sort -u | while read -r dl; do
            dd_daddr=${dl%% *}; dd_daddr=${dd_daddr#daddr=}
            dd_lba=${dl##* }; dd_lba=${dd_lba#lba=}
            dd if="${MXFS_DEV:-/dev/sda}" of="$drc_bd/blk_${dd_daddr}.bin" \
               bs=512 skip="$dd_lba" count=8 iflag=direct 2>/dev/null || true
        done
        # sess13: journald rotates in ~85s under probe volume, losing the
        # P10-DIRDUMP / DLMTR ring output for early rounds by the time the
        # host pulls kernlogs.  Snapshot the ring buffer NOW, at the miss,
        # into the blkdump dir (pulled into the artifact by run.sh).
        dmesg | tail -n 6000 > "$drc_bd/dmesg_at_rdmiss.txt" 2>/dev/null || true
        ls "$D" 2>/dev/null | sort > "/tmp/drc_got.$$"
        rdmiss=$(comm -13 "/tmp/drc_got.$$" "/tmp/drc_exp.$$" | tr '\n' ' ')
        echo "mxfs-drc-RDMISS round=$round rank=$R readdir=$readdir_cnt missing_from_readdir=[$rdmiss]" > /dev/kmsg 2>/dev/null
        echo "drc-RDMISS round=$round rank=$R missing_first_view=[$rdmiss0] missing_from_readdir=[$rdmiss]" >&2
        # sess60 DIAGNOSTIC (does NOT change pass/fail): classify each
        # readdir-missing name — is it directly lookup-able (leaf-hash present =
        # enumeration miss / leaf-data divergence) or ENOENT (durable data
        # loss)?  And does a 2nd readdir show it (transient stale-block)?
        for nm in $rdmiss0; do
            if [ -e "$D/$nm" ]; then st=LOOKUP_OK; else st=LOOKUP_ENOENT; fi
            if ls "$D" 2>/dev/null | grep -qx "$nm"; then rr=REREAD_SHOWS; else rr=REREAD_MISS; fi
            echo "mxfs-drc-CLASS round=$round rank=$R name=$nm $st $rr" > /dev/kmsg 2>/dev/null
        done
        # sess10(a9a03929): second dump AFTER the lookup classification — the
        # delta vs .mxfs_dirdump1 shows whether the lookups healed the view.
        [ -e "$D/.mxfs_dirdump2" ] 2>/dev/null || true
        rm -f "/tmp/drc_got.$$" "/tmp/drc_exp.$$"
        # sess41: dump the in-kernel dir-landing ring NOW (overhead-free during
        # the run; printed only on this fail) so the failing round's COMPLETE
        # landing order is in the snapshot below.
        echo 1 > /sys/module/mxfs/parameters/dland_dump 2>/dev/null || true
        # sess61: snapshot the kernel ring at the FAILURE MOMENT, before the
        # next round's create wave spams P60-LBMAP et al out of the buffer.
        dmesg > "/root/drc_fail_r${round}_rank${R}.dmesg" 2>/dev/null || true
    fi

    if [ "$readdir_cnt" != "$EXP" ] || [ "$lookup_fail" != 0 ] || [ "$content_bad" != 0 ]; then
        echo "mxfs-drc-FAIL round=$round rank=$R readdir=$readdir_cnt exp=$EXP lookup_fail=$lookup_fail missing=[$missing]" > /dev/kmsg 2>/dev/null
        echo "drc round=$round rank=$R readdir=$readdir_cnt/$EXP lookup_fail=$lookup_fail missing=[$missing]" >&2
        # sess69: persistent fail-round marker (survives kernel-ring rotation),
        # and snapshot the verify-phase ring NOW for this round regardless of
        # whether it was a readdir shortfall or a leaf-hash lookup_fail.
        echo "round=$round rank=$R readdir=$readdir_cnt/$EXP lookup_fail=$lookup_fail missing=[$missing]" >> /root/drc_failrounds.txt
        dmesg > "/root/drc_failverify_r${round}_rank${R}.dmesg" 2>/dev/null || true
        # sess8 FAIL-FAST: a failed round ends the test NOW.  The old loop
        # ran every remaining round after a failure — a wedged cluster then
        # burned 20+ minutes of cascading barrier timeouts before reporting.
        echo "mxfs-DRCph r=${round} rank=${R} PHASE=verify-done" > /dev/kmsg 2>/dev/null || true
        coord_signal_abort "ROUND_FAIL rank=${R} round=${round} readdir=${readdir_cnt}/${EXP} lookup_fail=${lookup_fail}"
        coord_done FAIL
        finish
        exit 1
    fi

    echo "mxfs-DRCph r=${round} rank=${R} PHASE=verify-done" > /dev/kmsg 2>/dev/null || true
    drc_barrier "drc_r${round}_vr"

    # Reuse stressor: rank 1 frees the whole dir (inode + leaf/data daddrs) so
    # the next round reallocs and reuses them.  This is the exact op that has
    # hung D-state cluster-wide in prior runs (rm stuck in xfs_buf_iowait,
    # confirmed live 2026-07-11 run61b) — bounded + hang-detected rather than
    # left to block this node (and, via cascading barrier timeouts, all
    # other peers) for the full per-run timeout with zero RESULT lines
    # anywhere.
    if [ "$R" = 1 ]; then
        # sess9: no sync after rm — next round's mkdir/creates re-coordinate
        # through the DLM regardless; same rationale as the mkdir sync drop.
        if run_bounded "drc-rm-r${round}" "$DRC_HANG_THRESHOLD_S" rm -rf "$D"; then
            :
        else
            dmesg > "/root/drc_hang_rm_r${round}_rank${R}.dmesg" 2>/dev/null || true
            coord_signal_abort "SYSCALL_HANG rank=${R} op=rm-rf round=${round}"
            finish_hang rm-rf "round=${round} dir=${D}"
            exit 1
        fi
    fi
    echo "mxfs-DRCph r=${round} rank=${R} PHASE=rm-done" > /dev/kmsg 2>/dev/null || true
    drc_barrier "drc_r${round}_cl"
    rounds_done=$((rounds_done + 1))
done

# Pace assertion (RULE 0): the time box must have fit at least MIN_ROUNDS
# full reuse cycles.  Slower than that IS the failure — reported in seconds,
# not discovered after 24 slow rounds.
drc_elapsed=$(( $(date +%s) - drc_t0 ))
ckeq "drc rounds_done>=${MIN_ROUNDS} (${rounds_done} in ${drc_elapsed}s)" \
     "1" "$(( rounds_done >= MIN_ROUNDS ? 1 : 0 ))"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
