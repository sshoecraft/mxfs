#!/bin/bash
# relgate_fault_inject.sh — EXERCISE and VERIFY the sess309 step-6 F1
# deferred-release enforcement path via the relgate fault engine.
#
# WHY THIS EXISTS
#   0.11.511 (sess307 ruling, sess309 landing) made an incomplete release
#   proof DEFER (-EAGAIN + per-cluster retry worker) instead of CASing the
#   grant away, with a bounded WEDGE (60s no-progress / 300s total ->
#   P-ICLUS-WEDGE, grant pinned, admission closed, force shutdown) as the
#   fail-safe end.  Board runs exercised the defer path only incidentally
#   (5 natural episodes, sess310).  RULE 6 requires the enforcement
#   boundary to be exercised ON PURPOSE: force the proof to fail at each
#   guarded stage and watch the machinery hold the invariant.
#
# HOW THE FAULT WORKS
#   mxfs.relgate_fault_stage arms a delay (relgate_fault_delay_ms) at one
#   stage of the ICLUS release path; hits log P282-RELGATE-FAULT.  The
#   fault is DELAY-ONLY: a defer results only when concurrent dirtying of
#   the released cluster lands inside the delay window and the settle/
#   proof recheck catches it.  So the driver arms the fault with
#   oneshot=0 on a node UNDER hot-shared-dir churn (peers force BASTs,
#   local churn redirties the dir's inode cluster during the delay).
#   Stages driven: 7=OBLIG_ZERO (post-settle), 9=FLUSH_DONE (post-flush,
#   pre-verify), 10=PROOF (post-proof-loop; downstream tripwire coverage).
#
# WHAT COUNTS AS PASS — defer mode (all of these, per RULE 6)
#   1. P282-RELGATE-FAULT fired at every driven stage (fault really ran).
#   2. >=1 P280-RELEASE-CERT with cas=0 defer=N (a real deferral: the
#      release path REFUSED to CAS without proof).
#   3. Every episode resolved: no P-ICLUS-WEDGE, wedges=0, and the
#      target still writes afterwards (admission reopened).
#   4. cas_noproof_v2 == 0 on the target (THE enforcement invariant).
#   5. Zero kernel faults on target/peers.
#
# WHAT COUNTS AS PASS — wedge mode
#   Sustained churn + repeated stage-7 delay holds one cluster's proof
#   failure past the 60s no-progress bound:
#   1. P-ICLUS-WEDGE fires on the target (bounded end reached, not loop).
#   2. Cert with defer=5 (WEDGE) and cas=0 — the grant was PINNED, never
#      CASed away without proof.
#   3. The target mount force-shuts-down; PEERS KEEP WORKING (containment).
#   4. cas_noproof_v2 == 0 on the target even through the wedge.
#   Exit 3 (INCONCLUSIVE) if churn never holds a single cluster failing
#   long enough — that is a driver limitation, not an FS verdict.
#   NOTE: wedge mode shuts down the target's mount; re-prep the cluster
#   afterwards (./run.sh <N> caw prep_cluster).
#
# INODE-CLASS MODES (sess315/0.11.512, sess312 ruling items 5+10)
#   Production config (icluster_dlm=0): the ICLUS path never runs, so the
#   same stage numbers arm the INODE placement sites in the relbar proof
#   body instead.  These sites are FORCE-capable: with
#   mxfs.relgate_fault_force=1 an armed hit does not merely delay — it
#   forces the modeled failure deterministically:
#     stage 7 (OBLIG_ZERO)  -> forced "ledger still open": defer branch
#                              (P228-RELBAR-DEFER, class=1 defer cert)
#     stage 9 (FLUSH_DONE)  -> forced FIRST ticket-check failure; the
#                              direct flush usually recovers it (transient)
#     stage 10 (PROOF)      -> forced post-flush proof failure (persistent
#                              for that attempt): proof_failed defer
#   inode mode PASS: every stage's P282 hit with force=1; stages 7/10
#   produced >=1 class=1 defer cert (cas=0 defer=[1-4]); every episode
#   resolved (success grew, zero P-INODE-WEDGE); cas_noproof_v2==0;
#   liveness on all nodes; zero kernel faults.
#   inodewedge mode: one shared file, fault_res=<its ino>, oneshot=0,
#   force=1 stage 7 -> every release attempt of THAT inode defers; the
#   60s no-progress bound expires -> PASS iff P-INODE-WEDGE fired, a
#   class=1 WEDGE cert (cas=0 defer=5) emitted, the target force-shut-
#   down, peers stayed live, cas_noproof_v2==0.  Target mount is dead
#   afterwards: re-prep the cluster (./run.sh <N> caw prep_cluster).
#
# USAGE
#   tests/relgate_fault_inject.sh [defer|wedge|inode|inodewedge] [target] [npeers] [nodes]
#     target  node under fault (default test2)
#     npeers  contending peers, testK upward skipping target (default 3)
#     nodes   fleet size for context only (default 32)
#
# RULE 0 budget:
#   defer mode: 3 stages x (arm 5s + churn 20s + settle 5s + harvest 5s)
#     x <=2 attempts + final sweep ~20s  => <=240s.  Cap the invocation
#     at 300s; longer means a wedge or an unreachable node, both FAIL.
#   wedge mode: churn until wedge, cap 170s (60s bound + margin) + 30s
#     verify => cap the invocation at 240s.
#   inode mode: 3 stages x (arm 5s + churn 15s + settle 5s + harvest 5s)
#     x <=2 cycles + final sweep ~20s => <=200s.  Cap at 300s.
#   inodewedge mode: same shape as wedge mode => cap at 240s.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

MODE="${1:-defer}"
TARGET="${2:-test2}"
NPEERS="${3:-3}"
STAMP=$(date -u +%Y%m%d_%H%M%S)
OUT="$REPO/tests/logs/relgate_${MODE}_$STAMP"
mkdir -p "$OUT"
WD="/mnt/shared/.relgate_$STAMP"
PARAMS=/sys/module/mxfs/parameters

# Peers: walk up from test3, skip the target.
PEERS=""
k=1
while [ "$(echo "$PEERS" | wc -w)" -lt "$NPEERS" ]; do
    k=$(( k + 1 ))
    [ "test$k" = "$TARGET" ] && continue
    PEERS="$PEERS test$k"
done

echo "=== relgate_fault_inject: mode=$MODE target=$TARGET peers=[$PEERS] out=$OUT ==="

node_set() { # node param value
    timeout 20 "$SSH" "$1" "echo $3 > $PARAMS/$2" >/dev/null 2>&1
}

counters() { # node -> latest P280-RELEASE-CERT-TOTAL line
    timeout 20 "$SSH" "$1" \
        "echo 1 > $PARAMS/release_cert_dump; dmesg | grep P280-RELEASE-CERT-TOTAL | tail -1" 2>/dev/null
}

cfield() { # line name -> value
    echo "$1" | grep -o "$2=[-0-9]*" | head -1 | cut -d= -f2
}

# The fault stages live in the ICLUS (inode-cluster) release proof path,
# which runs only when a peer BASTs this node off an inode-cluster grant.
# Learned by failing: per-node private create/rm churn produces ONLY AG
# (class=1) releases — fault_hits stayed 0 across 6 windows.  So every
# node appends to the SAME shared file set: cross-node same-inode EX
# ping-pong forces full ICLUS releases on the target while its own next
# append redirties the cluster mid-release — exactly the defer condition.
churn_start() { # seconds
    local secs="$1" off=0 p
    timeout 30 "$SSH" "$TARGET" \
        "mkdir -p $WD && cd $WD && for i in \$(seq 0 63); do : > s\$i; done" >/dev/null 2>&1
    CHURN_PIDS=""
    for p in $TARGET $PEERS; do
        timeout $(( secs + 10 )) "$SSH" "$p" \
            "cd $WD && timeout $secs bash -c 'i=$off; while :; do echo x >> s\$((i%64)); i=\$((i+1)); done' 2>/dev/null; true" \
            > /dev/null 2>&1 &
        CHURN_PIDS="$CHURN_PIDS $!"
        off=$(( off + 16 ))
    done
}

churn_wait() {
    local p
    for p in $CHURN_PIDS; do wait "$p" 2>/dev/null; done
    CHURN_PIDS=""
}

arm() { # stage delay_ms
    node_set "$TARGET" release_cert_log 1 &&
    node_set "$TARGET" relgate_fault_oneshot 0 &&
    node_set "$TARGET" relgate_fault_res 0 &&
    node_set "$TARGET" relgate_fault_delay_ms "$2" &&
    node_set "$TARGET" relgate_fault_stage "$1"
}

disarm() {
    node_set "$TARGET" relgate_fault_stage 0
    node_set "$TARGET" relgate_fault_delay_ms 100
    node_set "$TARGET" relgate_fault_oneshot 1
}

# INODE-class force arms: delay 0 (the force IS the failure), force=1.
arm_force() { # stage oneshot res
    node_set "$TARGET" release_cert_log 1 &&
    node_set "$TARGET" relgate_fault_oneshot "$2" &&
    node_set "$TARGET" relgate_fault_res "$3" &&
    node_set "$TARGET" relgate_fault_delay_ms 0 &&
    node_set "$TARGET" relgate_fault_force 1 &&
    node_set "$TARGET" relgate_fault_stage "$1"
}

disarm_force() {
    node_set "$TARGET" relgate_fault_stage 0
    node_set "$TARGET" relgate_fault_force 0
    node_set "$TARGET" relgate_fault_res 0
    node_set "$TARGET" relgate_fault_delay_ms 100
    node_set "$TARGET" relgate_fault_oneshot 1
}

# Single-file cross-node churn (inodewedge): every node appends to ONE
# shared file so the target's EX grant on that inode is BASTed away
# repeatedly, driving release attempts of exactly the faulted resource.
churn_one_start() { # seconds file
    local secs="$1" f="$2" p
    CHURN_PIDS=""
    for p in $TARGET $PEERS; do
        timeout $(( secs + 10 )) "$SSH" "$p" \
            "cd $WD && timeout $secs bash -c 'while :; do echo x >> $f; done' 2>/dev/null; true" \
            > /dev/null 2>&1 &
        CHURN_PIDS="$CHURN_PIDS $!"
    done
}

liveness() { # node tag
    timeout 30 "$SSH" "$1" \
        "mkdir -p $WD && : > $WD/.live_$2 && echo WRITE_OK" 2>/dev/null | grep -q WRITE_OK
}

fail=0

if [ "$MODE" = "defer" ]; then
    base=$(counters "$TARGET")
    if [ -z "$base" ]; then
        echo "=== INFRA-FAIL: cannot read release counters on $TARGET (build lacks the cert engine, or node unreachable) ==="
        exit 2
    fi
    echo "$base" > "$OUT/counters_before.log"
    total_defer_certs=0
    for cycle in 1 2; do
        DELAY=$(( cycle == 1 ? 1500 : 3000 ))
        WIN=20
        cycle_all_stages=1
        for stage in 7 9 10; do
            timeout 20 "$SSH" "$TARGET" "dmesg -C" >/dev/null 2>&1
            arm "$stage" "$DELAY" || { echo "=== INFRA-FAIL: could not arm stage $stage on $TARGET ==="; exit 2; }
            churn_start "$WIN"
            churn_wait
            disarm
            sleep 5   # let the retry worker resolve open episodes
            LOG="$OUT/stage${stage}_c${cycle}.log"
            timeout 40 "$SSH" "$TARGET" "dmesg" > "$LOG" 2>&1
            p282=$(grep -c "P282-RELGATE-FAULT stage=$stage " "$LOG")
            defers=$(grep 'P280-RELEASE-CERT ' "$LOG" | grep -c 'cas=0 .*defer=[1-4]:')
            wedges=$(grep -c 'P-ICLUS-WEDGE' "$LOG")
            faults=$(grep -ciE 'kernel BUG|BUG:|Oops|general protection|Call Trace' "$LOG")
            echo "--- stage $stage cycle $cycle: P282=$p282 defer_certs=$defers wedges=$wedges faults=$faults ---"
            total_defer_certs=$(( total_defer_certs + defers ))
            if [ "$wedges" -gt 0 ]; then echo "=== FAIL: unexpected wedge at stage $stage (defer bounds should not expire in a ${WIN}s window) ==="; fail=1; fi
            if [ "$faults" -gt 0 ]; then echo "=== FAIL: kernel fault during stage $stage ==="; fail=1; fi
            if [ "$p282" -eq 0 ]; then
                cycle_all_stages=0
                echo "    (stage $stage: fault never hit in cycle $cycle)"
                [ "$cycle" = 2 ] && { echo "=== FAIL: stage $stage never exercised after 2 cycles ==="; fail=1; }
            fi
        done
        # One full cycle where every stage fired AND deferrals happened is enough.
        if [ "$cycle_all_stages" = 1 ] && [ "$total_defer_certs" -ge 1 ] && [ "$fail" = 0 ]; then
            break
        fi
    done
    after=$(counters "$TARGET")
    echo "$after" > "$OUT/counters_after.log"
    noproof=$(cfield "$after" cas_noproof_v2)
    wedged=$(cfield "$after" wedges)
    succ_b=$(cfield "$base" success); succ_a=$(cfield "$after" success)
    def_b=$(( $(cfield "$base" defer_oblig) + $(cfield "$base" defer_io) + $(cfield "$base" defer_pincil) + $(cfield "$base" defer_flush) ))
    def_a=$(( $(cfield "$after" defer_oblig) + $(cfield "$after" defer_io) + $(cfield "$after" defer_pincil) + $(cfield "$after" defer_flush) ))
    echo "--- counters: defers $def_b -> $def_a, success $succ_b -> $succ_a, cas_noproof_v2=$noproof wedges=$wedged ---"
    [ "$total_defer_certs" -ge 1 ] || [ "$def_a" -gt "$def_b" ] || { echo "=== FAIL: no deferral was ever provoked (defer path unexercised) ==="; fail=1; }
    [ "${noproof:-1}" = 0 ] || { echo "=== FAIL: cas_noproof_v2=$noproof (a CAS went through without proof) ==="; fail=1; }
    [ "${wedged:-1}" = 0 ] || { echo "=== FAIL: wedges=$wedged ==="; fail=1; }
    [ "$succ_a" -gt "$succ_b" ] || { echo "=== FAIL: no successful release after the fault windows (episodes did not resolve) ==="; fail=1; }
    ok=0
    for n in $TARGET $PEERS; do liveness "$n" post && ok=$(( ok + 1 )); done
    want=$(( 1 + $(echo "$PEERS" | wc -w) ))
    [ "$ok" = "$want" ] || { echo "=== FAIL: liveness $ok/$want after defer windows ==="; fail=1; }
    node_set "$TARGET" release_cert_log 0
    if [ "$fail" = 0 ]; then
        echo "=== relgate_fault_inject defer PASS: all stages exercised, $total_defer_certs defer cert(s), episodes resolved, cas_noproof_v2=0, liveness $ok/$want ==="
        exit 0
    fi
    echo "=== relgate_fault_inject defer FAIL — logs in $OUT ==="
    exit 1
fi

if [ "$MODE" = "wedge" ]; then
    timeout 20 "$SSH" "$TARGET" "dmesg -C" >/dev/null 2>&1
    arm 7 2500 || { echo "=== INFRA-FAIL: could not arm ==="; exit 2; }
    # Continuous churn; poll for the wedge (60s no-progress bound + margin).
    churn_start 170
    hit=0
    for i in $(seq 1 21); do
        sleep 8
        if timeout 20 "$SSH" "$TARGET" "dmesg | grep -c 'P-ICLUS-WEDGE'" 2>/dev/null | grep -qv '^0$'; then
            hit=1; break
        fi
    done
    disarm
    timeout 60 "$SSH" "$TARGET" "dmesg" > "$OUT/target_dmesg.log" 2>&1
    for p in $PEERS; do
        ( timeout 40 "$SSH" "$p" "dmesg | tail -300" > "$OUT/dmesg_$p.log" 2>&1 ) &
    done
    wait
    # Cut the churn short — the wedge (or the 170s cap) already decided.
    for p in $CHURN_PIDS; do kill "$p" 2>/dev/null; done
    CHURN_PIDS=""
    if [ "$hit" = 0 ]; then
        echo "=== INCONCLUSIVE (exit 3): no wedge within 170s of held churn — delay-only fault cannot hold a proof failure past the 60s bound; a hard-fail fault mode is needed ==="
        node_set "$TARGET" release_cert_log 0
        exit 3
    fi
    wcert=$(grep 'P280-RELEASE-CERT ' "$OUT/target_dmesg.log" | grep -c 'cas=0 .*defer=5:')
    shut=$(grep -cE 'shutdown|SHUTDOWN' "$OUT/target_dmesg.log")
    line=$(counters "$TARGET")
    noproof=$(cfield "$line" cas_noproof_v2)
    ok=0
    for p in $PEERS; do liveness "$p" postwedge && ok=$(( ok + 1 )); done
    want=$(echo "$PEERS" | wc -w)
    echo "--- wedge: P-ICLUS-WEDGE fired, wedge_certs=$wcert shutdown_lines=$shut cas_noproof_v2=${noproof:-?} peer_liveness=$ok/$want ---"
    [ "$wcert" -ge 1 ] || { echo "=== FAIL: no WEDGE certificate (defer=5, cas=0) ==="; fail=1; }
    [ "$shut" -ge 1 ] || { echo "=== FAIL: target did not force-shutdown after wedge ==="; fail=1; }
    [ "${noproof:-1}" = 0 ] || { echo "=== FAIL: cas_noproof_v2=$noproof through the wedge ==="; fail=1; }
    [ "$ok" = "$want" ] || { echo "=== FAIL: peer liveness $ok/$want — wedge was not contained ==="; fail=1; }
    if [ "$fail" = 0 ]; then
        echo "=== relgate_fault_inject wedge PASS: bounded end reached, grant pinned (never CASed unproven), peers contained ==="
        echo "    NOTE: $TARGET mount is shut down — re-prep the cluster now."
        exit 0
    fi
    echo "=== relgate_fault_inject wedge FAIL — logs in $OUT ==="
    exit 1
fi

if [ "$MODE" = "inode" ]; then
    base=$(counters "$TARGET")
    if [ -z "$base" ]; then
        echo "=== INFRA-FAIL: cannot read release counters on $TARGET ==="
        exit 2
    fi
    # The INODE sites exist only under production routing.
    icl=$(timeout 20 "$SSH" "$TARGET" "cat $PARAMS/icluster_dlm" 2>/dev/null)
    if [ "${icl:-1}" != 0 ]; then
        echo "=== INFRA-FAIL: icluster_dlm=$icl on $TARGET — inode mode needs production config (icluster_dlm=0) ==="
        exit 2
    fi
    echo "$base" > "$OUT/counters_before.log"
    total_defer_certs=0
    for cycle in 1 2; do
        WIN=15
        cycle_all_stages=1
        for stage in 7 9 10; do
            timeout 20 "$SSH" "$TARGET" "dmesg -C" >/dev/null 2>&1
            arm_force "$stage" 1 0 || { echo "=== INFRA-FAIL: could not force-arm stage $stage on $TARGET ==="; exit 2; }
            churn_start "$WIN"
            churn_wait
            disarm_force
            sleep 5   # let dwork/stranded re-arm resolve the episode
            LOG="$OUT/inode_stage${stage}_c${cycle}.log"
            timeout 40 "$SSH" "$TARGET" "dmesg" > "$LOG" 2>&1
            p282=$(grep -c "P282-RELGATE-FAULT stage=$stage .*force=1" "$LOG")
            defers=$(grep 'P280-RELEASE-CERT class=1 ' "$LOG" | grep -c 'cas=0 .*defer=[1-4]:')
            p228=$(grep -c 'P228-RELBAR' "$LOG")
            wedges=$(grep -c 'P-INODE-WEDGE' "$LOG")
            nocause=$(grep -c 'P-INODE-DEFER-NOCAUSE' "$LOG")
            faults=$(grep -ciE 'kernel BUG|BUG:|Oops|general protection|Call Trace' "$LOG")
            echo "--- inode stage $stage cycle $cycle: P282=$p282 defer_certs=$defers P228=$p228 wedges=$wedges nocause=$nocause faults=$faults ---"
            total_defer_certs=$(( total_defer_certs + defers ))
            if [ "$wedges" -gt 0 ]; then echo "=== FAIL: unexpected INODE wedge at stage $stage (a one-shot forced defer must resolve, not expire the bounds) ==="; fail=1; fi
            if [ "$nocause" -gt 0 ]; then echo "=== FAIL: P-INODE-DEFER-NOCAUSE at stage $stage (cause derivation invariant broke) ==="; fail=1; fi
            if [ "$faults" -gt 0 ]; then echo "=== FAIL: kernel fault during stage $stage ==="; fail=1; fi
            if [ "$p282" -eq 0 ]; then
                cycle_all_stages=0
                echo "    (stage $stage: fault never hit in cycle $cycle)"
                [ "$cycle" = 2 ] && { echo "=== FAIL: stage $stage never exercised after 2 cycles ==="; fail=1; }
            elif [ "$stage" != 9 ] && [ "$defers" -eq 0 ]; then
                # 7 and 10 model failures that MUST defer; 9 is the
                # transient leg (direct flush recovers in-attempt).
                cycle_all_stages=0
                echo "    (stage $stage: forced hit but no class=1 defer cert in cycle $cycle)"
                [ "$cycle" = 2 ] && { echo "=== FAIL: stage $stage forced hit produced no deferral after 2 cycles ==="; fail=1; }
            fi
        done
        if [ "$cycle_all_stages" = 1 ] && [ "$total_defer_certs" -ge 2 ] && [ "$fail" = 0 ]; then
            break
        fi
    done
    after=$(counters "$TARGET")
    echo "$after" > "$OUT/counters_after.log"
    noproof=$(cfield "$after" cas_noproof_v2)
    wedged=$(cfield "$after" wedges)
    succ_b=$(cfield "$base" success); succ_a=$(cfield "$after" success)
    echo "--- counters: success $succ_b -> $succ_a, cas_noproof_v2=$noproof wedges=$wedged ---"
    [ "$total_defer_certs" -ge 2 ] || { echo "=== FAIL: <2 forced INODE deferrals (stages 7 and 10 must each defer) ==="; fail=1; }
    [ "${noproof:-1}" = 0 ] || { echo "=== FAIL: cas_noproof_v2=$noproof (a CAS went through without proof) ==="; fail=1; }
    [ "${wedged:-1}" = 0 ] || { echo "=== FAIL: wedges=$wedged ==="; fail=1; }
    [ "$succ_a" -gt "$succ_b" ] || { echo "=== FAIL: no successful release after the fault windows (episodes did not resolve) ==="; fail=1; }
    ok=0
    for n in $TARGET $PEERS; do liveness "$n" post && ok=$(( ok + 1 )); done
    want=$(( 1 + $(echo "$PEERS" | wc -w) ))
    [ "$ok" = "$want" ] || { echo "=== FAIL: liveness $ok/$want after inode fault windows ==="; fail=1; }
    node_set "$TARGET" release_cert_log 0
    if [ "$fail" = 0 ]; then
        echo "=== relgate_fault_inject inode PASS: stages 7/9/10 force-exercised, $total_defer_certs class=1 defer cert(s), episodes resolved, cas_noproof_v2=0, liveness $ok/$want ==="
        exit 0
    fi
    echo "=== relgate_fault_inject inode FAIL — logs in $OUT ==="
    exit 1
fi

if [ "$MODE" = "inodewedge" ]; then
    icl=$(timeout 20 "$SSH" "$TARGET" "cat $PARAMS/icluster_dlm" 2>/dev/null)
    if [ "${icl:-1}" != 0 ]; then
        echo "=== INFRA-FAIL: icluster_dlm=$icl on $TARGET — inodewedge needs production config (icluster_dlm=0) ==="
        exit 2
    fi
    # One shared file; its inode is the ONLY faulted resource, so the
    # forced-defer episode (and the wedge) is contained to that inode.
    INO=$(timeout 30 "$SSH" "$TARGET" \
        "mkdir -p $WD && echo seed > $WD/wf && stat -c %i $WD/wf" 2>/dev/null | tr -d '[:space:]')
    if ! [[ "$INO" =~ ^[0-9]+$ ]] || [ "$INO" = 0 ]; then
        echo "=== INFRA-FAIL: could not create/stat the wedge file on $TARGET (got '$INO') ==="
        exit 2
    fi
    echo "--- wedge file $WD/wf ino=$INO ---"
    timeout 20 "$SSH" "$TARGET" "dmesg -C" >/dev/null 2>&1
    arm_force 7 0 "$INO" || { echo "=== INFRA-FAIL: could not force-arm ==="; exit 2; }
    churn_one_start 170 wf
    hit=0
    for i in $(seq 1 21); do
        sleep 8
        if timeout 20 "$SSH" "$TARGET" "dmesg | grep -c 'P-INODE-WEDGE '" 2>/dev/null | grep -qv '^0$'; then
            hit=1; break
        fi
    done
    disarm_force
    timeout 60 "$SSH" "$TARGET" "dmesg" > "$OUT/target_dmesg.log" 2>&1
    for p in $PEERS; do
        ( timeout 40 "$SSH" "$p" "dmesg | tail -300" > "$OUT/dmesg_$p.log" 2>&1 ) &
    done
    wait
    for p in $CHURN_PIDS; do kill "$p" 2>/dev/null; done
    CHURN_PIDS=""
    if [ "$hit" = 0 ]; then
        echo "=== FAIL: no P-INODE-WEDGE within 170s of forced no-progress churn on ino=$INO — the 60s bound did not fire ==="
        node_set "$TARGET" release_cert_log 0
        exit 1
    fi
    wcert=$(grep 'P280-RELEASE-CERT class=1 ' "$OUT/target_dmesg.log" | grep -c 'cas=0 .*defer=5:')
    wline=$(grep 'P-INODE-WEDGE ' "$OUT/target_dmesg.log" | head -1)
    fence=$(grep -c 'P-INODE-WEDGE-FENCE' "$OUT/target_dmesg.log")
    shut=$(grep -cE 'shutdown|SHUTDOWN' "$OUT/target_dmesg.log")
    line=$(counters "$TARGET")
    noproof=$(cfield "$line" cas_noproof_v2)
    ok=0
    for p in $PEERS; do liveness "$p" postwedge && ok=$(( ok + 1 )); done
    want=$(echo "$PEERS" | wc -w)
    echo "--- inodewedge: $wline"
    echo "--- inodewedge: wedge_certs=$wcert fence_hits=$fence shutdown_lines=$shut cas_noproof_v2=${noproof:-?} peer_liveness=$ok/$want ---"
    echo "$wline" | grep -q "ino=$INO " || { echo "=== FAIL: wedge fired on a different inode than the faulted one ==="; fail=1; }
    [ "$wcert" -ge 1 ] || { echo "=== FAIL: no class=1 WEDGE certificate (defer=5, cas=0) ==="; fail=1; }
    echo "$wline" | grep -qE 'pin_rc=0' || { echo "=== FAIL: wedge pin_rc!=0 — the grant was NOT pinned on disk ==="; fail=1; }
    [ "$shut" -ge 1 ] || { echo "=== FAIL: target did not force-shutdown after wedge ==="; fail=1; }
    [ "${noproof:-1}" = 0 ] || { echo "=== FAIL: cas_noproof_v2=$noproof through the wedge ==="; fail=1; }
    [ "$ok" = "$want" ] || { echo "=== FAIL: peer liveness $ok/$want — wedge was not contained ==="; fail=1; }
    [ "$fence" -ge 1 ] || echo "    (note: P-INODE-WEDGE-FENCE never observed — shutdown fence likely beat every post-wedge acquire; not a FAIL)"
    if [ "$fail" = 0 ]; then
        echo "=== relgate_fault_inject inodewedge PASS: bounded end reached on ino=$INO, grant pinned (never CASed unproven), target shut down, peers contained ==="
        echo "    NOTE: $TARGET mount is shut down — re-prep the cluster now."
        exit 0
    fi
    echo "=== relgate_fault_inject inodewedge FAIL — logs in $OUT ==="
    exit 1
fi

echo "usage: tests/relgate_fault_inject.sh [defer|wedge|inode|inodewedge] [target] [npeers]"
exit 2
