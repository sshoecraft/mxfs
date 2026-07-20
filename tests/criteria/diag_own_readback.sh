#!/bin/bash
# diag_own_readback.sh — minimal 2-node reproducer for the OWN-FILE
# readback corruption seen in cache_coherency's cross_write_read.
#
# Real symptom (cross_write_read, Phase 3):
#   "Node 2 verifies node 2 integrity: expected='fe6326bf...'
#    actual='5fa05ea9...'"
# i.e. a node reads back its OWN just-written 1MB file with a md5 that
# DIFFERS from what it wrote — and this happens AFTER a *peer* read of
# that file forced the owner node's inode lock EX -> PR downconvert.
#
# This script isolates that exact sequence on just two nodes:
#
#   Phase A  node17 writes f17 (its own 1MB file) + a sidecar .md5,
#            node18 writes f18 similarly (both nodes hold EX on their
#            own file's inode).
#   barrier "wrote"
#   Phase B  node18 reads node17's file f17  -> forces node17 EX->PR
#            downconvert (the BAST flush on node17).  Cross-read md5 is
#            compared to the sidecar md5 node17 published.
#   barrier "peerread"
#   Phase C  node17 RE-READS ITS OWN file f17.  drop_caches first so the
#            read goes to disk (post-downconvert on-disk state).  Compare
#            R17 to W17.  THIS is the key check — own-file readback after
#            the peer-induced downconvert.
#
# Per-iter records: cross-read OK/MISMATCH, own-readback OK/MISMATCH,
# sizes, and on any mismatch the first-64-byte hexdump of expected(src)
# vs actual, plus a zeros/short/other classification.
#
# Models tests/criteria/lib.sh (fresh_cluster_mount / teardown_all) and
# tests/lib/cluster.sh (dir-marker barriers).  Lives in the source tree
# per the project persistent-scripts rule.
#
# Nodes: test17 test18.  Device /dev/sda -> /mnt/shared (criteria
# defaults).  SSH: tools/mxfs_sshpass.sh NODE /tmp/.mxfs_pass "CMD".

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

# ---------- Config ----------
NODES=(test17 test18)
OWNER="${NODES[0]}"     # node17 — writes f17, re-reads its own file
PEER="${NODES[1]}"      # node18 — reads f17 to force OWNER's downconvert
ITERS=${1:-12}
OP_TIMEOUT=120          # hard per-node-op timeout (seconds)
ORB_DIR="orb"           # subdir under the mount for our files
LOGDIR="$MXFS_REPO/tests/logs"
LOG="$LOGDIR/diag_own_readback.log"
# DROP_CACHES=1 (default) does `echo 3 > drop_caches` on OWNER before the
# own re-read so the read hits disk.  Set DROP_CACHES=0 to test whether
# the mismatch surfaces from cache alone.
DROP_CACHES="${DROP_CACHES:-1}"
mkdir -p "$LOGDIR"

# Password file must already exist -- never hardcode credentials here.
if [ ! -f "$MXFS_PASS" ]; then
    echo "ERROR: $MXFS_PASS not found -- create it with the cluster root password before running this script (echo '<password>' > \"$MXFS_PASS\"; chmod 600 \"$MXFS_PASS\")." >&2
    exit 1
fi

# Whole-script watchdog: ~90s/iter + 300s for mount/teardown.
set_script_timeout $(( ITERS * 90 + 300 ))

# ---------- Logging ----------
log() {
    echo "[$(date -u +%H:%M:%S)] $1" | tee -a "$LOG"
}

# raw ssh w/ explicit per-op timeout; does NOT strip stdout lines (we
# need exact md5/hexdump bytes).
rssh() {
    local node="$1"; shift
    timeout "$OP_TIMEOUT" "$MXFS_SSH" "$node" "$MXFS_PASS" "$*"
}

# Dir-marker barrier on the shared FS (models tests/lib/cluster.sh).
# Each node touches a marker; everyone waits for `expected` markers.
barrier() {
    local name="$1" node="$2" expected="$3"
    local bdir="$MXFS_MOUNT/.orb_barriers/$name"
    rssh "$node" "
        mkdir -p '$bdir' 2>/dev/null
        touch '$bdir/$node'
        sync
        for i in \$(seq 1 120); do
            c=\$(find '$bdir' -maxdepth 1 -name 'test*' 2>/dev/null | wc -l)
            [ \"\$c\" -ge $expected ] && exit 0
            sleep 1
        done
        echo BARRIER_TIMEOUT_$name
        exit 0
    "
}

# ---------- Header ----------
{
    echo "============================================================"
    echo "diag_own_readback  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "owner=$OWNER  peer=$PEER  iters=$ITERS  drop_caches=$DROP_CACHES"
    echo "module=$MXFS_MODULE  dev=$MXFS_DEV  mnt=$MXFS_MOUNT"
    echo "============================================================"
} | tee -a "$LOG"

# ---------- Bring up a fresh 2-node cluster ----------
log "tearing down any existing mxfs on ${NODES[*]} ..."
teardown_all "${NODES[*]}"
log "mounting fresh cluster (mkfs on $OWNER, mount both) ..."
if ! fresh_cluster_mount "$OWNER" "$PEER"; then
    log "FATAL: fresh_cluster_mount failed; aborting"
    exit 2
fi
log "cluster mounted on $OWNER + $PEER at $MXFS_MOUNT"

# Create work dir + barrier root once; barrier so both nodes see it.
rssh "$OWNER" "mkdir -p $MXFS_MOUNT/$ORB_DIR $MXFS_MOUNT/.orb_barriers; sync" >/dev/null 2>&1
for NODE in "${NODES[@]}"; do
    rssh "$NODE" "mkdir -p $MXFS_MOUNT/$ORB_DIR 2>/dev/null; sync" >/dev/null 2>&1 &
done
wait
barrier "init" "$OWNER" 1 >/dev/null 2>&1
barrier "init" "$PEER"  1 >/dev/null 2>&1

# ---------- Tallies ----------
CROSS_OK=0; CROSS_MISMATCH=0
OWN_OK=0;   OWN_MISMATCH=0
TIMEOUTS=""
CAPTURED=0          # forensic captures of own-readback mismatch
FORENSICS=""

for ITER in $(seq 1 "$ITERS"); do
    log "------ ITER $ITER ------"
    F17="$MXFS_MOUNT/$ORB_DIR/f17.iter${ITER}"
    F18="$MXFS_MOUNT/$ORB_DIR/f18.iter${ITER}"

    # ===== Phase A: each node writes its OWN 1MB file + sidecar md5 =====
    # OWNER (node17): dd random -> /tmp/src17, cp to F17, sync, sidecar md5
    # (written + synced BEFORE the "wrote" barrier so PEER can read it).
    OWN_WLOG=$(mktemp -t orb_w17.XXXXXX)
    (
        rssh "$OWNER" "
            src=/tmp/src17.iter${ITER}
            dd if=/dev/urandom of=\$src bs=1M count=1 2>/dev/null
            w17=\$(md5sum \$src | awk '{print \$1}')
            cp \$src $F17
            sync
            echo \$w17 > ${F17}.md5
            sync
            sz=\$(stat -c%s $F17 2>/dev/null)
            echo W17 md5=\$w17 size=\$sz
            # keep src17 around for hexdump-on-mismatch ground truth
        " > "$OWN_WLOG" 2>&1
        echo "rc=$?" >> "$OWN_WLOG"
    ) &
    OWN_WPID=$!
    # PEER (node18) writes its own f18 similarly so it too holds EX.
    P_WLOG=$(mktemp -t orb_w18.XXXXXX)
    (
        rssh "$PEER" "
            src=/tmp/src18.iter${ITER}
            dd if=/dev/urandom of=\$src bs=1M count=1 2>/dev/null
            w18=\$(md5sum \$src | awk '{print \$1}')
            cp \$src $F18
            sync
            echo \$w18 > ${F18}.md5
            sync
            rm -f \$src
            sz=\$(stat -c%s $F18 2>/dev/null)
            echo W18 md5=\$w18 size=\$sz
        " > "$P_WLOG" 2>&1
        echo "rc=$?" >> "$P_WLOG"
    ) &
    P_WPID=$!
    wait "$OWN_WPID" 2>/dev/null
    wait "$P_WPID"   2>/dev/null

    W17=$(sed -n 's/^W17 md5=\([^ ]*\).*/\1/p' "$OWN_WLOG")
    W17SZ=$(sed -n 's/.*size=\([0-9]*\).*/\1/p' "$OWN_WLOG")
    if [ -z "$W17" ]; then
        log "  write $OWNER: FAILED/TIMEOUT -> $(tr '\n' ' ' < "$OWN_WLOG")"
        TIMEOUTS="$TIMEOUTS write17:iter$ITER"
    else
        log "  write $OWNER: W17=$W17 size=$W17SZ"
    fi
    if ! grep -q '^W18 ' "$P_WLOG"; then
        log "  write $PEER: FAILED/TIMEOUT -> $(tr '\n' ' ' < "$P_WLOG")"
        TIMEOUTS="$TIMEOUTS write18:iter$ITER"
    fi
    rm -f "$P_WLOG"

    # ===== barrier "wrote" — both files + sidecars durable =====
    barrier "wrote$ITER" "$OWNER" 2 >/dev/null 2>&1 &
    bp1=$!
    barrier "wrote$ITER" "$PEER"  2 >/dev/null 2>&1 &
    bp2=$!
    wait "$bp1" 2>/dev/null; wait "$bp2" 2>/dev/null
    log "  barrier wrote$ITER passed"

    # ===== Phase B: PEER reads OWNER's file -> forces OWNER EX->PR =====
    # Single deterministic read (no retry) — that is the genuine test.
    BLOG=$(mktemp -t orb_b.XXXXXX)
    rssh "$PEER" "
        sync
        exp=\$(cat ${F17}.md5 2>/dev/null)
        act=\$(md5sum $F17 2>/dev/null | awk '{print \$1}')
        sz=\$(stat -c%s $F17 2>/dev/null)
        echo CROSS exp=\$exp act=\$act sz=\$sz
    " > "$BLOG" 2>&1
    CEXP=$(sed -n 's/.*exp=\([^ ]*\).*/\1/p' "$BLOG")
    CACT=$(sed -n 's/.*act=\([^ ]*\).*/\1/p' "$BLOG")
    CSZ=$(sed -n 's/.*sz=\([0-9]*\).*/\1/p' "$BLOG")
    rm -f "$BLOG"
    if [ -n "$CEXP" ] && [ "$CEXP" = "$CACT" ]; then
        CROSS_OK=$((CROSS_OK+1))
        log "  CROSS-READ ($PEER reads $OWNER's f17): OK md5=$CACT sz=$CSZ"
    else
        CROSS_MISMATCH=$((CROSS_MISMATCH+1))
        log "  *** CROSS-READ MISMATCH iter$ITER expected='$CEXP' actual='$CACT' sz='$CSZ' ***"
    fi

    # ===== barrier "peerread" — the downconvert has happened =====
    barrier "peerread$ITER" "$OWNER" 2 >/dev/null 2>&1 &
    bp3=$!
    barrier "peerread$ITER" "$PEER"  2 >/dev/null 2>&1 &
    bp4=$!
    wait "$bp3" 2>/dev/null; wait "$bp4" 2>/dev/null
    log "  barrier peerread$ITER passed"

    # ===== Phase C: OWNER RE-READS ITS OWN file (the key check) =====
    DROP=""
    [ "$DROP_CACHES" = "1" ] && DROP="sync; echo 3 > /proc/sys/vm/drop_caches; sync"
    CLOG=$(mktemp -t orb_c.XXXXXX)
    rssh "$OWNER" "
        $DROP
        r17=\$(md5sum $F17 2>/dev/null | awk '{print \$1}')
        sz=\$(stat -c%s $F17 2>/dev/null)
        echo OWN r17=\$r17 sz=\$sz
    " > "$CLOG" 2>&1
    R17=$(sed -n 's/.*r17=\([^ ]*\).*/\1/p' "$CLOG")
    R17SZ=$(sed -n 's/.*sz=\([0-9]*\).*/\1/p' "$CLOG")
    rm -f "$CLOG"

    if [ -z "$W17" ]; then
        log "  OWN-READBACK iter$ITER: skipped (no W17 ground truth this iter)"
    elif [ -n "$R17" ] && [ "$R17" = "$W17" ]; then
        OWN_OK=$((OWN_OK+1))
        log "  OWN-READBACK ($OWNER re-reads own f17 after downconvert): OK md5=$R17 sz=$R17SZ"
    else
        OWN_MISMATCH=$((OWN_MISMATCH+1))
        log "  *** OWN-READBACK MISMATCH iter$ITER expected(W17)='$W17' actual(R17)='$R17' sz='$R17SZ' (correct=1048576) ***"

        # ----- maximal forensic capture -----
        # actual bytes as OWNER reads them now (post-downconvert, on disk)
        actual_hex=$(rssh "$OWNER" "od -A d -t x1 $F17 2>/dev/null | head -4")
        actual_sz=$(rssh "$OWNER" "stat -c%s $F17 2>/dev/null")
        # expected bytes = the source OWNER wrote this iter (kept in /tmp)
        expected_hex=$(rssh "$OWNER" "od -A d -t x1 /tmp/src17.iter${ITER} 2>/dev/null | head -4")
        # zeros / short / other classification on the actual file
        nonzero=$(rssh "$OWNER" "tr -d '\\000' < $F17 2>/dev/null | wc -c")
        zverdict="non-zero-content"
        [ "$nonzero" = "0" ] && zverdict="ALL-ZEROS"
        nature="OTHER"
        if [ "$zverdict" = "ALL-ZEROS" ]; then
            nature="ZEROS"
        elif [ "$actual_sz" != "1048576" ]; then
            nature="SHORT(size=$actual_sz)"
        fi
        # does the bad content match PEER's f18 this iter? (cross-file bleed)
        f18_md5=$(rssh "$OWNER" "cat ${F18}.md5 2>/dev/null")
        [ -n "$f18_md5" ] && [ "$f18_md5" = "$R17" ] && nature="OTHER-FILE(f18)"
        # does the actual on disk match the PEER's cross-read actual? (i.e.
        # both peer and owner now see the same WRONG data -> on-disk bad)
        same_as_peer="?"
        [ -n "$CACT" ] && { [ "$CACT" = "$R17" ] && same_as_peer="YES(peer-saw-same)" || same_as_peer="NO(peer-saw-different)"; }

        block=$(cat <<EOF

  --- FORENSIC: OWN-READBACK iter${ITER} owner=${OWNER} ---
    expected_md5 (W17, what owner wrote)      = ${W17}
    actual_md5   (R17, owner re-read of own)  = ${R17}
    cross-read   (peer ${PEER} saw)           = ${CACT}
    own actual matches peer cross-read?       = ${same_as_peer}
    size: write=${W17SZ} reread=${R17SZ} stat=${actual_sz}  (correct=1048576: $([ "$R17SZ" = "1048576" ] && echo YES || echo NO))
    zero_check = ${zverdict} (non-null bytes=${nonzero})
    NATURE = ${nature}
    EXPECTED first-64-bytes (owner's source /tmp/src17.iter${ITER}):
$(echo "$expected_hex" | sed 's/^/      /')
    ACTUAL first-64-bytes (owner re-read of $F17):
$(echo "$actual_hex" | sed 's/^/      /')
  --- end forensic ---
EOF
)
        FORENSICS="${FORENSICS}${block}"
        echo "$block" >> "$LOG"
        CAPTURED=$((CAPTURED+1))
    fi

    # clean up owner's src for this iter unless we just captured it
    rssh "$OWNER" "rm -f /tmp/src17.iter${ITER}" >/dev/null 2>&1 || true

    # Early stop after enough captures (max forensics, then stop).
    if [ "$CAPTURED" -ge 3 ]; then
        log "captured $CAPTURED own-readback mismatches — stopping early after iter $ITER"
        break
    fi

    # ===== iter-end barrier =====
    barrier "done$ITER" "$OWNER" 2 >/dev/null 2>&1 &
    bp5=$!
    barrier "done$ITER" "$PEER"  2 >/dev/null 2>&1 &
    bp6=$!
    wait "$bp5" 2>/dev/null; wait "$bp6" 2>/dev/null
    rm -f "$OWN_WLOG"
done

# ---------- dmesg health check ----------
log "------ dmesg health check ------"
DMESG_BAD=""
for NODE in "${NODES[@]}"; do
    cnt=$(rssh "$NODE" "dmesg 2>/dev/null | grep -cE 'BUG:|Oops|Call Trace|general protection|hung task|kernel NULL pointer|Kernel panic'" 2>/dev/null | tail -1 | tr -d ' \r\n')
    [ -z "$cnt" ] && cnt="?"
    log "  $NODE dmesg dirty count = $cnt"
    if [ "$cnt" != "0" ] && [ "$cnt" != "?" ]; then
        DMESG_BAD="$DMESG_BAD $NODE($cnt)"
        rssh "$NODE" "dmesg 2>/dev/null | grep -E 'BUG:|Oops|Call Trace|general protection|hung task|kernel NULL pointer|Kernel panic' | tail -20" >> "$LOG" 2>&1
    fi
done

# ---------- Summary ----------
{
    echo ""
    echo "============================================================"
    echo "SUMMARY  diag_own_readback  end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  iters run            = $ITER (of $ITERS requested)"
    echo "  drop_caches          = $DROP_CACHES"
    echo "  CROSS-READ  OK / MISMATCH = $CROSS_OK / $CROSS_MISMATCH  (peer reads owner's file)"
    echo "  OWN-READBACK OK / MISMATCH = $OWN_OK / $OWN_MISMATCH  (owner re-reads own file after downconvert)"
    echo "  timeouts/wedges      = ${TIMEOUTS:-none}"
    echo "  dmesg dirty nodes    = ${DMESG_BAD:-none}"
    if [ "$OWN_MISMATCH" -gt 0 ]; then
        echo "  RESULT: OWN-FILE readback corruption REPRODUCED in isolation."
        echo "  --- forensics ---"
        echo "$FORENSICS"
    else
        echo "  RESULT: own-file readback CLEAN across $ITER iters."
        echo "  (the bug did not surface in this isolated 2-node sequence)"
    fi
    echo "============================================================"
} | tee -a "$LOG"

# ---------- Teardown: PARALLEL umount, 60s per-node timeout ----------
# Serial umount;rmmod has wedged nodes in the past — avoid it.
log "tearing down cluster (parallel, 60s/node) ..."
for NODE in "${NODES[@]}"; do
    ( timeout 60 "$MXFS_SSH" "$NODE" "$MXFS_PASS" \
        "fuser -k $MXFS_MOUNT 2>/dev/null; umount $MXFS_MOUNT 2>/dev/null; sleep 1; rmmod mxfs 2>/dev/null" \
        >/dev/null 2>&1 ) &
done
wait
log "teardown complete"

exit 0
