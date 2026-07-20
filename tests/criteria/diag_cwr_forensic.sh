#!/bin/bash
# diag_cwr_forensic.sh — forensic discriminator for the RARE cross-node
# 1MB file-data corruption seen in the cache_coherency cross_write_read
# sub-test.
#
# Goal: when a cross-node read of a 1MB file returns the wrong bytes,
# determine WHICH failure mode it is:
#
#   * BLOCK-ALLOCATION OVERLAP  — the actual md5 of the bad file equals
#     the EXPECTED md5 of some OTHER node's file written this iter.  Two
#     nodes allocated the same on-disk extent; one file's data landed in
#     the other's blocks.
#
#   * STALE-EXTENT / DURABILITY — the actual bytes are all-zeros, a
#     short/truncated read, or some other content that matches no
#     sibling file.  The write never reached disk durably, or a stale
#     extent was read back.
#
# Models tests/cluster/test_cross_write_read.sh + tests/lib/cluster.sh
# barriers + tests/criteria/lib.sh cluster setup.
#
# Nodes: test17 test18 test19 test20 (mxfs.1 cluster).
# SSH:   tools/mxfs_sshpass.sh NODE /tmp/.mxfs_pass "CMD".
#
# Per the project rule, this lives in the source tree (tests/criteria/).

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

# ---------- Config ----------
NODES=(test17 test18 test19 test20)
ITERS=${1:-6}                  # iteration count (override via $1)
OP_TIMEOUT=180                 # hard per-node-op timeout (seconds)
CWR_DIR=".cwr"                 # subdir under the mount for our files
LOGDIR="$MXFS_REPO/tests/logs"
LOG="$LOGDIR/diag_cwr_forensic.log"
mkdir -p "$LOGDIR"

# Password file must already exist -- never hardcode credentials here.
if [ ! -f "$MXFS_PASS" ]; then
    echo "ERROR: $MXFS_PASS not found -- create it with the cluster root password before running this script (echo '<password>' > \"$MXFS_PASS\"; chmod 600 \"$MXFS_PASS\")." >&2
    exit 1
fi

# Watchdog: whole script must not exceed this wall.  Scale with ITERS:
# each iter is bounded by a handful of OP_TIMEOUT-capped parallel ops plus
# barriers; ~120s/iter is generous.  Add 300s for mount/teardown.
set_script_timeout $(( ITERS * 120 + 300 ))

# ---------- Logging ----------
log() {
    local msg="$1"
    echo "[$(date -u +%H:%M:%S)] $msg" | tee -a "$LOG"
}

# raw ssh with explicit per-op timeout (does NOT strip stdout lines like
# lib.sh ssh_node does — we need exact hexdump/md5 bytes verbatim).
rssh() {
    local node="$1"; shift
    timeout "$OP_TIMEOUT" "$MXFS_SSH" "$node" "$MXFS_PASS" "$*"
}

# ---------- Header ----------
{
    echo "============================================================"
    echo "diag_cwr_forensic  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "nodes=${NODES[*]}  iters=$ITERS  module=$MXFS_MODULE"
    echo "============================================================"
} | tee -a "$LOG"

# ---------- Bring up a fresh cluster ----------
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
log "tearing down any existing mxfs on ${NODES[*]} ..."
teardown_all "${NODES[*]}"
log "mounting fresh cluster (mkfs on $NODE0, mount all) ..."
if ! fresh_cluster_mount "$NODE0" "${REST[@]}"; then
    log "FATAL: fresh_cluster_mount failed; aborting"
    exit 2
fi
log "cluster mounted on all ${#NODES[@]} nodes at $MXFS_MOUNT"

# Create the shared work dir + barrier root once, from node0.
rssh "$NODE0" "mkdir -p $MXFS_MOUNT/$CWR_DIR $MXFS_MOUNT/.cwr_barriers; sync" >/dev/null 2>&1

# ---------- Barrier helpers (dir-marker barrier on the shared FS) ----------
# Each node touches a marker; everyone waits for all N markers.
barrier() {
    local name="$1" node="$2" expected="$3"
    local bdir="$MXFS_MOUNT/.cwr_barriers/$name"
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

# ---------- Per-iter machinery ----------
TOTAL_READS=0
TOTAL_MISMATCH=0
TOTAL_MISSING=0         # harness visibility lags (not data corruption)
MISMATCH_DETAILS=""     # accumulated forensic blocks
TIMEOUTS=""

N=${#NODES[@]}

for ITER in $(seq 1 "$ITERS"); do
    log "------ ITER $ITER ------"

    # --- Phase 0: ensure $CWR_DIR is coherent on every node BEFORE any
    # write.  Node0 created it at startup, but on a fresh cluster the
    # dirent may not yet be visible on the other nodes (DLM dir-lock not
    # yet acquired).  Each node mkdir -p's (idempotent) then we barrier so
    # the directory is durably present cluster-wide before writes begin.
    # Without this, iter1 races: a write lands "No such file or directory"
    # and looks like a (false) data mismatch. ---
    declare -A DPID
    for NODE in "${NODES[@]}"; do
        rssh "$NODE" "mkdir -p $MXFS_MOUNT/$CWR_DIR 2>/dev/null; sync" >/dev/null 2>&1 &
        DPID[$NODE]=$!
    done
    for NODE in "${NODES[@]}"; do wait "${DPID[$NODE]}" 2>/dev/null; done
    declare -A D2PID
    for NODE in "${NODES[@]}"; do
        barrier "d$ITER" "$NODE" "$N" >/dev/null 2>&1 &
        D2PID[$NODE]=$!
    done
    for NODE in "${NODES[@]}"; do wait "${D2PID[$NODE]}" 2>/dev/null; done

    # --- Phase 1: each node writes its distinct 1MB file + sidecar md5 ---
    # Write to a LOCAL temp first, md5 the local source, then cp onto the
    # shared mount, sync.  Sidecar md5 is the md5 of the source bytes the
    # node intended to write — the ground truth for that node's file.
    declare -A WPID
    declare -A WLOG
    for NODE in "${NODES[@]}"; do
        wlog=$(mktemp -t cwr_w.XXXXXX)
        WLOG[$NODE]="$wlog"
        (
            rssh "$NODE" "
                src=/tmp/cwr_src.${NODE}.iter${ITER}
                dst=$MXFS_MOUNT/$CWR_DIR/data_${NODE}.iter${ITER}
                dd if=/dev/urandom of=\$src bs=1M count=1 2>/dev/null
                md5=\$(md5sum \$src | awk '{print \$1}')
                # Retry the cp until the shared dir is visible on this node
                # (dirent coherence can lag right after a fresh mount).
                ok=0
                for t in \$(seq 1 10); do
                    mkdir -p $MXFS_MOUNT/$CWR_DIR 2>/dev/null
                    if cp \$src \$dst 2>/dev/null; then ok=1; break; fi
                    sync; sleep 1
                done
                if [ \$ok -ne 1 ]; then echo WRITE_FAIL_${NODE} md5=\$md5; rm -f \$src; exit 1; fi
                sync
                echo \$md5 > \${dst}.md5
                sync
                rm -f \$src
                sz=\$(stat -c%s \$dst 2>/dev/null)
                echo WROTE_${NODE} md5=\$md5 size=\$sz
            " > "$wlog" 2>&1
            echo "rc=$?" >> "$wlog"
        ) &
        WPID[$NODE]=$!
    done
    for NODE in "${NODES[@]}"; do
        wait "${WPID[$NODE]}" 2>/dev/null
        wl="${WLOG[$NODE]}"
        if grep -q 'WROTE_' "$wl"; then
            log "  write $NODE: $(grep 'WROTE_' "$wl" | head -1)"
        else
            log "  write $NODE: FAILED/TIMEOUT -> $(tr '\n' ' ' < "$wl")"
            TIMEOUTS="$TIMEOUTS write:$NODE:iter$ITER"
        fi
        rm -f "$wl"
    done

    # --- Phase 2: cross-node barrier — all writes+syncs done ---
    declare -A BPID
    for NODE in "${NODES[@]}"; do
        barrier "w$ITER" "$NODE" "$N" >/dev/null 2>&1 &
        BPID[$NODE]=$!
    done
    for NODE in "${NODES[@]}"; do wait "${BPID[$NODE]}" 2>/dev/null; done
    log "  barrier w$ITER passed"

    # --- Phase 3: each node reads ALL 4 files, verifies md5 ---
    # MATCHES tests/cluster/test_cross_write_read.sh EXACTLY: after the
    # write+sync+barrier the reader does `sync` (filesystem barrier) +
    # `sleep 2`, then reads each peer file's sidecar md5 and the data
    # file's actual md5 EXACTLY ONCE — NO retry loop on the read side.
    # The retry loop previously here masked the rare cross-node content
    # corruption bug by re-reading until coherence caught up.  We must NOT
    # retry: a single deterministic read is the genuine test.
    #
    # Per reading node, emit one line per file:
    #   READ <reader> file=<owner> expected=<md5> actual=<md5> size=<n>
    declare -A RPID
    declare -A RLOG
    for READER in "${NODES[@]}"; do
        rlog=$(mktemp -t cwr_r.XXXXXX)
        RLOG[$READER]="$rlog"
        # Build a remote loop reading every owner's file this iter.
        owners="${NODES[*]}"
        (
            rssh "$READER" "
                sync
                sleep 2
                for owner in $owners; do
                    f=$MXFS_MOUNT/$CWR_DIR/data_\${owner}.iter${ITER}
                    # SINGLE read of sidecar md5, data md5, and size — no
                    # retry.  Empty values are recorded verbatim and Phase
                    # 4 classifies them as MISSING/VISIBILITY (distinct
                    # from a real content mismatch where both sides are
                    # present but differ = GENUINE-MISMATCH).
                    exp=\$(cat \${f}.md5 2>/dev/null)
                    act=\$(md5sum \$f 2>/dev/null | awk '{print \$1}')
                    sz=\$(stat -c%s \$f 2>/dev/null)
                    echo READ $READER file=\$owner expected=\$exp actual=\$act size=\$sz
                done
            " > "$rlog" 2>&1
            echo "rc=$?" >> "$rlog"
        ) &
        RPID[$READER]=$!
    done
    for READER in "${NODES[@]}"; do wait "${RPID[$READER]}" 2>/dev/null; done

    # --- Phase 4: analyze reads, capture forensics on mismatch ---
    for READER in "${NODES[@]}"; do
        rl="${RLOG[$READER]}"
        if ! grep -q '^READ ' "$rl"; then
            log "  read $READER: FAILED/TIMEOUT -> $(tr '\n' ' ' < "$rl")"
            TIMEOUTS="$TIMEOUTS read:$READER:iter$ITER"
            rm -f "$rl"
            continue
        fi
        while IFS= read -r line; do
            case "$line" in READ\ *) : ;; *) continue ;; esac
            # parse: READ <reader> file=<owner> expected=<m> actual=<m> size=<n>
            r_reader=$(echo "$line" | awk '{print $2}')
            r_owner=$(echo "$line"  | sed -n 's/.*file=\([^ ]*\).*/\1/p')
            r_exp=$(echo "$line"    | sed -n 's/.*expected=\([^ ]*\).*/\1/p')
            r_act=$(echo "$line"    | sed -n 's/.*actual=\([^ ]*\).*/\1/p')
            r_sz=$(echo "$line"     | sed -n 's/.*size=\([^ ]*\).*/\1/p')
            TOTAL_READS=$((TOTAL_READS + 1))

            if [ -n "$r_exp" ] && [ "$r_exp" = "$r_act" ]; then
                continue   # match, good
            fi

            # Distinguish a real data divergence from a metadata
            # visibility lag.  Because the read is now SINGLE-SHOT (no
            # retry), an empty sidecar or data md5 means the sidecar or
            # data file simply was not visible/readable on this node at the
            # one moment we read it — a dirent/small-file coherence lag.
            # Classify as MISSING/VISIBILITY (distinct from a real content
            # mismatch where both sides are present but differ).
            if [ -z "$r_exp" ] || [ -z "$r_act" ]; then
                TOTAL_MISSING=$((TOTAL_MISSING + 1))
                log "  --- MISSING/VISIBILITY iter$ITER reader=$r_reader owner=$r_owner expected='$r_exp' actual='$r_act' size='$r_sz' (single-read dirent/small-file coherence lag, not 1MB data corruption) ---"
                continue
            fi

            # GENUINE-MISMATCH — both md5 non-empty and they differ.  This
            # is the bug we are hunting: maximal forensic capture.
            TOTAL_MISMATCH=$((TOTAL_MISMATCH + 1))
            log "  *** GENUINE-MISMATCH iter$ITER reader=$r_reader owner=$r_owner expected=$r_exp actual=$r_act size=$r_sz ***"

            # Cross-correlate: does actual md5 equal any sibling's EXPECTED md5?
            # Gather all sidecar md5s this iter from the reader's view.
            siblings=$(rssh "$READER" "
                for o in ${NODES[*]}; do
                    em=\$(cat $MXFS_MOUNT/$CWR_DIR/data_\${o}.iter${ITER}.md5 2>/dev/null)
                    echo \$o \$em
                done
            " 2>/dev/null)
            verdict="ZEROS/OLD/OTHER"
            collide_with=""
            while IFS= read -r sib; do
                so=$(echo "$sib" | awk '{print $1}')
                sm=$(echo "$sib" | awk '{print $2}')
                [ -z "$sm" ] && continue
                if [ "$sm" = "$r_act" ] && [ "$so" != "$r_owner" ]; then
                    verdict="OVERLAP"
                    collide_with="$so"
                fi
            done <<< "$siblings"

            # Hexdump first 64 bytes of the ACTUAL (bad) file as read by reader.
            actual_hex=$(rssh "$READER" "od -A d -t x1 $MXFS_MOUNT/$CWR_DIR/data_${r_owner}.iter${ITER} 2>/dev/null | head -4")
            actual_sz=$(rssh "$READER" "stat -c%s $MXFS_MOUNT/$CWR_DIR/data_${r_owner}.iter${ITER} 2>/dev/null")
            # Hexdump first 64 bytes of the EXPECTED SOURCE — the owner's
            # own file as the owner node itself reads it (ground truth).
            expected_hex=$(rssh "$r_owner" "od -A d -t x1 $MXFS_MOUNT/$CWR_DIR/data_${r_owner}.iter${ITER} 2>/dev/null | head -4")
            owner_md5=$(rssh "$r_owner" "md5sum $MXFS_MOUNT/$CWR_DIR/data_${r_owner}.iter${ITER} 2>/dev/null | awk '{print \$1}'")
            owner_sz=$(rssh "$r_owner" "stat -c%s $MXFS_MOUNT/$CWR_DIR/data_${r_owner}.iter${ITER} 2>/dev/null")
            # All-zeros check on the actual file (as seen by reader).
            zcheck=$(rssh "$READER" "tr -d '\\000' < $MXFS_MOUNT/$CWR_DIR/data_${r_owner}.iter${ITER} 2>/dev/null | wc -c")
            zverdict="non-zero-content"
            [ "$zcheck" = "0" ] && zverdict="ALL-ZEROS"

            block=$(cat <<EOF

  --- FORENSIC: iter${ITER} reader=${r_reader} owner=${r_owner} ---
    expected_md5 (sidecar) = ${r_exp}
    actual_md5   (reader read) = ${r_act}
    owner_md5    (owner re-read of own file) = ${owner_md5}
    size (reader stat) = ${r_sz}  actual_stat=${actual_sz}  owner_stat=${owner_sz}  (correct=1048576: $([ "$r_sz" = "1048576" ] && echo YES || echo NO))
    zero_check   = ${zverdict} (non-null bytes=${zcheck})
    CROSS-CORRELATION VERDICT = ${verdict}$([ -n "$collide_with" ] && echo " (actual matches expected md5 of ${collide_with}'s file -> ${collide_with} and ${r_owner} collided -> BLOCK-ALLOCATION OVERLAP)")
    EXPECTED-SOURCE first-64-bytes hexdump (owner ${r_owner} reads own file):
$(echo "$expected_hex" | sed 's/^/      /')
    ACTUAL first-64-bytes hexdump (as read by ${r_reader}):
$(echo "$actual_hex" | sed 's/^/      /')
  --- end forensic ---
EOF
)
            MISMATCH_DETAILS="${MISMATCH_DETAILS}${block}"
            echo "$block" >> "$LOG"
        done < "$rl"
        rm -f "$rl"
    done

    # --- Phase 5: read barrier so all nodes finish iter before next ---
    declare -A B2PID
    for NODE in "${NODES[@]}"; do
        barrier "r$ITER" "$NODE" "$N" >/dev/null 2>&1 &
        B2PID[$NODE]=$!
    done
    for NODE in "${NODES[@]}"; do wait "${B2PID[$NODE]}" 2>/dev/null; done
    log "  barrier r$ITER passed (iter $ITER complete)"
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
    echo "SUMMARY  diag_cwr_forensic  end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  iters             = $ITERS"
    echo "  total reads          = $TOTAL_READS"
    echo "  GENUINE-MISMATCH     = $TOTAL_MISMATCH  (both md5 non-empty, differ = the bug)"
    echo "  MISSING/VISIBILITY   = $TOTAL_MISSING  (single-read dirent/small-file coherence lag)"
    echo "  OK                   = $(( TOTAL_READS - TOTAL_MISMATCH - TOTAL_MISSING ))"
    echo "  timeouts/wedges    = ${TIMEOUTS:-none}"
    echo "  dmesg dirty nodes  = ${DMESG_BAD:-none}"
    if [ "$TOTAL_MISMATCH" -gt 0 ]; then
        echo "  --- mismatch forensics ---"
        echo "$MISMATCH_DETAILS"
    else
        echo "  RESULT: harness ran clean — 0 mismatches in $TOTAL_READS reads."
        echo "  (the bug is rarer than ~$TOTAL_READS reads in $ITERS iters)"
    fi
    echo "============================================================"
} | tee -a "$LOG"

# ---------- Teardown ----------
log "tearing down cluster ..."
parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

exit 0
