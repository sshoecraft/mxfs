#!/bin/bash
# diag_tinyfile_alias.sh — minimal reproducer for the TINY-FILE INODE-DATA
# aliasing bug isolated out of cache_coherency's rename_visibility.
#
# Refined symptom (rename_visibility): node1 creates two adjacent tiny
# files back-to-back — before_1 (ino 135, content "content_1_1") and
# before_2 (ino 136, content "content_1_2") — and afterward reading ino 135
# returns ino 136's content ("content_1_2").  The dirent name->ino map is
# proven correct; the FILE DATA of 135 reads as 136's data.  Files are
# TINY (~12 bytes).  Hypothesis: a local create/write/extent bug aliases
# adjacent tiny files' data.  Earlier 1MB reproducers were the wrong size
# class and came back clean.
#
# This script hunts the bug at the right size class (tiny text files),
# starting from the smallest possible config:
#
#   TEST A  single node test17, plain create (NO rename).  40 distinct
#           tiny files per iter; sync + drop_caches; read each back and
#           assert exact content.  8 iters.
#   TEST B  single node test17, WITH the rename (mirrors rename_visibility
#           exactly): create before_$i, sync, mv before_$i -> after_$i,
#           sync, drop_caches, read after_$i and assert content_$i.  8 iters.
#   TEST C  only if A and B are BOTH clean: 2-node (test17+test18), each
#           node creates its own tiny files in a shared dir, sync, barrier,
#           drop_caches, each node reads its OWN files back and asserts.
#           8 iters.
#
# For every mismatch we record: file, expected content, actual content,
# whether the actual matches an ADJACENT file's content (next/prev), and
# stat size.  We also note whether drop_caches was required (TEST A is run
# both cached and after-drop on iter 1 to settle that).
#
# Models tests/criteria/lib.sh helpers and tests/criteria/diag_own_readback.sh
# structure.  Lives in the source tree per the persistent-scripts rule.
#
# Nodes: test17 (+ test18 for TEST C).  Device /dev/sda -> /mnt/shared.
# SSH: tools/mxfs_sshpass.sh NODE /tmp/.mxfs_pass "CMD".

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

# ---------- Config ----------
N1="test17"
N2="test18"
ITERS=${ITERS:-8}
NFILES=${NFILES:-40}
OP_TIMEOUT=120          # hard per-node-op timeout (seconds)
TA_DIR="ta"             # subdir under the mount for our files
LOGDIR="$MXFS_REPO/tests/logs"
LOG="$LOGDIR/diag_tinyfile_alias.log"
mkdir -p "$LOGDIR"
: > "$LOG"

# Password file must already exist -- never hardcode credentials here.
if [ ! -f "$MXFS_PASS" ]; then
    echo "ERROR: $MXFS_PASS not found -- create it with the cluster root password before running this script (echo '<password>' > \"$MXFS_PASS\"; chmod 600 \"$MXFS_PASS\")." >&2
    exit 1
fi

# Whole-script watchdog.  A=8 iters, B=8 iters, C=8 iters; each iter is
# create+sync+read of 40 tiny files (fast).  Budget generously.
set_script_timeout $(( ITERS * 60 + 600 ))

# ---------- Logging ----------
log() { echo "[$(date -u +%H:%M:%S)] $1" | tee -a "$LOG"; }

# raw ssh w/ explicit per-op timeout; does NOT strip stdout lines.
rssh() {
    local node="$1"; shift
    timeout "$OP_TIMEOUT" "$MXFS_SSH" "$node" "$MXFS_PASS" "$*"
}

# Dir-marker barrier (for TEST C).
barrier() {
    local name="$1" node="$2" expected="$3"
    local bdir="$MXFS_MOUNT/.tfa_barriers/$name"
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
    echo "diag_tinyfile_alias  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "n1=$N1 n2=$N2  iters=$ITERS  nfiles=$NFILES"
    echo "module=$MXFS_MODULE  dev=$MXFS_DEV  mnt=$MXFS_MOUNT"
    echo "============================================================"
} | tee -a "$LOG"

# Global tallies
A_READS=0; A_MISMATCH=0
A_ADJ=0                    # of A mismatches, how many matched an adjacent file
A_DIRMAGIC=0              # of A mismatches whose bytes carry an XFS dir magic
B_READS=0; B_MISMATCH=0
B_ADJ=0
C_READS=0; C_MISMATCH=0
C_ADJ=0
A_CACHED_READS=0; A_CACHED_MISMATCH=0   # iter1 cached (no drop) probe
DROP_REQUIRED="unknown"
MISMATCH_DETAILS=""

# Classify a mismatch: does actual content match the next or prev file's
# expected content?  Args: iter, idx, actual_content.  Returns string.
classify_adjacent() {
    local iter="$1" idx="$2" actual="$3"
    local prev=$((idx-1)) next=$((idx+1))
    local exp_prev="content_${iter}_${prev}"
    local exp_next="content_${iter}_${next}"
    if [ "$actual" = "$exp_next" ]; then
        echo "ADJACENT-NEXT(f_${next})"
    elif [ "$actual" = "$exp_prev" ]; then
        echo "ADJACENT-PREV(f_${prev})"
    else
        # search all indices for which file's content it matches
        local hit="none"
        local j
        for j in $(seq 1 "$NFILES"); do
            if [ "$actual" = "content_${iter}_${j}" ]; then hit="f_${j}(non-adjacent)"; break; fi
        done
        echo "$hit"
    fi
}

# =====================================================================
# Bring up single-node cluster on N1 (mkfs + mount, just one node).
# =====================================================================
log "tearing down any existing mxfs on $N1 $N2 ..."
teardown_all "$N1 $N2"
log "mounting single-node mxfs on $N1 (mkfs + mount) ..."
if ! fresh_cluster_mount "$N1"; then
    log "FATAL: fresh_cluster_mount $N1 failed; aborting"
    exit 2
fi
log "single-node mxfs mounted on $N1 at $MXFS_MOUNT"

# =====================================================================
# TEST A — single node, plain create (no rename)
# =====================================================================
log ""
log "################ TEST A: single-node plain create ################"
for ITER in $(seq 1 "$ITERS"); do
    DIR="$MXFS_MOUNT/$TA_DIR"
    # Build the per-iter create+read script on the node.  We capture, for
    # every file, the read-back content so the coordinator can classify.
    # On iter 1 we ALSO read cached (before drop_caches) to learn whether
    # drop is required to surface the bug.
    CACHED_PROBE=""
    if [ "$ITER" = "1" ]; then
        CACHED_PROBE='
            echo "=== A-CACHED iter1 (no drop) ==="
            for i in $(seq 1 '"$NFILES"'); do
                c=$(cat "$DIR/f_$i" 2>/dev/null)
                echo "CACHED $i [$c]"
            done
        '
    fi
    OUT=$(rssh "$N1" "
        set -e
        DIR='$DIR'
        rm -rf \"\$DIR\"; mkdir -p \"\$DIR\"; cd \"\$DIR\"
        for i in \$(seq 1 $NFILES); do
            printf 'content_%d_%d\\n' $ITER \$i > \"f_\$i\"
        done
        $CACHED_PROBE
        sync; echo 3 > /proc/sys/vm/drop_caches; sync
        echo '=== A-DROPPED ==='
        for i in \$(seq 1 $NFILES); do
            # base64 the raw bytes so binary garbage (e.g. a stale dir
            # block header) survives the SSH/shell round-trip intact.
            b64=\$(base64 -w0 \"\$DIR/f_\$i\" 2>/dev/null)
            sz=\$(stat -c%s \"\$DIR/f_\$i\" 2>/dev/null)
            # also surface the first 4 magic bytes in hex for classification
            mg=\$(od -An -N4 -tx1 \"\$DIR/f_\$i\" 2>/dev/null | tr -d ' \\n')
            echo \"DROP \$i sz=\$sz mg=\$mg b64=\$b64\"
        done
        rm -f \"\$DIR\"/f_* ; sync
    " 2>&1)

    # Parse cached probe (iter1 only).  Strip CRs; use bash regex.
    if [ "$ITER" = "1" ]; then
        while IFS= read -r line; do
            line="${line%$'\r'}"
            if [[ "$line" =~ ^CACHED\ ([0-9]+)\ \[(.*)\]$ ]]; then
                idx="${BASH_REMATCH[1]}"
                act="${BASH_REMATCH[2]}"
                exp="content_${ITER}_${idx}"
                A_CACHED_READS=$((A_CACHED_READS+1))
                [ "$act" != "$exp" ] && A_CACHED_MISMATCH=$((A_CACHED_MISMATCH+1))
            fi
        done <<< "$OUT"
    fi

    # Parse dropped reads.  Strip CRs; use bash regex for safety.
    iter_mm=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        if [[ "$line" =~ ^DROP\ ([0-9]+)\ sz=([0-9]*)\ mg=([0-9a-f]*)\ b64=(.*)$ ]]; then
            idx="${BASH_REMATCH[1]}"
            sz="${BASH_REMATCH[2]}"
            mg="${BASH_REMATCH[3]}"
            b64="${BASH_REMATCH[4]}"
            act=$(printf '%s' "$b64" | base64 -d 2>/dev/null | tr -d '\0\r\n')
            exp="content_${ITER}_${idx}"
            A_READS=$((A_READS+1))
            if [ "$act" != "$exp" ]; then
                A_MISMATCH=$((A_MISMATCH+1))
                iter_mm=$((iter_mm+1))
                adj=$(classify_adjacent "$ITER" "$idx" "$act")
                case "$adj" in ADJACENT-*) A_ADJ=$((A_ADJ+1));; esac
                # XDB3=58444233 XDD3=58444433 XDB2=58443242 XDD2=58443244
                dirmagic=""
                case "$mg" in
                    58444233*) dirmagic="DIR-BLOCK-MAGIC(XDB3)";;
                    58444433*) dirmagic="DIR-DATA-MAGIC(XDD3)";;
                    58443242*) dirmagic="DIR-BLOCK-MAGIC(XDB2)";;
                    58443244*) dirmagic="DIR-DATA-MAGIC(XDD2)";;
                esac
                [ -n "$dirmagic" ] && { adj="$adj $dirmagic"; A_DIRMAGIC=$((A_DIRMAGIC+1)); }
                d="  [A iter$ITER] f_$idx exp='$exp' act='$act' sz=$sz mg=$mg match=$adj"
                MISMATCH_DETAILS="${MISMATCH_DETAILS}${d}
"
                log "  *** A MISMATCH: f_$idx exp='$exp' act='$act' sz=$sz mg=$mg match=$adj ***"
            fi
        fi
    done <<< "$OUT"
    log "  A iter$ITER: $NFILES files, mismatches=$iter_mm (running total $A_MISMATCH/$A_READS)"
done

# Settle drop_required question from iter1 probe.
if [ "$A_CACHED_MISMATCH" -gt 0 ]; then
    DROP_REQUIRED="no (mismatch present cached, before drop_caches)"
elif [ "$A_MISMATCH" -gt 0 ]; then
    DROP_REQUIRED="yes (clean cached on iter1; mismatch only after drop_caches)"
else
    DROP_REQUIRED="n/a (no mismatch in TEST A)"
fi
log "TEST A done: $A_MISMATCH/$A_READS reads mismatched (adjacent=$A_ADJ). cached-probe(iter1): $A_CACHED_MISMATCH/$A_CACHED_READS"

# =====================================================================
# TEST B — single node, WITH the rename (mirror rename_visibility)
# =====================================================================
log ""
log "################ TEST B: single-node create+rename ################"
for ITER in $(seq 1 "$ITERS"); do
    DIR="$MXFS_MOUNT/$TA_DIR"
    OUT=$(rssh "$N1" "
        set -e
        DIR='$DIR'
        rm -rf \"\$DIR\"; mkdir -p \"\$DIR\"; cd \"\$DIR\"
        # create before_\$i with distinct tiny content
        for i in \$(seq 1 $NFILES); do
            printf 'content_%d_%d\\n' $ITER \$i > \"before_\$i\"
        done
        sync
        # rename before_\$i -> after_\$i
        for i in \$(seq 1 $NFILES); do
            mv \"before_\$i\" \"after_\$i\"
        done
        sync; echo 3 > /proc/sys/vm/drop_caches; sync
        echo '=== B-DROPPED ==='
        for i in \$(seq 1 $NFILES); do
            b64=\$(base64 -w0 \"\$DIR/after_\$i\" 2>/dev/null)
            sz=\$(stat -c%s \"\$DIR/after_\$i\" 2>/dev/null)
            mg=\$(od -An -N4 -tx1 \"\$DIR/after_\$i\" 2>/dev/null | tr -d ' \\n')
            echo \"DROP \$i sz=\$sz mg=\$mg b64=\$b64\"
        done
        rm -f \"\$DIR\"/after_* \"\$DIR\"/before_* ; sync
    " 2>&1)

    iter_mm=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        if [[ "$line" =~ ^DROP\ ([0-9]+)\ sz=([0-9]*)\ mg=([0-9a-f]*)\ b64=(.*)$ ]]; then
            idx="${BASH_REMATCH[1]}"
            sz="${BASH_REMATCH[2]}"
            mg="${BASH_REMATCH[3]}"
            b64="${BASH_REMATCH[4]}"
            act=$(printf '%s' "$b64" | base64 -d 2>/dev/null | tr -d '\0\r\n')
            exp="content_${ITER}_${idx}"
            B_READS=$((B_READS+1))
            if [ "$act" != "$exp" ]; then
                B_MISMATCH=$((B_MISMATCH+1))
                iter_mm=$((iter_mm+1))
                adj=$(classify_adjacent "$ITER" "$idx" "$act")
                case "$adj" in ADJACENT-*) B_ADJ=$((B_ADJ+1));; esac
                case "$mg" in
                    58444233*) adj="$adj DIR-BLOCK-MAGIC(XDB3)";;
                    58444433*) adj="$adj DIR-DATA-MAGIC(XDD3)";;
                    58443242*) adj="$adj DIR-BLOCK-MAGIC(XDB2)";;
                    58443244*) adj="$adj DIR-DATA-MAGIC(XDD2)";;
                esac
                d="  [B iter$ITER] after_$idx exp='$exp' act='$act' sz=$sz mg=$mg match=$adj"
                MISMATCH_DETAILS="${MISMATCH_DETAILS}${d}
"
                log "  *** B MISMATCH: after_$idx exp='$exp' act='$act' sz=$sz mg=$mg match=$adj ***"
            fi
        fi
    done <<< "$OUT"
    log "  B iter$ITER: $NFILES files, mismatches=$iter_mm (running total $B_MISMATCH/$B_READS)"
done
log "TEST B done: $B_MISMATCH/$B_READS reads mismatched (adjacent=$B_ADJ)"

# =====================================================================
# TEST C — 2-node shared dir (only if A and B BOTH clean)
# =====================================================================
RUN_C=0
if [ "$A_MISMATCH" -eq 0 ] && [ "$B_MISMATCH" -eq 0 ]; then
    RUN_C=1
fi

if [ "$RUN_C" = "1" ]; then
    log ""
    log "############ TEST C: 2-node shared-dir tiny files ############"
    log "A and B both clean -> bringing $N2 into the cluster"
    # Add N2 to the existing mount (N1 already mounted).  fresh_cluster_mount
    # re-mkfs's; instead just mount N2 against the live FS.
    rssh "$N2" "
        for try in 1 2 3 4 5; do
            mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
            [ -f $MXFS_MODULE ] && break
            sleep 2
        done
        $MXFS_PREP >/tmp/prep.log 2>&1
        modprobe libcrc32c
        insmod $MXFS_MODULE 2>/dev/null
        mount -t mxfs -o dlm_transport=tcp $MXFS_DEV $MXFS_MOUNT && echo MOUNTED_N2
    " 2>&1 | tee -a "$LOG"
    if ! rssh "$N2" "mount | grep -q ' on $MXFS_MOUNT type mxfs'" >/dev/null 2>&1; then
        log "WARN: $N2 failed to join; skipping TEST C"
        RUN_C=0
    fi
fi

if [ "$RUN_C" = "1" ]; then
    for ITER in $(seq 1 "$ITERS"); do
        DIR="$MXFS_MOUNT/$TA_DIR"
        # Each node owns a distinct file namespace in the SAME shared dir.
        # Node 1 uses prefix n1_, node 2 uses n2_.  Content embeds node id.
        # n1=1, n2=2 for content tagging.
        rssh "$N1" "mkdir -p $MXFS_MOUNT/.tfa_barriers $DIR 2>/dev/null; sync" >/dev/null 2>&1
        barrier "Cinit$ITER" "$N1" 1 >/dev/null 2>&1
        barrier "Cinit$ITER" "$N2" 1 >/dev/null 2>&1

        # both nodes create their own tiny files concurrently
        CW1=$(mktemp); CW2=$(mktemp)
        ( rssh "$N1" "
            cd $DIR
            for i in \$(seq 1 $NFILES); do printf 'content_1_%d\\n' \$i > \"n1_\$i\"; done
            sync
            echo N1_WROTE
          " > "$CW1" 2>&1 ) &
        ( rssh "$N2" "
            cd $DIR
            for i in \$(seq 1 $NFILES); do printf 'content_2_%d\\n' \$i > \"n2_\$i\"; done
            sync
            echo N2_WROTE
          " > "$CW2" 2>&1 ) &
        wait
        rm -f "$CW1" "$CW2"

        barrier "Cwrote$ITER" "$N1" 2 >/dev/null 2>&1 &
        barrier "Cwrote$ITER" "$N2" 2 >/dev/null 2>&1 &
        wait

        # each node drops caches then reads its OWN files back
        for spec in "$N1 1 n1" "$N2 2 n2"; do
            set -- $spec
            node="$1"; nid="$2"; pfx="$3"
            CR=$(rssh "$node" "
                sync; echo 3 > /proc/sys/vm/drop_caches; sync
                cd $DIR
                for i in \$(seq 1 $NFILES); do
                    b64=\$(base64 -w0 \"${pfx}_\$i\" 2>/dev/null)
                    sz=\$(stat -c%s \"${pfx}_\$i\" 2>/dev/null)
                    mg=\$(od -An -N4 -tx1 \"${pfx}_\$i\" 2>/dev/null | tr -d ' \\n')
                    echo \"DROP \$i sz=\$sz mg=\$mg b64=\$b64\"
                done
            " 2>&1)
            iter_mm=0
            while IFS= read -r line; do
                line="${line%$'\r'}"
                if [[ "$line" =~ ^DROP\ ([0-9]+)\ sz=([0-9]*)\ mg=([0-9a-f]*)\ b64=(.*)$ ]]; then
                    idx="${BASH_REMATCH[1]}"
                    sz="${BASH_REMATCH[2]}"
                    mg="${BASH_REMATCH[3]}"
                    b64="${BASH_REMATCH[4]}"
                    act=$(printf '%s' "$b64" | base64 -d 2>/dev/null | tr -d '\0\r\n')
                    exp="content_${nid}_${idx}"
                    C_READS=$((C_READS+1))
                    if [ "$act" != "$exp" ]; then
                        C_MISMATCH=$((C_MISMATCH+1))
                        iter_mm=$((iter_mm+1))
                        # adjacency within this node's own namespace
                        prev=$((idx-1)); next=$((idx+1))
                        adj="none"
                        if [ "$act" = "content_${nid}_${next}" ]; then adj="ADJACENT-NEXT(${pfx}_${next})"; C_ADJ=$((C_ADJ+1));
                        elif [ "$act" = "content_${nid}_${prev}" ]; then adj="ADJACENT-PREV(${pfx}_${prev})"; C_ADJ=$((C_ADJ+1)); fi
                        case "$mg" in
                            58444233*) adj="$adj DIR-BLOCK-MAGIC(XDB3)";;
                            58444433*) adj="$adj DIR-DATA-MAGIC(XDD3)";;
                            58443242*) adj="$adj DIR-BLOCK-MAGIC(XDB2)";;
                            58443244*) adj="$adj DIR-DATA-MAGIC(XDD2)";;
                        esac
                        d="  [C iter$ITER $node] ${pfx}_$idx exp='$exp' act='$act' sz=$sz mg=$mg match=$adj"
                        MISMATCH_DETAILS="${MISMATCH_DETAILS}${d}
"
                        log "  *** C MISMATCH ($node): ${pfx}_$idx exp='$exp' act='$act' sz=$sz mg=$mg match=$adj ***"
                    fi
                fi
            done <<< "$CR"
        done

        # cleanup files for next iter
        rssh "$N1" "rm -f $DIR/n1_* $DIR/n2_*; sync" >/dev/null 2>&1
        barrier "Cdone$ITER" "$N1" 2 >/dev/null 2>&1 &
        barrier "Cdone$ITER" "$N2" 2 >/dev/null 2>&1 &
        wait
        log "  C iter$ITER: mismatches=$iter_mm (running total $C_MISMATCH/$C_READS)"
    done
    log "TEST C done: $C_MISMATCH/$C_READS reads mismatched (adjacent=$C_ADJ)"
else
    if [ "$A_MISMATCH" -ne 0 ] || [ "$B_MISMATCH" -ne 0 ]; then
        log ""
        log "TEST C SKIPPED: A or B already reproduced (A=$A_MISMATCH B=$B_MISMATCH); single-node is the smaller config."
    fi
fi

# =====================================================================
# dmesg health
# =====================================================================
log ""
log "------ dmesg health check ------"
DMESG_BAD=""
CNODES="$N1"
[ "$RUN_C" = "1" ] && CNODES="$N1 $N2"
for NODE in $CNODES; do
    cnt=$(rssh "$NODE" "dmesg 2>/dev/null | grep -cE 'BUG:|Oops|Call Trace|general protection|hung task|kernel NULL pointer|Kernel panic'" 2>/dev/null | tail -1 | tr -d ' \r\n')
    [ -z "$cnt" ] && cnt="?"
    log "  $NODE dmesg dirty count = $cnt"
    if [ "$cnt" != "0" ] && [ "$cnt" != "?" ]; then
        DMESG_BAD="$DMESG_BAD $NODE($cnt)"
        rssh "$NODE" "dmesg 2>/dev/null | grep -E 'BUG:|Oops|Call Trace|general protection|hung task|kernel NULL pointer|Kernel panic' | tail -20" >> "$LOG" 2>&1
    fi
done

# =====================================================================
# Summary
# =====================================================================
SMALLEST="none-in-${ITERS}-iters"
if [ "$A_MISMATCH" -gt 0 ]; then SMALLEST="single-node-plain (TEST A)";
elif [ "$B_MISMATCH" -gt 0 ]; then SMALLEST="single-node-rename (TEST B)";
elif [ "$C_MISMATCH" -gt 0 ]; then SMALLEST="2-node (TEST C)"; fi

# Are bad reads always adjacent?
adj_verdict="n/a"
total_mm=$((A_MISMATCH + B_MISMATCH + C_MISMATCH))
total_adj=$((A_ADJ + B_ADJ + C_ADJ))
if [ "$total_mm" -gt 0 ]; then
    if [ "$total_adj" -eq "$total_mm" ]; then adj_verdict="ALWAYS adjacent ($total_adj/$total_mm)";
    elif [ "$total_adj" -eq 0 ]; then adj_verdict="NEVER adjacent (0/$total_mm)";
    else adj_verdict="SOMETIMES adjacent ($total_adj/$total_mm)"; fi
fi

{
    echo ""
    echo "============================================================"
    echo "SUMMARY  diag_tinyfile_alias  end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  iters=$ITERS  nfiles=$NFILES"
    echo "  TEST A (single-node plain):   mismatch/reads = $A_MISMATCH/$A_READS  (adjacent=$A_ADJ)"
    echo "  TEST A cached probe (iter1):  mismatch/reads = $A_CACHED_MISMATCH/$A_CACHED_READS"
    echo "  drop_caches required:         $DROP_REQUIRED"
    echo "  TEST B (single-node rename):  mismatch/reads = $B_MISMATCH/$B_READS  (adjacent=$B_ADJ)"
    if [ "$RUN_C" = "1" ]; then
        echo "  TEST C (2-node shared dir):   mismatch/reads = $C_MISMATCH/$C_READS  (adjacent=$C_ADJ)"
    else
        echo "  TEST C (2-node shared dir):   not run"
    fi
    echo "  smallest config reproducing:  $SMALLEST"
    echo "  bad data adjacency:           $adj_verdict"
    echo "  bad bytes carry XFS dir-magic: $A_DIRMAGIC of $A_MISMATCH TEST-A mismatches (XDB3/XDD3 = a dir block aliased into the file's data extent)"
    echo "  dmesg dirty nodes:            ${DMESG_BAD:-none}"
    if [ "$total_mm" -gt 0 ]; then
        echo "  --- mismatch details ---"
        printf '%s' "$MISMATCH_DETAILS"
    else
        echo "  RESULT: tiny-file data aliasing did NOT reproduce in any test."
    fi
    echo "============================================================"
} | tee -a "$LOG"

# =====================================================================
# Teardown: PARALLEL umount, 60s per-node timeout
# =====================================================================
log "tearing down cluster (parallel, 60s/node) ..."
for NODE in $N1 $N2; do
    ( timeout 60 "$MXFS_SSH" "$NODE" "$MXFS_PASS" \
        "fuser -k $MXFS_MOUNT 2>/dev/null; umount $MXFS_MOUNT 2>/dev/null; sleep 1; rmmod mxfs 2>/dev/null" \
        >/dev/null 2>&1 ) &
done
wait
log "teardown complete"

exit 0
