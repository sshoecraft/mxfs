#!/bin/bash
# tcp_token_plumbing_verify.sh — verification for docs/tcp-authority-ledger.md
# build-order STEP 1 (TCP token plumbing, sess420, 0.30.0).
#
# Claim under test: on the TCP transport every lock arm in dlm/v5_mount.c now
# fills mxfs_grant_result from the master-delivered grant_gen, so the images a
# TCP node commits carry a nonzero {grant_epoch, lineage} token.  Before the
# fix every TCP image was "noepoch" (AG class) or "durnoep"/"none" (inode
# class) in the P228-TOKCLASS / P239-OWNAUTH capture-point histograms
# (pal/linux/xfs_buf_item.c), which is exactly why the replay gate could never
# match a TCP image against any manifest (D-0288).
#
# Shape (fleet already prepped 32/tcp by the caller):
#   1. srcgate: every workload node runs the TREE's srcversion.
#   2. Snapshot the last P228-TOKCLASS + P239-OWNAUTH block on each node.
#   3. Each workload node creates FILES 4 KiB files in a private directory,
#      rewrites them, then unlinks half — enough logged metadata + data
#      images to cross the 8192-token report modulus at least once.
#   4. Re-read the block; PASS iff on EVERY workload node the report advanced
#      (n grew) and the delta shows noepoch == 0, durnoep == 0, ag > 0 and
#      durable > 0.
#
# the budget rule (derived): the workload is 3 x FILES small-file ops in a PRIVATE
# dir (no cross-node contention); native XFS does 6000 such ops in ~1.5 s,
# 2x ceiling => 3 s, but the dir is on a 32-node TCP mount whose per-op
# DLM round trip is ~1 ms => ~6 s.  Workload timeout WL_S=30 s per node
# (a timeout is a FAIL, not a retry).  Whole harness ~60 s; caller bound 90 s.
#
# Usage: tests/tcp_token_plumbing_verify.sh <label> [nodes-csv] [files]
set -u
LABEL=${1:?label}
NODES=${2:-test1,test2,test3,test4}
FILES=${3:-2000}
WL_S=30
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_tcptok
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
echo "=== tcp_token_plumbing_verify label=$LABEL nodes=$NODES files=$FILES out=$OUT $(date -u +%FT%TZ) ==="

# Last complete report block per node -> $OUT/<node>.<tag>
snap() {
    local tag=$1 n
    for n in ${NODES//,/ }; do
        timeout 20 "$SSH" "$n" "grep -E 'P228-TOKCLASS n=|P239-OWNAUTH n=' /dev/null; dmesg | grep -E 'P228-TOKCLASS n=|P239-OWNAUTH n=' | tail -2" \
            2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you' > "$OUT/$n.$tag" &
    done
    wait
}
# field <file> <line-key> <field-key>  (0 when the line is absent)
field() { grep -a "$2" "$1" | tail -1 | grep -o " $3=[0-9]*" | head -1 | cut -d= -f2; }

for n in ${NODES//,/ }; do
    sv=$(timeout 20 "$SSH" "$n" "cat /sys/module/mxfs/srcversion; grep -c ' $MNT ' /proc/mounts" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you' | tr '\n' ' ')
    case "$sv" in
        "$TREE_SV 1 "*) pass "srcgate $n runs $TREE_SV and has $MNT mounted" ;;
        *) fail "srcgate $n: got '$sv' want '$TREE_SV 1'" ;;
    esac
done
[ $fails -eq 0 ] || { echo "=== tcp_token_plumbing_verify $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

snap before
t0=$(date +%s)
for n in ${NODES//,/ }; do
    (
        timeout $WL_S "$SSH" "$n" "d=$MNT/tcptok_${LABEL}_$n; mkdir -p \$d && cd \$d && \
            errs=0; t0=\$(date +%s%3N); \
            for i in \$(seq 1 $FILES); do head -c 4096 /dev/urandom > f\$i 2>/tmp/tcptok.err || { errs=\$((errs+1)); echo \"ERR create f\$i: \$(cat /tmp/tcptok.err)\"; }; done; \
            echo \"PHASE create ms=\$((\$(date +%s%3N)-t0)) errs=\$errs\"; t1=\$(date +%s%3N); \
            for i in \$(seq 1 $FILES); do head -c 4096 /dev/urandom > f\$i 2>/tmp/tcptok.err || { errs=\$((errs+1)); echo \"ERR overwrite f\$i: \$(cat /tmp/tcptok.err)\"; }; done; \
            echo \"PHASE overwrite ms=\$((\$(date +%s%3N)-t1)) errs=\$errs\"; t2=\$(date +%s%3N); \
            for i in \$(seq 1 2 $FILES); do rm f\$i 2>/tmp/tcptok.err || { errs=\$((errs+1)); echo \"ERR unlink f\$i: \$(cat /tmp/tcptok.err)\"; }; done; sync; \
            echo \"PHASE unlink ms=\$((\$(date +%s%3N)-t2)) errs=\$errs\"; [ \$errs -eq 0 ] && echo WL_OK" \
            > "$OUT/$n.wl" 2>&1; echo "rc=$?" >> "$OUT/$n.wl"
    ) &
done
wait
wall=$(( $(date +%s) - t0 ))
echo "  INFO workload wall=${wall}s (budget ${WL_S}s)"
for n in ${NODES//,/ }; do
    if grep -q '^WL_OK' "$OUT/$n.wl" && grep -q '^rc=0' "$OUT/$n.wl"; then
        pass "workload $n completed"
    else
        fail "workload $n: $(tail -2 "$OUT/$n.wl" | tr '\n' ' ')"
    fi
done
# One more sync + a metadata touch so the last partial report window flushes
# through the CIL; the histogram is emitted at the 8192-token boundary only.
for n in ${NODES//,/ }; do
    timeout 15 "$SSH" "$n" "sync; sleep 2" >/dev/null 2>&1 &
done
wait
snap after

for n in ${NODES//,/ }; do
    b="$OUT/$n.before"; a="$OUT/$n.after"
    n0=$(field "$b" P228-TOKCLASS n); n1=$(field "$a" P228-TOKCLASS n)
    ne0=$(field "$b" P228-TOKCLASS noepoch); ne1=$(field "$a" P228-TOKCLASS noepoch)
    ag0=$(field "$b" P228-TOKCLASS ag); ag1=$(field "$a" P228-TOKCLASS ag)
    du0=$(field "$b" P239-OWNAUTH durable); du1=$(field "$a" P239-OWNAUTH durable)
    dn0=$(field "$b" P239-OWNAUTH durnoep); dn1=$(field "$a" P239-OWNAUTH durnoep)
    : "${n0:=0}" "${n1:=0}" "${ne0:=0}" "${ne1:=0}" "${ag0:=0}" "${ag1:=0}" "${du0:=0}" "${du1:=0}" "${dn0:=0}" "${dn1:=0}"
    echo "  INFO $n tokens n=$n0->$n1 noepoch=$ne0->$ne1 ag=$ag0->$ag1 durable=$du0->$du1 durnoep=$dn0->$dn1"
    # sess426: the P228 counters live in the module and reset on every
    # reload; dmesg keeps the previous incarnation's last report, so a
    # 'before' sample above the 'after' one is a reload, not a regression —
    # the report advanced iff after > before, or after > 0 after a reset.
    if [ "$n1" -lt "$n0" ]; then echo "  INFO $n counters reset by a module reload (before=$n0 after=$n1): evaluating after alone"; n0=0; ne0=0; ag0=0; du0=0; dn0=0; fi
    if [ "$n1" -gt "$n0" ]; then pass "$n report advanced ($((n1-n0)) tokens)"; else fail "$n report did NOT advance (n=$n0->$n1): workload below the 8192-token modulus or capture broken"; continue; fi
    [ $((ne1-ne0)) -eq 0 ] && pass "$n noepoch delta 0" || fail "$n noepoch delta $((ne1-ne0)) — AG images still untokenized on TCP"
    [ $((dn1-dn0)) -eq 0 ] && pass "$n durnoep delta 0" || fail "$n durnoep delta $((dn1-dn0)) — DURABLE_EX inode tenures with epoch 0 on TCP"
    [ $((ag1-ag0)) -gt 0 ] && pass "$n AG-class tokens minted ($((ag1-ag0)))" || fail "$n no AG-class tokens minted"
    [ $((du1-du0)) -gt 0 ] && pass "$n durable inode tokens minted ($((du1-du0)))" || fail "$n no durable inode tokens minted"
done
for n in ${NODES//,/ }; do
    timeout 20 "$SSH" "$n" "rm -rf $MNT/tcptok_${LABEL}_$n" >/dev/null 2>&1 &
done
wait
echo "=== tcp_token_plumbing_verify $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
