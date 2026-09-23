#!/bin/sh
# d512_t8_inject.sh — D-512 cycle-2 verification T8 (sess415 ruling item 11):
# impossible-state containment via the 0.28.5 synthetic drain-failure
# injectors (dbg_rel_fail_ino / dbg_rel_fail_kind, one-shot per-ino):
#
#   kind 2  site-1 invalidate failure  (benign: unlock refused, grant kept,
#           dwork retry re-runs the drain and completes — bounded liveness)
#   kind 1  site-1 writeback failure   (fail-stop: wedge + shutdown)
#   kind 3  site-2 post-NL flush fail  (fail-stop: wedge + shutdown)
#   kind 4  protective-reload dirty-mismatch (poison + fail-stop shutdown)
#
# Required asserts (ruling: "must freeze/withdraw, never return to service"):
#   - P-D512-INJECT kind=N fired on H;
#   - the containment marker fired (INVFAIL / WBFAIL / DRAIN2-WBFAIL /
#     DIRTY-MISMATCH [+ P-INODE-WEDGE for 1/3]);
#   - destructive kinds: H's mount is DEAD (probe write fails) and W's
#     blocked read was NOT served early (still blocked at +8s — the unlock
#     was never published over the failed drain);
#   - kind 2: W's read COMPLETES bounded (<=30s) with H's md5 (retry drain
#     released coherently) and H's mount stays ALIVE;
#   - zero splats (BUG:/Oops) on every involved node.
# W-read eventual completion after H's withdraw+recovery is recorded as
# INFO (RECOVERY lines) — liveness disposal is ndr's domain, but an rc=0
# completion with garbage content would be a real defect: md5s printed.
#
# Uses DISJOINT holder nodes per kind so one wedge cannot mask the next
# trigger; leaves up to 3 nodes wedged/shutdown — RUN `./run.sh 32 caw
# prep_cluster` AFTER this test before any other rig work.
#
# the budget rule (derived): srcgate 10s + kind2 ~45s + 3 destructive triggers
# ~35s each + final harvest bounded by the LAST read's 200s window
# => ~370s. Caller bound 420s.
#
# Usage: tests/d512_t8_inject.sh <label> [W] [H2] [H1] [H3] [H4]
#        (defaults: test1 test2 test3 test4 test5)
set -u
LABEL=${1:?label}
W=${2:-test1}; H2=${3:-test2}; H1=${4:-test3}; H3=${5:-test4}; H4=${6:-test5}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${D512_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d512t8}
mkdir -p "$OUT"
# rs/rsx/measure/capture_require (tests/lib/rig.sh): the kernel-log captures
# a verdict is counted from cross the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.  Adopted by reading
# (a 5-node harness: no fault/healthy lap on the 2-node rig).
. "$(dirname "$0")/lib/rig.sh"
P=/sys/module/mxfs/parameters
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS

D="$MNT/.d512t8_$LABEL"
echo "=== d512_t8_inject label=$LABEL W=$W kinds: 2=$H2 1=$H1 3=$H3 4=$H4 out=$OUT $(date -u +%FT%TZ) ==="

# -- build-identity gate: every involved node must run the injector build --
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
for n in "$W" "$H2" "$H1" "$H3" "$H4"; do
    nsv=$(timeout 15 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | filt | tr -dc 'A-F0-9')
    if [ "$nsv" != "$TREESV" ]; then
        echo "ABORT: $n runs srcversion '$nsv' != tree '$TREESV' — prep_cluster with 0.28.5 first"
        exit 2
    fi
done
echo "  build gate OK: all 5 nodes on $TREESV"
MARKPFX="D512T8-$LABEL-$$"
timeout 20 $SSH "$H2" "mkdir -p '$D'" >/dev/null 2>&1

arm_and_dirty() { # $1=holder $2=file $3=kind -> prints "md5 ino" via $OUT file
    timeout 25 $SSH "$1" "
        echo '$MARKPFX' > /dev/kmsg
        dd if=/dev/urandom of='$2' bs=4096 count=8 2>/dev/null || exit 1
        ino=\$(stat -c %i '$2')
        echo \$ino > $P/dbg_rel_fail_ino
        echo $3 > $P/dbg_rel_fail_kind
        dd if=/dev/urandom of='$2' bs=4096 count=8 2>/dev/null || exit 1
        md5sum '$2' | cut -d' ' -f1
        echo \$ino
      " 2>/dev/null | filt
}
hdmesg() { rs 25 "$1" "dmesg | sed -n \"/$MARKPFX/,\\\$p\""; }   # polling only (markwait); never counted
hdm() { measure "$1" 25 "$2" '^DMESG_END$' "the kernel log on $1 from the lap marker" "dmesg | sed -n \"/$MARKPFX/,\\\$p\"; echo DMESG_END"; }
markwait() { # $1=holder $2=grep-pattern $3=secs — poll dmesg-from-mark
    i=0
    while [ "$i" -lt "$3" ]; do
        if hdmesg "$1" | grep -aq "$2"; then return 0; fi
        sleep 1; i=$((i+1))
    done
    return 1
}

# ---------------- kind 2: invalidate failure (benign retry) ----------------
echo "--- kind 2 (site-1 invalidate fail -> refuse unlock, retry) H=$H2 ---"
F="$D/k2.dat"
arm_and_dirty "$H2" "$F" 2 > "$OUT/h_k2.txt"
hmd5=$(sed -n 1p "$OUT/h_k2.txt" | tr -dc 'a-f0-9')
if [ -z "$hmd5" ]; then echo "  FAIL kind2 setup"; fails=$((fails+1)); else
    t0=$(date +%s%N)
    value_now_into wmd5 "$W" 35 "$OUT/rv_wmd5_1.txt" '^[0-9a-f]{32}$' "wmd5 on $W" "md5sum '$F' | cut -d' ' -f1"
    t1=$(date +%s%N); wall_ms=$(( (t1 - t0) / 1000000 ))
    hdm "$H2" "$OUT/dmesg_k2.txt"
    ck "kind2: P-D512-INJECT fired" "$(grep -ac 'P-D512-INJECT ino=[0-9]* kind=2' "$OUT/dmesg_k2.txt" | sed 's/^0$/0/;s/^[1-9][0-9]*$/1/')" "1"
    ck "kind2: INVFAIL containment marker" "$(grep -ac 'P-D512-REL-DRAIN-INVFAIL' "$OUT/dmesg_k2.txt" | sed 's/^[1-9][0-9]*$/1/')" "1"
    ck "kind2: no wedge (retry path, not fail-stop)" "$(grep -ac 'P-INODE-WEDGE' "$OUT/dmesg_k2.txt")" "0"
    ck "kind2: W read completed bounded (<=30s)" "$([ -n "$wmd5" ] && [ "$wall_ms" -le 30000 ] && echo yes || echo no:${wall_ms}ms)" "yes"
    ck "kind2: W md5 == H md5" "$([ "$wmd5" = "$hmd5" ] && echo same || echo differ)" "same"
    value_now_into alive "$H2" 10 "$OUT/rv_alive_2.txt" '^ok$' "alive on $H2" "touch '$D/k2probe' && echo ok"; alive=$(printf '%s\n' "$alive" | tr -dc 'a-z')
    ck "kind2: H mount still alive" "$alive" "ok"
    echo "  INFO kind2 wall=${wall_ms}ms"
fi

# ------------- destructive kinds 1/3/4: trigger + containment --------------
# W's reads run bg from clyde with their own 200s timeout; harvested at end.
# v2 (sess416): NO command substitution around the launcher — $(...) waits
# for EOF on the inherited pipe, so the first run's "+8s still blocked"
# check silently ran only AFTER the read completed (68s for kind 1).  The
# pid comes back in TRPID; rc is the ssh/timeout rc, not the filter's.
trigger_read() { # $1=file $2=tag — bg read, records rc + md5 + wall
    (
        s0=$(date +%s)
        # sess418: `md5sum | cut` returned cut's rc (0) even when md5sum
        # FAILED — the TCP lap reported rc=0 md5=<empty> for a read that
        # died EIO in a quarantined domain.  Capture md5sum's own rc and
        # its stderr so a failed read is never reported as a success.
        timeout 200 $SSH "$W" "m=\$(md5sum '$1' 2>&1); rc=\$?; echo \"\$m\" | cut -d' ' -f1; exit \$rc" > "$OUT/wraw_$2.txt" 2>/dev/null
        rc=$?
        s1=$(date +%s)
        r=$(filt < "$OUT/wraw_$2.txt" | head -1 | tr -dc 'a-f0-9')
        [ "$rc" -ne 0 ] && r="FAILED($(filt < "$OUT/wraw_$2.txt" | tr -d '\n' | cut -c1-80))"
        echo "rc=$rc wall_s=$((s1 - s0)) md5=$r" > "$OUT/wread_$2.txt"
    ) &
    TRPID=$!
}

dk() { # $1=kind $2=holder $3=inject-marker-extra-pattern
    k=$1; H=$2; cpat=$3
    echo "--- kind $k (fail-stop) H=$H ---"
    F="$D/k$k.dat"
    if [ "$k" = 4 ]; then
        # kind 4 trigger: H writes, W reads (H releases), arm on H, H re-reads
        # -> re-acquire -> protective reload -> injected dirty-mismatch.
        timeout 25 $SSH "$H" "echo '$MARKPFX' > /dev/kmsg; dd if=/dev/urandom of='$F' bs=4096 count=8 2>/dev/null && md5sum '$F' | cut -d' ' -f1 && stat -c %i '$F'" 2>/dev/null | filt > "$OUT/h_k4.txt"
        hmd5=$(sed -n 1p "$OUT/h_k4.txt" | tr -dc 'a-f0-9')
        ino=$(sed -n 2p "$OUT/h_k4.txt" | tr -dc '0-9')
        if [ -z "$ino" ]; then echo "  FAIL kind4 setup"; fails=$((fails+1)); return; fi
        timeout 30 $SSH "$W" "md5sum '$F'" >/dev/null 2>&1   # BAST H -> release
        sleep 1
        timeout 20 $SSH "$H" "echo $ino > $P/dbg_rel_fail_ino; echo 4 > $P/dbg_rel_fail_kind" >/dev/null 2>&1
        timeout 30 $SSH "$H" "cat '$F' > /dev/null 2>&1; echo reread_rc=\$?" 2>/dev/null | filt > "$OUT/h_k4_reread.txt"
        rpid=""
    else
        arm_and_dirty "$H" "$F" "$k" > "$OUT/h_k$k.txt"
        hmd5=$(sed -n 1p "$OUT/h_k$k.txt" | tr -dc 'a-f0-9')
        if [ -z "$hmd5" ]; then echo "  FAIL kind$k setup"; fails=$((fails+1)); return; fi
        trigger_read "$F" "k$k"; rpid=$TRPID  # BASTs H -> injected drain fail
        sleep 8
        if kill -0 "$rpid" 2>/dev/null; then early=blocked; else early=served; fi
        ck "kind$k: W not served early (blocked @8s)" "$early" "blocked"
    fi
    if markwait "$H" "P-D512-INJECT ino=[0-9]* kind=$k" 20; then inj=1; else inj=0; fi
    ck "kind$k: P-D512-INJECT fired" "$inj" "1"
    hdm "$H" "$OUT/dmesg_k$k.txt"
    ck "kind$k: containment marker" "$(grep -ac "$cpat" "$OUT/dmesg_k$k.txt" | sed 's/^[1-9][0-9]*$/1/')" "1"
    if [ "$k" != 4 ]; then
        ck "kind$k: grant pinned (P-INODE-WEDGE)" "$(grep -ac 'P-INODE-WEDGE' "$OUT/dmesg_k$k.txt" | sed 's/^[1-9][0-9]*$/1/')" "1"
    fi
    value_now_into dead "$H" 10 "$OUT/rv_dead_3.txt" '^(alive|dead)$' "dead on $H" "touch '$D/k${k}probe' 2>/dev/null && echo alive || echo dead"; dead=$(printf '%s\n' "$dead" | tr -dc 'a-z')
    ck "kind$k: H mount dead (never returns to service)" "$dead" "dead"
    echo "$hmd5" > "$OUT/hmd5_k$k.txt"
}

dk 1 "$H1" 'P-D512-REL-DRAIN-WBFAIL'
dk 3 "$H3" 'P-D512-DRAIN2-WBFAIL'
dk 4 "$H4" 'P-D512-DIRTY-MISMATCH'

# kind-4 extra: the wedged/poisoned holder's own re-read must not have
# returned garbage silently — record its rc (nonzero expected).
if [ -s "$OUT/h_k4_reread.txt" ]; then
    echo "  INFO kind4 H reread: $(cat "$OUT/h_k4_reread.txt")"
fi

# ------------------------- harvest + splat sweep ---------------------------
echo "--- harvest (bounded by the reads' own 200s timeouts) ---"
wait
for k in 1 3; do
    if [ -s "$OUT/wread_k$k.txt" ]; then
        echo "  RECOVERY kind$k W-read: $(cat "$OUT/wread_k$k.txt") (H md5 $(cat "$OUT/hmd5_k$k.txt" 2>/dev/null))"
    fi
done
for n in "$W" "$H2" "$H1" "$H3" "$H4"; do
    window_into "$OUT/rv_s_4.txt" "$n" 25; s=$(cat "$OUT/rv_s_4.txt" | grep -aEc 'BUG:|Oops' | tr -dc '0-9')
    ck "zero splats on $n" "${s:-nossh}" "0"
done

echo "NOTE: nodes $H1 $H3 $H4 are wedged/shutdown by design — run './run.sh 32 caw prep_cluster' before further rig work."
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS: T8 injector matrix 4/4 kinds contained"; exit 0; fi
echo "VERDICT FAIL: $fails assertion(s)"; exit 1
