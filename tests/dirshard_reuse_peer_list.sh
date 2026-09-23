#!/bin/bash
# dirshard_reuse_peer_list.sh [creator] [peer] [laps]
#
# D-0533 directed verification (sess473): a PEER that has CACHED the members
# of a sharded directory must still see the directory correctly after the
# creator removes it and the next sharded mkdir REUSES those inode numbers
# for a different incarnation.  Before the 0.64.19 fix the peer's lock-less
# manifest probe returned its stale cached shell (old generation) and readdir
# failed EUCLEAN ('Structure needs cleaning'); on the deletion path the same
# stale shell read as "already gone" and the manifest bit was cleared over a
# live container (the D-0526 leak shape).
#
# Arm A (list after reuse), per lap:
#   creator: sharded mkdir A (N=16) + 8 files     peer: ls A (caches members)
#   creator: rm files, rmdir A, sharded mkdir B (N=16) + 8 files
#   peer:    ls B  -> must list 8, rc 0, and take < 300 ms (budget: a 16-shard
#            listing of 8 files; measured 20-60 ms on a warm peer)
# Arm B (peer rmdir after reuse), per lap:
#   creator: sharded mkdir C + 8 files            peer: ls C (caches members)
#   creator: rm files, rmdir C, sharded mkdir D (N=16), no files
#   peer:    rmdir D -> must succeed (its free path probes members it cached
#            under C's incarnation); creator: stat D -> ENOENT
# The chain's fleet-unmount chk_mxfs afterwards must show no 'leaked internal
# inode' (arm B's failure mode on the platter).
#
# Verdict: every lap's peer listing count/rc/pace and peer rmdir rc, plus the
# peer's kernel log: P-DIRSHARD-STRANGER = 0 and P-DIRSHARD-SHELL-UNCONVERGED
# = 0.  P-DIRSHARD-SHELL / -ADOPTED counts are reported (they are the fix
# engaging: nonzero proves the stale-shell mechanism was exercised; zero means
# the peer never held a stale shell and the lap was vacuous for D-0533).
#
# derived time budgets: sharded mkdir N=16 < 2 s, rmdir < 2 s, 8 creates < 1 s,
# peer listing < 300 ms; per lap ~6 ssh calls (~3 s) -> 20 laps < 200 s.
# Exit 0 PASS, 1 FAIL, 2 INFRA.
set -u
N1=${1:-test1}; N2=${2:-test2}; LAPS=${3:-20}
MNT=/mnt/shared
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH=$REPO/tools/mxfs_sshpass.sh
PY=/src/mxfs/tests/dirshard_ioctl.py
PACE_MS=300
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/tests/evidence/${TS}_dirshard_reuse_peer
mkdir -p "$OUT"
fails=0; vacuous=0
say() { echo "[dsreuse] $*"; }
fail() { say "FAIL: $*"; fails=$((fails+1)); }
r() { # r <node> <cmd>  (banner-stripped stdout; rc in $RC)
    local n="$1"; shift
    local o
    o=$(timeout 60 "$SSH" "$n" "$@" 2>&1); RC=$?
    echo "$o" | grep -av '^Unauthorized access\|^If you are not\|^Warning: Permanently\|^$'
}
echo "=== dirshard_reuse_peer_list creator=$N1 peer=$N2 laps=$LAPS @ $TS out=$OUT ==="
for n in $N1 $N2; do
    sv=$(r $n "cat /sys/module/mxfs/srcversion; grep -c ' $MNT ' /proc/mounts; strings -a /src/mxfs/mxfs.ko | grep -c P-DIRSHARD-SHELL-ADOPTED" | tr '\n' ' ')
    echo "$n: $sv" | tee "$OUT/pre_$n.txt"
    set -- $sv
    [ "${2:-0}" = 1 ] || { say "INFRA: $MNT not mounted on $n"; exit 2; }
    [ "${3:-0}" -ge 1 ] || { say "INFRA: module on $n lacks the D-0533 revalidation (pre-0.64.19 build)"; exit 2; }
done
# sharded mkdir is refused unless the module parameter allows it; the
# filesystem must also have been formatted with mkfs.mxfs -D
r $N2 "dmesg --clear; echo 1 > /sys/module/mxfs/parameters/dirshard_mkdir_enable" >/dev/null
r $N1 "dmesg --clear; echo 1 > /sys/module/mxfs/parameters/dirshard_mkdir_enable; rm -rf $MNT/dsr_* 2>/dev/null; true" >/dev/null

mk() { # mk <node> <name> <nfiles>
    r "$1" "python3 $PY mkdir $MNT $2 16 >/dev/null && cd $MNT/$2 && for i in \$(seq 1 $3); do echo \$i > f\$i || echo CREATE_FAIL; done; echo MK_RC=\$?"
}
for lap in $(seq 1 "$LAPS"); do
    A=dsr_a_$lap; B=dsr_b_$lap; C=dsr_c_$lap; D=dsr_d_$lap
    # ── arm A ──
    o=$(mk $N1 $A 8); echo "$o" | grep -q 'MK_RC=0' || fail "lap $lap: mkdir $A: $o"
    o=$(r $N2 "ls $MNT/$A | wc -l"); [ "$(echo "$o" | tail -1)" = 8 ] || fail "lap $lap: peer pre-list $A: $o"
    o=$(r $N1 "cd $MNT/$A && rm -f f* && cd / && rmdir $MNT/$A; echo RMDIR_RC=\$?"); echo "$o" | grep -q 'RMDIR_RC=0' || fail "lap $lap: rmdir $A: $o"
    o=$(mk $N1 $B 8); echo "$o" | grep -q 'MK_RC=0' || fail "lap $lap: mkdir $B: $o"
    o=$(r $N2 "s=\$(date +%s%N); n=\$(ls $MNT/$B 2>&1 | wc -l); rc=\${PIPESTATUS[0]}; e=\$(date +%s%N); echo n=\$n rc=\$rc ms=\$(( (e-s)/1000000 )); ls $MNT/$B 2>&1 | head -3")
    echo "lap $lap armA: $(echo "$o" | head -1)" | tee -a "$OUT/laps.txt"
    set -- $(echo "$o" | head -1 | tr '=' ' ')
    n=${2:-}; rc=${4:-}; ms=${6:-}
    { [ "$n" = 8 ] && [ "$rc" = 0 ]; } || fail "lap $lap: peer list of reused $B: $(echo "$o" | tr '\n' '|' | cut -c1-200)"
    [ -n "$ms" ] && [ "$ms" -lt "$PACE_MS" ] || fail "lap $lap: peer list of $B took ${ms:-?} ms (2x-native-XFS ceiling $PACE_MS)"
    o=$(r $N1 "cd $MNT/$B && rm -f f* && cd / && rmdir $MNT/$B; echo RMDIR_RC=\$?"); echo "$o" | grep -q 'RMDIR_RC=0' || fail "lap $lap: rmdir $B: $o"
    # ── arm B ──
    o=$(mk $N1 $C 8); echo "$o" | grep -q 'MK_RC=0' || fail "lap $lap: mkdir $C: $o"
    o=$(r $N2 "ls $MNT/$C | wc -l"); [ "$(echo "$o" | tail -1)" = 8 ] || fail "lap $lap: peer pre-list $C: $o"
    o=$(r $N1 "cd $MNT/$C && rm -f f* && cd / && rmdir $MNT/$C; echo RMDIR_RC=\$?"); echo "$o" | grep -q 'RMDIR_RC=0' || fail "lap $lap: rmdir $C: $o"
    o=$(r $N1 "python3 $PY mkdir $MNT $D 16 | tail -1"); [ "$(echo "$o" | tail -1)" = OK ] || fail "lap $lap: mkdir $D: $o"
    o=$(r $N2 "s=\$(date +%s%N); rmdir $MNT/$D 2>&1; rc=\$?; e=\$(date +%s%N); echo rc=\$rc ms=\$(( (e-s)/1000000 ))")
    echo "lap $lap armB: $(echo "$o" | tail -1)" | tee -a "$OUT/laps.txt"
    echo "$o" | tail -1 | grep -q '^rc=0' || fail "lap $lap: peer rmdir of reused $D: $(echo "$o" | tr '\n' '|' | cut -c1-200)"
    o=$(r $N1 "stat $MNT/$D 2>&1 | grep -c 'No such file'"); [ "$(echo "$o" | tail -1)" = 1 ] || fail "lap $lap: $D still visible on creator after the peer's rmdir: $o"
done

# ── kernel-side evidence on the peer (the node holding the stale shells) ──
for n in $N2 $N1; do
    o=$(r $n "for m in P-DIRSHARD-SHELL-ADOPTED P-DIRSHARD-SHELL-UNCONVERGED 'P-DIRSHARD-SHELL ' P-DIRSHARD-BLK-REFRESH P-DIRSHARD-BLK-KEEP P-DIRSHARD-STRANGER P-DIRSHARD-GONE P-DIRSHARD-CORRUPT P-DIRSHARD-IGET-FAIL P-DIRSHARD-LOAD-FAIL 'Structure needs cleaning' 'WARNING:' 'BUG:' Oops; do printf '%s=%s ' \"\$m\" \"\$(dmesg | grep -ac -- \"\$m\")\"; done; echo")
    echo "$n markers: $o" | tee "$OUT/markers_$n.txt"
    r $n "dmesg | grep -a 'P-DIRSHARD-SHELL\|P-DIRSHARD-STRANGER\|P-DIRSHARD-GONE\|P-DIRSHARD-CORRUPT\|P-DIRSHARD-BLK-\|P-DIRSHARD-LOAD-FAIL\|WARNING:\|BUG:' | head -80" > "$OUT/dmesg_$n.txt"
done
m=$(cat "$OUT/markers_$N2.txt")
g() { echo "$m" | grep -o "$1=[0-9]*" | head -1 | cut -d= -f2; }
[ "$(g P-DIRSHARD-STRANGER)" = 0 ] || fail "peer logged P-DIRSHARD-STRANGER=$(g P-DIRSHARD-STRANGER) (stale shell served as a stranger)"
[ "$(g P-DIRSHARD-CORRUPT)" = 0 ] || fail "peer logged P-DIRSHARD-CORRUPT=$(g P-DIRSHARD-CORRUPT) (D-0534: stale manifest block / other corruption verdict)"
[ "$(g P-DIRSHARD-SHELL-UNCONVERGED)" = 0 ] || fail "peer logged P-DIRSHARD-SHELL-UNCONVERGED=$(g P-DIRSHARD-SHELL-UNCONVERGED)"
[ "$(g 'WARNING:')" = 0 ] && [ "$(g 'BUG:')" = 0 ] && [ "$(g Oops)" = 0 ] || fail "peer kernel splat: $m"
adopted=$(g P-DIRSHARD-SHELL-ADOPTED); refreshed=$(g P-DIRSHARD-BLK-REFRESH)
say "peer exposure: adopted=${adopted:-0} blk_refresh=${refreshed:-0} (D-0534 arm is vacuous unless blk_refresh > 0)"
[ "${adopted:-0}" -gt 0 ] || { vacuous=1; say "NOTE: peer never adopted a stale shell (ADOPTED=0) — the reuse never landed on a number the peer had cached; lap is VACUOUS for D-0533"; }
say "fails=$fails adopted=${adopted:-0} out=$OUT"
if [ "$fails" -eq 0 ] && [ "$vacuous" -eq 0 ]; then echo "VERDICT PASS dirshard_reuse_peer laps=$LAPS adopted=$adopted out=$OUT"; exit 0
elif [ "$fails" -eq 0 ]; then echo "VERDICT VACUOUS dirshard_reuse_peer laps=$LAPS adopted=0 out=$OUT"; exit 1
else echo "VERDICT FAIL dirshard_reuse_peer fails=$fails adopted=${adopted:-0} out=$OUT"; exit 1; fi
