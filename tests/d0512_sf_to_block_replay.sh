#!/bin/bash
# d0512_sf_to_block_replay.sh — D-DIR-SF-TO-BLOCK-RETYPE-VOIDS-AUTHORITY-TOKEN-
# SLICE-REFUSED-0512, the instrumented verification leg for ruling A′ (ccmemory
# docs/rulings/d0512-blft-retype-authority-void-aprime.md).
#
# One node (the VICTIM) creates a fresh directory and 24 files with 40-char
# names: a 512 B v3 inode's shortform literal area (~336 B) holds ~7 such
# entries, so the 8th create runs xfs_dir2_sf_to_block on the victim — the
# transaction chain 35 point 13 refused (dir block re-typed DIR_DATA ->
# DIR_BLOCK after the authority capture).  The victim's own producer-side
# lines (P-AUTHCAP-RETYPE-OK / P-AUTHCAP-VOID / P-AUTHCAP-INJECT /
# P-AUTHCAP-RETYPE-MIXED) are harvested BEFORE it is destroyed (its journal
# is volatile), then the survivors foreign-replay its slice.
#
#   arm fix      : authcap_inject=0  -> expect RETYPE-OK on the victim, the
#                  slice replays COMPLETE, the directory lists every created
#                  name (the converting create included) on a survivor with
#                  zero classless tokens.
#   arm inject1  : authcap_inject=1  -> the re-proof is recorded MIXED ->
#                  expect the replayer to REFUSE the slice (negative arm).
#   arm inject2  : authcap_inject=2  -> the re-proof is skipped (pending at
#                  commit -> voided) -> expect REFUSE (negative arm).
#
# Usage: tests/d0512_sf_to_block_replay.sh <label> <fix|inject1|inject2> [victim=test2] [N=32] [survivor=test1]
# Precondition: fresh `./run.sh <N> caw prep_cluster` (fleet mounted on the
# tree's mxfs.ko).  The victim is left DESTROYED; the caller re-preps.
#
# the budget rule (derived): srcgate 32 x ssh ~15 s; knobs ~10 s; 24 creates on an
# idle directory < 5 s; destroy 5 s; death = lease 62 s + election + slice
# replay (~5 s snapshot proof + replay) ~15 s -> outcome by ~90 s, polled to
# 200 s; verify ~10 s.  Caller bound 300 s.
set -u
LABEL=${1:?label}
ARM=${2:?fix|inject1|inject2}
VIC=${3:-test2}
N=${4:-32}
SUR=${5:-test1}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
PASS=$(tools/mxfs_secrets.sh passfile 2>/dev/null)
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
PARM=/sys/module/mxfs/parameters
case "$ARM" in fix) INJ=0;; inject1) INJ=1;; inject2) INJ=2;; *) echo "bad arm $ARM"; exit 2;; esac
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0512_${LABEL}_${ARM}
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$PASS" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
echo "=== d0512_sf_to_block_replay label=$LABEL arm=$ARM inject=$INJ victim=$VIC survivor=$SUR N=$N sv=$TREE_SV out=$OUT $(date -u +%FT%TZ) ==="

# 1. srcgate + knobs on every node (per-node evidence)
for i in $(seq 1 "$N"); do
    sshq 25 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED
        echo 1 > $PARM/target_cache_protected; echo 1 > $PARM/foreign_replay_token_enforce
        [ test$i = $VIC ] && echo $INJ > $PARM/authcap_inject || echo 0 > $PARM/authcap_inject
        echo enforce=\$(cat $PARM/foreign_replay_token_enforce) tcp=\$(cat $PARM/target_cache_protected) inject=\$(cat $PARM/authcap_inject)" > "$OUT/test$i.gate" &
done; wait
# sess445 lap 1: arming enforce BEFORE target_cache_protected is silently
# refused by the knob's F2 prerequisite check, and the replay then ran
# enforcement-OFF (every image 'unauthorized').  Order fixed above; the
# gate now FAILS CLOSED on any node that does not read enforce=1.
bad=""
for i in $(seq 1 "$N"); do grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate" && grep -q 'enforce=1 tcp=1' "$OUT/test$i.gate" || bad="$bad test$i"; done
[ -z "$bad" ] && pass "srcgate: $N nodes on $TREE_SV, mounted" || { fail "srcgate/mount:$bad"; echo "=== d0512 $LABEL $ARM: fails=$fails out=$OUT ==="; exit 1; }
grep -q "inject=$INJ" "$OUT/$VIC.gate" && pass "victim $VIC authcap_inject=$INJ" || fail "victim knob: $(cat "$OUT/$VIC.gate" | tr '\n' ' ')"

# 2. the victim's identity and the workload
VNODE=$(sshq 20 "$VIC" "dmesg | grep -ao 'DLM init: node_id=[0-9]*' | tail -1 | cut -d= -f2")
info "victim node_id=$VNODE"
STAMP=@$(date +%s)
D="$MNT/d0512_${LABEL}_${ARM}"
# sess446 (chain 42 lap 2, tests/evidence/20260829T111303Z_d0512_s445e_fix +
# ..._inject1): 24 sync'd creates then `sync` left only the victim's LAST 3-4
# transactions in its slice (P273-SHADOW-EVAL txn=4 buf=14 / txn=3 buf=10) —
# mxfs_destage_kick pushes the AIL on every create, so the sf->block txn
# (create ~8) was covered long before the crash and BOTH arms replayed
# COMPLETE without ever seeing the re-typed image.  The conversion must be
# the victim's LAST transaction: create one file at a time and stop the
# moment the victim's dmesg shows the re-type (P-AUTHCAP-RETYPE-OK / -MIXED /
# -VOID / -INJECT for this run); no sync afterwards.  NCR = files created.
sshq 60 "$VIC" "b=\$(dmesg | grep -ac 'P-AUTHCAP-RETYPE\|P-AUTHCAP-VOID\|P-AUTHCAP-INJECT'); mkdir -p '$D' && n=0; for i in \$(seq 1 24); do dd if=/dev/urandom of='$D'/file_\$(printf %03d \$i)_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx bs=4096 count=1 oflag=sync 2>/dev/null; n=\$i; a=\$(dmesg | grep -ac 'P-AUTHCAP-RETYPE\|P-AUTHCAP-VOID\|P-AUTHCAP-INJECT'); [ \$a -gt \$b ] && break; done; echo \$n; stat -c 'dir_ino=%i' '$D'; dmesg | grep -a 'P-AUTHCAP\|P240-AUTHCAP' | tail -30" > "$OUT/victim_workload.txt" 2>&1
NCR=$(grep -xE '[0-9]+' "$OUT/victim_workload.txt" | head -1)
DINO=$(grep -o 'dir_ino=[0-9]*' "$OUT/victim_workload.txt" | cut -d= -f2)
case "${NCR:-x}" in ''|*[!0-9]*) fail "victim create count unreadable: $(head -3 "$OUT/victim_workload.txt" | tr '\n' ' ')";; *) [ "$NCR" -ge 2 ] && [ "$NCR" -lt 24 ] && pass "victim stopped at create #$NCR = the sf->block conversion (dir ino=$DINO); it is the victim's last transaction" || fail "victim created $NCR files without a re-type line (expected the conversion by ~8)";; esac
LASTF=$(printf 'file_%03d_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' "${NCR:-1}")
ok_n=$(grep -ac 'P-AUTHCAP-RETYPE-OK' "$OUT/victim_workload.txt"); void_n=$(grep -ac 'P-AUTHCAP-VOID' "$OUT/victim_workload.txt")
mixed_n=$(grep -ac 'P-AUTHCAP-RETYPE-MIXED' "$OUT/victim_workload.txt"); inj_n=$(grep -ac 'P-AUTHCAP-INJECT' "$OUT/victim_workload.txt")
info "victim producer lines: retype_ok=$ok_n void=$void_n mixed=$mixed_n inject=$inj_n"
grep -a 'P-AUTHCAP' "$OUT/victim_workload.txt" | head -6 | sed 's/^/    /' | cut -c1-220
case "$ARM" in
  fix)     [ "$ok_n" -ge 1 ] && [ "$void_n" -eq 0 ] && [ "$mixed_n" -eq 0 ] && pass "producer: sf->block re-proved under the new type (RETYPE-OK>=1, VOID=0, MIXED=0)" || fail "producer: retype_ok=$ok_n void=$void_n mixed=$mixed_n (expected OK>=1, VOID=0, MIXED=0)";;
  inject1) [ "$mixed_n" -ge 1 ] && pass "producer: injected MIXED recorded" || fail "producer: no RETYPE-MIXED line (inject=1)";;
  inject2) [ "$inj_n" -ge 1 ] && [ "$void_n" -ge 1 ] && pass "producer: injected skip -> VOID why=retype_nodirty at commit" || fail "producer: inject=$inj_n void=$void_n (inject=2 expects both >=1)";;
esac

# 3. kill the victim (a different boot: virsh destroy)
$VIRSH destroy "$VIC" > "$OUT/destroy.txt" 2>&1; sleep 3
TD=$(date +%s)
info "victim destroyed at $(date -u +%FT%TZ)"

# 4. the survivors' verdict on the victim's slice
outcome=""; replayer=""
for a in $(seq 1 20); do
    sleep 10
    for i in $(seq 1 "$N"); do
        [ "test$i" = "$VIC" ] && continue
        ( sshq 25 "test$i" "journalctl -k --since '$STAMP' --no-pager 2>/dev/null | grep -a 'victim_node=$VNODE\|foreign replay of dead slot\|foreign replay of slot [0-9]* complete\|foreign replay of slot [0-9]* failed\|slice replay refused\|POLICY-REFUSED\|P227-FR-TORN\|P227-TOKEN.*class=0\|P273-SHADOW-EVAL\|P240-QUAR-IMPORT'" > "$OUT/test$i.replay" 2>/dev/null ) &
    done; wait
    for i in $(seq 1 "$N"); do
        [ "test$i" = "$VIC" ] && continue
        if grep -aq 'foreign replay of slot [0-9]* complete' "$OUT/test$i.replay"; then outcome=COMPLETE; replayer=test$i; fi
        if grep -aq 'slice replay refused\|POLICY-REFUSED\|foreign replay of slot [0-9]* failed' "$OUT/test$i.replay"; then outcome=REFUSED; replayer=test$i; fi
    done
    [ -n "$outcome" ] && break
done
RW=$(( $(date +%s) - TD ))
info "replay outcome=$outcome replayer=$replayer at +${RW}s"
[ -n "$replayer" ] && { grep -a 'P273-SHADOW-EVAL\|P227-TOKEN.*class=0\|slice replay refused\|complete' "$OUT/$replayer.replay" | head -6 | sed 's/^/    /' | cut -c1-230; }
classless=$( [ -n "$replayer" ] && grep -ao 'classless=[0-9]*' "$OUT/$replayer.replay" | tail -1 | cut -d= -f2 || echo "?")
case "$ARM" in
  fix)     [ "$outcome" = COMPLETE ] && pass "survivor $replayer replayed the victim's slice COMPLETE (+${RW}s)" || fail "expected COMPLETE, got '${outcome:-none}' (+${RW}s)"
           [ "${classless:-1}" = 0 ] && pass "replayer saw classless=0 (the dir block image is authorized)" || fail "replayer classless=${classless:-?}";;
  *)       [ "$outcome" = REFUSED ] && pass "survivor $replayer REFUSED the slice (negative arm $ARM, +${RW}s)" || fail "negative arm $ARM: expected REFUSED, got '${outcome:-none}' (+${RW}s)";;
esac
[ "$RW" -le 200 ] && pass "death->verdict wall ${RW}s <= 200s" || fail "death->verdict wall ${RW}s > 200s (budget)"

# 5. the directory as the survivors see it
sshq 40 "$SUR" "ls '$D' 2>&1 | wc -l; ls '$D' 2>&1 | tail -3; cat '$D'/$LASTF > /dev/null 2>&1 && echo READ_OK || echo READ_FAIL=\$?" > "$OUT/survivor_view.txt" 2>&1
SN=$(head -1 "$OUT/survivor_view.txt")
if [ "$ARM" = fix ]; then
    [ "$SN" = "${NCR:-24}" ] && grep -q READ_OK "$OUT/survivor_view.txt" && pass "survivor $SUR lists all $NCR entries incl. the converting create and reads $LASTF after replay" || fail "survivor view (want $NCR entries + READ_OK): $(tr '\n' ' ' < "$OUT/survivor_view.txt" | cut -c1-200)"
else
    info "survivor view after refusal: $(tr '\n' ' ' < "$OUT/survivor_view.txt" | cut -c1-200)"
fi
# host-safety probes on the survivors' logs
for i in $(seq 1 "$N"); do [ "test$i" = "$VIC" ] && continue; grep -aq 'BUG:\|Oops\|Corruption' "$OUT/test$i.replay" && fail "test$i: BUG/Oops/Corruption in the window"; done
echo "=== d0512 $LABEL $ARM: fails=$fails outcome=${outcome:-none} out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
