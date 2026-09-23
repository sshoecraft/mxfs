#!/bin/bash
# (bash: tests/lib/rig.sh uses indirect expansion and printf -v; under sh
#  the lap died with "Bad substitution" before its first verdict, s59h)
# d512_race_verify.sh — D-512 cycle-1 race-injection legs (sess413 ruling
# verification matrix; sess415 ruling: safe on the current build).
#
# Uses the dbg_incarn_race_ino/dbg_incarn_racewin_ms window knobs (0.28.3):
# a gated data path holds a post-gate-check window; a second process's
# open() fires dbg_incarn_poison_ino mid-window, publishing the poison
# between the racer's gate check and its work.
#
# LEG write:   racer = buffered dd write.  The window sits at write_iter
#   entry (post-gate); the poison lands mid-window; the iomap_begin
#   -ESTALE RECHECK under the op's own lock must then refuse the write.
#   Assert: racer rc != 0, window+poison+revoke markers fired, and a fresh
#   read returns the BASELINE byte (nothing of the racer's data survived).
# LEG writeback: racer = fsync of a dirtied file.  Its fsync gate passes
#   pre-poison; the writepages window holds; the poison lands mid-window;
#   writepages proceeds into the revocation worker's truncate (folio-lock
#   interaction — the deadlock-risk pair).  Assert: bounded completion (no
#   hang), window+poison+revoke markers, zero splats.  (Content may be the
#   racer's or the baseline — same incarnation, both safe; liveness and
#   revocation are the assertions here.)
# LEG fault (sess416): racer = mmap'd read via tools/mxfs_mmapio; its page
#   fault enters the xfs_filemap_fault post-gate window; the poison lands
#   mid-window.  Assert: bounded completion, outcome is same-incarnation
#   byte or SIGBUS (never garbage), fresh mapping recovers the baseline,
#   window+poison+revoke markers, zero splats.
#
# the budget rule (derived): per leg ~8s (setup 2 + window 1.5 + waits 3 + dmesg 2)
# x3 + 5s slack => ~35s total.  Caller bound 120s.
#
# Usage: tests/d512_race_verify.sh <label> [node]   (default test5)
set -u
LABEL=${1:?label}; NODE=${2:-test5}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${D512_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d512race}
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
P=/sys/module/mxfs/parameters
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
ckge() { if [ "${2:-0}" -ge "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=${2:-0} want>=$3"; fails=$((fails+1)); fi; }

echo "=== d512_race_verify label=$LABEL node=$NODE out=$OUT $(date -u +%FT%TZ) ==="
MARK="D512R-$LABEL-$$-$(date -u +%s)"
timeout 20 $SSH "$NODE" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1

# ---------- LEG write ----------
F="$MNT/d512race_${LABEL}_w.dat"
timeout 20 $SSH "$NODE" \
  "dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'B' > '$F' && sync -f '$F' && stat -c %i '$F'" \
  2>/dev/null | filt > "$OUT/w_ino.txt"
ino=$(tr -dc 0-9 < "$OUT/w_ino.txt")
if [ -z "$ino" ]; then echo "VERDICT FAIL: write-leg setup failed"; exit 2; fi
echo "write leg ino=$ino"
timeout 20 $SSH "$NODE" "echo 6000 > $P/dbg_incarn_racewin_ms && echo $ino > $P/dbg_incarn_race_ino" >/dev/null 2>&1
# racer enters the write_iter window; the trigger POLLS ON-NODE for the
# window marker and poisons the moment it appears (first harness version
# used a fixed sleep and landed 1.5s AFTER the 1500ms window — the racer
# legitimately completed pre-poison; evidence 20260824T065956Z_d512race).
( timeout 40 $SSH "$NODE" \
    "dd if=/dev/zero of='$F' bs=4096 count=1 conv=notrunc 2>/dev/null; echo WRC=\$?" \
    > "$OUT/w_racer.txt" 2>/dev/null ) &
WPID=$!
timeout 30 $SSH "$NODE" \
  "for i in \$(seq 1 75); do dmesg | tail -30 | grep -q 'P-D512-RACEWIN ino=$ino site=write_iter' && break; sleep 0.2; done; echo $ino > $P/dbg_incarn_poison_ino; cat '$F' >/dev/null 2>&1; echo TRIGGER_DONE" >/dev/null 2>&1
wait "$WPID"
timeout 20 $SSH "$NODE" "echo 0 > $P/dbg_incarn_racewin_ms; echo 0 > $P/dbg_incarn_race_ino" >/dev/null 2>&1
wrc=$(grep -a 'WRC=' "$OUT/w_racer.txt" | tail -1 | cut -d= -f2)
# retirement happens on the next lookups; poll up to 10s for a fresh read
n=0; first=""
while [ $n -lt 10 ]; do
    measure "$NODE" 20 "$OUT/rv_first_1.txt" '^READ_RC=[0-9]+$' "first on $NODE" "head -c1 '$F' 2>/dev/null; printf '\nREAD_RC=%s\n' \$?"; first=$(grep -av '^READ_RC=' "$OUT/rv_first_1.txt" | head -c1)
    [ "$first" = "B" ] && break
    sleep 1; n=$((n+1))
done
ck   "write racer refused (rc!=0)" "$([ "${wrc:-0}" != 0 ] && echo refused || echo completed)" "refused"
ck   "baseline byte survived"      "${first:-none}" "B"

# ---------- LEG writeback ----------
G="$MNT/d512race_${LABEL}_wb.dat"
timeout 20 $SSH "$NODE" \
  "dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'C' > '$G' && sync -f '$G' && dd if=/dev/zero of='$G' bs=4096 count=2 conv=notrunc 2>/dev/null && stat -c %i '$G'" \
  2>/dev/null | filt > "$OUT/wb_ino.txt"
gino=$(tr -dc 0-9 < "$OUT/wb_ino.txt")
if [ -z "$gino" ]; then echo "VERDICT FAIL: wb-leg setup failed"; exit 2; fi
echo "writeback leg ino=$gino (dirty pages pending)"
timeout 20 $SSH "$NODE" "echo 6000 > $P/dbg_incarn_racewin_ms && echo $gino > $P/dbg_incarn_race_ino" >/dev/null 2>&1
( timeout 40 $SSH "$NODE" "sync -f '$G' 2>/dev/null; echo SRC=\$?" > "$OUT/wb_racer.txt" 2>/dev/null ) &
SPID=$!
timeout 30 $SSH "$NODE" \
  "for i in \$(seq 1 75); do dmesg | tail -30 | grep -q 'P-D512-RACEWIN ino=$gino site=writepages' && break; sleep 0.2; done; echo $gino > $P/dbg_incarn_poison_ino; cat '$G' >/dev/null 2>&1; echo TRIGGER_DONE" >/dev/null 2>&1
wait "$SPID"
timeout 20 $SSH "$NODE" "echo 0 > $P/dbg_incarn_racewin_ms; echo 0 > $P/dbg_incarn_race_ino" >/dev/null 2>&1
src=$(grep -ac 'SRC=' "$OUT/wb_racer.txt")
ckge "writeback racer returned (no hang)" "$src" 1

# ---------- LEG fault (sess416: mmap helper tools/mxfs_mmapio) ----------
# Racer = mmap'd read whose page fault enters the xfs_filemap_fault
# post-gate window (site=fault); the poison lands mid-window.  The access
# must complete from the SAME (pre-poison) incarnation or SIGBUS — never
# hang, never serve another incarnation's bytes.  A fresh mapping after
# retirement then reads the baseline again (file still live on disk; the
# poison is synthetic).
MM=/src/mxfs/tools/mxfs_mmapio
FF="$MNT/d512race_${LABEL}_f.dat"
timeout 20 $SSH "$NODE" \
  "dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'D' > '$FF' && sync -f '$FF' && stat -c %i '$FF'" \
  2>/dev/null | filt > "$OUT/f_ino.txt"
fino=$(tr -dc 0-9 < "$OUT/f_ino.txt")
if [ -z "$fino" ]; then echo "VERDICT FAIL: fault-leg setup failed"; exit 2; fi
echo "fault leg ino=$fino"
# The racer's page must NOT already be in the page cache: a read fault on a
# cached folio is served by ->map_pages (fault-around) and never enters
# xfs_filemap_fault, so the site=fault window cannot fire (s62a: window 0,
# the racer read 0x44 straight from the cache the setup dd left behind).
# drop_caches evicts the clean setup pages; the fault then takes the gated
# path.
timeout 20 $SSH "$NODE" "sync; echo 3 > /proc/sys/vm/drop_caches; echo 6000 > $P/dbg_incarn_racewin_ms && echo $fino > $P/dbg_incarn_race_ino" >/dev/null 2>&1
( timeout 40 $SSH "$NODE" "$MM r '$FF' 0; echo FRC=\$?" > "$OUT/f_racer.txt" 2>/dev/null ) &
FPID=$!
timeout 30 $SSH "$NODE" \
  "for i in \$(seq 1 75); do dmesg | tail -30 | grep -q 'P-D512-RACEWIN ino=$fino site=fault' && break; sleep 0.2; done; echo $fino > $P/dbg_incarn_poison_ino; cat '$FF' >/dev/null 2>&1; echo TRIGGER_DONE" >/dev/null 2>&1
wait "$FPID"
timeout 20 $SSH "$NODE" "echo 0 > $P/dbg_incarn_racewin_ms; echo 0 > $P/dbg_incarn_race_ino" >/dev/null 2>&1
frc=$(grep -a 'FRC=' "$OUT/f_racer.txt" | tail -1 | cut -d= -f2 | tr -dc '0-9')
fout=$(grep -a 'read=\|sig=' "$OUT/f_racer.txt" | tail -1 | tr -d '\r')
case "$fout" in
  read=0x44|sig=SIGBUS) fsafe=safe ;;
  *) fsafe="unsafe:${fout:-none}:rc=${frc:-?}" ;;
esac
ck   "fault racer bounded (returned)" "$([ -n "${frc:-}" ] && echo yes || echo no)" "yes"
ck   "fault racer outcome safe (same-incarn read or SIGBUS)" "$fsafe" "safe"
n=0; ffirst=""
while [ $n -lt 10 ]; do
    measure "$NODE" 20 "$OUT/rv_ffirst_2.txt" '^READ_RC=[0-9]+$' "ffirst on $NODE" "$MM r '$FF' 0; printf '\nREAD_RC=%s\n' \$?"; ffirst=$(grep -av '^READ_RC=' "$OUT/rv_ffirst_2.txt" | grep -a 'read=' | tail -1 | cut -d= -f2)
    [ "$ffirst" = "0x44" ] && break
    sleep 1; n=$((n+1))
done
ck   "post-poison fresh mmap read recovers baseline" "${ffirst:-none}" "0x44"

# ---------- markers ----------
timeout 25 $SSH "$NODE" "dmesg | sed -n \"/$MARK/,\\\$p\"" 2>/dev/null | filt > "$OUT/node_dmesg.txt"
win_w=$(grep -ac "P-D512-RACEWIN ino=$ino site=write_iter" "$OUT/node_dmesg.txt")
win_wb=$(grep -ac "P-D512-RACEWIN ino=$gino site=writepages" "$OUT/node_dmesg.txt")
win_f=$(grep -ac "P-D512-RACEWIN ino=$fino site=fault" "$OUT/node_dmesg.txt")
poi=$(grep -ac "P34H-DBG-POISON" "$OUT/node_dmesg.txt")
rev=$(grep -ac "P34H-INCARN-REVOKED" "$OUT/node_dmesg.txt")
splat=$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep|possible circular' "$OUT/node_dmesg.txt")
ckge "write_iter window fired" "$win_w" 1
ckge "writepages window fired" "$win_wb" 1
ckge "fault window fired" "$win_f" 1
ckge "poisons fired" "$poi" 3
ckge "revocations completed" "$rev" 3
ck   "zero splats" "$splat" "0"

timeout 20 $SSH "$NODE" "rm -f '$F' '$G' '$FF'" >/dev/null 2>&1
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS: race legs write+writeback+fault"; exit 0; fi
echo "VERDICT FAIL: $fails assertion(s)"; exit 1
