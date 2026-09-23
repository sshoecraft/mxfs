#!/bin/bash
# sess475 chain 117: D-0532 directed concurrency arm (design-consult bar, ccmemory
# ccloop-c7ee71c6-sess474-GPT-ruling-dirshard-closure-blocked-by-d0133-chk-
# d0532-nodlm-d0133-sb-sync-probes §2): ONE genuine DLM holder + another task
# on the nowait/unlock path with a BAST pending — the holder count must not be
# decremented, no drain/unlock under the live holder, release only at the
# genuine final-holder transition, then the BAST drains.
#
# Shape (H = holder node test1, P = peer test2, F = a published regular file):
#   1. H creates F (1 MiB), syncs; P reads F (publishes it, P caches PR); H
#      rewrites 4 KiB (H holds EX again, dinode clean after a log force).
#   2. H arms three one-shot knobs for F's ino: dbg_bast_pause_ino (drain parks
#      PAUSE_MS before its reg-durable loop), dbg_relog_force_ino (the drain's
#      P146V re-log arm is forced once = the nowait-ILOCK path under test),
#      dbg_iolock_hold_ino (the next IOLOCK_EXCL admission parks HOLD_MS).
#   3. (sess476 reorder — s475a was vacuous, see the arm body) H's task A
#      writes 4 KiB of 'A' at offset 4096 (buffered write: IOLOCK_EXCL ->
#      mxfs_dlm_ilock_begin -> parked HOLD_MS with i_dlm_ex_holders counted,
#      EX held).  Once P-IOLOCK-HOLD is visible, H re-dirties F with a
#      timestamp update (sess479: without it F is clean at BAST time and the
#      release takes the S_ISREG already-durable early-out, which returns
#      before both injection points — that is what made s476a vacuous), then
#      P writes 4 KiB of 'P' at offset 0 (needs EX -> BAST to H's LIVE holder
#      -> H's drain starts and parks).
#   4. The drain resumes (PAUSE_MS < 1 s + HOLD_MS), takes the P146V path:
#      xfs_ilock_nowait(ILOCK_EXCL) succeeds (A holds only the IOLOCK), commit,
#      xfs_iunlock_nodlm.  Probe P146V-RELOG-HOLDERS prints ex_before/ex_after.
#   5. A's hold ends, its write completes, its IOLOCK end is the final-holder
#      transition -> the deferred BAST drains -> P's write completes.
# Verdict on H's ring (bounded by a kmsg mark) and P's write wall:
#   - P-BAST-PAUSE, P146V-FORCE, P146V-RELOG-HOLDERS all present (the arm is
#     NOT vacuous);
#   - if P-IOLOCK-HOLD was printed BEFORE P-BAST-PAUSE-END (A admitted
#     mid-drain, the concurrent case): ex_before == ex_after == 1 on the
#     RELOG-HOLDERS line, P15H-LIVE-SKIP >= 1 (the anchored unlock deferred
#     under the live holder), P71-UNDERFLOW == 0, P's write wall >= HOLD_MS -
#     1 s (P waited for A's genuine end);
#   - else (A admitted only after the drain — exclusion by admission): the
#     RELOG-HOLDERS line shows ex_before == ex_after == 0, P71 == 0, and the
#     result is recorded as ORDER=serialized (still a PASS for the counter
#     invariant, but the concurrent case was not reached — rerun with a longer
#     PAUSE_MS);
#   - after both writes: F[0..4095] == 'P' bytes and F[4096..8191] == 'A'
#     bytes on BOTH nodes (coherency), no shutdown / corruption lines.
# budget: prep 300 (95-118 s measured); arm wall ~ PAUSE_MS + HOLD_MS + 10 s.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s475a}
GATE=${GATE:-tests/evidence/sess475_chain116_d0133_s475a.log}
LOG=tests/evidence/sess475_chain117_d0532_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
LAPS=${LAPS:-2}
PAUSE_MS=${PAUSE_MS:-4000}
HOLD_MS=${HOLD_MS:-10000}
H=${H:-test1}; P=${P:-test2}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
DM=tests/evidence/sess475_chain117_dmesg_$LABEL
mkdir -p "$DM"
OUT=$DM
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# sess479: a failed prep invalidates every arm below it.  Chain 116 s479a
# scored twelve FAILs against a fleet that ./run.sh had refused to prep (host
# preflight rc=3), which reads exactly like a regression in the build under
# test.  Stop instead of scoring: an unprepped fleet measures nothing.
prep_arm() { # <tag>
  local t=$1 T0=$(date +%s) rc
  timeout 300 ./run.sh 32 caw prep_cluster; rc=$?
  echo "STAGE prep $t rc=$rc wall=$(( $(date +%s) - T0 ))s"
  [ "$rc" = 0 ] && return 0
  echo "ABORT $t: prep_cluster rc=$rc — no arm can yield a verdict; scoring one would be fabricating evidence."
  echo "RESULTS: fails=$fails ABORTED_ON_PREP tag=$t rc=$rc"
  echo "DONE $(date -u +%FT%TZ)"
  exit 2
}
lap() { local b="$1" l="$2"; shift 2; local T0=$(date +%s); timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"; }
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
install_ko() {
  [ -f "$1" ] || { echo "install_ko: missing $1"; return 1; }
  cp "$1" mxfs.ko || return 1
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do [ -f "$(dirname "$1")/tools/$t" ] && cp "$(dirname "$1")/tools/$t" tools/$t; done
  local sv; sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$2"; [ "$sv" = "$2" ]
}
PAT='P-BAST-PAUSE\|P146V\|P-IOLOCK-HOLD\|P15H-LIVE-SKIP\|P71-UNDERFLOW\|P70-BP\|P51-REL\|P176-OBLIGATION\|P189-RELOG\|shutdown\|Corruption\|corruption'
{
  echo "=== sess475 chain117 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) LAPS=$LAPS PAUSE_MS=$PAUSE_MS HOLD_MS=$HOLD_MS H=$H P=$P ==="
  install_ko "$PROD_KO" "$PROD_SV" || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  for L in $(seq 1 $LAPS); do
    tag=lap$L; MK="D0532-$LABEL-$tag"
    prep_arm "$tag"
    D=$MNT/.d0532_$LABEL; F=$D/F$L
    for n in $H $P; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
    rs 30 "$H" "mkdir -p $D && dd if=/dev/urandom of=$F bs=1M count=1 status=none && sync && echo made" | grep -q made || { echo "ABORT: $tag create F on $H"; fails=$((fails+1)); continue; }
    value_now_into ino "$H" 15 "$OUT/rv_ino_1.txt" '^[0-9]+$' "ino on $H" "stat -c %i $F"
    rs 30 "$P" "cat $F > /dev/null && echo pubok" | grep -q pubok || { echo "ABORT: $tag publish via $P"; fails=$((fails+1)); continue; }
    # sess479: deliberately NO sync here.  The drain's S_ISREG already-durable
    # early-out (xfs/xfs_mxfs_dlm.c) returns before both injection points when
    # the inode is neither in the AIL nor pinned, so a synced rewrite leaves F
    # clean at BAST time and the arm cannot reach the code it tests.  Leaving
    # the rewrite unsynced keeps the inode in the CIL and pinned through A's
    # park, which is what makes the drain fall through to the durable loop.
    rs 30 "$H" "dd if=/dev/zero of=$F bs=4k count=1 conv=notrunc status=none && echo rew" | grep -q rew || { echo "ABORT: $tag rewrite on $H"; fails=$((fails+1)); continue; }
    sleep 2
    echo "  INFO $tag F=$F ino=$ino"
    rs 15 "$H" "echo $PAUSE_MS > /sys/module/mxfs/parameters/dbg_bast_pause_ms; echo $HOLD_MS > /sys/module/mxfs/parameters/dbg_iolock_hold_ms; echo $ino > /sys/module/mxfs/parameters/dbg_bast_pause_ino; echo $ino > /sys/module/mxfs/parameters/dbg_relog_force_ino; echo $ino > /sys/module/mxfs/parameters/dbg_iolock_hold_ino; cat /sys/module/mxfs/parameters/dbg_bast_pause_ino /sys/module/mxfs/parameters/dbg_relog_force_ino /sys/module/mxfs/parameters/dbg_iolock_hold_ino | tr '\n' ' '" | sed 's/^/  INFO knobs armed: /'
    # sess476 (chain 117 s475a was VACUOUS: P's write finished in 49 ms
    # BEFORE task A started — H's EX from the rewrite had already been
    # demoted, so P took EX by CAS with no BAST, no drain, no PAUSE).  Order
    # the concurrent case by construction: H's task A goes FIRST and parks at
    # its IOLOCK_EXCL DLM admission (EX granted, i_dlm_ex_holders=1,
    # P-IOLOCK-HOLD); once the park is visible, P's write requests EX -> BAST
    # to H's LIVE holder -> the drain parks (P-BAST-PAUSE) -> forced re-log
    # under the holder -> P15H-LIVE-SKIP -> A's hold ends -> BAST drains ->
    # P's write completes (wall >= HOLD_MS - 1 s).
    ( rs $(( HOLD_MS / 1000 + 60 )) "$H" "s=\$(date +%s%N); python3 -c \"import os; fd=os.open('$F', os.O_WRONLY); os.pwrite(fd, b'A'*4096, 4096); os.fsync(fd); os.close(fd)\"; rc=\$?; e=\$(date +%s%N); echo AWRITE rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))" | grep -a AWRITE > "$DM/${tag}_awrite.txt" ) &
    # sess479: the gate that holds P back until A is parked used to be
    # `... | grep -qv '^0$'`, whose success predicate is "some output line is
    # not exactly 0" — true for ANY unexpected line, false for empty output,
    # and never a numeric test of the count.  In s479e it opened on the FIRST
    # check ("after 0 polls") before A had parked, so P acquired EX, wrote in
    # 50 ms and handed the grant to H BEFORE the holder existed: the arm
    # measured a peer write against no live holder, which is exactly the
    # vacuity it was rewritten to avoid.  Require an integer count >= 1, and
    # stamp the ordering on ONE clock (this host's) so a later reader never has
    # to infer it from a wall time again.
    t=0; parked=0
    t0ms=$(( $(date +%s%N) / 1000000 ))
    while [ $t -lt 60 ]; do
        c=$(rs 10 "$H" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -ac 'P-IOLOCK-HOLD ino=$ino '" | tr -dc '0-9')
        case "$c" in ''|*[!0-9]*) : ;; *) [ "$c" -ge 1 ] && { parked=1; break; };; esac
        sleep 0.5; t=$((t+1))
    done
    tparkms=$(( $(date +%s%N) / 1000000 ))
    echo "  INFO $tag holder A parked=$parked on $H after $t polls (0.5 s each) count='${c:-none}' t_park=+$(( tparkms - t0ms ))ms"
    [ "$parked" = 1 ] || { echo "  ABORT $tag: A never parked (P-IOLOCK-HOLD absent after $t polls) — refusing to run the peer write, which would measure nothing"; fails=$((fails+1)); continue; }
    # sess479: s476a was VACUOUS for a proven reason — at BAST time F was
    # CLEAN.  H's step-2 rewrite ends in sync, and A parks at its IOLOCK_EXCL
    # DLM admission BEFORE its pwrite dirties anything, so the release drain
    # took the S_ISREG already-durable early-out (xfs/xfs_mxfs_dlm.c
    # "Already-durable early-out": !in_AIL && i_pincount == 0 -> goto
    # reg_durable_done).  That early-out returns BEFORE BOTH injection points
    # (mxfs_dbg_bast_pause and the P146V force), so P-BAST-PAUSE / P146V-FORCE
    # could never print and the concurrent case was unreachable by
    # construction.  Re-dirty F while A holds it: utimes goes through
    # xfs_trans_alloc_ichange, which takes ILOCK_EXCL only and never
    # IOLOCK_EXCL, so it does not block behind A; it logs the inode into the
    # CIL, leaving it pinned so the drain falls through to the durable loop.
    # sess479, CORRECTED: the re-dirty used to be `touch -m $F` here, on the
    # claim that utimes takes ILOCK_EXCL only and never IOLOCK_EXCL.  That is
    # WRONG at the VFS layer: xfs_setattr_nonsize itself does not take the
    # IOLOCK, but the VFS holds i_rwsem across notify_change, and i_rwsem IS
    # the IOLOCK that task A is parked on.  The touch therefore blocked behind
    # A for its whole hold -- s479i measured it: t_park=+1434ms but
    # t_redirty=+10911ms, i.e. 9.5 s blocked, finishing exactly as A's 10 s
    # hold expired, so the peer wrote at 10.9 s against no holder (48 ms) and
    # the arm was vacuous a third time, that time because of this line.
    # The inode is now dirtied BEFORE A parks, by leaving the rewrite above
    # unsynced, so nothing has to touch the inode during the hold at all.
    tdirtyms=$(( $(date +%s%N) / 1000000 ))
    echo "  INFO $tag order stamps: t_park=+$(( tparkms - t0ms ))ms t_redirty=+$(( tdirtyms - t0ms ))ms t_pwrite_launch=+$(( tdirtyms - t0ms ))ms (A must be parked before t_pwrite_launch)"
    ( rs $(( (PAUSE_MS + HOLD_MS) / 1000 + 60 )) "$P" "s=\$(date +%s%N); python3 -c \"import os; fd=os.open('$F', os.O_WRONLY); os.pwrite(fd, b'P'*4096, 0); os.fsync(fd); os.close(fd)\"; rc=\$?; e=\$(date +%s%N); echo PWRITE rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))" | grep -a PWRITE > "$DM/${tag}_pwrite.txt" ) &
    wait
    cat "$DM/${tag}_pwrite.txt" "$DM/${tag}_awrite.txt" | sed 's/^/  /'
    sleep 3
    for n in $H $P; do rs 40 "$n" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -a '$PAT'" > "$DM/${tag}_$n.txt"; done
    hf="$DM/${tag}_$H.txt"
    pw=$(grep -ao 'wall_ms=[0-9]*' "$DM/${tag}_pwrite.txt" | cut -d= -f2); prc=$(grep -ao 'rc=[0-9]*' "$DM/${tag}_pwrite.txt" | cut -d= -f2)
    holders=$(grep -a "P146V-RELOG-HOLDERS ino=$ino " "$hf" | tail -1 | grep -ao 'ex_before=[0-9]* ex_after=[0-9]*')
    order=$(awk -v ino="$ino" '/P-IOLOCK-HOLD ino='"$ino"' /{h=NR} /P-BAST-PAUSE-END ino='"$ino"' /{e=NR} END{ if (h && e) print (h < e) ? "concurrent" : "serialized"; else print "unknown" }' "$hf")
    echo "  RESULT $tag ino=$ino order=$order relog_holders=[$holders] live_skip=$(grep -ac 'P15H-LIVE-SKIP' "$hf") p71=$(grep -ac 'P71-UNDERFLOW' "$hf") p71_peer=$(grep -ac 'P71-UNDERFLOW' "$DM/${tag}_$P.txt") pwrite_rc=$prc pwrite_wall_ms=$pw"
    ck "$tag: drain parked (P-BAST-PAUSE) for ino $ino" "$(grep -ac "P-BAST-PAUSE ino=$ino " "$hf")" "1"
    ck "$tag: re-log forced (P146V-FORCE) and taken (RELOG-HOLDERS line)" "$(grep -ac "P146V-FORCE ino=$ino \|P146V-RELOG-HOLDERS ino=$ino " "$hf")" "2"
    ck "$tag: genuine IOLOCK_EXCL holder admitted (P-IOLOCK-HOLD)" "$(grep -ac "P-IOLOCK-HOLD ino=$ino " "$hf")" "1"
    ck "$tag: P71-UNDERFLOW == 0 on $H and $P" "$(( $(grep -ac 'P71-UNDERFLOW' "$hf") + $(grep -ac 'P71-UNDERFLOW' "$DM/${tag}_$P.txt") ))" "0"
    ck "$tag: holder count unchanged across the re-log's raw unlock" "$(echo "$holders" | awk -F'[= ]' '{print ($2==$4)?"same":"changed"}')" "same"
    if [ "$order" = concurrent ]; then
      ck "$tag: (concurrent) holder count was 1 on both sides of the re-log" "$holders" "ex_before=1 ex_after=1"
      ck "$tag: (concurrent) anchored unlock deferred under the live holder (P15H-LIVE-SKIP)" "$([ "$(grep -ac 'P15H-LIVE-SKIP' "$hf")" -ge 1 ] && echo yes || echo no)" "yes"
      ck "$tag: (concurrent) peer's write waited for the holder's genuine end (wall >= HOLD_MS - 1000)" "$([ "${pw:-0}" -ge $(( HOLD_MS - 1000 )) ] && echo yes || echo no)" "yes"
    else
      echo "  NOTE $tag: order=$order — the holder was not admitted mid-drain; the counter invariant still holds (see RESULT) but the concurrent case was not reached"
    fi
    ck "$tag: peer's write succeeded (rc=0)" "${prc:-none}" "0"
    for n in $H $P; do
      measure "$n" 20 "$OUT/rv_got_$n.txt" '^READ_RC=[0-9]+$' "the content class of $F on $n" "python3 -c \"import sys; d=open('$F','rb').read(8192); print('P' if d[:4096]==b'P'*4096 else 'x', 'A' if d[4096:8192]==b'A'*4096 else 'x')\"; printf '\nREAD_RC=%s\n' \$?"; got=$(grep -av '^READ_RC=' "$OUT/rv_got_$n.txt" | tr -d ' ')
      ck "$tag: $n sees P's bytes at 0 and A's bytes at 4096" "$got" "PA"
    done
    ck "$tag: no shutdown/corruption lines on $H/$P" "$(cat "$hf" "$DM/${tag}_$P.txt" | grep -ac 'shutdown\|Corruption\|corruption')" "0"
    grep -a "P-BAST-PAUSE\|P146V\|P-IOLOCK-HOLD\|P15H-LIVE-SKIP\|P71" "$hf" | cut -c1-230 | sed 's/^/  /'
  done
  echo "RESULTS: fails=$fails $(grep -a '^  RESULT' "$LOG" | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
