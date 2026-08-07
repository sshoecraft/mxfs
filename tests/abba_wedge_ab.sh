#!/bin/bash
# abba_wedge_ab.sh — DETERMINISTIC A/B for D-BAST-WRITEBACK-ABBA-DEADLOCK.
#
# THE DEFECT (captured live on test27, ccloop c7ee71c6 sess24):
#   A) kworker mxfs-ino-bast   folio_wait_bit_common <- __folio_lock
#        <- write_cache_pages <- ... <- filemap_write_and_wait_range
#        <- mxfs_dlm_bast_process        => holds the inode DLM tenure,
#                                           BLOCKED ON A FOLIO LOCK
#   B) kworker flush-252:1     mxfs_dlm_ilock_begin <- xfs_ilock
#        <- xfs_map_blocks <- iomap_writepage_map <- write_cache_pages
#                                        => holds THAT folio lock,
#                                           BLOCKED ON THE INODE LOCK
#
# WHY SESS24's EXERCISER COULD NOT REPRODUCE IT (root read off the code,
# sess25).  mxfs_dlm_bast_process calls filemap_write_and_wait TWICE:
#
#   site 1 (xfs_mxfs_dlm.c, "Flush dirty pages to disk") runs while
#          i_dlm_mode is STILL the granted mode.  mxfs_dlm_ilock_begin's
#          nest-admit fast path (i_dlm_mode >= request) therefore grants a
#          colliding writeback submitter outright.  NOTHING EVER PARKS.
#   site 2 (the S_ISREG durability flush) runs AFTER
#          `ip->i_dlm_mode = MXFS_LOCK_NL` and BEFORE the wire unlock.  Every
#          nest-admit now fails, so the submitter parks in the demote-wait
#          STILL HOLDING ITS FOLIO, and this flush walks into folio_lock() on
#          it.  This is the ABBA site.
#
# sess24's injection broke out of its window on `state == BAST|DEMOTING`,
# which is reached at site 1 — hence 200/200 "collisions" with 0 P47, 0 P25
# and no wedge in either arm.  The parking precondition is mode==NL, not the
# state.  This harness therefore synchronises on the OTHER half, which is
# what that session's handoff named as the missing piece:
#
#   mxfs.fix28_drain_stall_ms stalls the DRAIN once, mid-batch, inside its
#   site-2 flush — after write_cache_pages has fetched a dirty-tagged folio
#   batch and locked its first folio.  A submitter arriving during the stall
#   locks a LATER folio of that same batch and parks holding it; when the
#   stall ends the drain walks into folio_lock() on exactly that folio.
#   (writeback_get_folio() locks unconditionally and works off the batch it
#   already fetched, so the submitter having cleared the dirty bit is not a
#   reprieve — see mm/page-writeback.c.)
#
# ARMS (one build, no re-prep between them):
#   arm 0 : mxfs.fix27_shared_admit=0 — NEGATIVE CONTROL.  Shared-class
#           writeback submitters are refused.  Expect: WEDGE.
#   arm 1 : mxfs.fix27_shared_admit=1 — FIX ON.  Expect: no wedge, and
#           P25-IOEND-ADMIT src=writepages > 0 proving the admit ran.
#
# RECOVERY: the demote-wait re-evaluates mxfs_ilock_admit_ioend every 3s
# (FIX-24 poll), so writing 1 to fix27_shared_admit un-wedges a node that arm
# 0 already deadlocked.  This script always attempts that before exiting, so
# a negative-control run costs a stall, not a node.
#
# Usage: tests/abba_wedge_ab.sh <drain-host> <peer-host> <0|1> [secs] [stall_ms] [mnt]
set -u
A="${1:?drain host (the node that will release)}"
B="${2:?peer host (the node that BASTs it)}"
ARM="${3:?0 = negative control, 1 = fix on}"
SECS="${4:-70}"
STALL="${5:-1200}"
MNT="${6:-/mnt/shared}"

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
D="$MNT/.abba_wedge"
F="$D/f0"
MB=16
NF=6        # independent files -> independent drain opportunities per round
MARK="ABBA_${ARM}_$(date -u +%H%M%S)"

say() { printf '%s\n' "$*"; }
on()  { timeout "${2:-60}" "$SSH" "$1" "$3" 2>/dev/null; }

say "=== abba_wedge_ab: drain=$A peer=$B arm=$ARM stall=${STALL}ms secs=$SECS mark=$MARK ==="

for h in "$A" "$B"; do
  m=$(on "$h" 20 "mountpoint -q $MNT && echo OK || echo NO")
  [ "$m" = OK ] || { say "PRECOND FAIL: $h has no $MNT"; exit 2; }
done

# ---- arm the knobs -------------------------------------------------------
# fix28 (the drain-side stall) belongs ONLY on the node that will drain.
on "$A" 20 "echo $ARM > /sys/module/mxfs/parameters/fix27_shared_admit;
            echo $STALL > /sys/module/mxfs/parameters/fix28_drain_stall_ms;
            echo 0 > /sys/module/mxfs/parameters/fix27_delay_ms;
            echo 0 > /sys/module/mxfs/parameters/fix26_delay_ms;
            echo '$MARK ARMED' > /dev/kmsg" >/dev/null
on "$B" 20 "echo $ARM > /sys/module/mxfs/parameters/fix27_shared_admit" >/dev/null
say "armed: fix27_shared_admit=$ARM fix28_drain_stall_ms=$STALL (on $A)"

# ---- prime the file ------------------------------------------------------
on "$A" 180 "mkdir -p $D; for i in \$(seq 0 $((NF-1))); do dd if=/dev/zero of=$D/f\$i bs=1M count=$MB oflag=direct 2>/dev/null; done; sync" >/dev/null

# ---- drive both halves ---------------------------------------------------
# writer  : keeps re-dirtying the page cache so site 2 has folios to walk
#           (site 1 flushed the mapping clean, so without a re-dirtier the
#           site-2 flush finds nothing and can never block).
# syncer  : `sync` drives the bdi flusher — the exact task type (flush-252:1)
#           captured D-state in the live wedge.
# peer    : READS the files.  Measured, do not "improve" this into a write:
#           a peer write loop produced 2572 P7B-BASTNOTIFY and ZERO
#           P28-DRAINSITE2 over 100s — constant EX ping-pong keeps node A
#           re-acquiring, and the release pipeline never gets far enough to
#           reach the post-mode-clear flush.  A peer READ demotes A EX->PR and
#           lets the drain run to completion, which is what puts it at site 2.
#           Reliability instead comes from N independent files.
#
# Rounds, not one long window: the run stops as soon as the hazard is BUILT
# (P28-DRAINHOLD>0) or the node wedges, and reports honestly if neither
# happened rather than scoring "no wedge" on a round that never had one.
ROUND=25
MAXR=$(( (SECS + ROUND - 1) / ROUND ))
[ "$MAXR" -lt 1 ] && MAXR=1
BUILT=0; LIVE=""
for r in $(seq 1 "$MAXR"); do
  say "--- load round $r/$MAXR (${ROUND}s) ---"
  on "$A" 40 "for i in \$(seq 0 $((NF-1))); do
                nohup timeout $((ROUND+3)) sh -c \"while :; do dd if=/dev/zero of=$D/f\$i bs=64k count=256 conv=notrunc 2>/dev/null; done\" >/dev/null 2>&1 &
              done
              nohup timeout $((ROUND+3)) sh -c 'while :; do sync; done' >/dev/null 2>&1 &
              echo started" >/dev/null
  on "$B" 40 "for i in \$(seq 0 $((NF-1))); do
                nohup timeout $((ROUND+3)) sh -c \"while :; do cat $D/f\$i >/dev/null 2>&1; done\" >/dev/null 2>&1 &
              done
              echo started" >/dev/null
  sleep "$ROUND"

  # Liveness: a wedged node stays mounted and answers ls, so the only
  # reliable probe is whether it can finish a sync — exactly what test27
  # could not do.  `timeout 25 sync` is NOT usable: a sync blocked in D
  # state ignores SIGTERM, so the ssh itself hangs and the result is an
  # ambiguous empty string.  Stamp-file instead; the path is unique per run
  # so nothing ever needs removing.
  LIVE=$(on "$A" 60 "S=/run/mxfs_sync_${MARK}_$r
                     ( sync && echo SYNC_OK > \$S ) >/dev/null 2>&1 &
                     i=0; while [ \$i -lt 30 ]; do [ -f \$S ] && break; sleep 1; i=\$((i+1)); done
                     cat \$S 2>/dev/null || echo SYNC_WEDGED")
  HELD=$(on "$A" 30 "dmesg | sed -n '/$MARK ARMED/,\$p' | grep -c 'P28-DRAINHOLD'")
  say "round $r: sync=${LIVE:-NO_ANSWER} P28-DRAINHOLD=${HELD:-?}"
  [ "${HELD:-0}" -gt 0 ] 2>/dev/null && BUILT=1
  [ "$LIVE" = SYNC_WEDGED ] && break
  [ "$BUILT" = 1 ] && break
done
say "hazard constructed this run: $BUILT (1 = a drain stalled mid-batch at site 2)"
say "sync verdict: ${LIVE:-NO_ANSWER}"

DSTATE=$(on "$A" 30 "ps -eo stat=,pid=,comm= | awk '\$1 ~ /^D/ {print}' | head -20")
say "--- D-state tasks on $A ---"; printf '%s\n' "${DSTATE:-none}"

if printf '%s' "$DSTATE" | grep -qE "mxfs-ino-bast|flush-"; then
  say "--- stacks of the two suspected legs ---"
  on "$A" 40 "for p in \$(ps -eo stat=,pid=,comm= | awk '\$1 ~ /^D/ && (\$3 ~ /mxfs-ino-bast/ || \$3 ~ /^flush-/ || \$3 ~ /kworker/) {print \$2}' | head -6); do
                 echo \"### pid=\$p comm=\$(cat /proc/\$p/comm 2>/dev/null) wchan=\$(cat /proc/\$p/wchan 2>/dev/null)\";
                 cat /proc/\$p/stack 2>/dev/null | head -14; done"
fi

# ---- probe census (scoped to this run's marker) --------------------------
say "--- probe census on $A (since $MARK) ---"
on "$A" 40 "dmesg | sed -n '/$MARK ARMED/,\$p' > /run/abba_win.txt 2>/dev/null || dmesg > /run/abba_win.txt
            printf 'P28-DRAINSITE2 total   %s\n' \$(grep -c 'P28-DRAINSITE2' /run/abba_win.txt)
            printf 'P28-DRAINSITE2 dirty=1 %s\n' \$(grep 'P28-DRAINSITE2' /run/abba_win.txt | grep -c 'dirty=1')
            printf 'P28-DRAINHOLD          %s\n' \$(grep -c 'P28-DRAINHOLD' /run/abba_win.txt)
            printf 'P47-FILEBLOCK total    %s\n' \$(grep -c 'P47-FILEBLOCK' /run/abba_win.txt)
            printf 'P47 dsite=2 in_wb=1    %s\n' \$(grep 'P47-FILEBLOCK' /run/abba_win.txt | grep -c 'dsite=2 in_wb=1')
            printf 'P25-IOEND-ADMIT wp     %s\n' \$(grep 'P25-IOEND-ADMIT' /run/abba_win.txt | grep -c 'src=writepages')
            printf 'P73-WAITSTALL          %s\n' \$(grep -c 'P73-WAITSTALL' /run/abba_win.txt)
            echo '--- sample P47 lines ---'
            grep 'P47-FILEBLOCK' /run/abba_win.txt | grep 'in_wb=1' | tail -4
            echo '--- sample P28 lines ---'
            grep 'P28-DRAINHOLD' /run/abba_win.txt | tail -2"

# ---- always attempt recovery --------------------------------------------
say "--- disarming + recovery attempt on $A ---"
on "$A" 25 "echo 0 > /sys/module/mxfs/parameters/fix28_drain_stall_ms;
            echo 1 > /sys/module/mxfs/parameters/fix27_shared_admit;
            echo '$MARK RECOVER' > /dev/kmsg" >/dev/null
on "$B" 20 "echo 1 > /sys/module/mxfs/parameters/fix27_shared_admit" >/dev/null
REC=$(on "$A" 90 "timeout 60 sync && echo RECOVERED || echo STILL_WEDGED")
say "post-recovery sync: ${REC:-NO_ANSWER}"

if [ "$BUILT" != 1 ]; then
  say "=== INCONCLUSIVE arm=$ARM: the drain never stalled mid-batch at site 2, so no ABBA hazard existed this run.  NOT a control — re-run. ==="
  exit 3
fi
say "=== VERDICT arm=$ARM: hazard_built=1 during-load sync=${LIVE:-NO_ANSWER} after-knob-flip=${REC:-NO_ANSWER} ==="
