#!/bin/bash
# tests/dir_reuse_stale_shell.sh — targeted reproducer for the sess41 matrix
# B-side subtree EIO (ledger D-CROSSNODE-OPEN-UNLINK-DATA-LOSS,
# open_investigation_sess41_end).
#
# Mechanism under test: node B caches directory inodes of a tree; a peer (A)
# deletes the tree (peer-free ring sets ISTALE_CAW on B's shells) and then
# recreates dirs REUSING the same inode numbers (same-type dir->dir, new
# generation).  B's next path walk must take the P95-SAMETYPE-RELOAD in-place
# reload and serve the NEW incarnation.  The sess41 failure: B's walk of the
# reused subtree returned EIO with no dmesg line (suspect: reload adopt left a
# zapped/stale in-core data fork; xfs_lookup returns -EIO on
# xfs_ifork_zapped(dp) with no log).  A creates files INSIDE the reused dir
# concurrently with B's walk to race the reload against an active writer.
#
# RULE 0 budget: cycle = 2 mkdir + walk + rm -rf + reuse-retry (<=12 * 0.5s)
# + 20-file churn + 20-stat walk ~= 12s native-ish; 25 cycles ~= 300s cap.
#
# Modes:
#   dir2dir  — B caches dirs, A deletes+recreates same-ino dirs (default)
#   file2dir — open-unlink type-flip: A creates f + holds fd, B rm's f (defer,
#              B = unlink authority, zombie on B), A closes, B reaps/frees the
#              ino, A IMMEDIATELY reuses it as a DIR, B walks it.  B's stale
#              FILE shell for the ino must give way to the new DIR incarnation.
#
# usage: dir_reuse_stale_shell.sh [A=test1] [B=test2] [cycles=25] [mode=dir2dir]
set -u
NA="${1:-test1}"; NB="${2:-test2}"; CY="${3:-25}"; MODE="${4:-dir2dir}"
SSH=tools/mxfs_sshpass.sh
RID="drss_$(date +%s)_$$"
FAILS=0
REUSED=0

$SSH "$NB" "echo ${RID}-start > /dev/kmsg" >/dev/null 2>&1
$SSH "$NA" "echo ${RID}-start > /dev/kmsg" >/dev/null 2>&1

if [ "$MODE" = "file2dir" ]; then
for c in $(seq 1 "$CY"); do
  BASE="/mnt/shared/.${RID}_$c"
  D="$BASE/sub"
  # 1. A creates dir + victim file (+ a sacrificial dir with a HIGHER ino in
  #    the same AG — its later rmdir pulls the AG's DLM grant back to A so the
  #    reuse-mkdir's trylock pass does not skip the AG B freed into)
  $SSH "$NA" "mkdir -p $D && echo pay-$c > $D/vic && mkdir $D/sac" >/dev/null 2>&1
  I1=$($SSH "$NA" "stat -c '%i' $D/vic" 2>/dev/null | tr -d ' \r\n')
  $SSH "$NA" "nohup bash -c 'exec 9<$D/vic; echo \$\$ > /tmp/${RID}.$c.pid; sleep 120' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  sleep 1
  # 2. B caches the file, then rm's it -> B is unlink authority, defer (A's fd)
  $SSH "$NB" "cat $D/vic >/dev/null 2>&1; rm $D/vic" >/dev/null 2>&1
  sleep 2
  # 3. A closes -> B's reap frees I1
  $SSH "$NA" "kill \$(cat /tmp/${RID}.$c.pid) 2>/dev/null" >/dev/null 2>&1
  # wait for B's reap to free (P89/P88 cadence: first try 5s)
  FREED=0
  for w in 1 2 3 4 5 6 7 8 9 10; do
    n=$($SSH "$NB" "dmesg | sed -n \"/${RID}-start/,\\\$p\" | grep -cE 'P89-REAP-DONE ino=${I1}( |,|\$)|P92-REAP-RETIRE ino=${I1}( |,|\$)'" 2>/dev/null | tr -d ' \r\n')
    [ "${n:-0}" -gt 0 ] && { FREED=1; break; }
    sleep 3
  done
  # 4. A reuses the ino as a DIR (bounded retries).  Warm the victim AG's
  #    AG-DLM grant back to A first (file create under the same-AG BASE —
  #    files follow their parent's AG), else A's mkdir TRYLOCK pass skips the
  #    AG whose grant B took while reap-freeing, and reuse never happens.
  I2=""; k=0
  $SSH "$NA" "rmdir $D/sac" >/dev/null 2>&1   # ifree in the AG -> A takes the grant
  while [ $k -lt 12 ]; do
    k=$((k+1))
    $SSH "$NA" "mkdir $D/nd$k" >/dev/null 2>&1
    I2=$($SSH "$NA" "stat -c '%i' $D/nd$k" 2>/dev/null | tr -d ' \r\n')
    [ -n "$I2" ] && [ "$I2" = "$I1" ] && { ND="$D/nd$k"; break; }
    $SSH "$NA" "rmdir $D/nd$k" >/dev/null 2>&1
    sleep 1
  done
  RE=no; [ "${I2:-}" = "$I1" ] && { RE=yes; REUSED=$((REUSED+1)); }
  [ "$RE" = "no" ] && { ND="$D/ndX"; $SSH "$NA" "mkdir -p $ND" >/dev/null 2>&1; }
  # 5. A churns files inside the new dir; B walks it concurrently
  $SSH "$NA" "nohup bash -c 'for j in \$(seq 1 15); do echo x\$j > $ND/g\$j; sleep 0.2; done' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  ERR=$($SSH "$NB" "err=''; for t in \$(seq 1 15); do
      o=\$(LC_ALL=C ls $ND 2>&1 >/dev/null) || err=\"\$err ls[\$t]:\$o\"
      o=\$(LC_ALL=C stat -c %F $ND 2>&1 >/dev/null) || err=\"\$err st[\$t]:\$o\"
      sleep 0.2
    done; echo \"\$err\" | tr -d '\n' | cut -c1-300" 2>/dev/null)
  EIO=$(echo "$ERR" | grep -c "Input/output error")
  NOTDIR=$(echo "$ERR" | grep -c "Not a directory")
  LSN=$($SSH "$NB" "ls $ND 2>/dev/null | wc -l" </dev/null 2>/dev/null | tr -d ' \r\n')
  if [ "${EIO:-0}" -gt 0 ] || [ "${NOTDIR:-0}" -gt 0 ]; then
    echo "RESULT: FAIL | cycle=$c mode=file2dir reuse=$RE freed=$FREED ino=$I1->${I2:-?} B-err: $(echo "$ERR" | cut -c1-200)"
    FAILS=$((FAILS+1))
    $SSH "$NB" "echo ${RID}-FAIL-c$c > /dev/kmsg" >/dev/null 2>&1
    continue
  fi
  echo "cycle=$c ok mode=file2dir reuse=$RE freed=$FREED ino=$I1->${I2:-?} tries=$k B_sees=${LSN:-?}"
  $SSH "$NA" "rm -rf $BASE" >/dev/null 2>&1
done
else
for c in $(seq 1 "$CY"); do
  BASE="/mnt/shared/.${RID}_$c"
  D="$BASE/sub"
  # 1. A creates the tree; capture dir inos
  $SSH "$NA" "mkdir -p $D && echo pay-$c > $D/f0" >/dev/null 2>&1
  I1=$($SSH "$NA" "stat -c '%i' $D" 2>/dev/null | tr -d ' \r\n')
  # 2. B populates incore shells (dir inode + dentries + file)
  $SSH "$NB" "ls -la $D >/dev/null 2>&1; cat $D/f0 >/dev/null 2>&1"
  # 3. A deletes the tree -> dir inos freed; ring should mark B's shells stale
  $SSH "$NA" "rm -rf $BASE" >/dev/null 2>&1
  sleep 2   # deferred inactivation + evict-ring delivery
  # 4. A recreates until the sub dir REUSES ino I1 (bounded)
  I2=""; k=0
  while [ $k -lt 12 ]; do
    k=$((k+1))
    $SSH "$NA" "mkdir -p $D" >/dev/null 2>&1
    I2=$($SSH "$NA" "stat -c '%i' $D" 2>/dev/null | tr -d ' \r\n')
    [ -n "$I2" ] && [ "$I2" = "$I1" ] && break
    $SSH "$NA" "rm -rf $BASE" >/dev/null 2>&1
    sleep 1
  done
  RE=no; [ "$I2" = "$I1" ] && { RE=yes; REUSED=$((REUSED+1)); }
  # 5. A churns creates INSIDE the (possibly reused) dir in the background
  $SSH "$NA" "nohup bash -c 'for j in \$(seq 1 20); do echo x\$j > $D/g\$j; sleep 0.2; done' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  # 6. B walks the new incarnation repeatedly while A churns — errno capture
  ERR=$($SSH "$NB" "err=''; for t in \$(seq 1 20); do
      o=\$(LC_ALL=C ls $D 2>&1 >/dev/null) || err=\"\$err ls[\$t]:\$o\"
      o=\$(LC_ALL=C stat -c %i $D/f0 2>&1 >/dev/null) || true
      o=\$(LC_ALL=C cat $D/f0 2>&1 >/dev/null) || err=\"\$err cat[\$t]:\$o\"
      sleep 0.2
    done; echo \"\$err\" | tr -d '\n' | cut -c1-300" 2>/dev/null)
  GOT=$($SSH "$NB" "cat $D/f0 2>/dev/null" </dev/null 2>/dev/null)
  # f0 was recreated? no — f0 exists only in incarnation 1; step 4 mkdir only.
  # B must see the dir LISTABLE and the churn files appearing; f0 must be ENOENT
  # (deleted with incarnation 1) — an EIO anywhere is the defect.
  EIO=$(echo "$ERR" | grep -c "Input/output error")
  LSN=$($SSH "$NB" "ls $D 2>/dev/null | wc -l" </dev/null 2>/dev/null | tr -d ' \r\n')
  if [ "${EIO:-0}" -gt 0 ]; then
    echo "RESULT: FAIL | cycle=$c reuse=$RE ino=$I1->$I2 EIO-on-B: $(echo "$ERR" | cut -c1-200)"
    FAILS=$((FAILS+1))
    # freeze evidence, do not clean this tree
    $SSH "$NB" "echo ${RID}-FAIL-c$c > /dev/kmsg" >/dev/null 2>&1
    continue
  fi
  echo "cycle=$c ok reuse=$RE ino=$I1->$I2 tries=$k B_sees=${LSN:-?} err='${ERR:0:80}'"
  $SSH "$NA" "rm -rf $BASE" >/dev/null 2>&1
done
fi

P95=$($SSH "$NB" "dmesg | sed -n \"/${RID}-start/,\\\$p\" | grep -c 'P95-SAMETYPE-RELOAD'" 2>/dev/null | tr -d ' \r\n')
P95C=$($SSH "$NB" "dmesg | sed -n \"/${RID}-start/,\\\$p\" | grep -c 'P95C.*resolved=0'" 2>/dev/null | tr -d ' \r\n')
P34H=$($SSH "$NB" "dmesg | sed -n \"/${RID}-start/,\\\$p\" | grep -c 'P34H'" 2>/dev/null | tr -d ' \r\n')
CORR=$($SSH "$NB" "dmesg | sed -n \"/${RID}-start/,\\\$p\" | grep -ciE 'corruption|zapped'" 2>/dev/null | tr -d ' \r\n')
echo "SUMMARY: cycles=$CY reused=$REUSED fails=$FAILS B: p95=$P95 p95c_unresolved=$P95C p34h=$P34H corr=$CORR"
[ "$FAILS" -eq 0 ]
