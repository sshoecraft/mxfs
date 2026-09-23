#!/bin/bash
# sess493: ARE FSYNC-ACKNOWLEDGED CREATES DURABLE ACROSS A CRASH WHEN THE
# ACQUIRE-SIDE EVICT HAS RETIRED THE DIRECTORY BLOCK'S LOG ITEM?
# (D-NEWTENURE-RETIRE-DROPS-INAIL-LOGITEM-OF-COMMITTED-UNWRITTEN-DIR-BLOCK-WITHOUT-WRITE-0492)
#
# THE SHAPE.  Two nodes alternate creating fsync'd files in ONE shared
# directory, so every round on the victim opens a new tenure (the peer held EX
# in between).  On 0.70.9 the victim's first evict call of each tenure retires
# the in-AIL log item of the data block it has just logged (P491-NEWTENURE-
# RETIRE-UNDEST superset=0), on 0.70.11 it keeps it (P492-KEEP-UNDEST).  After
# the victim's LAST round it keeps the directory (the peer never touches it
# again, so no release drain runs), logs enough unrelated transactions to move
# its log tail past the retired records (a slice holds only its last few
# transactions), and is power-cycled.  The survivors fence and replay its
# slice; two of them then cold-read the directory and every expected name must
# be present with its content.  The victim is restarted at the end.
#
# PASS = replay complete on the verifier, missing=0 on both verifiers.
# A missing name on the buggy build is the loss itself; on the fixed build the
# retained log item pins the tail until the block is written, so nothing can
# be missing.
#
# SHAPE=single (s493c/s493d, the shape above) CANNOT lose on either build: the
# shared directory stays ONE data block, so every retired item is re-logged by
# the very next create and the last create's surviving item writes the whole
# block (s493c on 0.70.9: 50 undestaged retires, missing=0).  The hazard needs a
# block whose LAST modification is followed by an evict-triggering op on a
# DIFFERENT block.  SHAPE=multiblock (default) builds that: B prefills NPRE
# 24-char names so the directory spans three data blocks in leaf format, where
# xfs_dir2_leaf_addname places a new entry in the LOWEST-numbered data block
# whose bestfree fits it.  The victim's last round then repeats NPAIR times:
# unlink one prefill name from block 0 (a 40-byte hole, non-adjacent so holes
# never coalesce), create a 24-char name (40 bytes: fits the hole -> block 0),
# fsync it, then create a 100-char name (112 bytes: fits no hole, no block tail
# -> block 2).  The second create's modify-refresh evict runs with block 0
# committed-unwritten; on 0.70.9 it retires block 0's log item and nothing
# re-logs block 0 again, on 0.70.11 it keeps it.  Population at risk = the
# short names (missing) and the unlinked prefill names (reappearing = extra).
# The victim's own evict census for the last-round window is printed with the
# directory's inode so a lap whose arm never fired is visibly inconclusive.
#
# derived time budgets, derived: prep 300 (measured 113-127 s); rounds R x 2 x NF
# fsync'd shared-dir creates at ~30-60 ms each under handoffs -> 60 s; tail
# advance TAILN private creates ~10 s; destroy 5 s; dead-confirm ~62 s +
# fence + replay <= 150 s; verify 30 s; restart 60 s.  ~10 min per lap.
#
# Usage: bash tests/sess493_d0492_crash_durability.sh <label>
#        SHAPE=single reproduces the s493c/s493d shape; SHAPE=multiblock (default) is the s493f/s493g shape.
#
# RIG SHAPE IS A PARAMETER AND DEFAULTS TO THIS PROJECT'S TWO-NODE TCP RIG:
#   NNODES=2 DLM=tcp A=test1 B=test2 C=$B KO=mxfs.ko (the TREE's build)
# For the original 32-node CAW laps: NNODES=32 DLM=caw A=test3 B=test2 C=test4
#   KO=tests/evidence/sess493_frozen_07011/mxfs.ko
# On two nodes there is no third node, so the second verifier C falls back to B
# and the RESULT line marks the lap SINGLE-WITNESS -- missing_C then merely
# repeats missing_B and is not independent confirmation.
#
# The whole body is wrapped `{ ... } >> "$LOG" 2>&1`, so this prints NOTHING to
# the invoking shell.  Read tests/evidence/sess493_d0492_crash_durability_<label>.log.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s493c}
GATE=${GATE:-tests/evidence/sess491_evict_undest_s493b.log}
# sess565: the rig shape is now a PARAMETER, and it defaults to the two-node TCP
# rig this project actually runs.  It used to hardcode `run.sh 32 caw
# prep_cluster` while the header described a two-node workload, so reading the
# header and running it booted all 32 VMs, power-cycled 30 of them when they
# failed to come up, drove the host to zero free memory and left the two-node
# rig unmounted -- without ever reaching a round.  Pass NNODES=32 DLM=caw to get
# the original behaviour back.
NNODES=${NNODES:-2}
DLM=${DLM:-tcp}
# KO defaults to the TREE's build, not a frozen one.  The old default pointed at
# a 0.70.11 freeze, so a run that did not set KO measured a module days old while
# every log line said the tree's VERSION.  When KO already IS ./mxfs.ko there is
# nothing to swap and nothing to restore.
KO=${KO:-mxfs.ko}
# The old RESTORE_KO default named a file that does not exist, so the abort path
# failed to restore and would have left a frozen module as the tree's mxfs.ko for
# every later run.  Back up whatever is in the tree now and restore THAT.
RESTORE_KO=${RESTORE_KO:-}
MODARGS=${MODARGS:-dir_persig_flush=0}
A=${A:-test1}          # victim
B=${B:-test2}          # partner (alternating tenures) and first verifier
# Second verifier.  On a two-node rig there is no third node, so C falls back to
# B: the checks still run, they just do not get an independent witness.  A lap
# where B and C are the same node cannot distinguish "both verifiers agree" from
# "one verifier counted twice", and the RESULT line says so.
C=${C:-}
[ -n "$C" ] || { if [ "$NNODES" -ge 4 ]; then C=test4; else C=$B; fi; }
R=${R:-6}              # rounds
NF=${NF:-10}           # files per node per round
TAILN=${TAILN:-300}    # unrelated fsync'd creates after the last round (tail advance)
SHAPE=${SHAPE:-multiblock}   # single | multiblock (see header)
NPRE=${NPRE:-220}      # multiblock: prefill names (24 chars, 40-byte entries: ~100 per block -> 3 data blocks)
NPAIR=${NPAIR:-5}      # multiblock: (unlink, short create -> block 0, long create -> block 2) triples in the victim's last round
LOG=tests/evidence/sess493_d0492_crash_durability_$LABEL.log
O=tests/evidence/sess493_d0492_crash_durability_$LABEL
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/d0492_$LABEL
mkdir -p "$O"
nodes() { seq 1 "$NNODES" | sed 's/^/test/'; }

# one node's round: NF fsync'd creates (data + fsync + dir fsync) in the shared dir
round_py() { # <who> <round>
cat <<EOF
import os, sys
d = '$D'
for i in range(1, $NF + 1):
    p = '%s/%s_r%d_f%d' % (d, '$1', $2, i)
    fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, ('%s r$2 f%d\\n' % ('$1', i)).encode())
    os.fsync(fd); os.close(fd)
fd = os.open(d, os.O_RDONLY); os.fsync(fd); os.close(fd)
print('round-ok $1 $2')
EOF
}

# prefill name k (24 chars) — block 0 holds roughly the first 100 in creation order
pre_name() { printf 'pre_%04d_xxxxxxxxxxxxxxx' "$1"; }
# victim last-round names: short (24 chars, fits a prefill hole) and long (100 chars, fits nothing in block 0/1)
short_name() { printf 's%02d_xxxxxxxxxxxxxxxxxxxx' "$1"; }
long_name() { printf 'L%02d_%s' "$1" "$(printf 'y%.0s' $(seq 1 96))"; }
# prefill index unlinked by pair i: 1, 11, 21, ... (non-adjacent so the holes never coalesce)
unlink_idx() { echo $(( ($1 - 1) * 10 + 1 )); }

prefill_py() {
cat <<EOF
import os
d = '$D'
for k in range($NPRE):
    p = '%s/pre_%04d_xxxxxxxxxxxxxxx' % (d, k)
    fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, ('pre r0 f%d\\n' % k).encode())
    os.fsync(fd); os.close(fd)
fd = os.open(d, os.O_RDONLY); os.fsync(fd); os.close(fd)
print('prefill-ok')
EOF
}

# the victim's last round in the multiblock shape
lastround_py() { # <who> <round>
cat <<EOF
import os, time
d = '$D'
def fsync_dir():
    fd = os.open(d, os.O_RDONLY); os.fsync(fd); os.close(fd)
def mk(name, body):
    fd = os.open('%s/%s' % (d, name), os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, body.encode()); os.fsync(fd); os.close(fd)
for i in range(1, $NPAIR + 1):
    k = (i - 1) * 10 + 1
    os.unlink('%s/pre_%04d_xxxxxxxxxxxxxxx' % (d, k)); fsync_dir()
    mk('s%02d_xxxxxxxxxxxxxxxxxxxx' % i, '$1 r$2 f%d\\n' % i)
    mk('L%02d_' % i + 'y' * 96, '$1 r$2 f%d\\n' % (100 + i))
fsync_dir()
print('round-ok $1 $2')
EOF
}

{
  echo "=== sess493 d0492_crash_durability START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO A=$A B=$B C=$C R=$R NF=$NF TAILN=$TAILN MODARGS='$MODARGS' ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  # Only swap if KO is a DIFFERENT file from the tree's module.  Back the tree's
  # own build up first so the restore at the end has something real to put back.
  swapped=0
  if [ "$KO" -ef mxfs.ko ]; then
      echo "STAGE install_ko skipped: KO is the tree's own mxfs.ko (no swap, no restore needed)"
  else
      [ -n "$RESTORE_KO" ] || { RESTORE_KO="$O/tree_mxfs.ko.backup"; cp mxfs.ko "$RESTORE_KO"; }
      cp "$KO" mxfs.ko; swapped=1
  fi
  echo "STAGE install_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') swapped=$swapped keep_marker=$(strings -a mxfs.ko | grep -ac 'P492-KEEP-UNDEST') retire_marker=$(strings -a mxfs.ko | grep -ac 'P491-NEWTENURE-RETIRE-UNDEST')"
  t0=$(date +%s)
  MXFS_EXTRA_MODARGS="$MODARGS" timeout 300 ./run.sh "$NNODES" "$DLM" prep_cluster > "$O/prep.out" 2>&1; rc=$?
  echo "STAGE prep rc=$rc nodes=$NNODES dlm=$DLM wall=$(( $(date +%s) - t0 ))s budget=300s build=$(grep -ao 'build [0-9A-F]*' "$O/prep.out" | tail -1)"
  if [ "$rc" != 0 ]; then echo "ABORT: prep failed"; [ "$swapped" = 1 ] && cp "$RESTORE_KO" mxfs.ko; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')
  MARK="D0492-$LABEL"
  for n in $A $B $C; do timeout 20 $SSH "$n" "echo $MARK > /dev/kmsg; cat /sys/module/mxfs/parameters/dir_persig_flush; echo -n /; cat /sys/module/mxfs/parameters/dir_datascan_heal 2>/dev/null" 2>/dev/null | tr -d '[:space:]' > "$O/persig_$n.txt"; done
  # sess498: the second field is mxfs.dir_datascan_heal (absent before 0.70.18)
  echo "STAGE persig/heal A=$(cat "$O/persig_$A.txt") B=$(cat "$O/persig_$B.txt") C=$(cat "$O/persig_$C.txt")"

  # alternating tenures: B opens the directory, then A/B rounds, A last
  t0=$(date +%s)
  out=$(timeout 60 $SSH "$B" "mkdir -p $D && echo mkdir-ok" 2>/dev/null | tr -d '\r')
  echo "  mkdir on $B: $out"
  if [ "$SHAPE" = multiblock ]; then
      # B prefills so the directory spans three data blocks (leaf format);
      # budget: NPRE fsync'd creates at ~30-60 ms -> 60 s
      out=$(prefill_py | timeout 120 $SSH "$B" "python3 -" 2>&1 | grep -a 'prefill-ok\|Error\|error' | head -2 | tr '\n' ' ')
      echo "STAGE prefill on $B: $out n=$NPRE wall=$(( $(date +%s) - t0 ))s budget=60s"
  fi
  ok=0; MARK2="D0492-$LABEL-LASTROUND"
  for r in $(seq 1 "$R"); do
      for who in $B $A; do
          if [ "$SHAPE" = multiblock ] && [ "$who" = "$A" ] && [ "$r" = "$R" ]; then
              timeout 20 $SSH "$A" "echo $MARK2 > /dev/kmsg" >/dev/null 2>&1
              out=$(lastround_py "$who" "$r" | timeout 90 $SSH "$who" "python3 -" 2>&1 | grep -a 'round-ok\|Error\|error' | head -2 | tr '\n' ' ')
          else
              out=$(round_py "$who" "$r" | timeout 90 $SSH "$who" "python3 -" 2>&1 | grep -a 'round-ok\|Error\|error' | head -2 | tr '\n' ' ')
          fi
          case "$out" in *round-ok*) ok=$((ok + 1));; *) echo "  ROUND FAILED who=$who r=$r: $out";; esac
      done
  done
  echo "STAGE rounds ok=$ok/$(( R * 2 )) shape=$SHAPE wall=$(( $(date +%s) - t0 ))s budget=90s"
  # the victim's own evict census for this window (what the arm did to its blocks)
  timeout 30 $SSH "$A" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P491-NEWTENURE-RETIRE-UNDEST\|P492-KEEP-UNDEST\|P491-EVICT-UNDEST\|P34-NEWTENURE\|$MARK2' | cut -c1-330" > "$O/A_evict_census.txt" 2>/dev/null
  echo "  VICTIM evict census: retire_undest=$(grep -ac 'P491-NEWTENURE-RETIRE-UNDEST' "$O/A_evict_census.txt") retire_superset0=$(grep -a 'P491-NEWTENURE-RETIRE-UNDEST' "$O/A_evict_census.txt" | grep -ac 'superset=0 ') keep_undest=$(grep -ac 'P492-KEEP-UNDEST' "$O/A_evict_census.txt") keep_current=$(grep -ac 'epoch_rel=current' "$O/A_evict_census.txt") keep_prior=$(grep -ac 'epoch_rel=prior' "$O/A_evict_census.txt")"
  grep -a "ino=" "$O/A_evict_census.txt" | tail -3 | cut -c1-260 | sed 's/^/    A: /'
  if [ "$SHAPE" = multiblock ]; then
      # the last-round window only, keyed on the shared directory's inode: did the
      # arm act on an undestaged block of THIS directory after the short creates?
      dino=$(timeout 20 $SSH "$A" "stat -c %i $D" 2>/dev/null | tr -d '[:space:]')
      sed -n "/$MARK2/,\$p" "$O/A_evict_census.txt" > "$O/A_lastround_census.txt"
      lr_ret=$(grep -a 'P491-NEWTENURE-RETIRE-UNDEST' "$O/A_lastround_census.txt" | grep -ac "ino=$dino ")
      lr_keep=$(grep -a 'P492-KEEP-UNDEST' "$O/A_lastround_census.txt" | grep -ac "ino=$dino ")
      lr_daddrs=$(grep -a "ino=$dino " "$O/A_lastround_census.txt" | grep -ao 'daddr=[0-9]*' | sort | uniq -c | tr -s ' ' | tr '\n' ';')
      echo "  LASTROUND dir_ino=$dino retire_undest=$lr_ret keep_undest=$lr_keep per_daddr=[$lr_daddrs]"
      grep -a "ino=$dino " "$O/A_lastround_census.txt" | cut -c1-300 | sed 's/^/    LR: /'
  fi

  # tail advance on the victim: unrelated fsync'd creates in a private dir
  t0=$(date +%s)
  out=$(timeout 120 $SSH "$A" "mkdir -p $MNT/tail_$LABEL && python3 -c \"
import os
d='$MNT/tail_$LABEL'
for i in range($TAILN):
    fd=os.open('%s/t%d' % (d, i), os.O_CREAT|os.O_WRONLY, 0o644); os.write(fd, b'x'); os.fsync(fd); os.close(fd)
print('tail-ok')\"; grep -a 'P309\|log tail\|xlog_tail\|P-TAIL' /dev/null; cat /proc/loadavg" 2>&1 | grep -a 'tail-ok\|Error\|^[0-9]' | tr '\n' ' ')
  echo "STAGE tail_advance $out wall=$(( $(date +%s) - t0 ))s budget=120s"
  # the victim's journal is volatile: capture its slice geometry and slot before the kill
  timeout 25 $SSH "$A" "dmesg | grep -a 'claimed heartbeat slot\|P308\|P309' | tail -3 | cut -c1-240" > "$O/A_pre_destroy.txt" 2>/dev/null
  echo "  A pre-destroy: $(tr '\n' ' ' < "$O/A_pre_destroy.txt" | cut -c1-300)"
  KILL_T=$(date -u +%FT%T.%3NZ)
  timeout 60 sudo virsh -c qemu:///system destroy "$A" > "$O/kill.txt" 2>&1; echo "STAGE destroy $A rc=$? at $KILL_T"

  # survivors fence + replay: wait for a terminal replay line on B
  t0=$(date +%s); W=0; V=""
  while [ $W -lt 180 ]; do
      V=$(timeout 15 $SSH "$B" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P163-RECOVERY-COMPLETE\|POLICY-REFUSED\|FR-FAIL\|foreign replay of slot.*complete\|terminal verdict\|P241-RECOV-TERMINAL' | cut -c1-240" 2>/dev/null)
      echo "$V" | grep -aq 'P163-RECOVERY-COMPLETE\|POLICY-REFUSED\|FR-FAIL\|complete\|terminal' && break
      sleep 5; W=$((W + 5))
  done
  echo "STAGE replay_wait ${W}s budget=180s lines=$(echo "$V" | grep -ac .)"
  echo "$V" | head -4 | sed 's/^/    B: /'

  # verify on B and C after a cache drop: every expected name, with content
  if [ "$SHAPE" = multiblock ]; then
      gone=$(for i in $(seq 1 "$NPAIR"); do pre_name "$(unlink_idx "$i")"; echo; done | sort)
      want=$( { for r in $(seq 1 "$R"); do for who in $B $A; do
                    [ "$who" = "$A" ] && [ "$r" = "$R" ] && continue
                    for i in $(seq 1 "$NF"); do echo "${who}_r${r}_f${i}"; done; done; done
                for k in $(seq 0 $(( NPRE - 1 ))); do pre_name "$k"; echo; done | grep -vxF -f <(echo "$gone")
                for i in $(seq 1 "$NPAIR"); do short_name "$i"; echo; long_name "$i"; echo; done; } | sort)
      echo "$gone" > "$O/unlinked.txt"
  else
      want=$(for r in $(seq 1 "$R"); do for who in $B $A; do for i in $(seq 1 "$NF"); do echo "${who}_r${r}_f${i}"; done; done; done | sort)
  fi
  echo "$want" > "$O/expected.txt"
  for v in $B $C; do
      timeout 60 $SSH "$v" "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D 2>/dev/null | sort; echo ===; for f in \$(ls $D 2>/dev/null); do head -c 64 $D/\$f 2>/dev/null | tr -d '\n'; echo \" <\$f\"; done | grep -ac '^[a-z0-9]* r[0-9]* f[0-9]* <'" > "$O/verify_$v.txt" 2>/dev/null
      seen=$(sed -n '1,/^===/p' "$O/verify_$v.txt" | grep -v '^===' | sort)
      missing=$(comm -23 <(echo "$want") <(echo "$seen") | tr '\n' ',' | cut -c1-600)
      extra=$(comm -13 <(echo "$want") <(echo "$seen") | tr '\n' ',' | cut -c1-200)
      nmiss=$(comm -23 <(echo "$want") <(echo "$seen") | grep -c .)
      content_ok=$(tail -1 "$O/verify_$v.txt")
      nextra=$(comm -13 <(echo "$want") <(echo "$seen") | grep -c .)
      echo "  VERIFY $v: expected=$(echo "$want" | grep -c .) present=$(echo "$seen" | grep -c .) missing=$nmiss extra=$nextra content_ok=${content_ok:-?} missing_names=[$missing] extra_names=[$extra]"
      echo "$nmiss" > "$O/missing_$v.txt"; echo "$nextra" > "$O/extra_$v.txt"
  done
  # the victim's last-round files are the population at risk: name them explicitly
  seenB=$(sed -n '1,/^===/p' "$O/verify_$B.txt" | grep -v '^===' | sort)
  if [ "$SHAPE" = multiblock ]; then
      smiss=$(comm -23 <(echo "$want") <(echo "$seenB") | grep -c '^s[0-9][0-9]_')
      lmiss=$(comm -23 <(echo "$want") <(echo "$seenB") | grep -c '^L[0-9][0-9]_')
      back=$(comm -12 <(cat "$O/unlinked.txt") <(echo "$seenB") | grep -c .)
      echo "  AT-RISK: short(block0) missing on $B = $smiss/$NPAIR  long(block2) missing = $lmiss/$NPAIR  unlinked-reappeared = $back/$NPAIR"
  else
      lastmiss=$(comm -23 <(echo "$want") <(echo "$seenB") | grep -c "^${A}_r${R}_")
      echo "  AT-RISK: victim last round ${A}_r${R}_f1..$NF missing on $B = $lastmiss"
  fi
  # sweep the replayer(s) and B for the recovery lines
  for n in $(nodes); do
      [ "$n" = "$A" ] && continue
      ( timeout 60 $SSH "$n" "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P163-|elected|foreign replay|POLICY-REFUSED|FR-FAIL|quarantin|P241-|FENCE|fence|P492-KEEP|P491-NEWTENURE|mxfs-cc|shut down'" > "$O/probes_$n.txt" 2>/dev/null ) &
  done
  wait
  echo "  FLEET: replay_complete=$(cat "$O"/probes_test*.txt | grep -ac 'P163-RECOVERY-COMPLETE') refused=$(cat "$O"/probes_test*.txt | grep -ac 'POLICY-REFUSED') frfail=$(cat "$O"/probes_test*.txt | grep -ac 'FR-FAIL') quarantine=$(cat "$O"/probes_test*.txt | grep -a 'quarantin' | grep -avc 'quarantined=0x0') shutdown=$(cat "$O"/probes_test*.txt | grep -aci 'shut down') keep_undest_fleet=$(cat "$O"/probes_test*.txt | grep -ac 'P492-KEEP-UNDEST') retire_undest_fleet=$(cat "$O"/probes_test*.txt | grep -ac 'P491-NEWTENURE-RETIRE-UNDEST')"
  grep -ah 'elected\|foreign replay of slot' "$O"/probes_test*.txt | cut -c1-220 | head -4 | sed 's/^/    R: /'
  mb=$(cat "$O/missing_$B.txt"); mc=$(cat "$O/missing_$C.txt"); eb=$(cat "$O/extra_$B.txt"); ec=$(cat "$O/extra_$C.txt")
  if [ "$ok" = "$(( R * 2 ))" ] && [ "$mb" = 0 ] && [ "$mc" = 0 ] && [ "$eb" = 0 ] && [ "$ec" = 0 ] && [ "$(cat "$O"/probes_test*.txt | grep -ac 'P163-RECOVERY-COMPLETE')" -ge 1 ]; then
      echo "RESULT PASS missing_B=0 missing_C=0 extra_B=0 extra_C=0 rounds=$ok shape=$SHAPE verifiers=$( [ "$B" = "$C" ] && echo "$B(SINGLE-WITNESS: B and C are the same node, missing_C merely repeats missing_B)" || echo "$B,$C" )"
  else
      echo "RESULT FAIL missing_B=$mb missing_C=$mc extra_B=$eb extra_C=$ec rounds=$ok/$(( R * 2 )) shape=$SHAPE"
  fi
  timeout 60 sudo virsh -c qemu:///system start "$A" >> "$O/kill.txt" 2>&1; echo "STAGE restart $A rc=$?"
  # the next chain's prep needs the victim back: wait for ssh (boot measured ~40-60 s)
  t0=$(date +%s); up=0
  while [ $(( $(date +%s) - t0 )) -lt 150 ]; do
      timeout 10 $SSH "$A" "uptime" >/dev/null 2>&1 && { up=1; break; }
      sleep 5
  done
  echo "STAGE victim_back up=$up wall=$(( $(date +%s) - t0 ))s budget=150s"
  if [ "$swapped" = 1 ]; then
      cp "$RESTORE_KO" mxfs.ko
      echo "STAGE restore_tree_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$RESTORE_KO"
  else
      echo "STAGE restore_tree_ko skipped: no swap was made, tree mxfs.ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') untouched"
  fi
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
