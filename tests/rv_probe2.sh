#!/bin/bash
# rv_probe2.sh — fast 2-node shared-dir rename-visibility probe.
# test1 & test2 each create N files in a SHARED dir, barrier (sleep), each
# renames its files before->after, sync, then EACH node checks the PEER's
# renames are visible (old gone, new present, content preserved).
# Repro of test_rename_visibility's cross-node dir-block coherency failure.
set -u
cd "$(dirname "$0")/.."
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
D=/mnt/shared/.rvp
N=${1:-10}
s(){ timeout 60 "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE 'Warning|Unauthorized|authorized user'; }
s test1 "rm -rf $D; mkdir -p $D; sync"; sleep 1
echo "== phase1: create $N files each =="
s test1 "for i in \$(seq 1 $N); do echo c1_\$i > $D/n1_before_\$i; done; sync" &
s test2 "for i in \$(seq 1 $N); do echo c2_\$i > $D/n2_before_\$i; done; sync" &
wait; sleep 1
echo "== phase2: rename before->after =="
s test1 "for i in \$(seq 1 $N); do mv $D/n1_before_\$i $D/n1_after_\$i; done; sync" &
s test2 "for i in \$(seq 1 $N); do mv $D/n2_before_\$i $D/n2_after_\$i; done; sync" &
wait; sleep 2
echo "== phase3: each node verifies PEER's renames =="
echo "-- test1 checks test2's files --"
s test1 "ng=0; nm=0; bad=0; for i in \$(seq 1 $N); do [ -e $D/n2_before_\$i ] && ng=\$((ng+1)); [ -e $D/n2_after_\$i ] || nm=\$((nm+1)); c=\$(cat $D/n2_after_\$i 2>/dev/null); [ \"\$c\" = c2_\$i ] || bad=\$((bad+1)); done; echo \"old_still_present=\$ng new_missing=\$nm content_bad=\$bad of=$N\""
echo "-- test2 checks test1's files --"
s test2 "ng=0; nm=0; bad=0; for i in \$(seq 1 $N); do [ -e $D/n1_before_\$i ] && ng=\$((ng+1)); [ -e $D/n1_after_\$i ] || nm=\$((nm+1)); c=\$(cat $D/n1_after_\$i 2>/dev/null); [ \"\$c\" = c1_\$i ] || bad=\$((bad+1)); done; echo \"old_still_present=\$ng new_missing=\$nm content_bad=\$bad of=$N\""
echo "== cleanup =="
s test1 "rm -rf $D; sync"
