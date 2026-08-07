#!/bin/bash
# tests/openunlink_probe.sh — cross-node POSIX open-unlink semantics probe.
# Ledger: D-CROSSNODE-OPEN-UNLINK-DATA-LOSS (opened sess40 / ccloop session 22).
#
# POSIX: data of an open file remains readable through the fd after ANY
# unlink, including one performed by another node.  GFS2 preserves this via
# the iopen glock; OCFS2 via the orphan dir + open lock.  MXFS has no
# distributed open tracking, so the unlinker's inactivation truncates and
# frees a file a peer still holds open.
#
# FIRST CAPTURE (2026-08-01, build 0.11.330, test1/test2):
#   A: echo PRECIOUS-DATA-12345 > victim; exec 9<victim   (ino 536802)
#   B: rm victim  -> B droplink + inactive_truncate + P3-EFREE-Q agbno=67303
#   A: read fd 9  -> 20 x \0 (od-verified), stat shows mode 0000 "weird file"
# Silent data loss visible to the open reader; no error, no shutdown.
#
# usage: openunlink_probe.sh [nodeA=test1] [nodeB=test2]
# RESULT: PASS = data intact through held fd; FAIL = zeros/short/error.
set -u
NA="${1:-test1}"
NB="${2:-test2}"
SSH=tools/mxfs_sshpass.sh
RUNID="oux_$(date +%s)_$$"
D="/mnt/shared/.${RUNID}"
PAYLOAD="OPEN-UNLINK-PAYLOAD-${RUNID}"

$SSH "$NA" "echo ${RUNID}-MARK > /dev/kmsg; mkdir -p $D && echo $PAYLOAD > $D/victim" >/dev/null 2>&1
INO=$($SSH "$NA" "stat -c '%i' $D/victim" 2>/dev/null)
$SSH "$NA" "nohup bash -c 'exec 9<$D/victim; echo \$\$ > /tmp/${RUNID}.pid; sleep 300' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 1
$SSH "$NB" "echo ${RUNID}-MARK > /dev/kmsg; rm $D/victim" >/dev/null 2>&1
sleep 4
GOT=$($SSH "$NA" "P=\$(cat /tmp/${RUNID}.pid); dd if=/proc/\$P/fd/9 bs=256 count=1 2>/dev/null | tr -d '\0'" 2>/dev/null)
FREED=$($SSH "$NB" "dmesg | sed -n \"/${RUNID}-MARK/,\\\$p\" | grep -cE 'P3-EFREE-Q ino=${INO}|P145-FREE'" 2>/dev/null)
$SSH "$NA" "kill \$(cat /tmp/${RUNID}.pid) 2>/dev/null; rm -rf $D" >/dev/null 2>&1
if [ "$GOT" = "$PAYLOAD" ]; then
  echo "RESULT: PASS | test=openunlink_probe | ino=$INO peer_frees=$FREED | data intact through held fd after peer unlink"
  exit 0
else
  echo "RESULT: FAIL | test=openunlink_probe | ino=$INO peer_frees=$FREED got='${GOT:0:60}' | POSIX open-unlink violated: peer unlink destroyed data under a live fd"
  exit 1
fi
