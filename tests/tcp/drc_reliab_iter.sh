#!/bin/bash
# drc_reliab_iter.sh — ONE clean-reboot + dir_reuse_coherency iteration at N
# nodes over tcp.  Each invocation: virsh destroy+start all N VMs, wait for
# ssh, run ./run.sh N tcp dir_reuse_coherency, print PASS/FAIL.
#
# The 8/tcp MASS failure mode (sess46/this-session) is a VM-state CARRYOVER:
# run.sh does NOT reboot between runs, so a node left fenced/wedged by a prior
# run stays bad.  A clean reboot before every run is the reliability fix.  This
# harness proves the per-run pass rate the criterion ("working 100%") needs.
#
# Usage: tests/tcp/drc_reliab_iter.sh <N>
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
N="${1:?usage: drc_reliab_iter.sh <N>}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
mapfile -t NODES < <(seq 1 "$N" | sed 's/^/test/')

echo "## reboot $N node(s): ${NODES[*]} @ $(date -u +%T)"
for d in "${NODES[@]}"; do virsh -c qemu:///system destroy "$d" >/dev/null 2>&1; done
sleep 4
for d in "${NODES[@]}"; do virsh -c qemu:///system start "$d" >/dev/null 2>&1; done
for t in $(seq 1 50); do
  ok=1
  for n in "${NODES[@]}"; do timeout 5 $SSH "$n" $PASS true >/dev/null 2>&1 || ok=0; done
  [ "$ok" = 1 ] && { echo "## all up after $((t*5))s"; break; }
  sleep 5
done
sleep 5
# <ccloop sess49> Quiet the serial console: the build carries a heavy always-on
# pr_warn (KERN_WARNING=4) diagnostic flood (~44k lines/run). Synchronous console
# printk burns CPU -> a node stops servicing TCP heartbeats -> declared dead ->
# its work is lost (sess46/47 node-isolation MASS-loss). console_loglevel=4 keeps
# levels 0-3 (EMERG..ERR, incl real XFS corruption alerts) on the console but
# drops WARNING+ to the ring buffer only (still dmesg-visible for diagnosis).
# Set QUIET_CONSOLE=0 to disable.
if [ "${QUIET_CONSOLE:-1}" = 1 ]; then
  for n in "${NODES[@]}"; do
    timeout 6 $SSH "$n" $PASS 'echo 4 > /proc/sys/kernel/printk' >/dev/null 2>&1
  done
fi
echo "## run.sh $N tcp dir_reuse_coherency @ $(date -u +%T)"
OUT=$(./run.sh "$N" tcp dir_reuse_coherency 2>&1)
echo "$OUT" | grep -E 'PASS|FAIL|dir_reuse_coherency' | tail -3
echo "$OUT" | grep -q 'PASS  dir_reuse_coherency' && echo "ITER_RESULT=PASS" || echo "ITER_RESULT=FAIL"
