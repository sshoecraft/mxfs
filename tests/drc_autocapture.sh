#!/bin/bash
# drc_autocapture.sh — autonomous watcher for a dir_reuse@N/caw run (sess5).
# Detects, during the WORKLOAD (post prep-OK), a node that hard-hangs (goes
# unreachable while virsh domstate=running) and AUTO-CAPTURES the spinlock
# deadlock stack: virsh inject-nmi -> unknown_nmi_panic -> full CPU stacks to
# the serial log.  Also logs the terminal result.  Writes everything to $OUT so
# the capture survives a ccloop session handoff.
#
# Usage: drc_autocapture.sh <OUT> <run_log> [N]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"; PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
OUT="${1:?usage: OUT run_log [N]}"; RUNLOG="${2:?run_log}"; N="${3:-32}"
: > "$OUT"
log(){ echo "[$(date -u +%H:%M:%SZ)] $*" >> "$OUT"; }

log "autocapture start (N=$N)"
# wait for prep OK / abort
while :; do
  # NEVER `pgrep -f` (see tools/mxfs_pgrep.sh header — clyde 2026-08-04 wedge).
  "$REPO/tools/mxfs_pgrep.sh" "run[.]sh $N caw" >/dev/null 2>&1 || { log "run gone before prep-ok: $(grep -E 'PREP FAIL|ABORT|bad nodes' "$RUNLOG"|tail -1)"; exit 0; }
  grep -q "prep OK:" "$RUNLOG" 2>/dev/null && { log "prep OK"; break; }
  bad=$(grep -oE "bad nodes: test[0-9]+" "$RUNLOG" 2>/dev/null | tail -1)
  [ -n "$bad" ] && { n="${bad#bad nodes: }"; log "PREP-HANG $n -> inject-nmi"; virsh -c qemu:///system inject-nmi "$n" >/dev/null 2>&1; sleep 8; log "serial($n):"; tail -c 6000 "/var/log/libvirt/qemu/${n}-serial.log" 2>/dev/null | tr -d '\r' | grep -aE "panic|NMI|RIP|Call Trace|mxfs|xfs_|dlm_|caw_|spin|rcu|CPU:|<TASK>|lock" >> "$OUT"; exit 0; }
  sleep 5
done

lastr=""; stall=0
while :; do
  # NEVER `pgrep -f` (see tools/mxfs_pgrep.sh header — clyde 2026-08-04 wedge).
  "$REPO/tools/mxfs_pgrep.sh" "run[.]sh $N caw" >/dev/null 2>&1 || { log "TERMINAL: $(grep -E 'nodes_pass|  (PASS|FAIL)|dir_reuse' "$RUNLOG"|tail -2|tr '\n' '|')"; exit 0; }
  # hard-hang sweep across a spread sample
  for i in 1 4 8 12 16 20 24 28 32; do
    n="test$i"
    if ! timeout 6 "$SSH" "$n" "$PASS" true >/dev/null 2>&1; then
      # confirm it's really down (2nd try) and VM still running
      sleep 3
      if ! timeout 6 "$SSH" "$n" "$PASS" true >/dev/null 2>&1 && \
         virsh -c qemu:///system domstate "$n" 2>/dev/null | grep -q running; then
        log "HARD-HANG $n (unreachable, domstate=running) -> inject-nmi"
        pre=$(wc -c < "/var/log/libvirt/qemu/${n}-serial.log" 2>/dev/null || echo 0)
        virsh -c qemu:///system inject-nmi "$n" >/dev/null 2>&1
        for w in 1 2 3 4 5 6 7 8 9 10; do sleep 1; now=$(wc -c < "/var/log/libvirt/qemu/${n}-serial.log" 2>/dev/null||echo 0); [ "$now" -gt "$pre" ] && break; done
        log "=== $n panic backtrace ==="
        tail -c +$((pre+1)) "/var/log/libvirt/qemu/${n}-serial.log" 2>/dev/null | tr -d '\r' >> "$OUT"
        log "=== end $n backtrace ==="
        exit 0
      fi
    fi
  done
  # progress + stall note
  r=$(timeout 6 "$SSH" test1 "$PASS" 'dmesg 2>/dev/null|grep -oE "r=[0-9]+ rank=1"|tail -1|grep -oE "[0-9]+"' 2>/dev/null|tr -dc '0-9')
  if [ -n "$r" ] && [ "$r" != "$lastr" ]; then log "round=$r"; lastr="$r"; stall=0; else stall=$((stall+1)); fi
  [ "$stall" -ge 30 ] && { log "STALL@r=$lastr (~10min no advance) — likely wedge#3 P15-REL-ABORT starvation"; }
  sleep 20
done
