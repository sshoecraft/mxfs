#!/bin/bash
# sess487 chain 140: THE sess48 HANDOFF, AS A TEST — does a peer that forces
# the holder to give up a directory see the holder's LAST DELETES?
#
# THE GAP THIS REPRODUCES.  sess48 proved (raw-disk parse + cross-node write
# trace, 2/tcp) that a node's committed FINAL directory deletes were NOT
# destaged at its EX->PR downgrade, so a peer's cold read listed files the
# holder had deleted (uv "none remain got=10").  The per-modify synchronous
# directory flush (mxfs_dlm_dir_durable_signal, mxfs.dir_persig_flush=1) was
# re-introduced as the workaround and costs 4.5 ms on EVERY in-tenure create of
# the failing crash_consistency row (chain 137).  The release/drain pipeline
# has since been rebuilt around architectural invariant 1 (full drain before
# the on-disk unlock).  Before the flush can be made release-only, this exact
# shape must pass WITHOUT it.  Design-consult ruling (sess487): a targeted handoff
# test whose last operations are deletes, a peer that forces the acquire and
# reads cold, and the holder killed right after the unlock in some rounds, so
# success cannot come from the holder's cache.
#
# ONE ROUND (holder H, peer P, third node C rotate through the fleet):
#   1. P creates a fresh shared directory (so H's first create is a genuine
#      cross-node EX acquire), syncs.
#   2. H creates N files, syncs, then DELETES the last M of them and does NOT
#      sync — the deletes are committed, and whether they reach the platter
#      before a peer can read is entirely the release drain's job.
#   3. P drops its caches and lists the directory.  P's PR acquire forces H's
#      BAST downgrade (drain, then unlock), and P's read is a cold read of the
#      shared LUN.  Expected: exactly f1..f(N-M).
#   4. KILL rounds only: virsh destroy H immediately after P's read returned
#      (H's grant is gone by then), and C — which never touched the directory
#      — drops caches and lists it.  With H dead, nothing but the platter (and
#      any survivor replay of H's slice) can serve the answer.  H is restarted
#      and waited for (SSH up) so the next prep finds a whole fleet.
# A round FAILS if any reader's count differs from N-M, lists a deleted name,
# or misses a kept name.  Kernel probes that name this loss class
# (P-DIRSTALE, P17-CLOBBER, DURABLE-FAIL, P190-MODIFY-BASE-BEHIND,
# P61-ADOPT-DISK) are counted on H and P per round.
#
# MODES.  The whole round set runs once per mxfs.dir_persig_flush value in
# MODES (default "1 0": the shipping workaround, then release-only).  The mode
# is shipped to every node's insmod via MXFS_EXTRA_MODARGS through prep and
# READ BACK 32/32 before any round.  Mode 0 passing every round (including the
# kill rounds) is the correctness half the ruling requires; a mode-0 failure
# that mode 1 does not show is the sess48 gap re-opened — the release drain,
# not the flush, is then the thing to fix.
#
# derived time budgets, derived: prep 300 (measured 88-137 s) + readback; a normal
# round = P mkdir (~1 s) + H creates N=200 uncontended (~1-2 s at ~5 ms) +
# sync + deletes (~0.5 s) + P cold read (~1-2 s) -> 25 s cap per remote step,
# ~10 s measured expected; a kill round adds virsh destroy (~2 s), C's read,
# and the victim's boot to SSH (measured 60-120 s in run.sh power_cycle_node,
# 180 s bound).  ROUNDS=8 normal + KILL=2 -> ~9 min per mode, ~20 min total.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess487_handoff_coldread.sh s487f &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s487f}
GATE=${GATE:-tests/evidence/sess487_chain139_persig_ab_s487e.log}
LOG=tests/evidence/sess487_chain140_handoff_coldread_$LABEL.log
O=tests/evidence/sess487_handoff_coldread_$LABEL
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
N=${N:-200}
M=${M:-50}
ROUNDS=${ROUNDS:-8}
KILL=${KILL:-2}
MODES=${MODES:-1 0}
mkdir -p "$O"

nodes() { seq 1 32 | sed 's/^/test/'; }

readback() { # <param> <want>
    local p=$1 v=$2 ok=0 bad="" n
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/parameters/$p 2>/dev/null" > "$O/.rb.$p.$n" 2>/dev/null ) &
    done
    wait
    for n in $(nodes); do
        [ "$(tr -d '[:space:]' < "$O/.rb.$p.$n" 2>/dev/null)" = "$v" ] && ok=$((ok + 1)) || bad="$bad $n"
    done
    echo "  READBACK $p=$v: $ok/32${bad:+ ; MISMATCH:$bad}"
    [ "$ok" -eq 32 ]
}

# expected survivor list for a round: f1..f(N-M), sorted the way ls sorts
expected() { seq 1 $((N - M)) | sed 's/^/f/' | sort; }

# cold read on a node: drop caches, list, return "COUNT=<n>" then the names
coldread() { # <node> <dir>
    timeout 60 $SSH "$1" "echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; ls $2 2>/dev/null | sort | tr '\n' ' '; echo; echo RC=\$?" 2>/dev/null
}

probes() { # <node> <since>  -> count of loss-class probe lines since
    timeout 30 $SSH "$1" "journalctl -k --no-pager --since '$2' 2>/dev/null | grep -acE 'P-DIRSTALE|P17-CLOBBER|DURABLE-FAIL|P190-MODIFY-BASE-BEHIND|P61-ADOPT-DISK'" 2>/dev/null | tr -dc '0-9'
}

wait_ssh() { # <node> <bound_s>
    local dl=$(( $(date +%s) + $2 ))
    while [ "$(date +%s)" -lt "$dl" ]; do
        [ "$(timeout 8 $SSH "$1" 'echo SSH_UP' 2>/dev/null | grep -c SSH_UP)" = 1 ] && return 0
        sleep 5
    done
    return 1
}

round() { # <mode> <r> <kill 0|1>
    local mode=$1 r=$2 kill=$3
    local h=$(( (r - 1) % 32 + 1 )) p c hn pn cn
    p=$(( h % 32 + 1 )); c=$(( (h + 1) % 32 + 1 ))
    # kill rounds take their victims from the top of the fleet so later rounds
    # never pick a dead node as holder/peer/third
    if [ "$kill" = 1 ]; then h=$(( 33 - r )); p=1; c=2; fi
    hn=test$h; pn=test$p; cn=test$c
    local dir="$MNT/hcr_m${mode}_r${r}" since t0 out cnt names exp verdict=PASS why="" hp pp
    since=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
    timeout 25 $SSH "$pn" "rm -rf $dir; mkdir -p $dir && sync && echo MKDIR_OK" 2>/dev/null | grep -q MKDIR_OK || { echo "  round m$mode r$r H=$hn P=$pn: SETUP FAIL (mkdir on $pn)"; return 1; }
    out=$(timeout 60 $SSH "$hn" "cd $dir || exit 1; n=0; for i in \$(seq 1 $N); do echo x > f\$i && n=\$((n+1)); done; sync; d=0; for i in \$(seq $((N - M + 1)) $N); do rm -f f\$i && d=\$((d+1)); done; echo MADE=\$n DELETED=\$d" 2>/dev/null | grep MADE=)
    [ "$out" = "MADE=$N DELETED=$M" ] || { echo "  round m$mode r$r H=$hn P=$pn: WORKLOAD FAIL ($out)"; return 1; }
    out=$(coldread "$pn" "$dir"); names=$(echo "$out" | head -1); cnt=$(echo "$names" | wc -w)
    exp=$(expected | tr '\n' ' ' | sed 's/ $//')
    if [ "$cnt" -ne $((N - M)) ] || [ "$(echo "$names" | sed 's/ $//')" != "$exp" ]; then
        verdict=FAIL; why="peer $pn saw $cnt (want $((N - M)))"
        echo "$names" > "$O/m${mode}_r${r}_peer_names.txt"
    fi
    if [ "$kill" = 1 ]; then
        timeout 60 sudo virsh -c qemu:///system destroy "$hn" > /dev/null 2>&1; local krc=$?
        out=$(coldread "$cn" "$dir"); names=$(echo "$out" | head -1); local cnt2; cnt2=$(echo "$names" | wc -w)
        if [ "$cnt2" -ne $((N - M)) ] || [ "$(echo "$names" | sed 's/ $//')" != "$exp" ]; then
            verdict=FAIL; why="$why; third $cn after killing $hn saw $cnt2 (want $((N - M)))"
            echo "$names" > "$O/m${mode}_r${r}_third_names.txt"
        fi
        timeout 60 sudo virsh -c qemu:///system start "$hn" > /dev/null 2>&1
        wait_ssh "$hn" 180 && local back=up || local back=DOWN
        echo "  round m$mode r$r H=$hn P=$pn C=$cn KILL: destroy_rc=$krc peer=$cnt third=$cnt2 want=$((N - M)) holder_back=$back wall=$(( $(date +%s) - t0 ))s -> $verdict${why:+ ($why)}"
        return 0
    fi
    hp=$(probes "$hn" "$since"); pp=$(probes "$pn" "$since")
    echo "  round m$mode r$r H=$hn P=$pn: peer=$cnt want=$((N - M)) probes_H=${hp:-?} probes_P=${pp:-?} wall=$(( $(date +%s) - t0 ))s -> $verdict${why:+ ($why)}"
}

{
  echo "=== sess487 chain140 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ko_sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') N=$N M=$M ROUNDS=$ROUNDS KILL=$KILL MODES='$MODES' ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  for mode in $MODES; do
    echo "--- mode dir_persig_flush=$mode ---"
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="dir_persig_flush=$mode" timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep_m$mode.out" 2>&1; prc=$?
    echo "STAGE prep_m$mode rc=$prc wall=$(( $(date +%s) - t0 ))s"
    [ "$prc" = 0 ] || { echo "MODE $mode NOT RUN: prep rc=$prc"; continue; }
    readback dir_persig_flush "$mode" || { echo "MODE $mode NOT RUN: the fleet is not uniformly at dir_persig_flush=$mode"; continue; }
    pass=0; fail=0; nr=0
    for r in $(seq 1 "$ROUNDS"); do
        if out=$(round "$mode" "$r" 0); then echo "$out"; case "$out" in *'-> PASS'*) pass=$((pass+1));; *) fail=$((fail+1));; esac; else echo "$out"; nr=$((nr+1)); fi
    done
    for r in $(seq 1 "$KILL"); do
        if out=$(round "$mode" "$r" 1); then echo "$out"; case "$out" in *'-> PASS'*) pass=$((pass+1));; *) fail=$((fail+1));; esac; else echo "$out"; nr=$((nr+1)); fi
    done
    echo "STAGE mode_$mode rounds_pass=$pass rounds_fail=$fail rounds_not_run=$nr of $((ROUNDS + KILL))"
    echo "m$mode pass=$pass fail=$fail notrun=$nr" >> "$O/modes.txt"
  done

  echo "--- VERDICT ---"
  cat "$O/modes.txt" 2>/dev/null | sed 's/^/  /'
  m1f=$(grep '^m1 ' "$O/modes.txt" 2>/dev/null | sed -n 's/.*fail=\([0-9]*\).*/\1/p'); m0f=$(grep '^m0 ' "$O/modes.txt" 2>/dev/null | sed -n 's/.*fail=\([0-9]*\).*/\1/p')
  m0p=$(grep '^m0 ' "$O/modes.txt" 2>/dev/null | sed -n 's/.*pass=\([0-9]*\).*/\1/p')
  if [ "${m0f:-1}" = 0 ] && [ "${m0p:-0}" = $((ROUNDS + KILL)) ]; then
      echo "  MODE 0 (release-only durability) PASSED every round including the kill rounds: the release drain carries the sess48 shape on this build. This is the correctness half only; the row's saving is chain 139's number."
  elif [ "${m0f:-0}" -gt 0 ] && [ "${m1f:-0}" = 0 ]; then
      echo "  MODE 0 FAILED ${m0f} round(s) that mode 1 passed: the sess48 release-drain gap is STILL OPEN under invariant 1 — a defect in the drain, to be filed; the per-modify flush may not be removed until it is fixed."
  elif [ "${m1f:-0}" -gt 0 ]; then
      echo "  MODE 1 (the shipping workaround) FAILED ${m1f} round(s): the workaround does not cover the shape either — file it."
  else
      echo "  INCOMPLETE: not every mode ran all its rounds; read the STAGE lines."
  fi
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
