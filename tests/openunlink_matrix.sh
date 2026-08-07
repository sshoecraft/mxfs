#!/bin/bash
# tests/openunlink_matrix.sh — cross-node open-unlink functional matrix.
# Ledger: D-CROSSNODE-OPEN-UNLINK-DATA-LOSS + D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN.
# Design: GPT audit sess41 (memory ccloop-c7ee71c6-sess41-gpt-openunlink-audit-ruling),
# 9-group matrix.  This script covers the live-cluster groups:
#   basic        — A holds fd, B rm; data intact; close -> reap frees (P89)
#   reopen_nl    — C3 regression: open/read/close (grant demoted to NL), dcache
#                  reopen, B rm; before sess41 this read zeros (no grant, no bit)
#   eager_clear  — C4: last close publishes clear promptly; peer reap converges
#   multi_opener — A and C hold fds; free only after LAST cross-node close
#   mmap_only    — mapping (no fd) is protected activity; intact until munmap
#   rename_over  — mv G F drops F nlink->0 via rename path; same B6 protection
#   trunc_legal  — peer TRUNCATE of an open file must NOT be blocked (POSIX-legal
#                  coherent mutation; bits gate only nlink==0 inactivation)
#   reuse        — after reap-done, inode number reuse is clean (no stale-bit
#                  interference, no P87 for the new incarnation)
# Crash-point groups (opener death, unlinker death, recovery-EX-failure,
# TCP master failover) are separate arms — see the ledger entry.
#
# RULE 0 note: reap convergence is paced by MXFS_REAP_FIRST_MS=5s /
# MXFS_REAP_RETRY_MS=30s design cadence, not by I/O speed; per-case budgets
# below are cadence + margin, not perf assertions.  Whole matrix ~<420s.
#
# usage: openunlink_matrix.sh [nodeA=test1] [nodeB=test2] [nodeC=test3] [case...]
set -u
NA="${1:-test1}"
NB="${2:-test2}"
NC="${3:-test3}"
shift 3 2>/dev/null || shift $# 2>/dev/null
ONLY=("$@")
SSH=tools/mxfs_sshpass.sh
RUNID="oum_$(date +%s)_$$"
BASE="/mnt/shared/.${RUNID}"
FAILS=0
PASSES=0

say() { echo "[$(date +%H:%M:%S)] $*"; }

want_case() {
  [ ${#ONLY[@]} -eq 0 ] && return 0
  local c; for c in "${ONLY[@]}"; do [ "$c" = "$1" ] && return 0; done
  return 1
}

mark() { # mark <node> <tag>
  $SSH "$1" "echo ${RUNID}-$2 > /dev/kmsg" >/dev/null 2>&1
}

since() { # since <node> <tag> <grep-ERE>  -> count
  $SSH "$1" "dmesg | sed -n \"/${RUNID}-$2/,\\\$p\" | grep -cE '$3'" 2>/dev/null | tr -d ' \r\n'
}

wait_for() { # wait_for <node> <tag> <grep-ERE> <timeout_s>  -> 0 found
  local t=0
  while [ $t -lt "$4" ]; do
    local n; n=$(since "$1" "$2" "$3")
    [ "${n:-0}" -gt 0 ] && return 0
    sleep 3; t=$((t+3))
  done
  return 1
}

hold_fd() { # hold_fd <node> <path> <pidfile-suffix> — background holder, fd 9
  # sess46: WAIT FOR THE PIDFILE, not a fixed sleep.  The pidfile is written
  # only after `exec 9<` SUCCEEDS, so its presence proves the fd is open and
  # C3 protection (grant-at-open) is established BEFORE the caller triggers
  # the peer's rm — the matrix's intended ordering.  Under icluster routing
  # the open itself can block seconds in the cluster acquire; the old
  # `sleep 1` let the rm overtake the open and the case silently tested
  # open-DURING-free instead (now its own kernel guard:
  # P95-OPEN-STALE-INCARNATION).
  local t=0
  $SSH "$1" "nohup bash -c 'exec 9<$2; echo \$\$ > /tmp/${RUNID}.$3.pid; sleep 600' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  while [ $t -lt 30 ]; do
    $SSH "$1" "test -s /tmp/${RUNID}.$3.pid" >/dev/null 2>&1 && return 0
    sleep 1; t=$((t+1))
  done
  say "hold_fd: holder on $1 for $2 never opened (30s) — case will fail"
  return 1
}

read_fd() { # read_fd <node> <pidfile-suffix>
  $SSH "$1" "P=\$(cat /tmp/${RUNID}.$2.pid); dd if=/proc/\$P/fd/9 bs=4096 count=1 2>/dev/null | tr -d '\0'" 2>/dev/null
}

kill_holder() { # kill_holder <node> <pidfile-suffix>
  $SSH "$1" "kill \$(cat /tmp/${RUNID}.$2.pid) 2>/dev/null" >/dev/null 2>&1
}

verdict() { # verdict <case> <ok:0/1> <detail>
  if [ "$2" -eq 0 ]; then
    PASSES=$((PASSES+1)); echo "RESULT: PASS | case=$1 | $3"
  else
    FAILS=$((FAILS+1));  echo "RESULT: FAIL | case=$1 | $3"
  fi
}

$SSH "$NA" "mkdir -p $BASE" >/dev/null 2>&1

# ── basic: hold fd, peer rm, read intact, close, reap frees ────────────────
if want_case basic; then
  D=$BASE/basic; PAY="BASIC-$RUNID"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  mark "$NA" basicA; mark "$NB" basicB
  hold_fd "$NA" "$D/f" basic
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  sleep 3
  GOT=$(read_fd "$NA" basic)
  P87=$(since "$NB" basicB "P87-OPEN-DEFER ino=${INO} ")
  kill_holder "$NA" basic
  if [ "$GOT" = "$PAY" ]; then
    # after last close the owner's reap must retire the zombie
    if wait_for "$NB" basicB "P89-REAP-DONE ino=${INO}|P88-REAP-RETRY ino=${INO} .*iget_rc=-" 75; then
      verdict basic 0 "ino=$INO intact; defer=$P87; reap retired after close"
    else
      verdict basic 1 "ino=$INO intact but reap did NOT retire in 75s (defer=$P87) — liveness"
    fi
  else
    verdict basic 1 "ino=$INO DATA LOST got='${GOT:0:40}' defer=$P87"
  fi
fi

# ── reopen_nl: C3 — grant demoted to NL, dcache reopen, then peer rm ───────
if want_case reopen_nl; then
  D=$BASE/ropnl; PAY="ROPNL-$RUNID"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  # open+read+close so close_release demotes; wait out the demote queue
  $SSH "$NA" "cat $D/f >/dev/null" >/dev/null 2>&1
  sleep 5
  mark "$NA" ropnlA; mark "$NB" ropnlB
  hold_fd "$NA" "$D/f" ropnl        # dcache reopen — pre-C3 this held NO grant
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  sleep 3
  GOT=$(read_fd "$NA" ropnl)
  P90=$(since "$NA" ropnlA "P90-OPEN-PUBLISH ino=${INO} ")
  P87=$(since "$NB" ropnlB "P87-OPEN-DEFER ino=${INO} ")
  kill_holder "$NA" ropnl
  if [ "$GOT" = "$PAY" ] && [ "${P87:-0}" -gt 0 ]; then
    verdict reopen_nl 0 "ino=$INO intact after NL-reopen; publish=$P90 defer=$P87 (grant existed => C3 held)"
  else
    verdict reopen_nl 1 "ino=$INO got='${GOT:0:40}' publish=${P90:-0} defer=${P87:-0} — OPEN-AT-NL hole"
  fi
fi

# ── eager_clear: C4 — close clears promptly; owner reap converges fast ─────
if want_case eager_clear; then
  D=$BASE/eag; PAY="EAG-$RUNID"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  mark "$NA" eagA; mark "$NB" eagB
  hold_fd "$NA" "$D/f" eag
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  sleep 3
  kill_holder "$NA" eag             # last close NOW — bit must clear w/o evict
  CLR=0
  if wait_for "$NA" eagA "P91-OPEN-EAGER-CLEAR ino=${INO}" 20; then CLR=1; fi
  if wait_for "$NB" eagB "P89-REAP-DONE ino=${INO}|P88-REAP-RETRY ino=${INO} .*iget_rc=-" 75; then
    verdict eager_clear 0 "ino=$INO reap converged post-close (eager_clear_seen=$CLR)"
  else
    verdict eager_clear 1 "ino=$INO reap did not converge in 75s post-close (eager_clear_seen=$CLR)"
  fi
fi

# ── multi_opener: free only after the LAST cross-node close ────────────────
if want_case multi_opener; then
  D=$BASE/multi; PAY="MULTI-$RUNID"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  mark "$NB" multiB
  hold_fd "$NA" "$D/f" mA
  hold_fd "$NC" "$D/f" mC
  RMOUT=$($SSH "$NB" "LC_ALL=C rm $D/f 2>&1; echo rc=\$?" 2>/dev/null | tr '\n' ' ')
  sleep 3
  GA=$(read_fd "$NA" mA); GC=$(read_fd "$NC" mC)
  kill_holder "$NA" mA              # first close — C still holds
  sleep 8
  GC2=$(read_fd "$NC" mC)           # must STILL be intact
  kill_holder "$NC" mC              # last close
  OK=1
  [ "$GA" = "$PAY" ] && [ "$GC" = "$PAY" ] && [ "$GC2" = "$PAY" ] && OK=0
  if [ $OK -eq 0 ] && wait_for "$NB" multiB "P89-REAP-DONE ino=${INO}|P88-REAP-RETRY ino=${INO} .*iget_rc=-" 105; then
    verdict multi_opener 0 "ino=$INO both nodes intact; survived first close; freed after last"
  else
    verdict multi_opener 1 "ino=$INO A='$GA'==pay:$([ "$GA" = "$PAY" ]&&echo y||echo n) C2='$GC2'==pay:$([ "$GC2" = "$PAY" ]&&echo y||echo n) or reap stuck; rm_B: ${RMOUT:-?}"
  fi
fi

# ── mmap_only: mapping without fd is protected activity ────────────────────
if want_case mmap_only; then
  if $SSH "$NA" "command -v python3" >/dev/null 2>&1; then
    D=$BASE/mm; PAY="MMAP-$RUNID-0123456789abcdef"
    $SSH "$NA" "mkdir -p $D && printf '%s' $PAY > $D/f" >/dev/null 2>&1
    INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
    mark "$NB" mmB
    # holder: mmap SHARED then close the fd; keep the mapping; on signal, read+report
    $SSH "$NA" "nohup python3 -c '
import mmap, os, sys, time
fd = os.open(\"$D/f\", os.O_RDONLY)
m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
os.close(fd)
open(\"/tmp/${RUNID}.mm.pid\",\"w\").write(str(os.getpid()))
time.sleep(15)
open(\"/tmp/${RUNID}.mm.out\",\"w\").write(m[:].decode(\"utf-8\",\"replace\"))
m.close()
time.sleep(120)
' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
    sleep 2
    RMOUT=$($SSH "$NB" "LC_ALL=C rm $D/f 2>&1; echo rc=\$?" 2>/dev/null | tr '\n' ' ')
    sleep 16
    GOT=$($SSH "$NA" "cat /tmp/${RUNID}.mm.out" 2>/dev/null)
    $SSH "$NA" "kill \$(cat /tmp/${RUNID}.mm.pid) 2>/dev/null" >/dev/null 2>&1
    if [ "$GOT" = "$PAY" ]; then
      if wait_for "$NB" mmB "P89-REAP-DONE ino=${INO}|P88-REAP-RETRY ino=${INO} .*iget_rc=-" 105; then
        verdict mmap_only 0 "ino=$INO mapping read intact after peer rm; reap converged after munmap"
      else
        verdict mmap_only 1 "ino=$INO mapping intact but reap stuck 105s after munmap; rm_B: ${RMOUT:-?}"
      fi
    else
      verdict mmap_only 1 "ino=$INO MAPPING DATA LOST got='${GOT:0:40}'"
    fi
  else
    say "mmap_only: python3 missing on $NA — SKIP (counts as FAIL for coverage)"
    verdict mmap_only 1 "python3 unavailable on $NA; case not run"
  fi
fi

# ── rename_over: rename-over-target reaches nlink==0 via a different path ──
if want_case rename_over; then
  D=$BASE/ren; PAY="RENAME-TARGET-$RUNID"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f && echo other > $D/g" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  mark "$NB" renB
  hold_fd "$NA" "$D/f" ren
  $SSH "$NB" "mv -T $D/g $D/f" >/dev/null 2>&1
  sleep 3
  GOT=$(read_fd "$NA" ren)
  P87=$(since "$NB" renB "P87-OPEN-DEFER ino=${INO} ")
  kill_holder "$NA" ren
  if [ "$GOT" = "$PAY" ]; then
    if wait_for "$NB" renB "P89-REAP-DONE ino=${INO}|P88-REAP-RETRY ino=${INO} .*iget_rc=-" 75; then
      verdict rename_over 0 "ino=$INO intact through rename-over (defer=$P87); reap retired"
    else
      verdict rename_over 1 "ino=$INO intact but reap stuck (defer=$P87)"
    fi
  else
    verdict rename_over 1 "ino=$INO DATA LOST via rename-over got='${GOT:0:40}' defer=${P87:-0}"
  fi
fi

# ── trunc_legal: peer truncate must NOT be blocked AND must be visible ─────
# sess41: first run of this case found D-PEER-TRUNCATE-INVISIBLE-TO-PRIOR-
# HOLDER (RELOAD-SIZE-DROP-SKIP kept stale size + freed-extent map on a fresh
# tenure).  Assertions: truncate unblocked; opener's PATH stat/read coherent;
# fd read returns 0 bytes at EOF-0.
if want_case trunc_legal; then
  D=$BASE/tr; PAY="TRUNC-$RUNID"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  $SSH "$NA" "cat $D/f >/dev/null" >/dev/null 2>&1
  hold_fd "$NA" "$D/f" tr
  T0=$(date +%s)
  $SSH "$NB" "truncate -s 0 $D/f" >/dev/null 2>&1
  T1=$(date +%s)
  sleep 2
  SZ=$($SSH "$NA" "stat -c '%s' $D/f" 2>/dev/null | tr -d ' \r\n')
  RD=$($SSH "$NA" "cat $D/f 2>/dev/null | wc -c" 2>/dev/null | tr -d ' \r\n')
  FDRD=$($SSH "$NA" "P=\$(cat /tmp/${RUNID}.tr.pid); dd if=/proc/\$P/fd/9 bs=256 count=1 2>/dev/null | wc -c" 2>/dev/null | tr -d ' \r\n')
  kill_holder "$NA" tr
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  if [ $((T1-T0)) -le 20 ] && [ "${SZ:-x}" = "0" ] && [ "${RD:-x}" = "0" ] && [ "${FDRD:-x}" = "0" ]; then
    verdict trunc_legal 0 "peer truncate-to-0 in $((T1-T0))s; opener coherent (stat=0 read=0 fdread=0)"
  else
    verdict trunc_legal 1 "wall=$((T1-T0))s stat=${SZ:-?} read=${RD:-?} fdread=${FDRD:-?} — blocked or stale (D-PEER-TRUNCATE-INVISIBLE)"
  fi
fi

# ── trunc_partial: peer shrink 30->10 must show exactly the first 10 bytes ─
if want_case trunc_partial; then
  D=$BASE/trp
  $SSH "$NA" "mkdir -p $D && printf '0123456789ABCDEFGHIJKLMNOPQRS' > $D/f && cat $D/f >/dev/null" >/dev/null 2>&1
  hold_fd "$NA" "$D/f" trp
  $SSH "$NB" "truncate -s 10 $D/f" >/dev/null 2>&1
  sleep 2
  GOT=$($SSH "$NA" "cat $D/f" 2>/dev/null)
  kill_holder "$NA" trp
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  if [ "$GOT" = "0123456789" ]; then
    verdict trunc_partial 0 "opener sees exactly first 10 bytes after peer shrink"
  else
    verdict trunc_partial 1 "opener sees '${GOT:0:40}' (want '0123456789') after peer shrink"
  fi
fi

# ── reuse: post-reap inode reuse must be clean of stale bits ───────────────
if want_case reuse; then
  D=$BASE/ru; PAY="REUSE-$RUNID"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  mark "$NB" ruB
  hold_fd "$NA" "$D/f" ru
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  sleep 3
  kill_holder "$NA" ru
  if ! wait_for "$NB" ruB "P89-REAP-DONE ino=${INO}|P88-REAP-RETRY ino=${INO} .*iget_rc=-" 75; then
    verdict reuse 1 "precondition failed: ino=$INO never reaped"
  else
    mark "$NB" ru2
    # churn creates on B to reuse the number space; every file must be readable
    $SSH "$NB" "for i in \$(seq 1 300); do echo x\$i > $D/r\$i; done" >/dev/null 2>&1
    BAD=$($SSH "$NB" "c=0; for i in \$(seq 1 300); do [ \"\$(cat $D/r\$i 2>/dev/null)\" = \"x\$i\" ] || c=\$((c+1)); done; echo \$c" 2>/dev/null | tr -d ' \r\n')
    P87N=$(since "$NB" ru2 "P87-OPEN-DEFER")
    if [ "${BAD:-1}" = "0" ] && [ "${P87N:-0}" = "0" ]; then
      verdict reuse 0 "300 reuse-window creates clean; no stale-bit defers"
    else
      verdict reuse 1 "bad_files=$BAD stale_defers=$P87N in reuse window"
    fi
  fi
fi

$SSH "$NA" "rm -rf $BASE" >/dev/null 2>&1
echo "SUMMARY: openunlink_matrix pass=$PASSES fail=$FAILS"
[ $FAILS -eq 0 ]
