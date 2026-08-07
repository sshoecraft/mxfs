#!/bin/bash
#
# rig_dmesg_grep.sh — fetch a pattern from a node's kernel log and DISTINGUISH
# "the line is not there" from "we failed to look".
#
#   tests/rig_dmesg_grep.sh <host> <pattern> [-q]
#
# Exit codes (the whole point of this script):
#   0  HIT    — matched; matching lines are on stdout
#   1  MISS   — PROVEN absent: the remote dmesg ran, returned N>0 lines, and
#               none matched
#   2  ERROR  — nothing was proven.  ssh failed, timed out, dmesg failed, or
#               dmesg returned zero lines.  Treating this as a MISS is the bug
#               this script exists to prevent.
#
# WHY THIS EXISTS (sess79/sess80).  Twice in sess79 a grep for
# P236-WITHDRAW-REFUSED came back empty and a LATER grep found the same line
# carrying an EARLIER printk timestamp.  sess79 measured kmsg visibility
# latency directly and REFUTED it (worst 15.4ms, 0/10 never-visible) — so the
# empty results were not the kernel.  The remaining candidates are all
# "we failed to look and could not tell": ssh connect failure, `timeout N`
# killing the fetch, a dead/rebooting node, a wedged dmesg.  Every one of them
# produces empty stdout, which is byte-identical to a real no-match — and the
# usual caller shape
#
#     timeout 60 tools/mxfs_sshpass.sh $h "dmesg | grep -a PAT" 2>&1 | grep -v ...
#
# throws the exit code away twice (pipeline takes grep -v's status) and filters
# stderr, so the failure is invisible.  A grep that false-negatives silently
# turns a real failure into a PASS; sess27 found three board cells lying that
# way.  So: never infer absence, prove it.
#
# HOW absence is proven: the remote side snapshots dmesg to a file, then emits
# a sentinel carrying dmesg's exit status and the snapshot's line count.  No
# sentinel => the remote command did not finish => ERROR, not MISS.  Sentinel
# with lines=0 => we read an empty log => ERROR, not MISS.  Only a sentinel
# with rc=0 and lines>0 licenses reporting MISS.
#
# WHICH BOOT (sess80).  The sentinel also carries the node's boot_id.  printk
# timestamps are BOOT-RELATIVE, so a line stamped 92.168 is only "earlier than"
# a line stamped 120.0 if both came from the same boot — and the harnesses that
# produce this evidence reboot nodes routinely (the guard probe fences its
# victim, which reboots it).  Comparing stamps across a reboot makes a line look
# like it appeared before a grep that had already missed it, which is precisely
# the shape of the sess79 puzzle: three separate greps missed
# P236-WITHDRAW-REFUSED and a later one found it stamped 92.168009.  sess80
# measured and REFUTED all three mechanical explanations for that — kmsg
# visibility latency (worst 15.4ms, 0/10 invisible, sess79), fresh-ssh-per-poll
# fetch failure (tests/kmsg_fresh_ssh_miss_probe.sh, 30/30 HIT), and dmesg
# skipping records under log flood (zero /dev/kmsg sequence gaps across 179k
# records, quiet AND flooding).  Cross-boot stamp comparison is the remaining
# explanation and the one the evidence never ruled out; it cannot be proven
# retroactively, so instead it is made impossible to repeat.  ALWAYS record the
# boot_id alongside any printk stamp you intend to reason about.
#
set -u

HOST="${1:-}"
PATTERN="${2:-}"
QUIET=0
[ "${3:-}" = "-q" ] && QUIET=1

if [ -z "$HOST" ] || [ -z "$PATTERN" ]; then
    echo "usage: $0 <host> <pattern> [-q]" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
SSHPASS="$HERE/../tools/mxfs_sshpass.sh"

# Budget (RULE 0): a dmesg snapshot + grep is a sub-second operation.  ssh
# ConnectTimeout is 10s in the chokepoint, so 25s is connect + login + read
# with margin.  Anything slower is a sick node, which is ERROR — a fact worth
# reporting, not a reason to widen the timeout.
BUDGET=25

SNAP='/tmp/.rdg_snap'
# Single-quoted heredoc-ish remote script: no local expansion except $PATTERN,
# which is passed via the environment to keep it out of the quoting mess.
REMOTE='
  s='"$SNAP"'.$$
  dmesg > "$s" 2>/dev/null
  drc=$?
  n=$(wc -l < "$s" 2>/dev/null || echo 0)
  b=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)
  u=$(cut -d" " -f1 /proc/uptime 2>/dev/null || echo unknown)
  grep -a -e "$RDG_PAT" "$s"
  echo "__RDG_DONE drc=$drc lines=$n boot=$b uptime=$u"
  rm -f "$s"
'

OUT=$(RDG_PAT="$PATTERN" timeout "$BUDGET" "$SSHPASS" "$HOST" \
        "RDG_PAT='$PATTERN' sh -c '$REMOTE'" 2>/dev/null)
SSHRC=$?

SENTINEL=$(printf '%s\n' "$OUT" | grep -a '^__RDG_DONE ' | tail -1)

if [ -z "$SENTINEL" ]; then
    [ "$QUIET" = 1 ] || echo "ERROR $HOST: no sentinel — remote fetch did not complete (ssh/timeout rc=$SSHRC)" >&2
    exit 2
fi

DRC=$(printf '%s' "$SENTINEL" | sed -n 's/.*drc=\([0-9-]*\).*/\1/p')
LINES=$(printf '%s' "$SENTINEL" | sed -n 's/.*lines=\([0-9]*\).*/\1/p')
BOOT=$(printf '%s' "$SENTINEL" | sed -n 's/.*boot=\([^ ]*\).*/\1/p')
UPT=$(printf '%s' "$SENTINEL" | sed -n 's/.*uptime=\([^ ]*\).*/\1/p')
[ -n "$DRC" ] || DRC=-1
[ -n "$LINES" ] || LINES=0
[ -n "$BOOT" ] || BOOT=unknown
[ -n "$UPT" ] || UPT=unknown
# Every outcome carries the boot the log belongs to.  A printk stamp is only
# comparable to another stamp from the SAME boot_id.
PROV="boot=$BOOT uptime=${UPT}s"

if [ "$DRC" != "0" ]; then
    [ "$QUIET" = 1 ] || echo "ERROR $HOST: remote dmesg exited $DRC — log not read" >&2
    exit 2
fi
if [ "$LINES" -le 0 ]; then
    [ "$QUIET" = 1 ] || echo "ERROR $HOST: remote dmesg returned 0 lines — empty log is not proof of absence" >&2
    exit 2
fi

MATCHES=$(printf '%s\n' "$OUT" | grep -a -v '^__RDG_DONE ')
if [ -z "$MATCHES" ]; then
    [ "$QUIET" = 1 ] || echo "MISS $HOST: proven absent (read $LINES kernel log lines, none matched) $PROV" >&2
    exit 1
fi

printf '%s\n' "$MATCHES"
[ "$QUIET" = 1 ] || echo "HIT $HOST: $(printf '%s\n' "$MATCHES" | wc -l) line(s) of $LINES $PROV" >&2
exit 0
