#!/bin/bash
#
# fix_counter_watch.sh — sample, once a minute, the counters and kernel-log
# lines that say whether three net/mesh fixes are doing their work while the
# boards run, so the numbers survive the module reload between two boards and
# the kernel log rotating (a node's log holds about two minutes under load).
#
#   ag_release_nogrant_total   AG release finishers that reached the wire
#                              unlock with no grant of the node's (want 0)
#   ag_cached_phantom_total    cached AG hints found with nothing behind them
#   ag_release_dup_total       runners turned away from a committed release
#   ag_unlock_rearm_total      AG releases that ended "still held"
#   P52-PARTIAL-GRANT          a lower-mode grant completed a higher wait
#                              (want 0 lines)
#   P-GRANT-BELOW-WANT         the same event, now left pending (its total=)
#   P-TAUTH-RETARGET-DEPARTED  a page prepared for a departed node taken back
#                              on demand (its total=)
#   P-TAUTH-REMASTER-PARKED    requests parked on a page (lines in the log)
#   P-TAUTH-RELAY-ON-ASK       a page prepared to a node and never consumed,
#                              activated when its new owner asked (its total=)
#   dir_fmtrevert_behind_total clean block-form directory forks behind the
#                              platter replaced under a fresh EX grant
#   dir_fmtrevert_keep_total   in-core block-form directory kept over a
#                              shortform platter image
#
# Usage: tests/fix_counter_watch.sh LABEL STOPFILE NODE [NODE ...]
#   Runs until STOPFILE exists.  Launch it detached (nohup setsid ... &).
# Output: tests/evidence/fix_counter_watch_<LABEL>.out, one line per node per
#   sample: <iso> <node> src=<srcversion> up=<uptime, s>
#   nogrant= phantom= dup= rearm= partial= below= retarget= parked=
#   fmtbehind= fmtkeep= relay=
#   A node that does not answer in 15 s prints "<iso> <node> NOANSWER".
#
set -u
LABEL="${1:?usage: fix_counter_watch.sh LABEL STOPFILE NODE [NODE ...]}"
STOP="${2:?usage: fix_counter_watch.sh LABEL STOPFILE NODE [NODE ...]}"
shift 2
[ $# -ge 1 ] || { echo "no node given" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
SSH="$HERE/tools/mxfs_sshpass.sh"
O="tests/evidence/fix_counter_watch_$LABEL.out"
T=$(mktemp -d)
REMOTE='P=/sys/module/mxfs/parameters
d=$(dmesg 2>/dev/null)
tot() { printf "%s\n" "$d" | grep -a "$1" | tail -1 | sed -n "s/.* total=\([0-9]*\).*/\1/p"; }
printf "src=%s up=%s nogrant=%s phantom=%s dup=%s rearm=%s partial=%s below=%s retarget=%s parked=%s fmtbehind=%s fmtkeep=%s relay=%s\n" \
  "$(cat /sys/module/mxfs/srcversion 2>/dev/null || echo none)" "$(cut -d. -f1 /proc/uptime)" \
  "$(cat $P/ag_release_nogrant_total 2>/dev/null || echo -)" "$(cat $P/ag_cached_phantom_total 2>/dev/null || echo -)" \
  "$(cat $P/ag_release_dup_total 2>/dev/null || echo -)" "$(cat $P/ag_unlock_rearm_total 2>/dev/null || echo -)" \
  "$(printf "%s\n" "$d" | grep -ac P52-PARTIAL-GRANT)" "$(tot P-GRANT-BELOW-WANT)" "$(tot P-TAUTH-RETARGET-DEPARTED)" \
  "$(printf "%s\n" "$d" | grep -ac P-TAUTH-REMASTER-PARKED)" \
  "$(cat $P/dir_fmtrevert_behind_total 2>/dev/null || echo -)" "$(cat $P/dir_fmtrevert_keep_total 2>/dev/null || echo -)" \
  "$(tot P-TAUTH-RELAY-ON-ASK)"'
while [ ! -e "$STOP" ]; do
    now=$(date -u +%FT%TZ)
    for n in "$@"; do
        ( timeout 15 "$SSH" "$n" "$REMOTE" 2>/dev/null | grep -a '^src=' > "$T/$n" ) &
    done
    wait
    for n in "$@"; do
        if [ -s "$T/$n" ]; then echo "$now $n $(cat "$T/$n")"; else echo "$now $n NOANSWER"; fi
    done >> "$O"
    sleep 60
done
echo "FIX_COUNTER_WATCH_DONE $(date -u +%FT%TZ)" >> "$O"
