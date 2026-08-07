#!/bin/bash
#
# kmsg_flood_skip_probe.sh — does `dmesg` silently SKIP kernel log records while
# the kernel is flooding the ring buffer?
#
#   tests/kmsg_flood_skip_probe.sh <host> [flood_lines] [polls]
#
# HYPOTHESIS (falsifiable, sess80).  sess79 twice grepped a node for a line that
# provably existed and got nothing, then found it later with an EARLIER printk
# stamp.  It refuted kmsg visibility latency by measurement (worst 15.4ms).  The
# missed greps all happened on a node that had just been FENCED and force-shut-
# down — i.e. one spewing kernel log lines.  `dmesg` reads /dev/kmsg by default;
# a /dev/kmsg reader that the writer overtakes gets -EPIPE and must re-seek to
# the oldest still-available record, SKIPPING everything in between.  So under
# write pressure `dmesg` can omit records that are still in the buffer, and a
# later quiet invocation finds them.
#
# PREDICTION.  While flooding: `dmesg` MISSES a marker known to be in the
# buffer.  `dmesg -S` (forces the syslog(2) interface, which does not have the
# overtake-and-reseek behaviour) HITS it.  After the flood: both HIT.
#
# WHY IT MATTERS MORE THAN THE LINE IT WAS FOUND ON.  Every criterion in this
# project that greps dmesg for a failure marker does so on nodes that are
# failing — which is exactly when the log floods.  If dmesg skips under flood,
# those greps false-negative precisely when there is something to find, and a
# real failure is recorded as a PASS.  sess27 found three board cells lying
# this way.
#
# The whole measurement runs in ONE ssh session so the transport is not a
# variable (tests/kmsg_fresh_ssh_miss_probe.sh already showed fresh-ssh-per-poll
# is clean at 30/30 on an idle node).
#
# !! DESTRUCTIVE TO KERNEL-LOG EVIDENCE !!  The flood writes enough records to
# WRAP the target's ring buffer, which evicts every real kernel message that was
# in it.  sess80 ran this on test2 and afterwards a grep for "mxfs" across
# 176950 log lines matched NOTHING — the whole MXFS history was gone.  Only run
# it on a node whose log you are willing to lose, and never on a node holding
# evidence from a run you have not yet read.
#
# RESULT (sess80, test2): NOT REPRODUCED, and the mechanism is REFUTED by a
# better instrument.  This probe cannot separate "dmesg skipped a record" from
# "the log grew between the two sequential reads" — its first cut reported
# dmesg=2992 vs dmesg -S=3274 and that deficit is fully explained by the flood
# adding lines between the two commands, not by a skip.  It also showed dmesg -S
# is CAPPED (164483 lines, constant, while the log grew past 176000), so -S is
# the worse backend, not the safer one.  The decisive test is /dev/kmsg's own
# record SEQUENCE NUMBERS read in a single pass: zero gaps across 179535
# records, quiet AND flooding.  dmesg does not skip records on these nodes.
# Kept in-tree because the seq-gap check is the reusable part and because the
# refutation is worth not re-deriving.
#
set -u

HOST="${1:-}"
FLOOD="${2:-20000}"
POLLS="${3:-8}"

if [ -z "$HOST" ]; then
    echo "usage: $0 <host> [flood_lines] [polls]" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
SSHPASS="$HERE/../tools/mxfs_sshpass.sh"

echo "host=$HOST flood_lines=$FLOOD polls=$POLLS"

# Remote script.  Emits the marker FIRST so it is unconditionally present for
# every subsequent poll, then floods while polling both dmesg backends.
REMOTE=$(cat <<'EOS'
set -u

# CONTINUOUS flood for the whole measurement.  The first cut of this probe
# emitted the marker BEFORE a bounded flood, which put the marker at the OLD end
# of the buffer — outside the window a /dev/kmsg reader can be overtaken in, so
# it could never be skipped.  It still showed the skip in the LINE COUNTS
# (dmesg 2992 vs dmesg -S 3274, then 18312 vs 19726 — 282 then 1414 records
# missing).  The real sess79 failure grepped for a marker emitted DURING the
# storm, i.e. at the live end.  So: flood continuously, and emit the marker in
# the middle of it.
( while [ ! -f /tmp/.floodprobe_stop ]; do
      echo "FLOODPROBE-filler-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" > /dev/kmsg
  done ) &
FPID=$!

# Let the flood get ahead of any reader, then plant the marker at the live end.
sleep 2
M="FLOODPROBE-$$-MARKER"
echo "$M" > /dev/kmsg
sleep 1

k_hit=0; k_miss=0; s_hit=0; s_miss=0
p=0
while [ "$p" -lt POLLSN ]; do
    p=$((p+1))
    ck=$(dmesg 2>/dev/null | grep -c -a "$M")
    cs=$(dmesg -S 2>/dev/null | grep -c -a "$M")
    nk=$(dmesg 2>/dev/null | wc -l)
    ns=$(dmesg -S 2>/dev/null | wc -l)
    [ "$ck" -gt 0 ] && k_hit=$((k_hit+1)) || k_miss=$((k_miss+1))
    [ "$cs" -gt 0 ] && s_hit=$((s_hit+1)) || s_miss=$((s_miss+1))
    echo "poll $p FLOODING dmesg_match=$ck dmesg_lines=$nk | syslog_match=$cs syslog_lines=$ns"
done

touch /tmp/.floodprobe_stop
wait $FPID 2>/dev/null
rm -f /tmp/.floodprobe_stop

# After the flood: if the marker is now gone from BOTH backends the buffer
# genuinely wrapped past it, and any miss above is unattributable — say so
# rather than claiming a skip.
sleep 1
a_kmsg=$(dmesg 2>/dev/null | grep -c -a "$M")
a_sys=$(dmesg -S 2>/dev/null | grep -c -a "$M")
echo "AFTER quiet kmsg=$a_kmsg syslog=$a_sys"
echo "TALLY kmsg_hit=$k_hit kmsg_miss=$k_miss syslog_hit=$s_hit syslog_miss=$s_miss"
EOS
)
REMOTE=${REMOTE//FLOODN/$FLOOD}
REMOTE=${REMOTE//POLLSN/$POLLS}

# Budget (RULE 0): the flood is $FLOOD userspace writes to /dev/kmsg (~10k/s on
# these VMs) plus 4 full dmesg reads per poll.  180s covers 20k lines and 8
# polls with margin; a timeout here is itself a finding, not a reason to widen.
OUT=$(timeout 180 "$SSHPASS" "$HOST" "sh -c '$REMOTE'" 2>&1 | grep -v "authorized user\|disconnect immediately\|Warning: Permanently\|^$")
echo "$OUT"

echo "---"
TALLY=$(printf '%s\n' "$OUT" | grep '^TALLY ' | tail -1)
AFTER=$(printf '%s\n' "$OUT" | grep '^AFTER ' | tail -1)
if [ -z "$TALLY" ]; then
    echo "VERDICT: INCONCLUSIVE — remote probe did not complete (see output above)"
    exit 2
fi
km=$(printf '%s' "$TALLY" | sed -n 's/.*kmsg_miss=\([0-9]*\).*/\1/p')
sm=$(printf '%s' "$TALLY" | sed -n 's/.*syslog_miss=\([0-9]*\).*/\1/p')
ak=$(printf '%s' "$AFTER" | sed -n 's/.*kmsg=\([0-9]*\).*/\1/p')
as=$(printf '%s' "$AFTER" | sed -n 's/.*syslog=\([0-9]*\).*/\1/p')

if [ "${ak:-0}" = "0" ] && [ "${as:-0}" = "0" ]; then
    echo "VERDICT: UNATTRIBUTABLE — the marker left the buffer entirely (real wrap)."
    echo "         Lower flood_lines and re-run; a wrap is not a skip."
    exit 0
fi
if [ "${km:-0}" -gt 0 ] && [ "${sm:-0}" -eq 0 ]; then
    echo "VERDICT: CONFIRMED — under flood, dmesg (/dev/kmsg) MISSED a record that"
    echo "         dmesg -S (syslog(2)) saw every time, and that is still in the"
    echo "         buffer afterwards.  dmesg silently skips records under write"
    echo "         pressure.  Every dmesg-based failure grep in this project can"
    echo "         false-negative exactly when a node is failing.  Fix: read the"
    echo "         log with 'dmesg -S' (or journalctl -k), never bare dmesg."
    exit 0
fi
if [ "${km:-0}" -gt 0 ] && [ "${sm:-0}" -gt 0 ]; then
    echo "VERDICT: BOTH BACKENDS MISSED — not a /dev/kmsg reader artifact."
    echo "         The record is in the buffer after the flood but was invisible"
    echo "         during it.  Escalate (RULE 5); this is worse than a skip."
    exit 0
fi
echo "VERDICT: NOT REPRODUCED at flood=$FLOOD polls=$POLLS — dmesg never missed."
exit 0
