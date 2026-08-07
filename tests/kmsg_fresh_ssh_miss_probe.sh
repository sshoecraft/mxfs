#!/bin/bash
#
# kmsg_fresh_ssh_miss_probe.sh — reproduce the sess79 "grep missed a line that
# was already there" failure, and name its cause.
#
#   tests/kmsg_fresh_ssh_miss_probe.sh <host> [trials]
#
# BACKGROUND.  sess79 twice grepped a node for P236-WITHDRAW-REFUSED, got
# nothing, then found the same line later carrying an EARLIER printk stamp.
# It hypothesised kmsg visibility lag and MEASURED it: worst 15.4ms, 0/10
# never-visible — REFUTED.  But that measurement polled over ONE ssh session,
# and every real miss used a SEPARATE ssh session per grep.  Fresh-SSH-per-poll
# is therefore the one variable still untested, and it is the variable that
# carries all the silent failure modes (connect refusal, MaxStartups throttling,
# `timeout N` kill, login stall).
#
# HYPOTHESIS (falsifiable): a fetch issued over a FRESH ssh session sometimes
# fails to read the log at all, and the failure is indistinguishable from a
# no-match because the caller sees only empty stdout.
#
# METHOD.  Emit one unique marker to /dev/kmsg over its own ssh session.  Then
# poll for it `trials` times, each poll a NEW ssh session, using
# rig_dmesg_grep.sh so the three outcomes are separable:
#   HIT   — matched
#   MISS  — proven absent (dmesg ran, returned >0 lines, no match)
#   ERROR — we failed to look (no sentinel / dmesg failed / empty log)
#
# READING THE RESULT.  The marker is written BEFORE the first poll, so after
# ~20ms it exists unconditionally and every subsequent outcome is decidable:
#   any ERROR            -> HYPOTHESIS CONFIRMED.  The miss is a fetch failure
#                           masquerading as a no-match, and every ad-hoc
#                           `ssh ... "dmesg | grep"` in this project can lie.
#   any MISS             -> HYPOTHESIS REFUTED and something worse is true: the
#                           kernel log itself is non-monotonic across sessions.
#                           Capture the poll index and escalate (RULE 5).
#   all HIT              -> not reproduced at this rate; report the count
#                           honestly rather than declaring the thread closed.
#
set -u

HOST="${1:-}"
TRIALS="${2:-30}"

if [ -z "$HOST" ]; then
    echo "usage: $0 <host> [trials]" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
SSHPASS="$HERE/../tools/mxfs_sshpass.sh"
RDG="$HERE/rig_dmesg_grep.sh"

# Unique per run without Date.now-style helpers being unavailable here — this is
# bash, $$ + SECONDS is enough and is stable inside the run.
MARKER="RDGPROBE-$$-$RANDOM"

echo "host=$HOST trials=$TRIALS marker=$MARKER"

if ! timeout 25 "$SSHPASS" "$HOST" "echo '$MARKER' > /dev/kmsg" >/dev/null 2>&1; then
    echo "SETUP-FAIL: could not write the marker to /dev/kmsg on $HOST" >&2
    exit 2
fi

hit=0; miss=0; err=0
first_bad=""
for i in $(seq 1 "$TRIALS"); do
    out=$("$RDG" "$HOST" "$MARKER" 2>&1)
    rc=$?
    case "$rc" in
        0) hit=$((hit+1));  cls=HIT ;;
        1) miss=$((miss+1)); cls=MISS ;;
        *) err=$((err+1));  cls=ERROR ;;
    esac
    printf 'poll %2d: %-5s rc=%d %s\n' "$i" "$cls" "$rc" \
        "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-110)"
    if [ "$cls" != HIT ] && [ -z "$first_bad" ]; then
        first_bad="poll $i: $cls"
    fi
done

echo "---"
echo "RESULT host=$HOST trials=$TRIALS hit=$hit miss=$miss error=$err"
if [ "$err" -gt 0 ]; then
    echo "VERDICT: CONFIRMED — a fresh-ssh fetch failed to read the log ($err/$TRIALS)."
    echo "         An ad-hoc 'ssh host \"dmesg | grep PAT\"' would have reported"
    echo "         these as no-match.  First: $first_bad"
    exit 0
fi
if [ "$miss" -gt 0 ]; then
    echo "VERDICT: REFUTED, AND WORSE — the log read cleanly but a line known to"
    echo "         exist was absent ($miss/$TRIALS).  First: $first_bad"
    echo "         This is a kernel-log consistency defect, not a harness bug."
    exit 0
fi
echo "VERDICT: NOT REPRODUCED at $TRIALS trials — all polls HIT."
exit 0
