#!/bin/bash
# dirent_publish_integrity — no node may MUTATE a directory whose in-core base
# is not coherent with the epoch stamped on the grant it holds.
#
# WHY THIS EXISTS, AND WHY IT IS SEPARATE FROM dirent_durability
#   dirent_durability asks "did we actually lose an entry this run?".  That is
#   the symptom, and it is INTERMITTENT (~1 run in 10 at 32 nodes), so a green
#   cell there means "this run did not lose one" — NOT "the defect is fixed".
#   A board that flips green on a coin toss is worse than no board.
#
#   This criterion asks the deterministic question instead: did any node enter
#   the state from which the loss is possible?  That state has a probe and it
#   fires reliably, ~1x per storm run, whether or not an entry is lost:
#
#     P195-STALE-BASE-ALREADY-DIRTY ino=X grant_epoch=2 valid_epoch=0
#         — this tenure ALREADY mutated an epoch-stale base
#
#   Established sess21 (RULE-5 GPT review): once local mutations exist on an
#   epoch-stale base, NEITHER keep-mine NOR adopt-disk is correct, and merging
#   is unsafe across the shortform->block conversion.  So reaching this state at
#   all is the defect; whether a given run notices depends on timing.
#
#   Proven consequence (sfstorm_20260728_201959 ROUND 29, pino=46137485):
#     nlink=33 visible=31 expected=32 missing=[ node24_1 ] on ALL 32 nodes,
#     with ZERO nonzero mkdir(2) return codes cluster-wide — i.e. mkdir
#     returned success and the entry existed nowhere.
#
# Threshold: 0 occurrences.  This is EXPECTED TO FAIL until the freshness gate
# is implemented at EX acquire (adopt, then set valid_epoch, then expose the
# tenure to the operation).  That is deliberate: RULE 6 forbids carrying an
# unresolved credible defect as a green cell.  Do NOT silence this probe, widen
# the threshold, or delete the criterion to make the board green.
#
# Ordering: must run AFTER dirent_durability (P6), which generates the
# concurrent-mkdir pressure this looks for.  Hence P8.
SUITE_TEST_NAME=dirent_publish_integrity
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"
# ccloop c7ee71c6 sess27: this file NEVER SOURCED lib.sh, yet sess24 changed it
# to call the shared dirent_window_scope helper.  An undefined function is just
# a failed command: the call errored to stderr, DW_HAVE/DW_SOURCE/DW_TRUNC were
# never set, WINDOW was the empty string, both counters came out 0, and the
# criterion reported PASS having scanned ZERO kernel lines.  Every green cell it
# recorded after that change is vacuous.  Sourced AFTER MNT/NODES above so
# lib.sh's `: "${VAR:=...}"` defaults stay no-ops; this script prints its own
# RESULT line and does not use lib.sh's finish().
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

# P195 — the invariant violation itself (mutation on an epoch-stale base).
# P188 — a grant handed to a peer while a committed change of ours is not yet
#        at its home location (the release-barrier half of the same family).
# Scope to the CURRENT workload window.  dirent_durability stamps
# MXFS_DIRENT_WINDOW into the kernel log on every node when it starts; scan only
# what follows the LAST such marker.  dmesg survives module reload (and
# prep_cluster does not clear it), so an unscoped scan re-reports an hour-old
# hit on every subsequent run and the cell can never go green again even after
# the defect is fixed.
#
# No marker at all => the workload has not run on this node in this boot, so
# there is nothing to judge; scan nothing rather than judge stale evidence.
# sess24: scope via the shared helper -- the kmsg marker can rotate out of a
# short ring while the workload demonstrably ran (measured: 5 of 32 nodes), so it
# falls back to the durable window-start timestamp.  See lib.sh.
DW_FILE=$(mktemp)
dirent_window_scope "$DW_FILE"
WINDOW=$(cat "$DW_FILE"); rm -f "$DW_FILE"
have_window=$DW_HAVE
# Fail closed on an unset global rather than treating "" as "fine": an empty
# have_window is what made the first cut of this fix report a VACUOUS GREEN.
have_window=${have_window:-0}

p195=$(printf '%s' "$WINDOW" | grep -c 'P195-STALE-BASE-ALREADY-DIRTY'); p195=${p195:-0}
p188=$(printf '%s' "$WINDOW" | grep -c 'P188-REL-OBLIGATION-AT-UNLOCK');  p188=${p188:-0}

# The probe only exists from v0.11.169 on.  Absence of the marker on an older
# module is NOT evidence of absence of the defect, so say so rather than pass.
if ! grep -q 'P195-STALE-BASE-ALREADY-DIRTY' /proc/modules 2>/dev/null; then :; fi
probe_built=1
[ -e /sys/module/mxfs/parameters/epoch_stale_op_probe ] || probe_built=0

HITFILE="/root/dirent_publish_hits.$$.txt"
if [ "$p195" -gt 0 ] || [ "$p188" -gt 0 ]; then
    printf '%s' "$WINDOW" | grep -E 'P195-STALE-BASE-ALREADY-DIRTY|P188-REL-OBLIGATION-AT-UNLOCK' > "$HITFILE"
    echo "DPI-HIT-SAMPLE ($(hostname), first 3 of $((p195 + p188))):"
    head -3 "$HITFILE" | sed 's/^/  DPI-HIT: /'
fi

st=PASS; reason=""
if [ "$have_window" != 1 ]; then
    # ccloop c7ee71c6 sess27: have_window was COMPUTED and PRINTED but never
    # consulted, so a node that could not locate this run's window scanned an
    # EMPTY string, counted zero hits and reported PASS -- passing precisely
    # BECAUSE it had no evidence.  Observed on a full 32/caw board:
    # `window=0 win_src= win_trunc=` and PASS at 0s.  That is the vacuous green
    # the comment at line 59 warns about, one branch away from the
    # probe_built=0 rule directly below which already says unverifiable is not
    # a pass.  Apply the same rule to the window.
    st=FAIL
    reason="could not locate this run's dirent window (no MXFS_DIRENT_WINDOW marker in the ring and no durable start timestamp) — nothing to judge, and unverifiable is not a pass"
elif [ "$probe_built" = 0 ]; then
    st=FAIL
    reason="epoch_stale_op_probe not present in this build — cannot verify the invariant, and unverifiable is not a pass"
elif [ "$p195" -gt 0 ]; then
    st=FAIL
    reason="$p195 mutation(s) on an epoch-stale directory base (silent mkdir-loss precursor); $p188 release(s) with an unlanded committed change"
elif [ "$p188" -gt 0 ]; then
    st=FAIL
    reason="$p188 grant handoff(s) with a committed change not yet at its home location"
fi
echo "RESULT: $st | test=dirent_publish_integrity | nodes=$NODES | measured=stale_base_mutations=$p195 unlanded_at_unlock=$p188 probe=$probe_built window=$have_window win_src=$DW_SOURCE win_trunc=$DW_TRUNC | reason=$reason"
[ "$st" = PASS ]
