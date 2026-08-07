#!/bin/bash
# kernel_health — ZERO kernel-level faults on this node.
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess21)
#   Every kernel-level defect found in sess21 was INVISIBLE to the criteria
#   board and was found only by ad-hoc dmesg grepping while the board read
#   20/20 green:
#
#     * 32/tcp: "BUG: scheduling while atomic" on 8 nodes (a sleeping rwsem
#       taken under pag_ici_lock), then "soft lockup - CPU#2 stuck for 522s"
#       on test31 — that node stopped answering sshd entirely and never
#       released its AG grants, starving all 31 peers (9210 lock timeouts).
#     * 32/caw: "WARNING: at include/linux/rwsem.h:85 xfs_assert_ilocked" on
#       3 of 4 nodes — a broken ILOCK-mode invariant.
#
#   `soak` is the only other test that looks at dmesg, and it caps at 4 nodes
#   and scopes to its own 30 s window, so it catches these only by luck.  This
#   test judges the state the WHOLE run left this node in — every node, whole
#   boot window.
#
# Threshold: 0 hits.  A kernel BUG / lockup / atomic-sleep is never acceptable
# in a filesystem that has to stay up (RULE 6 — no accepted known defects).
#
# NOTE: a node wedged badly enough cannot run this script at all — it then
# produces NO_TERMINAL_RECORD, which the runner already scores as a failure.
# That is intentional: "too broken to report" must never read as "clean".
SUITE_TEST_NAME=kernel_health
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"

# Each pattern is a hard kernel fault, not a style warning:
#   BUG:/Oops/panic/general protection/NULL deref — memory or state corruption
#   soft lockup / hard LOCKUP           — a CPU spinning with no forward progress
#   scheduling while atomic             — slept holding a spinlock; this is what
#                                         CAUSED the 522 s lockup above
#   rcu_preempt self-detected stall     — same class, reported by RCU first
#   WARNING:                            — includes xfs_assert_ilocked, i.e. a
#                                         lock-mode invariant already broken
PAT='BUG:|Oops|Kernel panic|general protection|kernel NULL pointer|soft lockup|hard LOCKUP|scheduling while atomic|rcu_preempt self-detected|WARNING:'

HITFILE="/root/kernel_health_hits.$$.txt"
# sess23 (ccloop c7ee71c6): scope the scan to lines emitted AFTER the mxfs
# module loaded, and drop firmware/CPU boot notices.
#
# The bare pattern above matches the string "WARNING:" anywhere in dmesg, and
# a freshly booted node ALWAYS carries this at ~0.13s uptime:
#     ITS: WARNING: ITS mitigation depends on retpoline and rethunk support
# a CPU speculative-execution mitigation notice from the firmware/boot path
# that has nothing whatever to do with MXFS.  It only stayed hidden because
# long-lived nodes had scrolled it out of the ring; the moment a run rebooted
# them, kernel_health went red on 15 of 16 nodes with `hits=1
# kinds=[WARNING:]` and no MXFS fault anywhere.  A criterion that fails on a
# clean boot is worse than no criterion — it trains you to ignore it.
#
# Two scopings, both principled:
#  1. start at the last mxfs module load ("mxfs: MXFS" banner / DLM init) so we
#     only ever judge THIS incarnation of the module, never a previous boot's
#     residue.  Falls back to the whole ring if no marker is present (module
#     not loaded yet — then there is nothing of ours to blame anyway).
#  2. exclude boot-time firmware/CPU notices by source prefix, not by
#     whitelisting the specific text, so a different mitigation message next
#     kernel does not silently re-break this.
BOOTNOISE='^\[[^]]*\] (ITS|RETBleed|Spectre|MDS|TAA|MMIO|SRBDS|GDS|RFDS|x86/|microcode|acpi|ACPI|DMAR|tsc):'
dmesg 2>/dev/null \
  | awk '/mxfs: MXFS|DLM initialized|mxfs: module/{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' \
  | grep -Ev "$BOOTNOISE" \
  | grep -E "$PAT" > "$HITFILE" 2>/dev/null
hits=$(grep -c . "$HITFILE" 2>/dev/null); hits=${hits:-0}

# Persist a sample: once a VM is destroyed/rebooted the unflushed journal is
# gone, and a bare count is undiagnosable after the fact.
if [ "$hits" -gt 0 ]; then
    echo "KH-HIT-SAMPLE ($(hostname), first 5 of $hits):"
    head -5 "$HITFILE" | sed 's/^/  KH-HIT: /'
    # Name the distinct fault kinds so the aggregated line is actionable.
    kinds=$(grep -oE "$PAT" "$HITFILE" | sort -u | tr '\n' ',' | sed 's/,$//')
else
    kinds=""
    rm -f "$HITFILE" 2>/dev/null
fi

st=PASS; reason=""
if [ "$hits" -gt 0 ]; then
    st=FAIL
    reason="$hits kernel fault line(s): ${kinds}"
fi
echo "RESULT: $st | test=kernel_health | nodes=$NODES | measured=hits=$hits kinds=[${kinds}] | reason=$reason"
[ "$st" = PASS ]
