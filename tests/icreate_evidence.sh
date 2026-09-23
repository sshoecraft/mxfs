#!/bin/bash
# icreate_evidence.sh — summarise the D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-
# INODES-0510 probes in one or more dmesg captures (bootstrap legs write
# remounter_dmesg.txt / attempt*_dmesg.txt; any node dmesg dump works).
#
# Per file: counts of P-ICREATE-AUTH by verdict (APPLY / REDUNDANT / REFUSE
# + why), P-ICREATE-VERIFIED, P-ICREATE-VERIFY-FAIL (with why=), P-ICREATE-
# REFUSE, P133-ICLUSTER-SYNCINIT{,-FAIL,-GEOMETRY}, the P273-SHADOW-EVAL
# icreate=a/r/x + nonbuf_taint/taint_blocked fields per victim slot, and the
# terminal markers (ATOMIC-SKIP, TORN-UNPUBLISHED, P-BOOT-TERMINAL-SLICE,
# P-BOOT-RECOVERY-COMPLETE).  Read-only.
#
# Usage: tests/icreate_evidence.sh <dmesg.txt> [more.txt ...]
set -u
[ $# -ge 1 ] || { echo "usage: $0 <dmesg.txt> [...]"; exit 2; }
for f in "$@"; do
    [ -r "$f" ] || { echo "== $f: unreadable"; continue; }
    echo "== $f"
    printf '  P-ICREATE-AUTH: total=%s APPLY=%s REDUNDANT=%s REFUSE=%s' \
        "$(grep -ac 'P-ICREATE-AUTH' "$f")" \
        "$(grep -ac 'P-ICREATE-AUTH.*verdict=APPLY' "$f")" \
        "$(grep -ac 'P-ICREATE-AUTH.*verdict=REDUNDANT' "$f")" \
        "$(grep -ac 'P-ICREATE-AUTH.*verdict=REFUSE' "$f")"
    grep -ao 'P-ICREATE-AUTH.*why=[a-z-]*' "$f" | grep -ao 'why=[a-z-]*' | sort | uniq -c | awk '{printf " %s x%d", $2, $1}'
    echo
    printf '  P-ICREATE-VERIFIED=%s P-ICREATE-VERIFY-FAIL=%s P-ICREATE-REFUSE=%s' \
        "$(grep -ac 'P-ICREATE-VERIFIED' "$f")" \
        "$(grep -ac 'P-ICREATE-VERIFY-FAIL' "$f")" \
        "$(grep -ac 'P-ICREATE-REFUSE' "$f")"
    grep -ao 'P-ICREATE-VERIFY-FAIL.*why=[a-z-]*' "$f" | grep -ao 'why=[a-z-]*' | sort | uniq -c | awk '{printf " %s x%d", $2, $1}'
    echo
    printf '  P133: SYNCINIT=%s SYNCINIT-FAIL=%s SYNCINIT-GEOMETRY=%s\n' \
        "$(grep -ac 'P133-ICLUSTER-SYNCINIT agno' "$f")" \
        "$(grep -ac 'P133-ICLUSTER-SYNCINIT-FAIL' "$f")" \
        "$(grep -ac 'P133-ICLUSTER-SYNCINIT-GEOMETRY' "$f")"
    grep -a 'P273-SHADOW-EVAL' "$f" | sed -E 's/.*(victim_slot=[0-9]+).*(WOULD_APPLY=[0-9]+).*(txn=[0-9]+).*(all_apply=[0-9]+).*(taint_blocked=[0-9]+).*(nonbuf_taint=[0-9]+).*(enforce_admitted=[0-9]+).*(icreate=[0-9]+\/[0-9]+\/[0-9]+)?.*/  P273 \1 \2 \3 \4 \5 \6 \7 \8/' | head -40
    printf '  terminal: ATOMIC-SKIP=%s TORN-UNPUBLISHED=%s P-BOOT-TERMINAL-SLICE=%s POLICY-REFUSED=%s RECOVERY-COMPLETE=%s foreign_complete=%s foreign_failed=%s\n' \
        "$(grep -ac 'P227-FR-ATOMIC-SKIP' "$f")" \
        "$(grep -ac 'P227-FR-TORN-UNPUBLISHED' "$f")" \
        "$(grep -ac 'P-BOOT-TERMINAL-SLICE' "$f")" \
        "$(grep -ac 'POLICY-REFUSED' "$f")" \
        "$(grep -ac 'P-BOOT-RECOVERY-COMPLETE' "$f")" \
        "$(grep -ac 'foreign replay of slot .* complete' "$f")" \
        "$(grep -ac 'foreign replay of slot .* failed' "$f")"
    grep -a 'P-ICREATE-REFUSE\|P-ICREATE-VERIFY-FAIL\|P133-ICLUSTER-SYNCINIT-FAIL\|P133-ICLUSTER-SYNCINIT-GEOMETRY' "$f" | cut -c1-220 | head -12 | sed 's/^/  ! /'
done
