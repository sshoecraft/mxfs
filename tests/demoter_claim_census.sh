#!/bin/bash
# demoter_claim_census.sh — cluster-wide exposure census for the TWO-SLOT
# demoter claim (D-BAST-IRELE-INACTIVE-SELF-WEDGE).
#
# WHY THIS EXISTS
#   The two-slot claim is a fix verified by the ABSENCE of a wedge.  An absent
#   wedge is equally consistent with "the fix worked" and "the workload never
#   built the race", so the absence alone proves nothing.  This prints the
#   exposure directly:
#
#     slot2         > 0  a SECOND concurrent release drain on one inode was
#                        admitted and kept its demote-wait exemption.  This is
#                        the state that used to strand the first drain's
#                        trailing xfs_irele forever.  THE FIX PATH RAN.
#     contest       > 0  a THIRD concurrent drain was refused a slot — two
#                        slots are not enough and the wedge is still reachable.
#     foreign_clear > 0  a clear by a task while a DIFFERENT task owned a slot:
#                        the exact event that produced the wedge.  MUST be zero.
#     clear_noclaim      a clear with both slots empty — the DLM-state
#                        initializer resetting the field on an inode nobody is
#                        draining.  Benign, ~62/node/run, kept separate so
#                        foreign_clear stays a real assertion rather than a
#                        permanently-nonzero false alarm.
#
# Counters are cumulative per module load, so take a census before and after a
# workload to attribute a delta to it.
#
# HARVEST SOURCE: journalctl -k, NOT dmesg.  Measured on test19 mid-campaign the
# kernel ring held 1824 lines / 112 s while journalctl -k held 59067 lines going
# back 50 minutes — and the MXFS_DIRENT_WINDOW markers a scoped census needs had
# already scrolled out of dmesg.  Every `dmesg | grep -c` census in this campaign
# was reading a window shorter than the run it was measuring.
#
# Usage: tests/demoter_claim_census.sh <n_nodes> [label]

set -u
cd "$(dirname "$0")/.." || exit 1
N="${1:-32}"
LABEL="${2:-census}"
SSH=tools/mxfs_sshpass.sh

tot_s1=0 tot_s1n=0 tot_s2=0 tot_s2n=0 tot_c=0 tot_fc=0 tot_nc=0
tot_ls=0 tot_lc=0 tot_wp=0 nodes_wp=0
tot_rbt=0 tot_rbr=0 tot_p6s=0 tot_p6rb=0 nodes_p6rb=0
nodes_s2=0 nodes_c=0 nodes_fc=0 nodes_read=0
td=$(mktemp -d)

for i in $(seq 1 "$N"); do
    (
      timeout 25 "$SSH" "test$i" \
        "echo 1 > /sys/module/mxfs/parameters/demoter_dump 2>/dev/null
         journalctl -k --no-pager 2>/dev/null | grep -E 'P75-DEMOTER-(CLAIM|LEGACY)|P79-RACEBAIL' | tail -3" 2>/dev/null \
        | grep -oE '(slot1=|legacy_steal=|total=).*' | tr '\n' ' ' > "$td/test$i"
    ) &
done
wait

echo "=== P75 demoter-claim census [$LABEL] @ ${N} nodes ==="
for i in $(seq 1 "$N"); do
    line=$(cat "$td/test$i" 2>/dev/null)
    [ -z "$line" ] && { echo "  test$i  NO-READ"; continue; }
    nodes_read=$((nodes_read+1))
    # Parse by exact key=value tokens.  An earlier cut used anchored regexes
    # like `.*[^_]slot1=` — which cannot match at start-of-line and silently
    # reported slot1=0 on every node, a value the macro logic makes impossible
    # (slot 2 is only attempted after slot 1's cmpxchg fails).  Never parse
    # these with context-dependent patterns; read the token.
    kv() { tr ' ' '\n' <<<"$line" | sed -n "s/^$1=\([0-9]\+\)$/\1/p" | head -1; }
    s1=$(kv slot1); s1n=$(kv slot1_nest)
    s2=$(kv slot2); s2n=$(kv slot2_nest)
    c=$(kv contest); fc=$(kv foreign_clear); nc=$(kv clear_noclaim)
    ls_=$(kv legacy_steal); lc=$(kv legacy_clear_live); wp=$(kv wedge_precond)
    rbt=$(kv total); rbr=$(kv resolved)
    p6s=$(kv p6skip); p6rb=$(kv p6skip_after_rb)
    for v in s1 s1n s2 s2n c fc nc ls_ lc wp rbt rbr p6s p6rb; do [ -z "${!v}" ] && eval "$v=0"; done
    tot_nc=$((tot_nc+nc)); tot_ls=$((tot_ls+ls_)); tot_lc=$((tot_lc+lc)); tot_wp=$((tot_wp+wp))
    [ "$wp" -gt 0 ] && nodes_wp=$((nodes_wp+1))
    tot_rbt=$((tot_rbt+rbt)); tot_rbr=$((tot_rbr+rbr))
    tot_p6s=$((tot_p6s+p6s)); tot_p6rb=$((tot_p6rb+p6rb))
    [ "$p6rb" -gt 0 ] && nodes_p6rb=$((nodes_p6rb+1))
    if [ "$s1" -eq 0 ] && [ "$s2" -gt 0 ]; then
        echo "  test$i  PARSE-SUSPECT (slot1=0 with slot2>0 is impossible): $line"
    fi
    tot_s1=$((tot_s1+s1)); tot_s1n=$((tot_s1n+s1n))
    tot_s2=$((tot_s2+s2)); tot_s2n=$((tot_s2n+s2n))
    tot_c=$((tot_c+c));    tot_fc=$((tot_fc+fc))
    [ "$s2" -gt 0 ] && nodes_s2=$((nodes_s2+1))
    [ "$c"  -gt 0 ] && nodes_c=$((nodes_c+1))
    [ "$fc" -gt 0 ] && nodes_fc=$((nodes_fc+1))
    printf '  test%-3s slot1=%-7s nest=%-7s slot2=%-6s nest=%-6s contest=%-5s foreign_clear=%s\n' \
        "$i" "$s1" "$s1n" "$s2" "$s2n" "$c" "$fc"
done
rm -rf "$td"

echo "--- CLUSTER TOTALS (nodes_read=$nodes_read/$N) ---"
echo "  slot1=$tot_s1 slot1_nest=$tot_s1n"
echo "  slot2=$tot_s2 slot2_nest=$tot_s2n      <- EXPOSURE (nodes with slot2>0: $nodes_s2)"
echo "  contest=$tot_c                          (nodes: $nodes_c)  <- >0 means 2 slots insufficient"
echo "  foreign_clear=$tot_fc                   (nodes: $nodes_fc)  <- MUST be 0"
echo "  clear_noclaim=$tot_nc                   (benign initializer field resets, both slots empty)"
echo "--- legacy-clobber arm exposure (zero unless demoter_legacy_clobber=1) ---"
echo "  legacy_steal=$tot_ls        <- injected fault landed on a LIVE foreign claim"
echo "  legacy_clear_live=$tot_lc   <- legacy clear NULLed another task's live slot"
echo "  wedge_precond=$tot_wp       (nodes: $nodes_wp)  <- a steal VICTIM reached the demote-wait"
echo "--- P34J race-bail retry accounting (D-SILENT-MKDIR-LOSS H2) ---"
echo "  racebail_total=$tot_rbt resolved=$tot_rbr unresolved=$((tot_rbt-tot_rbr))"
echo "     unresolved>0 => the bail's promised 'caller retries post-drain' never happened"
echo "  p6_midtenure_skip=$tot_p6s   of which AFTER a race bail=$tot_p6rb (nodes: $nodes_p6rb)"
echo "     p6skip_after_rb>0 => the mid-tenure skip cleared i_dlm_stale WITHOUT reloading"
echo "     an image the race bail had deliberately discarded  (H2')"

rc=0
if [ "$nodes_read" -eq 0 ]; then
    echo "CENSUS INFRA-FAIL: no node produced a reading"; rc=2
elif [ "$tot_s2" -eq 0 ]; then
    echo "CENSUS: NO EXPOSURE — a concurrent second drain never occurred, so a"
    echo "        clean wedge result here does NOT verify the two-slot fix."
    rc=1
else
    echo "CENSUS: EXPOSED — $tot_s2 second-drain admissions on $nodes_s2 node(s)."
fi
[ "$tot_fc" -gt 0 ] && { echo "CENSUS: FOREIGN CLEAR OBSERVED — clobber reached the slot."; rc=3; }
[ "$tot_c"  -gt 0 ] && echo "CENSUS: CONTEST OBSERVED — a 3rd concurrent drain was refused a slot."
exit $rc
