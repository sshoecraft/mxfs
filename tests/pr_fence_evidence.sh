#!/bin/bash
# MXFS — PR fence evidence harness
#
# Measures, across a real node death on the 32-node CAW rig:
#
#   1. the size of the LUN's PR registration table before/during/after
#      (registrations are per-I_T NEXUS, not per node — a multipath node
#      holds one descriptor per path, so the table is ~2x the node count).
#      This is the evidence for whether a key-view buffer sized by
#      MXFS_MAX_NODES can truncate in practice.
#
#   2. what the survivors' fence path actually PROVED, via the
#      P236-FENCEKIND probe (sess71 typed fence outcome).  The verification
#      target for D-PR-FENCE-PREEMPT-WITHOUT-ABORT is that a real fence of
#      a live registered victim reports PREEMPT_ABORT_DONE / proves_excl=1,
#      not ILLEGAL REQUEST and not a RESERVATION CONFLICT swallowed as
#      success.
#
# Usage: tests/pr_fence_evidence.sh <victim-node-number> [observe-seconds]
#          e.g. tests/pr_fence_evidence.sh 17 120
#
# The victim is hard-destroyed (virsh destroy) so it never unregisters —
# that is the case the fence exists for.  Restart it afterwards with
#   sudo virsh -c qemu:///system start test<N>
set -u

cd "$(dirname "$0")/.." || exit 1
VICTIM_N="${1:?usage: pr_fence_evidence.sh <victim-node-number> [observe-seconds]}"
OBSERVE="${2:-120}"
VICTIM="test${VICTIM_N}"

# No secrets handling here: tools/mxfs_sshpass.sh (the SSH chokepoint) materializes
# the passfile from the secrets store itself.  This script used to `source
# tools/mxfs_secrets.sh`, which was both redundant and fatal — see the sourcing note
# in that file.
#
# Node IPs are dnsmasq leases, NOT sequential — always resolve by hostname.
# (env-test1-dhcp-reservation-fix-sess29: only test1/test2 have reservations.)
# A survivor we ask for wire state + logs.  Never the victim.
if [ "$VICTIM_N" = "1" ]; then OBS=test2; else OBS=test1; fi

# Survivors polled for fence evidence.  EVERY node races to fence the victim and
# exactly ONE wins, so this must be the WHOLE fleet, never a sample.  A sample of
# 1-8 reported "30 losers, no winner" and led straight to the wrong root cause
# (blaming the target for reaping the registration) — the winner was test9.
# One winner in 32 is exactly what a partial poll is guaranteed to miss.
SURVIVORS="$(seq 1 "${MXFS_NODES:-32}")"

sshq() { tools/mxfs_sshpass.sh "$1" "$2" 2>/dev/null | grep -v "^/tmp/\|Warning: Permanently\|^$\|Unauthorized access\|If you are not an authorized"; }

pr_table() {
    sshq "$OBS" 'sg_persist --in --read-keys /dev/mapper/mpatha 2>&1 | grep -E "generation.*keys follow"'
}
pr_holder() {
    sshq "$OBS" 'sg_persist --in --read-reservation /dev/mapper/mpatha 2>&1 | grep -E "Key=|type:"'
}

echo "=== MXFS PR fence evidence — victim=$VICTIM observe=${OBSERVE}s ==="
echo "--- build under test ---"
sshq "$OBS" 'cat /sys/module/mxfs/srcversion'

echo
echo "--- PRE: registration table ---"
pr_table
echo "--- PRE: reservation holder ---"
pr_holder

echo
echo "--- PRE: victim's own PR key (from its own dmesg) ---"
sshq "$VICTIM" 'dmesg | grep -oE "own key 0x[0-9a-f]+ visible" | tail -1' | grep -oE "0x[0-9a-f]+" \
    || echo "(victim key not recoverable from its dmesg)"

echo
echo "--- marker: window start ---"
MARK="PRFENCE-$(date -u +%s)"
for n in $SURVIVORS; do sshq "test$n" "echo '$MARK' > /dev/kmsg" & done; wait

echo "--- KILL: virsh destroy $VICTIM (no unregister — this is a crash) ---"
sudo virsh -c qemu:///system destroy "$VICTIM" 2>&1 | tail -2

echo
echo "--- observing ${OBSERVE}s ---"
for t in $(seq 10 10 "$OBSERVE"); do
    sleep 10
    printf 'T+%-4s ' "${t}s"
    pr_table
done

echo
echo "--- POST: registration table ---"
pr_table
echo "--- POST: reservation holder ---"
pr_holder

echo
echo "=== FENCE OUTCOMES across survivors (P236-FENCEKIND since marker) ==="
KINDS=$(mktemp -d)/kinds
: > "$KINDS"
for n in $SURVIVORS; do
    [ "$n" = "$VICTIM_N" ] && continue
    ( out=$(sshq "test$n" \
        "dmesg | sed -n '/$MARK/,\$p' | grep -E 'P236-FENCEKIND|P-PR-FENCE|P-PR-VIEW-TRUNC|P-PR-NORESV|P-PR-SELFFENCE'")
      [ -n "$out" ] && printf -- '--- test%s ---\n%s\n' "$n" "$out" >> "$KINDS" ) &
done
wait
sort "$KINDS"

echo
echo "--- outcome distribution (exactly ONE node must prove exclusion) ---"
grep -oE 'kind=[A-Z_]+\([0-9]+\) proves_excl=[01]' "$KINDS" | sort | uniq -c
provers=$(grep -c 'proves_excl=1' "$KINDS")
echo "nodes proving exclusion: $provers"
[ "$provers" -eq 1 ] || echo "!!! expected exactly 1 prover, got $provers"

echo
echo "--- who REPLAYED, and did that node prove exclusion? ---"
for n in $SURVIVORS; do
    [ "$n" = "$VICTIM_N" ] && continue
    ( r=$(sshq "test$n" "dmesg | sed -n '/$MARK/,\$p' | grep -E 'elected \(slot|foreign replay of dead slot'")
      [ -n "$r" ] && printf -- 'REPLAYER=test%s\n%s\n' "$n" "$r" ) &
done
wait

echo
echo "=== TRUNCATION CHECK (any node that could not read the whole table) ==="
for n in $SURVIVORS; do
    [ "$n" = "$VICTIM_N" ] && continue
    sshq "test$n" 'dmesg | grep -c "P-PR-VIEW-TRUNC"' \
        | grep -qE '^[1-9]' && echo "test$n: TRUNCATED VIEW OBSERVED"
done
echo "(no lines above = every survivor read the full registration table)"

echo
echo "=== restart the victim with: sudo virsh -c qemu:///system start $VICTIM ==="
