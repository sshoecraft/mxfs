#!/bin/bash
# pve_build_leg_kmsg.sh — one MXFS build leg on the physical pair's spare disks
# (scripts/pve_build_compare.sh <dir> mxfs: both disks TRIMmed and rested,
# MXFS on DRBD built on them, the concurrent VM installs run) with each host's
# kernel log for the leg kept beside it and the lines that grade the pair
# counted per host.  The pair's release criterion is no I/O error, hang,
# kernel warning, withdrawal or self-fence while the installs run, so a leg
# with any of those is a FAIL whatever its install times.
#
# Built to sit under tests/pve_knob_ab.sh, which sets a module parameter on
# both hosts, runs this with the arm's label as the last argument, then sets
# the next value:
#   ARM_BUDGET=4200 tests/pve_knob_ab.sh dl_noqueue_prepare_wouldblock "0 1" \
#       tests/pve_build_leg_kmsg.sh
#
# Usage: tests/pve_build_leg_kmsg.sh <label>
# Env:   PVE_PAIR ("192.168.1.80 192.168.1.81")  DISK (/dev/sdb)
#        MODEL (SVP100S)  COUNTS ("3 4")  as scripts/pve_build_compare.sh
#        PROBES  dynamic-debug formats switched on in mxfs on both hosts before
#                the leg (default: the no-queue and prepare-wanted probes); a module reload
#                switches them off again
# Output: tests/evidence/pve_build_leg_kmsg/<stamp>-<label>/: compare/ (the
#         leg), kmsg-<host>.txt, verdict.txt.  Exit 0 = PASS, 1 = FAIL.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
LABEL=${1:?label}
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
export DISK=${DISK:-/dev/sdb} MODEL=${MODEL:-SVP100S}
PROBES=${PROBES:-P-ACQ-NOQUEUE-PREPARE P-ACQ-NOQUEUE-LEDGER-NOTREADY P-PREPARE-WANTED P-ACQ-NOQUEUE-UNANSWERED P958-ACQ-GAVE-UP-RETIRED P-RREQ-NOQUEUE-SLOW P958-ACQ-GRANT-}
EVID="$REPO/tests/evidence/pve_build_leg_kmsg/$(date -u +%Y%m%dT%H%M%SZ)-$LABEL"
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/verdict.txt"; }
on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'; }

# What grades the leg.  The first group fails it; the second is counted only.
# A bare "Call Trace" is not in it: every kernel-originated trace follows one
# of these lines, and the module's own stall forensics (P278-HB-STALL) dump a
# stack at warn level on a healthy loaded host; they are counted instead.
BAD='I/O error|blocked for more than|WARNING:|BUG:|Oops|Shutting down filesystem|P-WITHDRAW|RECOVERY_BLOCKED|self-fenc|corrupt|failed after [0-9]+ retries'
COUNT='P-ACQ-NOQUEUE-PREPARE|P-ACQ-NOQUEUE-PREPARE-SLOW|P-ACQ-NOQUEUE-LEDGER-NOTREADY|P-PREPARE-WANTED|P-ACQ-NOQUEUE-UNANSWERED|P958-ACQ-IDLE-LOST|P958-ACQ-GAVE-UP-RETIRED|P-RREQ-NOQUEUE-SLOW|P958-ACQ-GRANT-CLAIMED|P958-ACQ-GRANT-RELEASED|P958-ACQ-GRANT-VANISHED|P960-AUTH-TRANSITION-NOQUEUE|P-ACQ-UNREACHABLE-MASTER-NOQUEUE|P278-HB-STALL'

declare -A T0
for h in "${H[@]}"; do
    T0[$h]=$(on "$h" "date +%s")
    [[ "${T0[$h]}" =~ ^[0-9]+$ ]] || { say "FAIL: cannot read the clock of $h: ${T0[$h]}"; exit 1; }
    for p in $PROBES; do
        on "$h" "echo 'module mxfs format \"$p\" +p' > /proc/dynamic_debug/control" >/dev/null
    done
    say "$h: build=$(on "$h" "cat /sys/module/mxfs/version /sys/module/mxfs/srcversion" | tr '\n' ' ')probes=$(on "$h" "grep -c '=p ' /proc/dynamic_debug/control")"
done
say "leg $LABEL: $DISK ($MODEL), builds ${COUNTS:-3 4}"
"$REPO/scripts/pve_build_compare.sh" "$EVID/compare" mxfs > "$EVID/compare.out" 2>&1
crc=$?
say "compare rc=$crc"
grep -aE 'installed after|never answered|never started|did not come up|could not be reset' "$EVID/compare/compare.log" | tee -a "$EVID/verdict.txt"

fail=0
for h in "${H[@]}"; do
    on "$h" "journalctl -k --since @${T0[$h]} --no-pager -o short-iso" 120 > "$EVID/kmsg-$h.txt"
    n=$(wc -l < "$EVID/kmsg-$h.txt")
    [ "$n" -gt 0 ] || { say "FAIL: $h kernel log for the leg is empty"; fail=1; continue; }
    nbad=$(grep -acE "$BAD" "$EVID/kmsg-$h.txt")
    say "$h kernel log: $n lines, bad=$nbad"
    for p in $(tr '|' ' ' <<<"$COUNT"); do
        say "  $h $p: $(grep -ac -- "$p " "$EVID/kmsg-$h.txt")"
    done
    if [ "$nbad" -gt 0 ]; then
        fail=1
        grep -aE "$BAD" "$EVID/kmsg-$h.txt" | head -20 | cut -c1-240 | sed "s/^/  $h: /" | tee -a "$EVID/verdict.txt"
    fi
done
grep -aq 'never answered\|never started\|did not come up\|could not be reset' "$EVID/compare/compare.log" && { say "an install or the leg's setup did not complete"; fail=1; }
[ "$crc" = 0 ] || fail=1
if [ "$fail" = 0 ]; then say "VERDICT PASS $LABEL"; else say "VERDICT FAIL $LABEL"; fi
exit "$fail"
