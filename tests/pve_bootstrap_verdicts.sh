#!/bin/bash
# pve_bootstrap_verdicts.sh — re-run a refused whole-cluster bootstrap on a
# DRBD pair with the replay's per-item authority verdicts printed, so the
# images that made the term terminal can be named.
#
# A bootstrap whose adopted replay refuses a transaction leaves the record
# REFUSED.  Clearing the term (chk_mxfs --clear-bootstrap) and mounting again
# replays the same slice, but NOT against the same victim: the refused term had
# already adopted the victim's heartbeat slot under its own identity, and the
# clear zeroes the escrow that held the original's, so the second bootstrap
# judges the slice against the adopter (measured 2026-10-07: term 15 refused 2
# of 395 transactions, term 16 after the clear refused all 395).  Use this to
# see the second bootstrap's verdicts, not to reproduce the first one's; for
# that, reproduce the outage (tests/pve_outage_lone_survivor.sh DIAG=1).
# The verdict lines (P227-TOKEN per
# buffer image, P227-TOKENSUM per transaction) are dynamic-debug probes, off
# by default; this turns them on for the one mount and off again.
#
# For D-DRBD-OUTAGE-BOOTSTRAP-REFUSES-THE-LAST-SURVIVORS-OWN-LOG.
#
# Usage: tests/pve_bootstrap_verdicts.sh
# Env:
#   PVE_PAIR      "<participant 0> <participant 1>" (default the nested pair
#                 "192.168.120.137 192.168.120.192")
#   RES / MNT     DRBD resource and mount point (default mxfs, /mnt/shared)
#   MOUNT_BUDGET  seconds from the unit's start to a mount verdict (default
#                 240: the boot program's DRBD wait, the bootstrap's scan and
#                 the replay took 45 s on the refusing run; twice that, plus
#                 the program's own first retry interval)
#
# Holds participant 1's unit stopped for the whole run so only participant 0
# bootstraps; leaves it stopped (start it by hand once the evidence is read).
# Evidence: tests/evidence/pve_outage_bootstrap_refused/verdicts-<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PAIR_S=${PVE_PAIR:-192.168.120.137 192.168.120.192}
read -r -a PAIR <<<"$PAIR_S"
P0=${PAIR[0]}
P1=${PAIR[1]}
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
MOUNT_BUDGET=${MOUNT_BUDGET:-240}
EVID="$REPO/tests/evidence/pve_outage_bootstrap_refused/verdicts-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1

on() {  # <host> <cmd> [timeout]
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }

say "evidence $EVID"
# a unit that had already failed runs no step-down on stop, and the bootstrap
# waits for the peer to be Secondary on the Connected link, so demote it here
on "$P1" "systemctl stop mxfs-drbd@$RES; drbdadm secondary $RES; systemctl is-active mxfs-drbd@$RES; grep -c ' $MNT mxfs ' /proc/mounts; grep ' cs:' /proc/drbd" 120 | tee -a "$EVID/log"
on "$P0" "systemctl stop mxfs-drbd@$RES; systemctl reset-failed mxfs-drbd@$RES; grep -c ' $MNT mxfs ' /proc/mounts; grep ' cs:' /proc/drbd" 120 | tee -a "$EVID/log"
if on "$P0" "grep -q ' $MNT mxfs ' /proc/mounts" 15; then
    say "ABORT: $P0 has $MNT mounted"; exit 1
fi

# the record as it stands, then the clear (needs the device open exclusively,
# so participant 0 is made Primary for it if the stop left it Secondary)
on "$P0" "drbdadm primary $RES 2>&1; chk_mxfs --bootstrap /dev/drbd0" 60 > "$EVID/bootstrap-before.txt"
say "record before: $(grep -aiE 'state' "$EVID/bootstrap-before.txt" | head -3 | tr '\n' ' ')"
on "$P0" "chk_mxfs --clear-bootstrap /dev/drbd0; echo CLEAR_RC=\$?" 60 > "$EVID/clear.txt"
cat "$EVID/clear.txt" | tee -a "$EVID/log"
grep -q 'CLEAR_RC=0' "$EVID/clear.txt" || { say "ABORT: the clear did not succeed"; exit 1; }
on "$P0" "drbdadm secondary $RES 2>&1" 30 | tee -a "$EVID/log"

# verdict probes on, for this mount only
on "$P0" "c=/proc/dynamic_debug/control; for f in P227-TOKEN P227-UNTAGGED P273-SHADOW-EVAL P-RMAN-EVAL P-BOOT; do echo \"module mxfs format \\\"\$f\\\" +p\" > \$c; done; grep -c 'P227-TOKEN' \$c; grep 'P227-TOKEN' \$c | head -3" 30 | tee -a "$EVID/log"
on "$P0" "echo '<5>mxfs-test: bootstrap verdicts run start' > /dev/kmsg" 15
T0=$(date +%s)
# a plain `systemctl start` blocked past its 60 s bound while the boot program
# waited for DRBD; do not wait on it here, the loop below watches the mount
on "$P0" "systemctl start --no-block mxfs-drbd@$RES" 30
verdict=none
while [ $(( $(date +%s) - T0 )) -lt "$MOUNT_BUDGET" ]; do
    # only this run's lines: earlier refusals in the same boot are not its verdict
    s=$(on "$P0" "grep -c ' $MNT mxfs ' /proc/mounts; journalctl -k -b --no-pager | sed -n '/mxfs-test: bootstrap verdicts run start/,\$p' | grep -a -c -E 'P-BOOT-REFUSED|P-BOOT-ADMISSION-REFUSED'" 20)
    if [ "$(head -1 <<<"$s")" = 1 ]; then verdict=mounted; break; fi
    if [ "$(tail -1 <<<"$s")" -gt 0 ] 2>/dev/null; then verdict=refused; break; fi
    sleep 5
done
say "mount verdict: $verdict after $(( $(date +%s) - T0 ))s"
on "$P0" "c=/proc/dynamic_debug/control; for f in P227-TOKEN P227-UNTAGGED P273-SHADOW-EVAL P-RMAN-EVAL P-BOOT; do echo \"module mxfs format \\\"\$f\\\" -p\" > \$c; done" 30
on "$P0" "journalctl -k -b --no-pager -o short-monotonic | sed -n '/mxfs-test: bootstrap verdicts run start/,\$p'" 90 > "$EVID/kernel.txt"
on "$P0" "chk_mxfs --bootstrap /dev/drbd0" 60 > "$EVID/bootstrap-after.txt"
say "kernel lines kept: $(wc -l < "$EVID/kernel.txt"); P227-TOKEN lines: $(grep -c 'P227-TOKEN ' "$EVID/kernel.txt"); TOKENSUM: $(grep -c 'P227-TOKENSUM' "$EVID/kernel.txt")"
grep -aE 'ATOMIC-SKIP|P-BOOT-(ADOPTED-REFUSED|REFUSING|REFUSED)' "$EVID/kernel.txt" | cut -c1-240 | tee -a "$EVID/log"
say "participant 1 ($P1) unit left stopped"
