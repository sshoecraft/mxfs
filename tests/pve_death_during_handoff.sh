#!/bin/bash
# pve_death_during_handoff.sh — a peer that dies while its survivor is in a
# view-change hand-off pass is declared dead on the survivor's own schedule,
# not when the pass ends.
#
# When a host rejoins, its peer hands it back its share of the ledger pages
# (mxfs_dlm_handoff_tick), one durable commit per page.  That pass ran on the
# TCP death worker ahead of the grace check and the DRBD exclusion check, so a
# death in the pass was not decided until it ended: on the physical pair a
# pass of 1303 pages held the worker 52.6 s (P-TCP-DEATH-PASS-HELD
# handoff=52627).  This puts participant 0 into such a pass and resets
# participant 1 inside it.
#
# Steps: both mounted Primary/Primary, Connected, UpToDate; participant 1's
# unit is stopped, so participant 0 serves every page; participant 0's dlm
# probes go on; participant 1's unit is started, and once it is mounted and
# participant 0 is logging view-change hand-offs, participant 1 is reset
# (sysrq b).  The time from the reset to participant 0's death declaration
# (P-DRBD-EXCL-DEATH, or the TCP grace's "declaring dead") is the result.
# Then participant 1 boots, its boot program brings it back, and the pair must
# be whole again.
#
# NESTED PAIR ONLY: it resets a host.  The physical pair (192.168.1.80/81) is
# refused.
#
# Usage: tests/pve_death_during_handoff.sh
# Env:
#   PVE_PAIR      "<addr> <addr>" (default the nested pair 192.168.120.192
#                 192.168.120.137); participant 1 is the higher address
#   DEATH_BUDGET  seconds from the reset to the death declaration (default 22:
#                 the DRBD exclusion path, measured on the rig at +10.9 s, x2)
#   MOUNT_BUDGET  seconds for a unit's start to its mount (default 300)
#   BOOT_BUDGET   seconds for the reset host to be whole again (default 420: a
#                 nested PVE boot, the boot program's release and resync, and
#                 the mount)
# Evidence: tests/evidence/pve_death_during_handoff/<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.120.192 192.168.120.137}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_death_during_handoff: PVE_PAIR must name two hosts"; exit 2; }
for h in "${PAIR[@]}"; do
    case "$h" in
        192.168.1.80|192.168.1.81)
            echo "pve_death_during_handoff: $h is the physical pair, which is never reset"; exit 2 ;;
    esac
done
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
DEATH_BUDGET=${DEATH_BUDGET:-22}
MOUNT_BUDGET=${MOUNT_BUDGET:-300}
BOOT_BUDGET=${BOOT_BUDGET:-420}
MNT=/mnt/shared
EVID="$REPO/tests/evidence/pve_death_during_handoff/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 2
DYN="module mxfs format \"%s%pV\""

on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
whole() {  # <host>: mounted Primary/Primary Connected UpToDate/UpToDate
    on "$1" "grep -q ' $MNT mxfs ' /proc/mounts && [ \"\$(drbdadm role mxfs)\" = Primary/Primary ] && [ \"\$(drbdadm cstate mxfs)\" = Connected ] && [ \"\$(drbdadm dstate mxfs)\" = UpToDate/UpToDate ] && echo WHOLE" 20 | grep -q WHOLE
}
until_ok() {  # <budget s> <cmd...>: run cmd every 2 s until it succeeds
    local budget=$1 t0
    shift
    t0=$(date +%s)
    until "$@"; do
        [ $(( $(date +%s) - t0 )) -lt "$budget" ] || return 1
        sleep 2
    done
}
mounted() { on "$1" "grep -q ' $MNT mxfs ' /proc/mounts && echo M" 20 | grep -q M; }
stopped() { on "$1" "systemctl is-active mxfs-drbd@mxfs" 20 | grep -qE '^(inactive|failed)$'; }
kmsg_since() {  # <host> <epoch>: the kernel log from then, epoch-stamped
    on "$1" "journalctl -k --since @$2 --no-pager -o short-unix" 60
}

say "survivor $P0, reset $P1; death budget ${DEATH_BUDGET}s"
for h in "$P0" "$P1"; do
    whole "$h" || { say "FAIL: $h is not mounted Primary/Primary, Connected, UpToDate; not starting"; exit 1; }
    say "$h build $(on "$h" 'cat /sys/module/mxfs/version /sys/module/mxfs/srcversion | tr "\n" " "' 20)"
done

# 1. participant 1 leaves: participant 0 then serves every page
on "$P1" "systemctl stop --no-block mxfs-drbd@mxfs" 30 >/dev/null
until_ok 230 stopped "$P1" || { say "FAIL: $P1's unit did not stop"; exit 1; }
say "$P1 stopped; $P0 serves every page"

# 2. participant 1 rejoins; participant 0 hands its share back
on "$P0" "echo '$DYN +p' > /proc/dynamic_debug/control" 20 >/dev/null
t_start=$(on "$P0" "date +%s" 20)
on "$P1" "systemctl reset-failed mxfs-drbd@mxfs 2>/dev/null; systemctl start --no-block mxfs-drbd@mxfs" 30 >/dev/null
until_ok "$MOUNT_BUDGET" mounted "$P1" || {
    on "$P0" "echo '$DYN -p' > /proc/dynamic_debug/control" 20 >/dev/null
    say "FAIL: $P1 did not mount within ${MOUNT_BUDGET}s"; exit 1; }
in_pass() { [ "$(kmsg_since "$P0" "$t_start" | grep -ac 'P-TAUTH-HANDOFF page=.*why=view-change')" -gt 0 ]; }
until_ok 20 in_pass || {
    on "$P0" "echo '$DYN -p' > /proc/dynamic_debug/control" 20 >/dev/null
    say "FAIL: $P1 mounted but $P0 logged no view-change hand-off within 20 s; nothing to measure"; exit 1; }

# 3. reset participant 1 inside the pass, timed on participant 0's clock
# (armed a second ahead, as tests/pve_pair_failover.sh resets, so the ssh
# returns before the host goes)
on "$P1" "echo 1 > /proc/sys/kernel/sysrq; nohup setsid sh -c 'sleep 1; echo b > /proc/sysrq-trigger' >/dev/null 2>&1 < /dev/null & echo RESET_ARMED" 15 | grep -q RESET_ARMED \
    || { on "$P0" "echo '$DYN -p' > /proc/dynamic_debug/control" 20 >/dev/null; say "FAIL: could not arm $P1's reset"; exit 1; }
t_reset=$(on "$P0" "python3 -c 'import time; print(f\"{time.time() + 1:.3f}\")'" 20)
say "$P1 reset at about $t_reset (participant 0's clock)"

# 4. participant 0's death declaration
death=
t0=$(date +%s)
while [ $(( $(date +%s) - t0 )) -lt $((DEATH_BUDGET + 60)) ]; do
    death=$(kmsg_since "$P0" "${t_reset%.*}" | grep -aE 'P-DRBD-EXCL-DEATH node=|did not reconnect within .* declaring dead' | head -1)
    [ -n "$death" ] && break
    sleep 2
done
kmsg_since "$P0" "$t_start" > "$EVID/kmsg-survivor.txt"
on "$P0" "echo '$DYN -p' > /proc/dynamic_debug/control" 20 >/dev/null
after=$(awk -v t="$t_reset" '$1 + 0 >= t + 0' "$EVID/kmsg-survivor.txt" | grep -ac 'P-TAUTH-HANDOFF page=.*why=view-change')
before=$(awk -v t="$t_reset" '$1 + 0 < t + 0' "$EVID/kmsg-survivor.txt" | grep -ac 'P-TAUTH-HANDOFF page=.*why=view-change')
held=$(grep -a 'P-TCP-DEATH-PASS-HELD' "$EVID/kmsg-survivor.txt" | grep -aoE 'handoff=[0-9]+' | sort -t= -k2 -n | tail -1)
verdict=PASS
if [ -z "$death" ]; then
    say "no death declaration on $P0 within $((DEATH_BUDGET + 60))s of the reset"
    verdict=FAIL
else
    t_death=${death%% *}
    death_ms=$(python3 -I -c 'import sys; print(int((float(sys.argv[1]) - float(sys.argv[2])) * 1000))' "$t_death" "$t_reset")
    say "death declared ${death_ms} ms after the reset: ${death#* }"
    [ "$death_ms" -le $((DEATH_BUDGET * 1000)) ] || verdict=FAIL
fi
say "view-change hand-offs on $P0: $before before the reset, $after after it; worst P-TCP-DEATH-PASS-HELD ${held:-none}"
[ "$after" -gt 0 ] || say "note: the pass had ended by the reset, so it was not measured inside one"
[ "$after" -gt 0 ] || verdict=FAIL

# 5. participant 1 comes back by itself
until_ok "$BOOT_BUDGET" whole "$P1" && until_ok 60 whole "$P0" || { say "FAIL: the pair was not whole again within ${BOOT_BUDGET}s"; verdict=FAIL; }
[ "$verdict" = FAIL ] || say "the pair is whole again"
say "RESULT: $verdict"
[ "$verdict" = PASS ]
