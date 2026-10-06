#!/bin/bash
# pve_pair_failover.sh — the failures docs/drbd-setup.md ("What happens when a
# node is lost") says a two-host Proxmox pair on MXFS-on-DRBD survives, run on
# the hosts themselves, each under a VM-like load on both hosts, with every
# fsynced file checked on both afterwards.
#
# The rig (scripts/drbd_rig.sh) proves the same paths on libvirt nodes it
# configures itself.  This runs on hosts set up from the guide alone —
# `make install`, the resource file, `mxfs-drbd@` — so it also proves what a
# user's installation does: the installed boot program, guard, fence handler
# and units, the host's real boot time, its Proxmox services.
#
# Usage: tests/pve_pair_failover.sh [step ...]
#   p1-crash   participant 1 is reset (sysrq b: no sync, no unmount).  The
#              survivor's load must see no I/O error; it excludes the dead
#              host, certifies the exclusion and replays its journal; the dead
#              host reboots, is released, resyncs and mounts by itself.
#   p0-crash   participant 0 is reset.  Participant 1 cannot tell that from a
#              cut link, so it freezes and restarts itself; both come back
#              through their boot programs and mount by themselves.
#   power-cut  both hosts are reset at once; both mount by themselves.
#   reboot     participant 1 is rebooted cleanly (systemctl reboot): its unit
#              unmounts and steps down, the survivor's load carries on without
#              a fence, and the host mounts again after its boot.
#   (default: p1-crash reboot power-cut p0-crash)
#
# Before each step both hosts must be mounted, DRBD Connected Primary/Primary
# UpToDate/UpToDate, running one MXFS build.  A step that fails stops the run.
#
# Env:
#   PVE_PAIR       "<addr> <addr>" (default "192.168.1.80 192.168.1.81");
#                  participant 0 is the lower address, as the fence decides
#   RES / MNT      DRBD resource and mount point (default mxfs, /mnt/shared)
#   BOOT_BUDGET    seconds from a reset to the host answering ssh (default 300:
#                  the HP Z400 pair boots in ~3 min, 2 of them retrying iSCSI
#                  logins to retired targets)
#   LOAD_S         seconds of load per step (default 120)
#
# Evidence: tests/evidence/pve_pair_failover/<UTC stamp>/<step>/ — each host's
# kernel log and boot-program journal since the step began, and fio's json.
#
# DESTRUCTIVE to whatever else runs on the hosts: guests on them die with the
# host in every crash step.  Run it on a pair with nothing else running.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_pair_failover: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
BOOT_BUDGET=${BOOT_BUDGET:-300}
LOAD_S=${LOAD_S:-120}
# The survivor's recovery after a peer reset: DRBD notices within 2 x ping-int
# + ping-timeout (~7 s with the guide's ping-int 3), then exclusion, witness,
# certificate and replay (13 s from the kill on the rig): twice that, rounded up.
RECOVER_BUDGET=60
# From the host answering ssh to its mount: the guard's release (5 s poll),
# DRBD connect and bitmap resync, the boot program's ordering, the mount's
# heartbeat scan (~64 s): ~100 s, rounded up.
REJOIN_BUDGET=180
# From both hosts answering ssh to both mounted after a pair outage: 143-148 s
# on the rig (self-outage-test); twice that.
OUTAGE_BUDGET=300
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_pair_failover/$STAMP"
mkdir -p "$EVID" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
die() { say "FAIL: $*"; exit 1; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi

# One line per host: unit, mount, DRBD state, the module's build, boot id.
STATE_CMD='
dev=$(drbdadm sh-dev '"$RES"' 2>/dev/null)
m=$(awk -v d="$dev" '\''$1 == d && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1)
echo "unit=$(systemctl is-active mxfs-drbd@'"$RES"') mnt=${m:-none} role=$(drbdadm role '"$RES"' 2>/dev/null) cs=$(drbdadm cstate '"$RES"' 2>/dev/null) ds=$(drbdadm dstate '"$RES"' 2>/dev/null) build=$(cat /sys/module/mxfs/srcversion 2>/dev/null) boot=$(cat /proc/sys/kernel/random/boot_id)"'

state() { on "$1" "$STATE_CMD" 20 | grep '^unit='; }
field() { sed -n "s/.* $2=\([^ ]*\).*/\1/p; s/^$2=\([^ ]*\).*/\1/p" <<<"$1" | head -1; }
pair_ok() {  # <state line>
    [ "$(field "$1" unit)" = active ] && [ "$(field "$1" mnt)" = "$MNT" ] \
        && [ "$(field "$1" role)" = Primary/Primary ] && [ "$(field "$1" cs)" = Connected ] \
        && [ "$(field "$1" ds)" = UpToDate/UpToDate ]
}
need_pair_up() {
    local s0 s1
    s0=$(state "$P0"); s1=$(state "$P1")
    pair_ok "$s0" || die "$P0 is not up as half of the pair: ${s0:-no answer}"
    pair_ok "$s1" || die "$P1 is not up as half of the pair: ${s1:-no answer}"
    [ "$(field "$s0" build)" = "$(field "$s1" build)" ] \
        || die "the hosts run different MXFS builds: $(field "$s0" build) / $(field "$s1" build)"
    BUILD=$(field "$s0" build)
}
boot_id() { field "$(state "$1")" boot; }

# wait_rebooted <host> <old boot id> <budget>: the host answers with a new boot id
wait_rebooted() {
    local t0 b
    t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt "$3" ]; do
        b=$(on "$1" 'cat /proc/sys/kernel/random/boot_id' 10 | grep -E '^[0-9a-f-]{36}$')
        [ -n "$b" ] && [ "$b" != "$2" ] && { echo $(( $(date +%s) - t0 )); return 0; }
        sleep 5
    done
    return 1
}
# wait_mounted <host> <budget>: the host is a full half of the pair again
wait_mounted() {
    local t0 s
    t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt "$2" ]; do
        s=$(state "$1")
        pair_ok "$s" && { echo $(( $(date +%s) - t0 )); return 0; }
        sleep 5
    done
    say "  $1 at the bound: ${s:-no answer}"
    return 1
}

# Each host writes and fsyncs 32 files of 64 KiB; the md5 of the set is kept.
declare -A SUMS
write_sets() {  # <step>
    local h out
    for h in "$P0" "$P1"; do
        out=$(on "$h" "d=$MNT/pvefail/$STAMP/$1/\$(hostname); mkdir -p \$d && for i in \$(seq 1 32); do head -c 65536 /dev/urandom > \$d/f\$i; done && sync -f \$d && cd \$d && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
        [ "${#out}" = 32 ] || die "$h could not write its fsynced set: $out"
        SUMS[$1.$h]=$out
    done
}
verify_sets() {  # <step>
    local h g out names
    names=$(on "$P0" "ls $MNT/pvefail/$STAMP/$1" 20 | tr '\n' ' ')
    for h in "$P0" "$P1"; do
        for g in "$P0" "$P1"; do
            out=$(on "$h" "cd $MNT/pvefail/$STAMP/$1/$(on "$g" hostname 10) && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
            [ "$out" = "${SUMS[$1.$g]}" ] || die "$h reads $g's fsynced set differently after $1: $out (written ${SUMS[$1.$g]}; sets: $names)"
        done
        on "$h" "touch $MNT/pvefail/$STAMP/$1/after.\$(hostname) && rm $MNT/pvefail/$STAMP/$1/after.\$(hostname) && echo W_OK" 30 | grep -q W_OK \
            || die "$h cannot write after $1"
    done
    say "  every fsynced file of both hosts intact on both, and both write"
}

# A VM-like load: O_DIRECT 4 KiB random 60/40 read/write at QD16 on a 1 GiB
# file of the host's own, time_based, detached so it outlives the ssh session.
start_loads() {  # <step>
    local h
    for h in "$P0" "$P1"; do
        on "$h" "command -v fio >/dev/null || { echo NO_FIO; exit 1; }
            e=io_uring; fio --enghelp 2>/dev/null | grep -q io_uring || e=libaio
            rm -f /root/pvefail_fio.json
            nohup setsid fio --name=vm --filename=$MNT/pvefail/load.\$(hostname) --size=1g --rw=randrw --rwmixread=60 \
                --bs=4k --iodepth=16 --ioengine=\$e --direct=1 --time_based --runtime=$LOAD_S \
                --output-format=json --output=/root/pvefail_fio.json >/dev/null 2>&1 < /dev/null &
            sleep 2; fuser $MNT/pvefail/load.\$(hostname) >/dev/null 2>&1 && echo LOAD_UP" 40 | grep -q LOAD_UP || die "no load on $h (fio installed? apt install fio)"
    done
}
# load_result <host>: waits for the host's fio to end, then its errors and worst latency
load_result() {
    on "$1" "for i in \$(seq 1 $((LOAD_S + 30))); do [ -s /root/pvefail_fio.json ] && break; sleep 1; done
        python3 -c 'import json; j=json.load(open(\"/root/pvefail_fio.json\"))[\"jobs\"][0]
print(\"LOAD err=%d read_ios=%d write_ios=%d lat_max_ms=%.0f\" % (j[\"error\"], j[\"read\"][\"total_ios\"], j[\"write\"][\"total_ios\"], max(j[\"read\"][\"lat_ns\"][\"max\"], j[\"write\"][\"lat_ns\"][\"max\"]) / 1e6))'" $((LOAD_S + 60)) | grep '^LOAD '
}

reset_host() {  # <host>: sysrq b one second after the ssh session ends
    on "$1" "echo 1 > /proc/sys/kernel/sysrq; nohup setsid sh -c 'sleep 1; echo b > /proc/sysrq-trigger' >/dev/null 2>&1 < /dev/null & echo RESET_ARMED" 15 | grep -q RESET_ARMED \
        || die "could not arm the reset on $1"
}

# Each host's evidence since the step began.
collect() {  # <step> <since epoch>
    local h d="$EVID/$1"
    mkdir -p "$d"
    for h in "$P0" "$P1"; do
        on "$h" "journalctl -k --no-pager -o short-iso --since @$2 | grep -aE 'mxfs|drbd|XFS' | cut -c1-400" 60 > "$d/klog.$h"
        on "$h" "journalctl --no-pager -o short-iso --since @$2 -u mxfs-drbd@$RES -u mxfs-drbd-guard -t mxfs-drbd-fence | cut -c1-400" 60 > "$d/units.$h"
        on "$h" "cat /root/pvefail_fio.json 2>/dev/null" 30 > "$d/fio.$h.json"
    done
}

step_p1_crash() {
    local b1 t0 s out
    write_sets p1-crash; start_loads p1-crash
    sleep 10
    b1=$(boot_id "$P1")
    say "p1-crash: resetting $P1 (participant 1) under load on both"
    t0=$(date +%s); reset_host "$P1"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not come back within ${BOOT_BUDGET}s of its reset"
    say "  $P1 answered again $s s after the reset"
    out=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P238-DRBD-FENCE-WITNESSED|P236-FENCE-CERTIFIED|P163-RECOVERY-COMPLETE|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
    grep -q P163-RECOVERY-COMPLETE <<<"$out" || die "$P0 did not complete the recovery of $P1: ${out:-no recovery lines}"
    grep -q P-RBLK <<<"$out" && die "$P0 refused operations as RECOVERY_BLOCKED: $out"
    say "  $P0: $out"
    s=$(wait_mounted "$P1" "$REJOIN_BUDGET") || die "$P1 did not mount again within ${REJOIN_BUDGET}s of answering"
    say "  $P1 mounted again $s s after answering"
    out=$(load_result "$P0")
    [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "the survivor's load saw an error: ${out:-no result}"
    say "  survivor $P0: $out"
    collect p1-crash "$t0"
    verify_sets p1-crash
}

step_p0_crash() {
    local b0 b1 t0 s
    write_sets p0-crash; start_loads p0-crash
    sleep 10
    b0=$(boot_id "$P0"); b1=$(boot_id "$P1")
    say "p0-crash: resetting $P0 (participant 0) under load on both; $P1 must freeze and restart itself"
    t0=$(date +%s); reset_host "$P0"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not restart itself within ${BOOT_BUDGET}s"
    say "  $P1 restarted itself and answered $s s after $P0's reset"
    s=$(wait_rebooted "$P0" "$b0" "$BOOT_BUDGET") || die "$P0 did not come back within ${BOOT_BUDGET}s of its reset"
    s=$(wait_mounted "$P0" "$OUTAGE_BUDGET") || die "$P0 did not mount within ${OUTAGE_BUDGET}s"
    say "  $P0 mounted"
    s=$(wait_mounted "$P1" "$OUTAGE_BUDGET") || die "$P1 did not mount within ${OUTAGE_BUDGET}s"
    say "  $P1 mounted $s s later"
    collect p0-crash "$t0"
    verify_sets p0-crash
}

step_power_cut() {
    local b0 b1 t0 s
    write_sets power-cut; start_loads power-cut
    sleep 10
    b0=$(boot_id "$P0"); b1=$(boot_id "$P1")
    say "power-cut: resetting both hosts at once under load"
    t0=$(date +%s); reset_host "$P0" & reset_host "$P1" & wait
    s=$(wait_rebooted "$P0" "$b0" "$BOOT_BUDGET") || die "$P0 did not come back within ${BOOT_BUDGET}s"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not come back within ${BOOT_BUDGET}s"
    say "  both answered again"
    s=$(wait_mounted "$P0" "$OUTAGE_BUDGET") || die "$P0 did not mount within ${OUTAGE_BUDGET}s of answering"
    say "  $P0 mounted"
    s=$(wait_mounted "$P1" "$OUTAGE_BUDGET") || die "$P1 did not mount within ${OUTAGE_BUDGET}s"
    say "  $P1 mounted $s s later"
    collect power-cut "$t0"
    verify_sets power-cut
}

step_reboot() {
    local b1 t0 s out
    write_sets reboot; start_loads reboot
    sleep 10
    b1=$(boot_id "$P1")
    say "reboot: rebooting $P1 cleanly under load on both"
    t0=$(date +%s)
    on "$P1" "nohup setsid sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 < /dev/null & echo REBOOTING" 15 | grep -q REBOOTING || die "could not reboot $P1"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not come back within ${BOOT_BUDGET}s"
    say "  $P1 answered again $s s after the reboot began"
    out=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P238-DRBD-FENCE-WITNESSED|P236-FENCE-CERTIFIED|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
    [ -z "$out" ] || die "a clean reboot of $P1 was handled as a loss on $P0: $out"
    s=$(wait_mounted "$P1" "$REJOIN_BUDGET") || die "$P1 did not mount again within ${REJOIN_BUDGET}s of answering"
    say "  $P1 mounted again $s s after answering"
    out=$(load_result "$P0")
    [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "the survivor's load saw an error: ${out:-no result}"
    say "  survivor $P0: $out"
    collect reboot "$t0"
    verify_sets reboot
}

STEPS=("$@")
[ "${#STEPS[@]}" -gt 0 ] || STEPS=(p1-crash reboot power-cut p0-crash)
for s in "${STEPS[@]}"; do
    case "$s" in p1-crash|p0-crash|power-cut|reboot) ;; *) echo "unknown step: $s"; exit 2 ;; esac
done
say "pve pair failover: participant 0 $P0, participant 1 $P1; steps: ${STEPS[*]}; evidence $EVID"
for s in "${STEPS[@]}"; do
    need_pair_up
    say "== $s (build $BUILD)"
    "step_${s//-/_}"
    say "== $s passed"
done
say "pve pair failover: passed (${STEPS[*]})"
