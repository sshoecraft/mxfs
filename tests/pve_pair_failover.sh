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
#   survivor-restart
#              participant 1 is powered off and stays off; participant 0
#              excludes it and carries on, then is itself reset.  It must
#              mount again alone, holding every fsynced file, and participant
#              1 must rejoin once it is powered on.  A host that dies while
#              its peer is being repaired is the case.
#   released-restart
#              as survivor-restart, but participant 1 first comes back without
#              DRBD (its unit masked, as when its unit files were lost), so
#              the survivor's guard releases it on its answer, and it dies
#              again before it ever connects; only then is participant 0
#              reset.  The physical pair did exactly this on 2026-10-05/06.
#   answering-restart
#              participant 1 is reset with its unit masked, so it comes back
#              answering with no DRBD; participant 0 recovers it and its guard
#              releases it.  Then participant 0 is reset with participant 1
#              still up that way.  Participant 0 must exclude it again and
#              mount alone, and its guard must not release participant 1
#              before that mount is done; then participant 1's unit starts and
#              the pair is whole.  Resets only: no host is powered off.
#   stale-promotion
#              participant 1 is powered off; participant 0 carries on and
#              writes, then its unit is stopped (up, not Primary, unmounted).
#              Participant 1 comes back with a replica that lacks those
#              writes, and a plain `drbdadm primary` on it must be refused;
#              then participant 0's unit starts and both mount again.
#   promotion-race
#              participant 0 is unmounted and Secondary on a Connected link
#              when the replication link fails on its side alone (ssh up).
#              Participant 1 must lose the tie-break and restart, never carry
#              on because its peer looks idle; a plain `drbdadm primary` on
#              participant 0 must be refused; then both mount again.
#   withdraw-both
#              both hosts' MXFS heartbeats stop past the 30 s authority lease
#              under load, as both hosts' did on 2026-10-06 when their writes
#              queued behind the guests' data: both mounts shut down with the
#              hosts up.  Each host's guard must rejoin its own mount (stop
#              what holds it, unmount, restart the unit) with no host restart,
#              and both must mount again.
#   withdraw-p1
#              the same on participant 1 alone: participant 0 carries on and
#              recovers it, and participant 1 rejoins without a restart.
#   withdraw-held
#              as withdraw-p1, while something the rejoin cannot stop holds
#              participant 1's mount (a tmpfs mounted inside it: no process to
#              kill, and the unmount answers busy).  The rejoin must give up on
#              the unmount after its rounds and restart the host itself, which
#              must come back and mount by itself; participant 0 carries on.
#   withdraw-guests
#              as withdraw-p1, while GUESTS Proxmox VMs whose disks are on the
#              mount run on participant 1, frozen (SIGSTOP) as a host short of
#              memory leaves its guests.  The rejoin must be rid of them and
#              unmounted within STEPDOWN_BUDGET of starting, and participant 0,
#              writing into a sparse file (every write allocates), must recover
#              participant 1, refuse nothing and see no I/O error.
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
#   PVE_POWER_ON   the command that powers a host on, run here with {name}
#                  replaced by the host's name and {addr} by its address; the
#                  steps that keep a host off need it.  The nested pair:
#                  'virsh -c qemu:///system start {name}'
#   PVE_POWER_OFF  the same for cutting a host's power.  Unset, the host is
#                  crashed with kernel.panic=0 and stays stopped until reset,
#                  so PVE_POWER_ON must reset it.  The nested pair:
#                  'virsh -c qemu:///system destroy {name}'
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
# A survivor that restarts alone mounts with the same work as the first mount
# after a pair outage (the heartbeat scan, its own journal's replay) and no
# peer to wait for, so the same bound.
ALONE_BUDGET=$OUTAGE_BUDGET
# From the excluded host answering ssh to the survivor's guard releasing it:
# the guard looks every 5 s and asks over ssh (ConnectTimeout 5).
RELEASE_BUDGET=30
# From sysrq o to the host no longer answering ping.
DOWN_BUDGET=30
# The withdraw steps pause a heartbeat this long, past the 30 s authority
# lease, so the mount shuts down while the host stays up.
WITHDRAW_PAUSE_MS=45000
# From the pause to a withdrawn host mounted again: the lease runs out (30 s),
# the guard sees the shutdown (5 s poll) and unmounts, and the unit's boot
# program mounts as after a pair outage (OUTAGE_BUDGET) -- the pause's length
# plus that.
WITHDRAW_BUDGET=$(( WITHDRAW_PAUSE_MS / 1000 + OUTAGE_BUDGET ))
# From the pause to a held host answering after its rejoin restarted it: the
# lease runs out (30 s), the guard sees the shutdown (5 s), three refused
# unmount rounds 5 s apart, the restart's 10 s delay -- 60 s, twice that --
# then the host's boot.
HELD_BUDGET=$(( 120 + BOOT_BUDGET ))
# withdraw-guests: frozen VMs on the withdrawn host, and from its rejoin's start
# to its unmount of the shut-down mount: killing every holder at once and their
# exit (a second or two), the unmount -- 15 s.  One `qm stop` per VM in turn
# took 74-90 s each on the swapping pve1, and participant 0 turns its wait for
# the step-down into I/O errors 120 s after the death (fence_blocked_after_ms).
GUESTS=${GUESTS:-3}
STEPDOWN_BUDGET=15
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
# Named for the pair too: two pairs' runs started in the same second shared
# one directory, and their logs interleaved.
EVID="$REPO/tests/evidence/pve_pair_failover/$STAMP-${PAIR[0]}"
mkdir -p "$EVID" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
# LEFT names what a failed step leaves changed on a host, so it can be undone.
LEFT=""
die() { say "FAIL: $*"; [ -z "$LEFT" ] || say "LEFT: $LEFT"; exit 1; }
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
# Mounted with the peer away: Primary on an UpToDate disk, link not Connected.
alone_ok() {  # <state line>
    local role ds
    role=$(field "$1" role); ds=$(field "$1" ds)
    [ "$(field "$1" unit)" = active ] && [ "$(field "$1" mnt)" = "$MNT" ] \
        && [ "${role%%/*}" = Primary ] && [ "$(field "$1" cs)" != Connected ] \
        && [ "${ds%%/*}" = UpToDate ]
}
# Each host's name, read while both answer: a host that is off is still
# named in the paths its files were written under.
declare -A NAME
need_pair_up() {
    local s0 s1
    s0=$(state "$P0"); s1=$(state "$P1")
    pair_ok "$s0" || die "$P0 is not up as half of the pair: ${s0:-no answer}"
    pair_ok "$s1" || die "$P1 is not up as half of the pair: ${s1:-no answer}"
    [ "$(field "$s0" build)" = "$(field "$s1" build)" ] \
        || die "the hosts run different MXFS builds: $(field "$s0" build) / $(field "$s1" build)"
    BUILD=$(field "$s0" build)
    NAME[$P0]=$(on "$P0" hostname 10); NAME[$P1]=$(on "$P1" hostname 10)
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
# wait_alone <host> <budget>: the host is mounted with its peer away
wait_alone() {
    local t0 s
    t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt "$2" ]; do
        s=$(state "$1")
        alone_ok "$s" && { echo $(( $(date +%s) - t0 )); return 0; }
        sleep 5
    done
    say "  $1 at the bound: ${s:-no answer}"
    on "$1" "journalctl -b --no-pager -o short-iso -t mxfs-drbd-fence | tail -4; journalctl -k -b --no-pager -o short-iso | grep -aE 'P-BOOT|P238|P-DRBD-ARM|refus' | tail -6" 30 | cut -c1-400 | sed 's/^/    /' | tee -a "$EVID/log"
    return 1
}

# Each host writes and fsyncs 32 files of 64 KiB; the md5 of the set is kept.
declare -A SUMS
write_set() {  # <step> <host>
    local out
    out=$(on "$2" "d=$MNT/pvefail/$STAMP/$1/\$(hostname); mkdir -p \$d && for i in \$(seq 1 32); do head -c 65536 /dev/urandom > \$d/f\$i; done && sync -f \$d && cd \$d && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    [ "${#out}" = 32 ] || die "$2 could not write its fsynced set: $out"
    SUMS[$1.$2]=$out
}
write_sets() { write_set "$1" "$P0"; write_set "$1" "$P1"; }
check_set() {  # <step> <reader> <writer>: the reader holds the writer's set as written
    local out
    out=$(on "$2" "cd $MNT/pvefail/$STAMP/$1/${NAME[$3]} && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    [ "$out" = "${SUMS[$1.$3]}" ] || die "$2 reads $3's fsynced set differently after $1: $out (written ${SUMS[$1.$3]}; sets: $(on "$2" "ls $MNT/pvefail/$STAMP/$1" 20 | tr '\n' ' '))"
}
check_writes() {  # <step> <host>
    on "$2" "touch $MNT/pvefail/$STAMP/$1/after.\$(hostname) && rm $MNT/pvefail/$STAMP/$1/after.\$(hostname) && echo W_OK" 30 | grep -q W_OK \
        || die "$2 cannot write after $1"
}
verify_sets() {  # <step>
    local h g
    for h in "$P0" "$P1"; do
        for g in "$P0" "$P1"; do check_set "$1" "$h" "$g"; done
        check_writes "$1" "$h"
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
                --output-format=json --output=/root/pvefail_fio.json >/dev/null 2>/root/pvefail_fio.err < /dev/null &
            # the file's create can wait on the other host's lock on the
            # directory, and fio's descriptor appears only once it returns
            for i in \$(seq 1 30); do fuser $MNT/pvefail/load.\$(hostname) >/dev/null 2>&1 && { echo LOAD_UP; exit 0; }; sleep 1; done
            echo \"NO_LOAD \$(tail -2 /root/pvefail_fio.err | tr '\n' ' ')\"" 60 > "$EVID/load.$h"
        grep -q LOAD_UP "$EVID/load.$h" || die "no load on $h: $(tail -1 "$EVID/load.$h")"
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
# The host stops dead, as at a power cut: nothing synced, no unit stopped, no
# leave message.  PVE_POWER_OFF when set; otherwise a kernel crash with
# kernel.panic=0, which leaves the host stopped until it is reset.  Not sysrq
# o: that is kernel_power_off(), which shuts devices down first, and on the
# nested pair it blocked until the softdog restarted the host 60 s later.
power_off_host() {  # <host>
    local cmd
    if [ -n "${PVE_POWER_OFF:-}" ]; then
        cmd=${PVE_POWER_OFF//\{name\}/${NAME[$1]}}
        cmd=${cmd//\{addr\}/$1}
        timeout 60 bash -c "$cmd" >>"$EVID/log" 2>&1 || die "could not power $1 off: $cmd"
        return
    fi
    on "$1" "echo 0 > /proc/sys/kernel/panic; echo 1 > /proc/sys/kernel/sysrq; nohup setsid sh -c 'sleep 1; echo c > /proc/sysrq-trigger' >/dev/null 2>&1 < /dev/null & echo OFF_ARMED" 15 | grep -q OFF_ARMED \
        || die "could not arm the crash on $1"
}
power_on_host() {  # <host>
    local cmd=${PVE_POWER_ON//\{name\}/${NAME[$1]}}
    cmd=${cmd//\{addr\}/$1}
    timeout 60 bash -c "$cmd" >>"$EVID/log" 2>&1 || die "could not power $1 on: $cmd"
}
# wait_down <host> <budget>: the host no longer answers ping
wait_down() {
    local t0
    t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt "$2" ]; do
        ping -c 1 -W 1 "$1" >/dev/null 2>&1 || { echo $(( $(date +%s) - t0 )); return 0; }
        sleep 1
    done
    return 1
}
# wait_recovered <survivor> <since> <budget>: the survivor completed the
# recovery of its dead peer, refusing nothing; prints seconds since <since>
wait_recovered() {
    local t0 out
    t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt "$3" ]; do
        out=$(on "$1" "journalctl -k --no-pager -o cat --since @$2 | grep -aoE 'P163-RECOVERY-COMPLETE|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
        grep -q P-RBLK <<<"$out" && { say "  $1 refused operations as RECOVERY_BLOCKED: $out"; return 1; }
        grep -q P163-RECOVERY-COMPLETE <<<"$out" && { echo $(( $(date +%s) - $2 )); return 0; }
        sleep 3
    done
    return 1
}
# wait_released <survivor> <since> <budget>: the survivor's guard released its
# excluded peer after <since> (a RELEASED receipt)
wait_released() {
    local t0
    t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt "$3" ]; do
        on "$1" "awk -v t=$2 '\$1 >= t && / result=RELEASED /' /var/lib/mxfs/drbd-fence.$RES" 20 | grep -q RELEASED \
            && { echo $(( $(date +%s) - t0 )); return 0; }
        sleep 3
    done
    return 1
}

# wait_journal <host> <since> <text> <budget>: the DRBD programs logged a line
# holding <text> after <since>; prints seconds since <since>
wait_journal() {
    local t0
    t0=$(date +%s)
    while [ $(( $(date +%s) - t0 )) -lt "$4" ]; do
        on "$1" "journalctl --no-pager -o cat -t mxfs-drbd-fence --since @$2 | grep -qF '$3' && echo SEEN" 20 | grep -q SEEN \
            && { echo $(( $(date +%s) - $2 )); return 0; }
        sleep 5
    done
    return 1
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

# The first half of both survivor steps: participant 1 is powered off under
# load and stays off; participant 0 recovers it with its load error-free.
p1_off_survivor_recovers() {  # <step>
    local t0 s out
    say "$1: powering $P1 (participant 1) off under load on both; it stays off"
    t0=$(date +%s); power_off_host "$P1"
    s=$(wait_down "$P1" "$DOWN_BUDGET") || die "$P1 still answers ${DOWN_BUDGET}s after its power-off"
    s=$(wait_recovered "$P0" "$t0" "$RECOVER_BUDGET") || die "$P0 did not recover $P1 within ${RECOVER_BUDGET}s of its power-off"
    say "  $P0 recovered $P1 $s s after its power-off"
    out=$(load_result "$P0")
    [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "the survivor's load saw an error: ${out:-no result}"
    say "  survivor $P0: $out"
    STEP_T0=$t0
}
# The second half: the survivor writes a set only it holds, is reset with its
# peer still off, and must mount alone holding every fsynced file.
survivor_reset_mounts_alone() {  # <step>
    local b0 s
    write_set "$1.alone" "$P0"
    b0=$(boot_id "$P0")
    say "  resetting $P0, the survivor, with $P1 still off"
    reset_host "$P0"
    s=$(wait_rebooted "$P0" "$b0" "$BOOT_BUDGET") || die "$P0 did not come back within ${BOOT_BUDGET}s of its reset"
    s=$(wait_alone "$P0" "$ALONE_BUDGET") || die "$P0 did not mount alone within ${ALONE_BUDGET}s of answering ($P1 is still off)"
    say "  $P0 mounted alone $s s after answering"
    check_set "$1" "$P0" "$P0"; check_set "$1" "$P0" "$P1"; check_set "$1.alone" "$P0" "$P0"
    check_writes "$1" "$P0"
    say "  $P0 alone holds every fsynced file of both hosts, and its own since, and writes"
}

step_survivor_restart() {
    local b1 s
    write_sets survivor-restart; start_loads survivor-restart
    sleep 10
    b1=$(boot_id "$P1")
    p1_off_survivor_recovers survivor-restart
    survivor_reset_mounts_alone survivor-restart
    power_on_host "$P1"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not answer within ${BOOT_BUDGET}s of its power-on"
    s=$(wait_mounted "$P1" "$REJOIN_BUDGET") || die "$P1 did not mount again within ${REJOIN_BUDGET}s of answering"
    say "  $P1 rejoined $s s after answering"
    collect survivor-restart "$STEP_T0"
    verify_sets survivor-restart
    check_set survivor-restart.alone "$P1" "$P0"
}

step_released_restart() {
    local b1 s
    write_sets released-restart; start_loads released-restart
    sleep 10
    # It comes back without DRBD, as pve2 did when a crash left its unit files empty.
    on "$P1" "systemctl mask mxfs-drbd@$RES >/dev/null 2>&1 && echo MASKED" 20 | grep -q MASKED \
        || die "could not mask mxfs-drbd@$RES on $P1"
    LEFT="$P1 has mxfs-drbd@$RES masked: systemctl unmask mxfs-drbd@$RES there"
    b1=$(boot_id "$P1")
    p1_off_survivor_recovers released-restart
    power_on_host "$P1"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not answer within ${BOOT_BUDGET}s of its power-on"
    s=$(wait_released "$P0" "$STEP_T0" "$RELEASE_BUDGET") || die "$P0 did not release $P1 within ${RELEASE_BUDGET}s of its answering with DRBD down"
    say "  $P0 released $P1 ${s}s after it answered with DRBD down; powering $P1 off again before it ever connects"
    b1=$(boot_id "$P1")
    power_off_host "$P1"
    s=$(wait_down "$P1" "$DOWN_BUDGET") || die "$P1 still answers ${DOWN_BUDGET}s after its power-off"
    survivor_reset_mounts_alone released-restart
    power_on_host "$P1"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not answer within ${BOOT_BUDGET}s of its power-on"
    on "$P1" "systemctl unmask mxfs-drbd@$RES >/dev/null 2>&1 && systemctl start --no-block mxfs-drbd@$RES && echo STARTED" 30 | grep -q STARTED \
        || die "could not unmask and start mxfs-drbd@$RES on $P1"
    LEFT=""
    s=$(wait_mounted "$P1" "$REJOIN_BUDGET") || die "$P1 did not mount again within ${REJOIN_BUDGET}s of its unit starting"
    say "  $P1 rejoined $s s after its unit started"
    collect released-restart "$STEP_T0"
    verify_sets released-restart
    check_set released-restart.alone "$P1" "$P0"
}

# answering-restart: participant 0 restarts while participant 1 is up and
# answering with no DRBD, as pve1 did at 09:46 on 2026-10-06 with pve2 on an
# install that had lost its DRBD units.  DRBD's record holds participant 1
# Outdated, so participant 0's boot program excludes it again and mounts
# alone, and the module's startup fence judges that exclusion until the mount
# completes.  pve1's guard released pve2 a minute into that mount (pve2
# answered), and the mount was refused at its 120 s bound.
step_answering_restart() {
    local b0 b1 t0 s out tm tr
    write_sets answering-restart; start_loads answering-restart
    sleep 10
    on "$P1" "systemctl mask mxfs-drbd@$RES >/dev/null 2>&1 && echo MASKED" 20 | grep -q MASKED \
        || die "could not mask mxfs-drbd@$RES on $P1"
    LEFT="$P1 has mxfs-drbd@$RES masked: systemctl unmask mxfs-drbd@$RES there, then start it"
    b1=$(boot_id "$P1")
    say "answering-restart: resetting $P1 (participant 1) under load on both; it comes back with no DRBD"
    t0=$(date +%s); reset_host "$P1"
    s=$(wait_recovered "$P0" "$t0" "$RECOVER_BUDGET") || die "$P0 did not recover $P1 within ${RECOVER_BUDGET}s of its reset"
    say "  $P0 recovered $P1 $s s after its reset"
    out=$(load_result "$P0")
    [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "the survivor's load saw an error: ${out:-no result}"
    say "  survivor $P0: $out"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not come back within ${BOOT_BUDGET}s of its reset"
    s=$(wait_released "$P0" "$t0" "$RELEASE_BUDGET") || die "$P0 did not release $P1 within ${RELEASE_BUDGET}s of its answering with DRBD down"
    say "  $P0 released $P1 ${s}s after it answered with DRBD down"
    write_set answering-restart.alone "$P0"
    b0=$(boot_id "$P0")
    say "  resetting $P0 (participant 0) with $P1 up and answering, DRBD down"
    reset_host "$P0"
    s=$(wait_rebooted "$P0" "$b0" "$BOOT_BUDGET") || die "$P0 did not come back within ${BOOT_BUDGET}s of its reset"
    s=$(wait_alone "$P0" "$ALONE_BUDGET") || die "$P0 did not mount alone within ${ALONE_BUDGET}s of answering ($P1 up, no DRBD)"
    say "  $P0 mounted alone $s s after answering"
    out=$(on "$P0" "journalctl -b --no-pager -o short-unix -t mxfs-drbd-fence | grep -a -E 'peer-outdated|is excluded \(episode|mounting as the survivor|: mounted /dev|holding .* out|released |failed \(rc=' | cut -c1-260" 30)
    echo "$out" > "$EVID/answering-restart.boot.$P0"
    sed 's/^/    /' <<<"$out" | tee -a "$EVID/log"
    tm=$(awk '/: mounted \/dev/ {print $1; exit}' <<<"$out")
    tr=$(awk '/released / {print $1; exit}' <<<"$out")
    [ -n "$tm" ] || die "$P0's journal does not show its boot program mounting"
    grep -q 'is excluded (episode' <<<"$out" || die "$P0 mounted alone without excluding $P1 at boot"
    if [ -n "$tr" ] && awk -v r="$tr" -v m="$tm" 'BEGIN { exit !(r < m) }'; then
        die "$P0's guard released $P1 before its own mount was done (released at $tr, mounted at $tm)"
    fi
    check_set answering-restart "$P0" "$P0"; check_set answering-restart "$P0" "$P1"; check_set answering-restart.alone "$P0" "$P0"
    check_writes answering-restart "$P0"
    say "  $P0 alone holds every fsynced file of both hosts, and its own since, and writes"
    on "$P1" "systemctl unmask mxfs-drbd@$RES >/dev/null 2>&1 && systemctl start --no-block mxfs-drbd@$RES && echo STARTED" 30 | grep -q STARTED \
        || die "could not unmask and start mxfs-drbd@$RES on $P1"
    LEFT=""
    s=$(wait_mounted "$P1" "$REJOIN_BUDGET") || die "$P1 did not mount again within ${REJOIN_BUDGET}s of its unit starting"
    say "  $P1 rejoined $s s after its unit started"
    collect answering-restart "$t0"
    verify_sets answering-restart
    check_set answering-restart.alone "$P1" "$P0"
}

step_stale_promotion() {
    local b1 s out
    write_sets stale-promotion; start_loads stale-promotion
    sleep 10
    b1=$(boot_id "$P1")
    p1_off_survivor_recovers stale-promotion
    write_set stale-promotion.alone "$P0"
    say "  stopping $P0's unit: it unmounts and steps down, so it is up, not Primary and unmounted"
    on "$P0" "systemctl stop mxfs-drbd@$RES && echo STOPPED" 200 | grep -q STOPPED || die "could not stop mxfs-drbd@$RES on $P0"
    LEFT="$P0's mxfs-drbd@$RES is stopped: systemctl start mxfs-drbd@$RES there"
    power_on_host "$P1"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not answer within ${BOOT_BUDGET}s of its power-on"
    # P1's replica lacks the set P0 wrote alone.  DRBD runs the fence-peer
    # handler for this promotion (a Consistent disk, the peer unknown); it
    # must not let a replica that may be stale become Primary.
    out=$(on "$P1" "echo DISK_BEFORE=\$(drbdadm dstate $RES); drbdadm primary $RES 2>&1 | tail -2; echo ROLE=\$(drbdadm role $RES) DISK=\$(drbdadm dstate $RES)" 120)
    echo "$out" > "$EVID/stale-promotion.$P1"
    if grep -q '^ROLE=Primary' <<<"$out"; then
        LEFT="$LEFT; $P1 was promoted on a stale replica: there drbdadm secondary $RES, remove /var/lib/mxfs/drbd-inhibit.$RES.json and nft table inet mxfs_fence_$RES, then drbdadm connect --discard-my-data $RES"
        die "$P1 was promoted on a stale replica by a plain drbdadm primary: $(tr '\n' ' ' <<<"$out")"
    fi
    on "$P1" "test -e /var/lib/mxfs/drbd-inhibit.$RES.json && echo HOLDS_INHIBIT" 10 | grep -q HOLDS_INHIBIT \
        && die "$P1 excluded $P0 for a promotion it refused"
    say "  a plain drbdadm primary on $P1's stale replica was refused: $(grep -E '^DISK_BEFORE=|^ROLE=' <<<"$out" | tr '\n' ' ')"
    on "$P0" "systemctl start --no-block mxfs-drbd@$RES && echo STARTED" 30 | grep -q STARTED || die "could not start mxfs-drbd@$RES on $P0"
    LEFT=""
    s=$(wait_mounted "$P0" "$OUTAGE_BUDGET") || die "the pair was not mounted again within ${OUTAGE_BUDGET}s of $P0's unit starting"
    say "  both mounted again $s s after $P0's unit started"
    collect stale-promotion "$STEP_T0"
    verify_sets stale-promotion
    check_set stale-promotion.alone "$P1" "$P0"
}

# Participant 0 unmounted and Secondary on a Connected link (its boot
# program's state just before it promotes) when the replication link fails on
# its side alone, ssh still up.  Participant 1 must lose the tie-break and
# restart, never carry on because its peer looks idle, and a plain drbdadm
# primary on participant 0 must be refused.  Then both mount again.
step_promotion_race() {
    local b1 s out tcut port bad=""
    write_sets promotion-race
    b1=$(boot_id "$P1")
    port=$(on "$P0" "drbdadm dump $RES 2>/dev/null | sed -n 's/.*address[[:space:]]*\(ipv4[[:space:]]*\)\{0,1\}$P0:\([0-9]*\);.*/\2/p' | head -1" 15)
    [ -n "$port" ] || die "no DRBD port for $P0 in resource $RES"
    out=$(on "$P0" "umount $MNT && drbdadm secondary $RES && echo \"P0_STATE \$(drbdadm role $RES) \$(drbdadm cstate $RES) \$(drbdadm dstate $RES)\"" 200)
    grep -q '^P0_STATE Secondary/Primary Connected UpToDate/UpToDate' <<<"$out" || die "$P0 is not Secondary on a Connected link: $out"
    LEFT="$P0 is unmounted and Secondary: systemctl restart mxfs-drbd@$RES there"
    tcut=$(on "$P1" "date +%s" 10)
    on "$P0" "nft add table inet pvefail_cut && nft add chain inet pvefail_cut in '{ type filter hook input priority -310; }' && nft add rule inet pvefail_cut in ip saddr $P1 tcp dport $port drop && nft add rule inet pvefail_cut in ip saddr $P1 tcp sport $port drop && echo CUT" 15 | grep -q CUT \
        || die "could not cut the replication link on $P0"
    LEFT="$LEFT; the link is cut on $P0: nft delete table inet pvefail_cut there"
    say "promotion-race: $P0 unmounted and Secondary; the replication link (port $port) cut on $P0 alone, ssh up"
    out=$(on "$P1" "for i in \$(seq 1 40); do r=\$(awk -v t=$tcut '\$1 >= t && / result=(TIEBREAK_LOST|EXCLUDED) / {print \$5}' /var/lib/mxfs/drbd-fence.$RES | tail -1); [ -n \"\$r\" ] && { echo \"P1_DECIDED \$r\"; exit 0; }; sleep 1; done; echo P1_UNDECIDED" 60)
    case "$out" in
        *"result=TIEBREAK_LOST"*) say "  $P1 lost the tie-break: its I/O froze, and it restarts because it was mounted" ;;
        *"result=EXCLUDED"*) bad="$bad; $P1 carried on: it excluded $P0, which only looked idle" ;;
        *) bad="$bad; $P1 recorded no decision within 40 s: $(tail -1 <<<"$out")" ;;
    esac
    out=$(on "$P0" "echo \"BEFORE \$(drbdadm cstate $RES) \$(drbdadm dstate $RES)\"; drbdadm primary $RES 2>&1 | tail -1; echo \"ROLE=\$(drbdadm role $RES) INHIBIT=\$(ls /var/lib/mxfs | grep -c inhibit)\"" 120)
    echo "$out" > "$EVID/promotion-race.$P0"
    if grep -q '^ROLE=Secondary' <<<"$out" && grep -q 'INHIBIT=0' <<<"$out"; then
        say "  a plain drbdadm primary on $P0 was refused, and it excluded nothing: $(grep -a '^BEFORE' <<<"$out")"
    else
        bad="$bad; $P0 was promoted with the link down: $(tr '\n' ' ' <<<"$out")"
    fi
    [ -z "$bad" ] || die "both hosts could win this split${bad} (DRBD may now be split: resolve by hand before anything else)"
    on "$P0" "nft delete table inet pvefail_cut && echo RESTORED" 15 | grep -q RESTORED || die "could not restore the link on $P0"
    s=$(wait_rebooted "$P1" "$b1" "$BOOT_BUDGET") || die "$P1 did not restart within ${BOOT_BUDGET}s"
    say "  $P1 restarted; the link is back; restarting $P0's unit"
    on "$P0" "systemctl restart --no-block mxfs-drbd@$RES && echo RESTARTED" 30 | grep -q RESTARTED || die "could not restart mxfs-drbd@$RES on $P0"
    LEFT=""
    s=$(wait_mounted "$P0" "$OUTAGE_BUDGET") || die "$P0 did not mount again within ${OUTAGE_BUDGET}s"
    s=$(wait_mounted "$P1" "$OUTAGE_BUDGET") || die "$P1 did not mount again within ${OUTAGE_BUDGET}s"
    say "  both mounted again"
    collect promotion-race "$tcut"
    verify_sets promotion-race
}

# withdraw <step> <host...>: those hosts' heartbeats stop past the authority
# lease under load on both.  Each must withdraw (its kernel log says so) and
# its guard rejoin it with no host restart; a host not paused must carry on
# with no I/O error and refuse nothing; both end mounted with every fsynced
# file intact.
withdraw() {
    local step=$1 h t0 s out
    local -A boot
    shift
    write_sets "$step"; start_loads "$step"
    sleep 10
    for h in "$P0" "$P1"; do boot[$h]=$(boot_id "$h"); done
    # The guard allows 3 rejoins an hour and keeps their times on disk, across
    # restarts; earlier steps and runs must not spend this step's.
    for h in "$@"; do on "$h" "rm -f /var/lib/mxfs/drbd-rejoin.$RES" 15 >/dev/null; done
    say "$step: pausing the MXFS heartbeat of $* for $(( WITHDRAW_PAUSE_MS / 1000 )) s under load on both, past the 30 s authority lease"
    t0=$(date +%s)
    for h in "$@"; do
        on "$h" "echo $WITHDRAW_PAUSE_MS > /sys/module/mxfs/parameters/dl_inject_hb_pause_ms && echo ARMED" 15 | grep -q ARMED \
            || die "could not pause $h's heartbeat"
    done
    LEFT="a withdrawn mount the guard did not rejoin stays down on $*: systemctl restart mxfs-drbd@$RES there"
    for h in "$@"; do
        s=$(wait_journal "$h" "$t0" "rejoined: " "$WITHDRAW_BUDGET") \
            || die "$h's guard did not rejoin its withdrawn mount within ${WITHDRAW_BUDGET}s of the pause"
        out=$(on "$h" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P-HB-INJECT-PAUSE|P290-AUTH-CLOSED|P290-AUTH-WITHDRAW|P131-SELF-FENCE' | sort | uniq -c | tr '\n' ' '" 30)
        grep -q -E 'P290-AUTH-WITHDRAW|P131-SELF-FENCE' <<<"$out" || die "$h rejoined, but its kernel log shows no withdrawal: ${out:-nothing}"
        say "  $h withdrew ($out) and its guard rejoined it: mounted again $s s after the pause"
    done
    for h in "$P0" "$P1"; do
        s=$(wait_mounted "$h" "$OUTAGE_BUDGET") || die "$h is not a full half of the pair again within ${OUTAGE_BUDGET}s"
        [ "$(boot_id "$h")" = "${boot[$h]}" ] || die "$h restarted: a withdrawn mount must rejoin without a host restart"
        case " $* " in *" $h "*) continue ;; esac
        out=$(load_result "$h")
        [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "$h, which did not withdraw, saw an I/O error: ${out:-no result}"
        say "  $h carried on: $out"
        out=$(on "$h" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P163-RECOVERY-COMPLETE|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
        grep -q P-RBLK <<<"$out" && die "$h refused operations as RECOVERY_BLOCKED: $out"
        say "  $h: ${out:-no recovery lines}"
    done
    LEFT=""
    say "  both mounted again, and neither host restarted"
    collect "$step" "$t0"
    verify_sets "$step"
}
step_withdraw_both() { withdraw withdraw-both "$P0" "$P1"; }
step_withdraw_p1() { withdraw withdraw-p1 "$P1"; }

# withdraw-held: participant 1 withdraws while a tmpfs mounted inside its
# mount holds it.  No process holds that, so nothing the rejoin stops or kills
# frees it, and the unmount answers busy every round: the rejoin's last resort,
# a restart of the host, is the only way back.  The restart must be the
# rejoin's own (its journal says so), not a watchdog's or this test's.
step_withdraw_held() {
    local b1 t0 s out
    write_sets withdraw-held; start_loads withdraw-held
    sleep 10
    b1=$(boot_id "$P1")
    on "$P1" "rm -f /var/lib/mxfs/drbd-rejoin.$RES" 15 >/dev/null
    on "$P1" "mkdir -p $MNT/pvefail/held && mount -t tmpfs -o size=1m mxfs-held $MNT/pvefail/held && echo HELD" 20 | grep -q HELD \
        || die "could not mount a tmpfs inside $P1's mount"
    LEFT="a tmpfs on $MNT/pvefail/held on $P1: umount it there"
    say "withdraw-held: a tmpfs inside $P1's mount holds it; pausing $P1's MXFS heartbeat for $(( WITHDRAW_PAUSE_MS / 1000 )) s under load on both"
    t0=$(date +%s)
    on "$P1" "echo $WITHDRAW_PAUSE_MS > /sys/module/mxfs/parameters/dl_inject_hb_pause_ms && echo ARMED" 15 | grep -q ARMED \
        || die "could not pause $P1's heartbeat"
    LEFT="$P1's withdrawn mount, held by a tmpfs on $MNT/pvefail/held: umount that, then systemctl restart mxfs-drbd@$RES there"
    s=$(wait_rebooted "$P1" "$b1" "$HELD_BUDGET") || die "$P1's rejoin did not restart the host within ${HELD_BUDGET}s of the pause"
    LEFT=""
    say "  $P1 restarted and answered again $s s after the pause"
    out=$(on "$P1" "journalctl -b -1 --no-pager -o cat -t mxfs-drbd-fence | grep -a -E 'umount of the shut-down|could not be unmounted|did not finish|restarting this host' | tail -4" 30)
    grep -q 'restarting this host' <<<"$out" || die "$P1 restarted, but its previous boot's journal does not show its rejoin restarting it: ${out:-nothing}"
    say "  $P1's rejoin before the restart: $(tr '\n' '|' <<<"$out" | cut -c1-400)"
    s=$(wait_mounted "$P1" "$REJOIN_BUDGET") || die "$P1 did not mount again within ${REJOIN_BUDGET}s of answering"
    say "  $P1 mounted again $s s after answering"
    out=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P163-RECOVERY-COMPLETE|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
    grep -q P163-RECOVERY-COMPLETE <<<"$out" || die "$P0 did not complete the recovery of $P1: ${out:-no recovery lines}"
    grep -q P-RBLK <<<"$out" && die "$P0 refused operations as RECOVERY_BLOCKED: $out"
    say "  $P0: $out"
    out=$(load_result "$P0")
    [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "$P0, which did not withdraw, saw an I/O error: ${out:-no result}"
    say "  $P0 carried on: $out"
    collect withdraw-held "$t0"
    verify_sets withdraw-held
}

# withdraw-guests: participant 1 withdraws while GUESTS VMs whose disks are on
# its mount run there, frozen (SIGSTOP), as a swapping host leaves them.  On
# pve1 (0.90.76, three 4 GiB build VMs on 11.7 GiB) the rejoin's `qm stop` of
# each in turn took 90, 90 and 74 s; participant 0, which can finish
# recovering participant 1's old incarnation only once that has stepped down,
# held the recovery blocked for 296 s and failed its own guests' writes.  The
# VMs boot nothing (an empty disk): only their QEMU holding the image open
# matters.  Participant 0 runs a second load that writes 64 KiB blocks at
# random into a sparse file, so its writes keep allocating -- the allocation
# group locks participant 1 mastered among them.
step_withdraw_guests() {
    local t0 s sd rc out i id ids="" b1 tr tu
    write_sets withdraw-guests; start_loads withdraw-guests
    for i in $(seq 1 "$GUESTS"); do
        out=$(on "$P1" "id=\$(pvesh get /cluster/nextid) && qm create \$id --name pvefail-g$i --memory 256 --cores 1 --scsihw virtio-scsi-single --scsi0 shared:1 --boot order=scsi0 >/dev/null && qm start \$id >/dev/null && kill -STOP \$(cat /var/run/qemu-server/\$id.pid) && echo \"GUEST \$id \$(cat /var/run/qemu-server/\$id.pid)\"" 120)
        id=$(sed -n 's/^GUEST \([0-9]*\) .*/\1/p' <<<"$out")
        [ -n "$id" ] || die "could not start and freeze test VM $i on $P1: $(tail -2 <<<"$out" | tr '\n' ' ')"
        ids="$ids $id"
        LEFT="test VMs$ids on $P1 (frozen or killed): there, for each, kill -9 its QEMU if running, then qm destroy <id> --purge 1"
    done
    say "  $P1 runs $GUESTS VMs on $MNT, frozen:$ids"
    out=$(on "$P0" "e=io_uring; fio --enghelp 2>/dev/null | grep -q io_uring || e=libaio
        rm -f $MNT/pvefail/thin.\$(hostname) /root/pvefail_thin.json
        nohup setsid fio --name=thin --filename=$MNT/pvefail/thin.\$(hostname) --size=8g --rw=randwrite --bs=64k --fallocate=none \
            --iodepth=4 --ioengine=\$e --direct=1 --time_based --runtime=$LOAD_S \
            --output-format=json --output=/root/pvefail_thin.json >/dev/null 2>/root/pvefail_thin.err < /dev/null &
        for i in \$(seq 1 30); do fuser $MNT/pvefail/thin.\$(hostname) >/dev/null 2>&1 && { echo THIN_UP; exit 0; }; sleep 1; done
        echo \"NO_THIN \$(tail -2 /root/pvefail_thin.err | tr '\n' ' ')\"" 60)
    grep -q THIN_UP <<<"$out" || die "no sparse-write load on $P0: $out"
    sleep 10
    on "$P1" "rm -f /var/lib/mxfs/drbd-rejoin.$RES" 15 >/dev/null
    b1=$(boot_id "$P1")
    say "withdraw-guests: pausing $P1's MXFS heartbeat for $(( WITHDRAW_PAUSE_MS / 1000 )) s under load on both"
    t0=$(date +%s)
    on "$P1" "echo $WITHDRAW_PAUSE_MS > /sys/module/mxfs/parameters/dl_inject_hb_pause_ms && echo ARMED" 15 | grep -q ARMED \
        || die "could not pause $P1's heartbeat"
    s=$(wait_journal "$P1" "$t0" "rejoined: " "$WITHDRAW_BUDGET")
    rc=$?
    out=$(on "$P1" "journalctl --no-pager -o short-unix -t mxfs-drbd-fence --since @$t0 | grep -a -E 'Rejoining|stopped VM|killed|processes that held|still hold|umount of the shut-down|unmounted the shut-down|restarting this host|rejoined: ' | cut -c1-240" 30)
    echo "$out" > "$EVID/withdraw-guests.rejoin.$P1"
    sed 's/^/    /' <<<"$out" | tee -a "$EVID/log"
    [ "$rc" = 0 ] || { collect withdraw-guests "$t0"; die "$P1's guard did not rejoin its withdrawn mount within ${WITHDRAW_BUDGET}s of the pause"; }
    say "  $P1 mounted again $s s after the pause"
    tr=$(awk '/Rejoining/ {print $1; exit}' <<<"$out"); tu=$(awk '/unmounted the shut-down/ {print $1; exit}' <<<"$out")
    [ -n "$tr" ] && [ -n "$tu" ] || die "$P1's journal does not show its rejoin starting and unmounting"
    sd=$(python3 -I -c 'import sys; print("%.1f" % (float(sys.argv[2]) - float(sys.argv[1])))' "$tr" "$tu")
    say "  $P1's rejoin: unmounted $sd s after it started"
    [ "$(boot_id "$P1")" = "$b1" ] || die "$P1 restarted: a withdrawn mount must rejoin without a host restart"
    out=$(on "$P0" "journalctl -k --no-pager -o short-unix --since @$t0 | grep -a -E 'P236-FENCE-CERTIFIED|P163-RECOVERY-COMPLETE|P238-FENCE-BLOCKED|P-RBLK-' | head -4 | cut -c1-200; journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P163-RECOVERY-COMPLETE|P238-FENCE-BLOCKED[A-Z-]*|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
    sed 's/^/    /' <<<"$out" | tee -a "$EVID/log"
    for h in "$P0" "$P1"; do
        s=$(wait_mounted "$h" "$OUTAGE_BUDGET") || die "$h is not a full half of the pair again within ${OUTAGE_BUDGET}s"
    done
    out=$(load_result "$P0")
    [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "$P0, which did not withdraw, saw an I/O error: ${out:-no result}"
    say "  $P0 carried on: $out"
    out=$(on "$P0" "for i in \$(seq 1 $((LOAD_S + 30))); do [ -s /root/pvefail_thin.json ] && break; sleep 1; done
        python3 -c 'import json; j=json.load(open(\"/root/pvefail_thin.json\"))[\"jobs\"][0]
print(\"THIN err=%d write_ios=%d lat_max_ms=%.0f\" % (j[\"error\"], j[\"write\"][\"total_ios\"], j[\"write\"][\"lat_ns\"][\"max\"] / 1e6))'; rm -f $MNT/pvefail/thin.\$(hostname)" $((LOAD_S + 60)) | grep '^THIN ')
    say "  $P0's sparse-file writer: ${out:-no result}"
    [ "$(sed -n 's/.*err=\([0-9]*\).*/\1/p' <<<"$out")" = 0 ] || die "$P0's sparse-file writer saw an I/O error: ${out:-no result}"
    out=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P163-RECOVERY-COMPLETE|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
    grep -q P163-RECOVERY-COMPLETE <<<"$out" || die "$P0 did not complete the recovery of $P1: ${out:-no recovery lines}"
    grep -q P-RBLK <<<"$out" && die "$P0 refused operations as RECOVERY_BLOCKED: $out"
    for id in $ids; do
        out=$(on "$P1" "qm status $id; qm destroy $id --purge 1 --destroy-unreferenced-disks 1 >/dev/null 2>&1; echo DESTROY_RC=\$?" 120)
        grep -q 'DESTROY_RC=0' <<<"$out" || die "could not destroy test VM $id on $P1: $(tr '\n' ' ' <<<"$out")"
    done
    LEFT=""
    collect withdraw-guests "$t0"
    verify_sets withdraw-guests
    awk -v s="$sd" -v b="$STEPDOWN_BUDGET" 'BEGIN { exit !(s <= b) }' \
        || die "$P1's rejoin took $sd s from its start to its unmount of the shut-down mount (budget ${STEPDOWN_BUDGET}s)"
}

STEPS=("$@")
[ "${#STEPS[@]}" -gt 0 ] || STEPS=(p1-crash reboot power-cut p0-crash)
for s in "${STEPS[@]}"; do
    case "$s" in
        p1-crash|p0-crash|power-cut|reboot|promotion-race|withdraw-both|withdraw-p1|withdraw-held|withdraw-guests|answering-restart) ;;
        survivor-restart|released-restart|stale-promotion)
            [ -n "${PVE_POWER_ON:-}" ] || { echo "$s keeps a host powered off: set PVE_POWER_ON to the command that powers one on"; exit 2; } ;;
        *) echo "unknown step: $s"; exit 2 ;;
    esac
done
say "pve pair failover: participant 0 $P0, participant 1 $P1; steps: ${STEPS[*]}; evidence $EVID"
for s in "${STEPS[@]}"; do
    need_pair_up
    say "== $s (build $BUILD)"
    "step_${s//-/_}"
    say "== $s passed"
done
say "pve pair failover: passed (${STEPS[*]})"
