#!/bin/bash
# pve_takeover_census.sh — what a survivor's lock requests meet on its dead
# peer's ledger pages while its takeover pass of them runs, and what that pass
# leaves behind, on a two-host Proxmox pair running MXFS on DRBD.
#
# The case: on the nested pair (2026-10-07) a survivor's mkdir waited 48 s
# "in transition" from inside its takeover pass of the dead peer's pages to
# 30 s past the pass's end, and failed with EAGAIN.  That pass had begun while
# the recovery completion was still publishing, skipped one page as "under
# judgement", and a page the pass skips is never visited by it again.
#
# Two probe trees of DIRS directories of FILES files: a/ written by participant
# 1 alone (it dies holding their locks exclusive), b/ written by participant 0
# and listed by participant 1 (it dies holding shared locks on directories
# participant 0 needs exclusive again).  Participant 0's takeover pass is slowed with
# the test knob dl_takeover_pause_ms (a sleep between two pages), participant 1
# is powered off and stays off, and once participant 0 has completed the
# recovery it makes a directory in every probe directory and stats every probe
# file while the pass crawls (tests/pve_takeover_probe.py).  Then the knob is
# cleared, the pass runs out, and the ledger is read from the platter for pages
# still under the dead incarnation (tools/tauth_page_auth.py).  Participant 1 is
# powered on and must rejoin.
#
# Fails when a probe operation fails or takes longer than OP_BUDGET_MS, or when
# a page is still under the dead incarnation once the pass has ended.
#
# Usage: tests/pve_takeover_census.sh
# Env:
#   PVE_PAIR       "<addr> <addr>" (default "192.168.120.137 192.168.120.192",
#                  the nested pair); participant 0 is the lower address
#   PVE_POWER_OFF / PVE_POWER_ON   as tests/pve_pair_failover.sh: {name} and
#                  {addr} are replaced (default: virsh destroy/start {name})
#   PAUSE_MS       the knob's sleep between two pages (default 500)
#   DIRS / FILES   the probe tree's shape (default 64 / 8)
#   OP_BUDGET_MS   the longest one probe operation may take (default 30000: a
#                  guest's own I/O timeout)
#
# Evidence: tests/evidence/pve_takeover_census/<UTC stamp>-<participant 0>/.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_takeover_census: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
PVE_POWER_OFF=${PVE_POWER_OFF:-virsh -c qemu:///system destroy {name}}
PVE_POWER_ON=${PVE_POWER_ON:-virsh -c qemu:///system start {name}}
PAUSE_MS=${PAUSE_MS:-500}
DIRS=${DIRS:-64}
FILES=${FILES:-8}
OP_BUDGET_MS=${OP_BUDGET_MS:-30000}
# From the power-off to the survivor's P163-RECOVERY-COMPLETE: DRBD's notice
# (~7 s), exclusion, witness, certificate and replay -- 13 s on the rig; twice
# that, rounded up (tests/pve_pair_failover.sh RECOVER_BUDGET).
RECOVER_BUDGET=60
# From the knob's clearing to the pass's end: the rest of the pass at its own
# pace, ~40 ms a page over a few hundred pages measured, with margin.
PASS_BUDGET=180
# From the power-on to the host mounted as half of the pair again: its boot
# (~60 s nested, 300 s budget on the physical pair) plus the rejoin (180 s).
REJOIN_BUDGET=480
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
EVID="$REPO/tests/evidence/pve_takeover_census/$STAMP-$P0"
mkdir -p "$EVID" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
# <host> <stdin file> <cmd> [timeout]: a program fed on stdin
on_in() {
    timeout "${4:-60}" "$SSHP" "$1" "$3" <"$2" 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
KNOB=/sys/module/mxfs/parameters/dl_takeover_pause_ms
clear_knob() { on "$P0" "echo 0 > $KNOB" 20 >/dev/null; }
# a failure after the power-off still powers participant 1 back on
P1_OFF=0
die() {
    say "FAIL: $*"; clear_knob
    if [ "$P1_OFF" = 1 ]; then
        timeout 120 bash -c "$ON_CMD" >>"$EVID/log" 2>&1 && say "  $P1 powered back on" || say "  LEFT: $P1 is powered off"
    fi
    exit 1
}
STATE_CMD='echo "unit=$(systemctl is-active mxfs-drbd@'"$RES"') mnt=$(awk '\''$2 == "'"$MNT"'" && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1) role=$(drbdadm role '"$RES"' 2>/dev/null) cs=$(drbdadm cstate '"$RES"' 2>/dev/null) ds=$(drbdadm dstate '"$RES"' 2>/dev/null) build=$(cat /sys/module/mxfs/srcversion 2>/dev/null)"'
state() { on "$1" "$STATE_CMD" 20 | grep '^unit='; }
pair_ok() {
    case "$1" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate "*) return 0 ;; esac
    return 1
}
hostcmd() {  # <template> <host>: {name} and {addr} replaced
    local c=${1//\{name\}/$(on "$2" hostname 10)}
    echo "${c//\{addr\}/$2}"
}
# census <dead node id>: the pages still under it, one AUTHPAGE line each
census() {
    on_in "$P0" "$REPO/tools/tauth_page_auth.py" "python3 -I - \$(drbdadm sh-dev $RES) --auth-node $1" 120 \
        | grep -E '^(AUTHPAGE|region) '
}

s0=$(state "$P0"); s1=$(state "$P1")
pair_ok "$s0" || die "$P0 is not up as half of the pair: ${s0:-no answer}"
pair_ok "$s1" || die "$P1 is not up as half of the pair: ${s1:-no answer}"
say "pair $P0 / $P1 on build ${s0##*build=}; pause ${PAUSE_MS} ms a page; probe tree ${DIRS}x${FILES}"
ON_CMD=$(hostcmd "$PVE_POWER_ON" "$P1"); OFF_CMD=$(hostcmd "$PVE_POWER_OFF" "$P1")

# 1. two probe trees.  a/: written by participant 1 alone, so it dies holding
# their locks exclusive.  b/: written by participant 0 and then listed by
# participant 1, so participant 1 dies holding shared locks on directories
# participant 0 created and needs exclusive again for a mkdir -- the shape of
# the mkdir that failed (the suite's set directory, made by participant 0 and
# looked up by participant 1).
TREE=$MNT/pvefail/census-$STAMP
MKTREE="mkdir -p \$t && cd \$t && for i in \$(seq 1 $DIRS); do mkdir d\$i && for j in \$(seq 1 $FILES); do echo \$i.\$j > d\$i/f\$j; done; done && sync -f . && find . -xdev | wc -l"
out=$(on "$P1" "t=$TREE/a; $MKTREE" 300)
[ "${out:-0}" -gt "$DIRS" ] 2>/dev/null || die "$P1 could not write the probe tree a: $out"
say "$P1 wrote $TREE/a ($out entries)"
out=$(on "$P0" "t=$TREE/b; $MKTREE" 300)
[ "${out:-0}" -gt "$DIRS" ] 2>/dev/null || die "$P0 could not write the probe tree b: $out"
out=$(on "$P1" "ls -lR $TREE/b | wc -l" 300)
[ "${out:-0}" -gt "$DIRS" ] 2>/dev/null || die "$P1 could not list the probe tree b: $out"
say "$P0 wrote $TREE/b and $P1 listed it ($out lines)"

# 2. the pass slowed on participant 0, then participant 1 powered off
on "$P0" "echo $PAUSE_MS > $KNOB && cat $KNOB" 20 | grep -qx "$PAUSE_MS" || die "could not set $KNOB on $P0"
t0=$(date +%s)
timeout 60 bash -c "$OFF_CMD" >>"$EVID/log" 2>&1 || die "could not power $P1 off: $OFF_CMD"
P1_OFF=1
say "$P1 powered off"
dead=""
while [ $(( $(date +%s) - t0 )) -lt "$RECOVER_BUDGET" ]; do
    dead=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | sed -n 's/.*P163-RECOVERY-COMPLETE slot=[0-9]* node=\([0-9]*\) .*/\1/p' | tail -1" 30)
    [ -n "$dead" ] && break
    sleep 2
done
[ -n "$dead" ] || die "$P0 did not complete the recovery of $P1 within ${RECOVER_BUDGET}s"
say "$P0 recovered $P1 (node $dead) $(( $(date +%s) - t0 )) s after its power-off"

# 3. the probe, while the pass crawls
during=$(census "$dead")
say "during the pass: $(grep -c '^AUTHPAGE' <<<"$during") pages under the dead incarnation ($(grep '^region' <<<"$during"))"
fails=0; worst=0; summary=""
for tr in a b; do
    probe=$(on_in "$P0" "$REPO/tests/pve_takeover_probe.py" "python3 -I - $TREE/$tr census.\$(hostname)" 900)
    echo "$probe" > "$EVID/probe-$tr.$P0"
    grep '^OP ' <<<"$probe" | head -20 | sed 's/^/  /' | tee -a "$EVID/log"
    s=$(grep '^SUMMARY ' <<<"$probe")
    say "probe of $tr/ on $P0: ${s:-no summary}"
    [ -n "$s" ] || die "the probe of $tr/ printed no summary"
    fails=$(( fails + $(sed -n 's/.*failures=\([0-9]*\).*/\1/p' <<<"$s") ))
    w=$(sed -n 's/.*worst_ms=\([0-9]*\).*/\1/p' <<<"$s")
    [ "$w" -gt "$worst" ] && worst=$w
    summary="$summary $tr:{$s}"
done
mid=$(census "$dead")
say "after the probe: $(grep -c '^AUTHPAGE' <<<"$mid") pages under the dead incarnation"

# 4. the pass runs out
clear_knob
t1=$(date +%s); ended=""
while [ $(( $(date +%s) - t1 )) -lt "$PASS_BUDGET" ]; do
    ended=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | grep -a 'P-DEPART-WORK-RECOVERY-TAKEOVER node=$dead ' | tail -1" 30)
    [ -n "$ended" ] && break
    sleep 3
done
[ -n "$ended" ] || say "  the pass did not end within ${PASS_BUDGET}s of the knob's clearing"
say "pass: $(sed 's/.*\(queued_ms=[0-9]* total_ms=[0-9]*\).*/\1/' <<<"${ended:-none}")"
after=$(census "$dead")
echo "$after" > "$EVID/census-after.$P0"
left=$(grep -c '^AUTHPAGE' <<<"$after")
say "after the pass: $left pages under the dead incarnation"
grep '^AUTHPAGE' <<<"$after" | head -10 | sed 's/^/  /' | tee -a "$EVID/log"
on "$P0" "journalctl -k --no-pager -o short-monotonic --since @$t0 | grep -a mxfs | cut -c1-500" 120 > "$EVID/klog.$P0"
say "$P0 lines: $(grep -aoE 'P-TAUTH-TAKEOVER-UNDER-JUDGEMENT|P960-AUTH-TRANSITION-[A-Z]+|P960-STALLED-PAGE|P-TAUTH-TAKEOVER-NOTACTIVE|P-TAUTH-PAGE-PARKED|P958-[A-Z-]+' "$EVID/klog.$P0" | sort | uniq -c | tr '\n' ' ')"

# 5. participant 1 back
timeout 120 bash -c "$ON_CMD" >>"$EVID/log" 2>&1 || die "could not power $P1 on: $ON_CMD"
P1_OFF=0
t2=$(date +%s)
while :; do
    s1=$(state "$P1")
    pair_ok "$s1" && break
    [ $(( $(date +%s) - t2 )) -lt "$REJOIN_BUDGET" ] || die "$P1 not mounted as half of the pair ${REJOIN_BUDGET}s after its power-on: ${s1:-no answer}"
    sleep 5
done
say "$P1 rejoined $(( $(date +%s) - t2 )) s after its power-on"

# verdict
[ "$fails" = 0 ] || die "$fails probe operations failed on $P0 during the pass"
[ "$worst" -le "$OP_BUDGET_MS" ] || die "one probe operation took $worst ms (budget $OP_BUDGET_MS)"
[ "$left" = 0 ] || die "$left pages are still under the dead incarnation $dead after the pass ended"
say "PASS"
