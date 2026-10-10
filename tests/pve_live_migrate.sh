#!/bin/bash
# pve_live_migrate.sh — live-migrate a running guest whose disk is on the
# shared MXFS storage back and forth between the two hosts of a Proxmox pair,
# with the guest writing throughout, and prove every byte it wrote survives
# every move.
#
# Live migration is what a dual-primary pair is for: both hosts have the
# guest's disk image open across the switchover (the source QEMU until it
# hands over, the target QEMU from then on), and with a sparse raw image the
# guest's first writes into a region allocate it on whichever host it is
# running on.  So each lap checks that what one host allocated and wrote is
# what the other reads.
#
# What it does:
#   1. A full clone of SRC_VMID (an installed guest with the QEMU agent, e.g.
#      a parked build VM) onto storage SHARED as raw, VMID, name mxfs-migr;
#      the source VM is only read.
#      The clone is read back on both hosts and must hash like the source.
#   2. Starts it and waits for its agent, its address and ssh (the agent
#      refuses guest-exec, so the guest is driven over ssh as root with the
#      lab nodes' password).  In the guest a writer loops over
#      MAXF files of WRITE_MB MiB each from /dev/urandom, fsyncs each and
#      records its sha256 beside it; it pauses between files on request.
#   3. LAPS online migrations, alternating hosts.  After each: the guest's
#      agent answers, the writer is paused, the guest drops its page cache
#      and every file with a recorded sum is read back from the disk and
#      checked, then the writer resumes.
#   4. Both hosts' kernel logs since the start, and the guest's, searched for
#      I/O errors, hung tasks, warnings, withdrawals and shutdowns.
#   5. The clone stopped and destroyed with its disk (KEEP=1 keeps it).
#
# PASS needs every migration to succeed within MIG_BUDGET, every check to
# verify every file, the writer to have completed files on both hosts, and
# no bad kernel line on either host or in the guest.
#
# Usage: tests/pve_live_migrate.sh
# Env:
#   PVE_PAIR    "<addr> <addr>" (default the physical pair)
#   SRC_VMID    installed guest to clone (default 100)
#   VMID        the clone's id (default 9100); an existing VM of that id is
#               reused only if this script created it (its description says so)
#   SHARED      storage for the clone's disk (default shared)
#   CPU         the clone's CPU model (default x86-64-v2: both hosts run it)
#   LAPS        migrations (default 6)
#   WRITE_MB    MiB per guest file (default 64)   MAXF  files before reuse (default 32)
#   SETTLE_S    seconds the writer runs between migrations (default 20)
#   IDLE_LAPS   laps (numbers) migrated with the writer paused, e.g. "2 4 6":
#               their downtime is the switchover's own, without the guest's
#               writes in flight to drain (default none)
#   MIG_BUDGET  seconds per migration (default 80: a 4 GiB guest's memory at
#               gigabit line rate is ~37 s, twice that, plus the measured ~5 s
#               of qm's own setup)
#   CLONE_BUDGET seconds for the clone (default 400: ~3.2 GiB allocated in the
#               source image, written through DRBD at the ~17-35 MB/s a lone
#               writer gets on this pair, twice that)
#   BOOT_BUDGET seconds from start to the agent answering (default 240)
#   EVID        evidence directory (default tests/evidence/pve_live_migrate/<stamp>)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_live_migrate: PVE_PAIR must name two hosts"; exit 2; }
SRC_VMID=${SRC_VMID:-100}
VMID=${VMID:-9100}
SHARED=${SHARED:-shared}
LAPS=${LAPS:-6}
WRITE_MB=${WRITE_MB:-64}
MAXF=${MAXF:-32}
SETTLE_S=${SETTLE_S:-20}
IDLE_LAPS=${IDLE_LAPS:-}
MIG_BUDGET=${MIG_BUDGET:-80}
CLONE_BUDGET=${CLONE_BUDGET:-400}
BOOT_BUDGET=${BOOT_BUDGET:-240}
# The clone's CPU model.  A build VM is `cpu: host`, which migrates only
# between identical CPUs: from the physical pair's i3-8100 to its W3520 the
# target QEMU died at resume ("kvm: Putting registers after init: Failed to
# set special registers: Invalid argument").  x86-64-v2 is what both run;
# Proxmox's default x86-64-v2-AES does not start on the W3520 (no AES-NI).
CPU=${CPU:-x86-64-v2}
TAG="mxfs live-migrate test clone (tests/pve_live_migrate.sh)"
EVID=${EVID:-$REPO/tests/evidence/pve_live_migrate/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$EVID"
LOG=$EVID/log
bad=0

on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { say "FAIL: $*"; bad=1; }
whole() {
    on "$1" "grep -q ' /mnt/shared mxfs ' /proc/mounts && [ \"\$(drbdadm role mxfs)\" = Primary/Primary ] && [ \"\$(drbdadm cstate mxfs)\" = Connected ] && [ \"\$(drbdadm dstate mxfs)\" = UpToDate/UpToDate ] && echo WHOLE" 20 | grep -q WHOLE
}
# node name <-> address
declare -A ADDR
for h in "${PAIR[@]}"; do
    n=$(on "$h" "hostname" 20 | tail -1)
    [ -n "$n" ] || { say "FAIL: $h did not answer"; exit 1; }
    ADDR[$n]=$h
done
node_of() {  # the node VMID's config is on, or empty
    on "${PAIR[0]}" "pvesh get /cluster/resources --type vm --output-format json" 30 |
        python3 -I -c 'import json,sys; v=[r for r in json.load(sys.stdin) if r.get("vmid")==int(sys.argv[1])]; print(v[0]["node"] if v else "")' "$1"
}
# run a shell command in the guest over ssh (the build's guest has root
# password login with the lab nodes' password; its QEMU agent refuses
# guest-exec), print its stdout, return its exit code.  The first argument,
# the host the guest runs on, is not needed: the guest keeps its address
# across a migration.
GIP=
gexec() {  # <host> <cmd> [timeout]
    on "$GIP" "$2" "${3:-60}"
}
guest_ip() {  # <host>: the guest's first IPv4 address on a non-loopback interface
    on "$1" "qm agent $VMID network-get-interfaces" 30 |
        python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(1)
for i in d:
    if i.get("name") == "lo":
        continue
    for a in i.get("ip-addresses", []):
        if a.get("ip-address-type") == "ipv4":
            print(a["ip-address"]); sys.exit(0)
sys.exit(1)'
}

for h in "${PAIR[@]}"; do
    whole "$h" || { say "FAIL: $h is not whole; not starting"; exit 1; }
    on "$h" "date +%s" 20 > "$EVID/t0-$h"
    on "$h" "cat /sys/module/mxfs/srcversion /sys/module/mxfs/version" 20 | tr '\n' ' ' | sed "s/^/$h build: /" | tee -a "$LOG"; echo >> "$LOG"
done

# 1. the clone
cur=$(node_of "$VMID")
if [ -n "$cur" ]; then
    desc=$(on "${ADDR[$cur]}" "qm config $VMID | sed -n 's/^description: //p'" 30)
    [[ "$desc" == *"pve_live_migrate"* ]] ||
        { say "FAIL: VM $VMID exists and was not made by this script ($desc); not touching it"; exit 1; }
    say "VM $VMID left by an earlier run on $cur: stopping and destroying it"
    on "${ADDR[$cur]}" "qm stop $VMID --skiplock 1 >/dev/null 2>&1; qm destroy $VMID --purge 1" 300 | tail -2 | tee -a "$LOG"
fi
src=$(node_of "$SRC_VMID")
[ -n "$src" ] && [ -n "${ADDR[$src]:-}" ] || { say "FAIL: source VM $SRC_VMID is on no node of the pair"; exit 1; }
on "${ADDR[$src]}" "qm status $SRC_VMID" 20 | grep -q 'status: stopped' || { say "FAIL: source VM $SRC_VMID is not stopped; a clone of a running guest is not consistent"; exit 1; }
say "cloning $SRC_VMID on $src to $VMID on storage $SHARED"
t=$(date +%s)
on "${ADDR[$src]}" "qm clone $SRC_VMID $VMID --full 1 --storage $SHARED --format raw --name mxfs-migr && qm set $VMID --description '$TAG' --onboot 0 --cpu $CPU >/dev/null && echo CLONED" "$CLONE_BUDGET" > "$EVID/clone.txt" 2>&1
clone_s=$(( $(date +%s) - t ))
grep -q CLONED "$EVID/clone.txt" || { say "FAIL: clone failed or exceeded ${CLONE_BUDGET}s after ${clone_s}s: $(tail -3 "$EVID/clone.txt" | tr '\n' ' ')"; exit 1; }
say "clone: ${clone_s}s; disk $(on "${ADDR[$src]}" "qm config $VMID | grep -E '^(virtio|scsi|sata|ide)[0-9]+:'" 20)"
# The clone, read on each host, must equal the source image: what one host
# wrote through MXFS is what both read.  Both raw files are 16 GiB, mostly
# holes; ~3.2 GiB allocated reads in under a minute on either host.
src_path=$(on "${ADDR[$src]}" "pvesm path \$(qm config $SRC_VMID | sed -n 's/^virtio0: \([^,]*\).*/\1/p')" 30)
dst_path=$(on "${ADDR[$src]}" "pvesm path \$(qm config $VMID | sed -n 's/^virtio0: \([^,]*\).*/\1/p')" 30)
declare -A SUM
for h in "${PAIR[@]}" src; do
    if [ "$h" = src ]; then t=${ADDR[$src]}; f=$src_path; else t=$h; f=$dst_path; fi
    ( on "$t" "sha256sum $f" 300 | awk '{print $1}' > "$EVID/sum-$h" ) &
done
wait
for h in "${PAIR[@]}" src; do SUM[$h]=$(cat "$EVID/sum-$h"); done
say "image sums: source on $src ${SUM[src]:0:16}; clone on ${PAIR[0]} ${SUM[${PAIR[0]}]:0:16}, on ${PAIR[1]} ${SUM[${PAIR[1]}]:0:16}"
for h in "${PAIR[@]}"; do
    [ -n "${SUM[src]}" ] && [ "${SUM[$h]}" = "${SUM[src]}" ] || fail "the clone read on $h does not match the source image"
done
[ "$bad" = 0 ] || exit 1

cleanup() {
    [ "${KEEP:-0}" = 1 ] && { say "KEEP=1: leaving VM $VMID"; return; }
    local n; n=$(node_of "$VMID")
    [ -n "$n" ] || return
    on "${ADDR[$n]}" "qm stop $VMID >/dev/null 2>&1; qm destroy $VMID --purge 1 >/dev/null 2>&1; echo DESTROY_RC=\$?" 300 | tail -1 | sed "s/^/VM $VMID on $n: /" | tee -a "$LOG"
}
trap cleanup EXIT

# 2. boot and the writer
host=${ADDR[$src]}
on "$host" "qm start $VMID" 120 | tee -a "$LOG"
t=$(date +%s)
until on "$host" "qm agent $VMID ping && echo PONG" 20 | grep -q PONG; do
    [ $(( $(date +%s) - t )) -lt "$BOOT_BUDGET" ] || { fail "the guest's agent did not answer within ${BOOT_BUDGET}s"; exit 1; }
    sleep 5
done
until GIP=$(guest_ip "$host") && [ -n "$GIP" ] && gexec "$host" 'true' 20; do
    [ $(( $(date +%s) - t )) -lt "$BOOT_BUDGET" ] || { fail "the guest did not answer over ssh within ${BOOT_BUDGET}s (address ${GIP:-none})"; exit 1; }
    sleep 5
done
say "guest up after $(( $(date +%s) - t ))s at $GIP: $(gexec "$host" 'uname -r; df -h / | tail -1' 30 | tr '\n' ' ')"
WRITER='mkdir -p /root/mig && cd /root/mig && rm -f stop stopped pause paused f*.tmp && n=0
while [ ! -e stop ]; do
  if [ -e pause ]; then : > paused; sleep 0.2; continue; fi
  rm -f paused
  n=$((n+1)); i=$(( (n-1) % '"$MAXF"' + 1 ))
  rm -f f$i.sha
  dd if=/dev/urandom of=f$i bs=1M count='"$WRITE_MB"' conv=fsync status=none || { echo "write f$i failed" >> errors; sleep 1; continue; }
  sha256sum f$i > f$i.sha.tmp && sync f$i.sha.tmp && mv f$i.sha.tmp f$i.sha && sync
  echo "$n $(date +%s) $(cat /proc/sys/kernel/hostname)" > count
done
: > stopped'
gexec "$host" "printf '%s\n' $(printf '%q' "$WRITER") > /root/mig-writer.sh && setsid nohup bash /root/mig-writer.sh > /root/mig-writer.out 2>&1 < /dev/null & echo WRITER_STARTED" 30 | grep -q WRITER_STARTED || { fail "the writer did not start"; exit 1; }

verify() {  # <host> <label> [stopped: the writer has exited, do not pause it]
    local out rc
    if [ "${3:-}" = stopped ]; then
        gexec "$1" 'cd /root/mig && for k in $(seq 1 600); do [ -e stopped ] && break; sleep 0.2; done; [ -e stopped ] || { echo NOT_STOPPED; exit 3; }' 150 > /dev/null || { fail "$2: the writer did not stop"; return; }
    else
        gexec "$1" 'cd /root/mig && touch pause; for k in $(seq 1 600); do [ -e paused ] && break; sleep 0.2; done; [ -e paused ] || { echo NOT_PAUSED; exit 3; }' 150 > /dev/null || { fail "$2: the writer did not pause"; return; }
    fi
    out=$(gexec "$1" 'cd /root/mig && sync && echo 3 > /proc/sys/vm/drop_caches && n=$(ls f*.sha 2>/dev/null | wc -l) && res=$(cat f*.sha | sha256sum -c 2>&1); ok=$(grep -c ": OK$" <<<"$res"); bad=$(grep -v ": OK$" <<<"$res"); echo "files=$n ok=$ok count=$(cat count) errors=$(cat errors 2>/dev/null | wc -l)"; [ -z "$bad" ] || echo "BAD: $bad"; [ "$n" = "$ok" ] && [ -z "$bad" ]' 600)
    rc=$?
    say "  $2 verify: $(echo "$out" | head -5 | tr '\n' ' ')"
    [ "$rc" = 0 ] || fail "$2: the guest's files did not all verify (rc=$rc)"
    gexec "$1" 'rm -f /root/mig/pause' 30 > /dev/null
}

sleep "$SETTLE_S"
verify "$host" "before the first migration"
hosts_written=" $src "

# 3. the laps
for lap in $(seq 1 "$LAPS"); do
    curn=$(node_of "$VMID")
    for n in "${!ADDR[@]}"; do [ "$n" != "$curn" ] && tgt=$n; done
    idle=0
    if [[ " $IDLE_LAPS " == *" $lap "* ]]; then
        idle=1
        gexec "${ADDR[$curn]}" 'cd /root/mig && touch pause; for k in $(seq 1 600); do [ -e paused ] && break; sleep 0.2; done; [ -e paused ]' 150 > /dev/null ||
            fail "lap $lap: the writer did not pause for an idle migration"
    fi
    say "lap $lap: $curn -> $tgt$([ "$idle" = 1 ] && echo ' (writer paused)')"
    t=$(date +%s)
    on "${ADDR[$curn]}" "qm migrate $VMID $tgt --online 1" "$MIG_BUDGET" > "$EVID/migrate-$lap.txt" 2>&1
    rc=$?
    wall=$(( $(date +%s) - t ))
    downtime=$(grep -aoiE 'downtime[: ]+[0-9.]+ ?ms' "$EVID/migrate-$lap.txt" | tail -1)
    speed=$(grep -aoE 'average migration speed: [^-]+' "$EVID/migrate-$lap.txt" | tail -1)
    xfer=$(grep -aoE 'transferred [0-9.]+ [KMG]iB of [0-9.]+ [KMG]iB' "$EVID/migrate-$lap.txt" | tail -1)
    say "  rc=$rc wall=${wall}s ${downtime:-downtime ?} ${speed:-} ${xfer:-}"
    [ "$rc" = 0 ] && grep -aq 'migration finished successfully' "$EVID/migrate-$lap.txt" || { fail "lap $lap: migration failed (rc=$rc): $(tail -3 "$EVID/migrate-$lap.txt" | tr '\n' ' ')"; break; }
    [ "$wall" -le "$MIG_BUDGET" ] || fail "lap $lap: migration took ${wall}s, over its ${MIG_BUDGET}s budget"
    [ "$(node_of "$VMID")" = "$tgt" ] || { fail "lap $lap: the VM is not on $tgt after the migration"; break; }
    host=${ADDR[$tgt]}
    on "$host" "qm agent $VMID ping && echo PONG" 30 | grep -q PONG || { fail "lap $lap: the guest's agent does not answer on $tgt"; break; }
    [ "$idle" = 1 ] && gexec "$host" 'rm -f /root/mig/pause' 30 > /dev/null
    sleep "$SETTLE_S"
    verify "$host" "lap $lap on $tgt"
    hn=$(gexec "$host" 'cat /root/mig/count' 20 | awk '{print $1}')
    say "  writer at file $hn"
    hosts_written+="$tgt "
done

# 4. stop the writer, final check, the logs
gexec "$host" 'touch /root/mig/stop' 20 > /dev/null
verify "$host" "final" stopped
gexec "$host" 'dmesg' 60 > "$EVID/guest-dmesg.txt"
gbad=$(grep -aiE 'I/O error|blk_update_request|buffer I/O|EXT4-fs error|XFS .*(error|corrupt|Shutting down)|blocked for more than|Call Trace' "$EVID/guest-dmesg.txt")
[ -z "$gbad" ] || { fail "the guest logged: $(head -3 <<<"$gbad" | tr '\n' ' ')"; }
say "guest dmesg: $(wc -l < "$EVID/guest-dmesg.txt") lines, bad=$(grep -c . <<<"$gbad")"
for h in "${PAIR[@]}"; do
    since=$(cat "$EVID/t0-$h")
    on "$h" "journalctl -k --since @$since --no-pager -o short-monotonic" 60 > "$EVID/kmsg-$h.txt"
    hbad=$(grep -aE 'I/O error|blocked for more than|WARNING:|BUG:|Oops|Shutting down filesystem|P-WITHDRAW|RECOVERY_BLOCKED|self-fence|corrupt' "$EVID/kmsg-$h.txt")
    say "$h kernel log: $(wc -l < "$EVID/kmsg-$h.txt") lines, mxfs $(grep -ac mxfs "$EVID/kmsg-$h.txt"), bad=$(grep -c . <<<"$hbad")"
    [ -z "$hbad" ] || fail "$h logged: $(head -3 <<<"$hbad" | tr '\n' ' ')"
    whole "$h" || fail "$h is not whole at the end"
done
for n in "${!ADDR[@]}"; do
    [[ "$hosts_written" == *" $n "* ]] || fail "the guest never ran on $n"
done
[ "$bad" = 0 ] && say "RESULT: PASS (evidence $EVID)" || say "RESULT: FAIL (evidence $EVID)"
exit "$bad"
