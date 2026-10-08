#!/bin/bash
# pve_cluster_write_authority.sh — when both hosts of an MXFS-on-DRBD pair
# write the same dinode at once, under which authority did each write it?
#
# DRBD 8.4 (two primaries) logs "Concurrent writes detected: local=<s>s +<n>,
# remote=<s>s +<n>" on both hosts when their in-flight writes overlap.  A
# holder's write of a block must complete before its grant moves, so for a
# coordinated filesystem the line can never appear; on the nested pair it did,
# for dinodes, under tests/pve_churn_fairness.sh run beside tests/pve_pair_profile.sh
# (D-DRBD-BOTH-HOSTS-WRITE-ONE-DINODE-AT-ONCE-AND-DRBD-DROPS-THE-LINK).
#
# pal/linux/xfs_buf.c's inode-cluster write already has a probe for each way a
# slot can be published without a write tenure: P219-LOGGED-NO-AUTHORITY (a
# logged or buffer-logged slot written with no EX, no release token and no
# demoter, or staged under a tenure that has since ended), P-FREEPUB-WRITE (a
# freed inode's FREE image published under its claim) and P218-CLUSTER-PASSENGER
# (an unlogged slot held only in PR, not in core, or whose buffer image is a
# different incarnation from the in-core one -- genmm=1 -- with skipped= saying
# whether it went out).  They are dynamic debug sites, off by default; the
# passenger line is ratelimited, so the counter dump is the total.  Beside them
# the module keeps a record of every inode slot a cluster write sends to the
# device (mxfs.slot_ring, read from /proc/fs/mxfs/slot_ring): the slot's
# sector, the image's inode, generation, mode and change count, the class it
# went out under (logged, buffer-logged, whole-buffer write, in core) and the
# in-core inode's lock mode, generation and flags, with the writer's comm.  It
# prints nothing on the write path, so no line is dropped.  This harness:
#
#  1. turns those sites on on both hosts (and the counter dump's own lines),
#     records the counters (mxfs.cluster_authority_dump) and turns the slot
#     record on;
#  2. runs the churn, by default with the function profiler on both hosts as
#     the recipe that first produced the conflicts (PROFILE=0 runs it alone),
#     while it takes each host's new slot records every second into
#     ring.<host>: participant 1 restarts itself seconds after a conflict, and
#     what was taken before that survives the restart;
#  3. records the counters again, saves each host's kernel lines of the window
#     (DRBD conflicts and state, the probes above, P34H incarnation poison,
#     release-drain stalls), and turns the sites and the record off again.
#
# Output: per host, the conflict lines with each sector mapped to its inode
# number, the probe lines for the same inode numbers, the counter deltas, and
# for each conflict the slot records of both writes it names: each host's last
# write of each conflicting sector at or before the conflict.  It grades
# nothing; it is an instrument.  A host that restarts itself in the window
# (participant 1 after a dropped link) has its kernel lines read from its
# previous boot.
#
# Usage: tests/pve_cluster_write_authority.sh
# Env:
#   PVE_PAIR  "<addr> <addr>" (default "192.168.120.137 192.168.120.192", the
#             nested pair)
#   PROFILE   1 (default) profile both hosts during the churn; 0 = churn alone
#   CHURN, WORK_S  passed to tests/pve_churn_fairness.sh
#   ROUNDS    churn runs back to back in one window (default 1).  A number
#             freed at one run's start was used in the run before, so a write
#             of it that outlives its free spans two runs; with ROUNDS>1 the
#             slot record covers both.  (The profiler covers at most 130 s.)
#
# A P-DIALLOC-DISKLIVE line (an allocator found a free number's home holding a
# live dinode) is listed with the probes, and the report then prints every slot
# record of that number from both hosts in time order: which host last wrote
# the live image the allocator found, and whether it did so after the free.
#
# Evidence: tests/evidence/pve_cluster_write_authority/<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PAIR_S=${PVE_PAIR:-192.168.120.137 192.168.120.192}
read -r -a PAIR <<<"$PAIR_S"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_cluster_write_authority: PVE_PAIR must name two hosts"; exit 2; }
PROFILE=${PROFILE:-1}
ROUNDS=${ROUNDS:-1}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_cluster_write_authority/$STAMP"
mkdir -p "$EVID" || exit 1
FORMATS="P219-LOGGED-NO-AUTHORITY P-FREEPUB-WRITE P218-CLUSTER-PASSENGER P218-CLUSTER-AUTHORITY-TOTAL P219-LOGGED-AUTHORITY-TOTAL"

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
sites() {  # <host> <+p|-p>
    local f cmd=""
    for f in $FORMATS; do
        cmd="$cmd echo 'module mxfs format \"$f\" $2' > /proc/dynamic_debug/control;"
    done
    on "$1" "$cmd echo SITES_DONE" 30 | grep -q SITES_DONE
}
counters() {  # <host> <label>: the dump's two lines, with a boot id and uptime
    on "$1" "echo 1 > /sys/module/mxfs/parameters/cluster_authority_dump; sleep 1; echo BOOT=\$(cat /proc/sys/kernel/random/boot_id) UP=\$(cut -d' ' -f1 /proc/uptime); journalctl -k -n 200 --no-pager -o cat | grep -aE 'P218-CLUSTER-SKIP|P218-CLUSTER-AUTHORITY-TOTAL|P219-LOGGED-AUTHORITY-TOTAL' | tail -3" 30 > "$EVID/counters.$2.$1"
}
# The slot record: on, then the number of the last record already there, so
# the takes start after it.
ring_start() {  # <host>
    on "$1" "echo 1 > /sys/module/mxfs/parameters/slot_ring && echo 18446744073709551615 > /sys/module/mxfs/parameters/slot_ring_since && head -1 /proc/fs/mxfs/slot_ring" 20 \
        | sed -n 's/^next=\([0-9]*\) .*/\1/p'
}
# ring_take <host> <since>: the host's records numbered above <since>, appended
# to ring.<host>; prints the number of the last one taken (nothing on failure)
ring_take() {
    local out last
    out=$(on "$1" "echo $2 > /sys/module/mxfs/parameters/slot_ring_since && cat /proc/fs/mxfs/slot_ring" 20) || return 1
    grep -a '^seq=' <<<"$out" >> "$EVID/ring.$1"
    last=$(grep -a '^seq=' <<<"$out" | tail -1 | sed -n 's/^seq=\([0-9]*\) .*/\1/p')
    echo "${last:-$2}"
}
# ring_poll <host> <since>: a take every second until ring.stop appears
ring_poll() {
    local h=$1 last=$2 n
    while [ ! -e "$EVID/ring.stop" ]; do
        n=$(ring_take "$h" "$last") && [ -n "$n" ] && last=$n
        sleep 1
    done
    echo "$last" > "$EVID/ring.last.$h"
}

for h in "${PAIR[@]}"; do
    s=$(on "$h" "echo \"name=\$(hostname) build=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) role=\$(drbdadm role mxfs 2>/dev/null) cs=\$(drbdadm cstate mxfs 2>/dev/null) boot=\$(cat /proc/sys/kernel/random/boot_id)\"" 20)
    say "$h: $s"
    case "$s" in *"role=Primary/Primary cs=Connected"*) ;; *) say "ABORT: $h is not a connected Primary"; exit 1 ;; esac
    echo "$s" > "$EVID/host.$h"
    sites "$h" +p || { say "ABORT: could not turn the probe sites on on $h"; exit 1; }
    counters "$h" before
done
declare -A RING0 POLLER
for h in "${PAIR[@]}"; do
    RING0[$h]=$(ring_start "$h")
    [ -n "${RING0[$h]}" ] || { say "ABORT: could not turn the slot record on on $h (a build without mxfs.slot_ring?)"; exit 1; }
    : > "$EVID/ring.$h"
done
for h in "${PAIR[@]}"; do
    ring_poll "$h" "${RING0[$h]}" &
    POLLER[$h]=$!
done
T0=$(date +%s)
say "probe sites on; counters recorded; slot record on from ${RING0[${PAIR[0]}]} / ${RING0[${PAIR[1]}]}; window starts $(date -u -d @$T0 +%FT%TZ)"

if [ "$PROFILE" = 1 ]; then
    env PVE_PAIR="$PAIR_S" EVID="$EVID/profile" SLOW_MS=300 INTERVAL_S=60 \
        FNS="mxfs_ilock_fallible mxfs_dlm_ilock_begin mxfs_ilock_wait_for_transition mxfs_dlm_lock_retries mxfs_dlm_lock dlm_lock_impl mxfs_dlm_bast_work_fn mxfs_dlm_ag_bast_work_fn mxfs_dlm_bast_notify mxfs_dlm_ilock_end mxfs_ag_dlm_lock mxfs_ag_dlm_unlock mxfs_trans_preacquire_inode_ags xfs_create xfs_remove xfs_rename xfs_file_write_iter xfs_log_force xfs_log_force_seq xfs_log_force_inode xfs_fs_sync_fs mxfs_pal_drbd_cas_emulate mxfs_drbd_reg_put mxfs_tauth_ledger_commit xfs_trans_commit xfs_trans_alloc" \
        timeout 240 "$REPO/tests/pve_pair_profile.sh" 130 > "$EVID/profile.out" 2>&1 &
    prof=$!
    # the churn starts once both hosts report the profiler on, or after 60 s
    for i in $(seq 1 60); do
        [ "$(grep -c 'profiling .* of .* functions' "$EVID/profile.out" 2>/dev/null)" -ge 2 ] && break
        sleep 1
    done
    say "profiler: $(grep -c 'profiling .* of .* functions' "$EVID/profile.out") of 2 hosts on"
fi
: > "$EVID/churn.out"
for r in $(seq 1 "$ROUNDS"); do
    env PVE_PAIR="$PAIR_S" timeout 300 "$REPO/tests/pve_churn_fairness.sh" >> "$EVID/churn.out" 2>&1
    say "churn round $r rc=$? ($(grep -aE '^iterations ' "$EVID/churn.out" | tail -1))"
done
[ "$PROFILE" = 1 ] && { wait "$prof"; say "profiler rc=$?"; }
T1=$(date +%s)
touch "$EVID/ring.stop"
for h in "${PAIR[@]}"; do wait "${POLLER[$h]}"; done

# A host that restarted in the window answers with a new boot id; its window
# lines are in its previous boot, and its slot records are what the takes got.
for h in "${PAIR[@]}"; do
    b0=$(sed -n 's/.* boot=\([^ ]*\).*/\1/p' "$EVID/host.$h")
    for i in $(seq 1 60); do on "$h" "true" 10 >/dev/null && break; sleep 5; done
    b1=$(on "$h" "cat /proc/sys/kernel/random/boot_id" 20)
    if [ "$b0" = "$b1" ]; then sel="-b 0"; say "$h: same boot"; else sel="-b -1"; say "$h: RESTARTED in the window (boot $b0 -> $b1); reading its previous boot"; fi
    on "$h" "journalctl -k $sel --since @$((T0 - 5)) --until @$((T1 + 5)) --no-pager -o short-unix" 120 > "$EVID/klog.$h"
    if [ "$b0" = "$b1" ]; then
        counters "$h" after
        sites "$h" -p || say "WARN: could not turn the sites off on $h"
        last=$(cat "$EVID/ring.last.$h" 2>/dev/null)
        ring_take "$h" "${last:-${RING0[$h]}}" >/dev/null
        on "$h" "echo 0 > /sys/module/mxfs/parameters/slot_ring" 20 >/dev/null || say "WARN: could not turn the slot record off on $h"
    fi
    say "$h: $(wc -l < "$EVID/ring.$h") slot records taken"
done

python3 -I - "$EVID" "${PAIR[0]}" "${PAIR[1]}" <<'PY' | tee -a "$EVID/log"
import re, sys, collections
evid, hosts = sys.argv[1], sys.argv[2:]
conf = re.compile(r"Concurrent writes detected: local=(\d+)s \+(\d+), remote=(\d+)s \+(\d+)")
tag = re.compile(r"\b(P219-LOGGED-NO-AUTHORITY|P-FREEPUB-WRITE|P218-CLUSTER-PASSENGER|P34H-INCARN-POISON|P-DIALLOC-DISKLIVE|P-DRAINWB-STALL|BAD! BarrierAck|ASSERTION[^\n]*|ProtocolError)")
inos = collections.defaultdict(list)
for h in hosts:
    try:
        lines = open(f"{evid}/klog.{h}", errors="replace").read().splitlines()
    except OSError:
        print(f"{h}: no kernel lines saved"); continue
    n = collections.Counter()
    for ln in lines:
        m = conf.search(ln)
        if m:
            n["conflict"] += 1
            print(f"{h} CONFLICT {ln.split(' ', 1)[0]} local={m.group(1)}+{m.group(2)} remote={m.group(3)}+{m.group(4)}")
        t = tag.search(ln)
        if t:
            n[t.group(1).split()[0]] += 1
            ino = re.search(r"\bino=(\d+)", ln)
            if ino:
                inos[ino.group(1)].append(f"{h} {ln.split(' ', 1)[0]} {t.group(1).split()[0]} " +
                                          " ".join(re.findall(r"\b(?:slot|gen|dlm_mode|staged|stage_mode|relflush|demoter|stale|img_mode|img_gen|epoch|incore_gen|fresh_gen|disk_gen|disk_mode|pr|genmm|nocore|skipped|comm|realns)=\S+", ln)))
    print(f"{h}: {dict(n)}")
for ino, ev in sorted(inos.items()):
    print(f"ino {ino}: {len(ev)} lines")
    for e in ev[:12]:
        print("   " + e[:300])
PY
# the slot record: census, each conflict's two writes, cross-host near-misses
python3 "$REPO/tools/slot_ring_report.py" "$EVID" "${PAIR[0]}" "${PAIR[1]}" 0.05 | tee -a "$EVID/log"
for f in "$EVID"/counters.*; do echo "== $(basename "$f")"; cat "$f"; done | tee -a "$EVID/log"
say "evidence $EVID"
