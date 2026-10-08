#!/bin/bash
# pve_pair_builds.sh — run concurrent OS image builds on the two physical
# Proxmox hosts, with every build VM's disk on the shared MXFS storage, and
# time each one.  Eight of these at once (four per host) is the workload that
# shut both hosts' MXFS down on 2026-10-06; it is the pair's real load test.
#
# Each build is `mkosimage proxmox/<location>/<spec> <name>` run here: packer's
# proxmox-iso builder creates the VM on that host (4 cores, 4 GiB, a 16 GiB
# virtio disk on storage `shared`, cache=none), installs the OS from the ISO
# storage with a kickstart, and waits up to 45 min for it to come up.
#
# Usage: scripts/pve_pair_builds.sh [per-host] [spec]
#   per-host  builds per host (default 4); names <PREFIX>1..<PREFIX>N, dealt
#             to the hosts in turn (with the default two, odd ones on pve1,
#             even ones on pve2)
#   spec      default alma-9.7-x86_64
# Env:
#   PREFIX        build name prefix (default alma9-)
#   LOCATIONS     "pve1 pve2" (mkosimage locations, in host order)
#   HOSTS         "192.168.1.80 192.168.1.81" (the same hosts' addresses)
#   COUNTS        builds per host, in host order, instead of per-host for all
#                 (e.g. "3 4": the hosts have different memory, and a build VM
#                 takes 4 GiB of it); names are still dealt in turn, a host
#                 dropping out of the deal once it has its count
#   BUILD_BUDGET  seconds per build (default 3000: packer's own 45 min wait for
#                 the installed system, plus VM creation, boot and post-build)
#   CREATE_BUDGET seconds from a build's start to its VM created (default 60:
#                 ~10 s measured, the kickstart ISO built and uploaded first)
#   STORAGE       the Proxmox storage for the build VMs' disks instead of the
#                 location's own (`shared`): `local-lvm` gives the same builds
#                 on each host's own disk, the baseline MXFS is measured against
#   DEFINES       further mkosimage defines, key=value[,key=value] (e.g.
#                 iso_url=https://vault.almalinux.org/9.7/isos/x86_64/AlmaLinux-9.7-x86_64-dvd.iso:
#                 AlmaLinux moved 9.7 to its vault and the spec's URL now 404s)
#   MKOS_FLAGS    further mkosimage flags (e.g. --local: install from the ISO
#                 already on the hosts' `iso` storage instead of having Proxmox
#                 download it, which fails at once when that storage is full;
#                 mkosimage still checks iso_url first, so pass both)
#   EVID          evidence directory (default tests/evidence/pve_pair_builds/<stamp>)
#   PROFILE=1     run tests/pve_pair_profile.sh on both hosts for the whole of
#                 the builds (evidence in $EVID/profile): which MXFS operations
#                 the builds' time went to
#   TRACE=1       run tests/pve_pair_write_bound.sh FIO=0 on both hosts for the
#                 whole of the builds: every compare-and-swap timed (TRACE_FNS
#                 adds functions, as its EXTRA_FNS), and both kernel logs since
#                 the start searched for heartbeat stalls, authority closures,
#                 self-fences and kernel warnings; its summary is appended here
#   PROBES        debug-probe formats to turn on on both hosts for the run and
#                 off again after it (e.g. "P15-REL-ABORT P79-STALEBAST-CLEAR"):
#                 a count of a probe line is evidence only while it is on
#   SAMPLE_S      seconds between samples of every running VM's block counters
#                 (default 60)
#   STOP_INSTALLED=1  stop a build (SIGTERM, so packer removes its VM) as soon
#                 as its guest answers as installed, instead of leaving it to
#                 packer's own end
#
# A build counts as installed when its guest's agent answers with the build's
# own hostname, which the installed system set and the installer did not: the
# time from the VM's start to that is what the storage under the build decides,
# measured whatever packer does afterwards.
#
# Every SAMPLE_S seconds each host's running VMs are asked for QEMU's own
# counters per drive (bytes, operations and their total time, flushes
# included) into $EVID/blockstat.txt, and the summary gives each build disk's
# totals: what a build's guest waited on, measured the same way whatever the
# storage under it.
#
# The builds start one after another, each once the previous one has created
# its VM: packer asks the cluster for the next free VM id, and two builds that
# ask at once get the same one (2026-10-06: "unable to create VM 103 - can't
# lock file", and that build never ran).
#
# Before starting, a stopped VM left by an earlier run of this script is
# destroyed with its disks: a failed build must be cleaned up before it is
# tried again.  A running one stops the run instead.  Then the disk images of
# such a VM that Proxmox could not remove are freed, once no VM in the cluster
# has its id: Proxmox removes a destroyed VM's configuration even when it
# cannot remove its disk ("Could not remove disk ... cfs-lock 'storage-shared'
# error: got lock request timeout", 2026-10-06, four of eight failed builds),
# and those images would fill the storage run after run.  Only VMs this script
# created are touched (tests/evidence/pve_pair_builds/owned_vms, each found by
# the kickstart ISO its build uploaded): the owner's own builds are named
# packer-* too, and a failed one may be kept to be looked at.  Nothing else on
# the hosts is touched.
#
# Output: one line per build (name, host, rc, wall), the summary in
# $EVID/summary.txt, each build's log in $EVID/<name>.log.  Exit 0 only when
# every build succeeded within its budget.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PER=${1:-4}
SPEC=${2:-alma-9.7-x86_64}
PREFIX=${PREFIX:-alma9-}
read -r -a LOCS <<<"${LOCATIONS:-pve1 pve2}"
read -r -a HOSTS <<<"${HOSTS:-192.168.1.80 192.168.1.81}"
BUILD_BUDGET=${BUILD_BUDGET:-3000}
CREATE_BUDGET=${CREATE_BUDGET:-60}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID=${EVID:-$REPO/tests/evidence/pve_pair_builds/$STAMP}
mkdir -p "$EVID" || exit 1
SUM="$EVID/summary.txt"
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUM"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
command -v mkosimage >/dev/null || { say "ABORT: no mkosimage here"; exit 1; }

NAMES=()
HIDX=()                             # the host index of each name
[ "${#LOCS[@]}" = "${#HOSTS[@]}" ] || { say "ABORT: LOCATIONS and HOSTS name different numbers of hosts"; exit 2; }
NH=${#HOSTS[@]}
if [ -n "${COUNTS:-}" ]; then
    read -r -a CNT <<<"$COUNTS"
    [ "${#CNT[@]}" = "$NH" ] || { say "ABORT: COUNTS names ${#CNT[@]} hosts, HOSTS $NH"; exit 2; }
else
    CNT=()
    for h in "${HOSTS[@]}"; do CNT+=("$PER"); done
fi
left=("${CNT[@]}")
while :; do
    dealt=0
    for k in $(seq 0 $(( NH - 1 ))); do
        [ "${left[$k]}" -gt 0 ] || continue
        NAMES+=("$PREFIX$(( ${#NAMES[@]} + 1 ))")
        HIDX+=("$k")
        left[$k]=$(( left[k] - 1 ))
        dealt=1
    done
    [ "$dealt" = 1 ] || break
done

# The VMs this harness created, across runs: "<host> <vmid> <vm name>" per
# line.  Only these are ever destroyed here, or have their disks freed: the
# owner's own builds are also named packer-*, and a failed one of theirs may be
# kept to be looked at.  A build's VM is recognised by the kickstart ISO its
# build uploaded (a name packer makes up per build), which its configuration
# references.
OWNED="$REPO/tests/evidence/pve_pair_builds/owned_vms"
touch "$OWNED" || exit 1
STORE=${STORAGE:-shared}

# Leftover VMs of earlier runs: destroy the stopped ones, refuse on a running
# one.  An entry stays while its VM or a disk image of its id is still there.
vmids=$(on "${HOSTS[0]}" "pvesh get /cluster/resources --type vm --output-format json" 30 \
    | python3 -I -c 'import json, sys; print(" ".join(str(v["vmid"]) for v in json.load(sys.stdin)) or "NONE")' 2>/dev/null)
keep=""
while read -r h id name; do
    [ -n "$id" ] || continue
    cur=$(on "$h" "qm list 2>/dev/null | awk -v id=$id '\$1 == id {print \$2, \$3}'" 30)
    if [ -n "$cur" ] && [ "${cur%% *}" = "$name" ]; then
        if [ "${cur#* }" != stopped ]; then
            say "ABORT: $h has build VM $id ($name) of an earlier run ${cur#* }; stop it first"
            exit 1
        fi
        out=$(on "$h" "qm destroy $id --purge 1 --destroy-unreferenced-disks 1 2>&1; echo DESTROY_RC=\$?" 120)
        rc=$(grep -o 'DESTROY_RC=[0-9]*' <<<"$out")
        say "$h: destroyed leftover build VM $id ($name) of an earlier run: $rc"
        [ "$rc" = DESTROY_RC=0 ] || { keep+="$h $id $name"$'\n'; continue; }
        [ -z "$vmids" ] || vmids=$(tr ' ' '\n' <<<"$vmids" | grep -v -x -- "$id" | tr '\n' ' ')
    elif [ -n "$cur" ]; then
        continue                    # the id names another VM now: not ours
    fi
    # Proxmox removes a destroyed VM's configuration even when it cannot remove
    # its disk ("Could not remove disk ... cfs-lock 'storage-shared' error: got
    # lock request timeout", 2026-10-06), and such images fill the storage run
    # after run: free this id's images once no VM in the cluster has the id.
    # If the cluster's VM list could not be read, nothing is freed.
    if [ -z "$vmids" ] || [[ " $vmids " == *" $id "* ]]; then
        keep+="$h $id $name"$'\n'
        continue
    fi
    left=0
    while read -r volid format type size vmid; do
        [ "$vmid" = "$id" ] || continue
        out=$(on "$h" "pvesm free $volid 2>&1; echo FREE_RC=\$?" 120)
        rc=$(grep -o 'FREE_RC=[0-9]*' <<<"$out")
        say "$h: freed orphaned image $volid of build VM $id ($name): $rc"
        [ "$rc" = FREE_RC=0 ] || left=1
    done < <(on "$h" "pvesm list $STORE 2>/dev/null | tail -n +2" 30)
    [ "$left" = 0 ] || keep+="$h $id $name"$'\n'
done < "$OWNED"
printf '%s' "$keep" > "$OWNED"

PROF_PID=
if [ "${PROFILE:-0}" = 1 ]; then
    PVE_PAIR="${HOSTS[*]}" EVID="$EVID/profile" STOP_FILE="$EVID/profile.stop" \
        "$REPO/tests/pve_pair_profile.sh" > "$EVID/profile.out" 2>&1 &
    PROF_PID=$!
    tp=$(date +%s)
    until grep -q -E 'profiling until|ABORT' "$EVID/profile/summary.txt" 2>/dev/null; do
        [ $(( $(date +%s) - tp )) -ge 60 ] && break
        sleep 2
    done
    grep -q 'profiling until' "$EVID/profile/summary.txt" 2>/dev/null \
        || { say "ABORT: the profile did not start: $(tail -2 "$EVID/profile.out" | tr '\n' ' ')"; kill "$PROF_PID" 2>/dev/null; exit 1; }
    say "profiling both hosts: $EVID/profile"
fi
probes() {  # +p | -p
    local h f cmd=""
    for f in ${PROBES:-}; do
        cmd+="echo 'module mxfs format \"$f\" $1' > /proc/dynamic_debug/control; "
    done
    [ -n "$cmd" ] || return 0
    for h in "${HOSTS[@]}"; do
        # the flags are the third field; a match on the line would also
        # match format text
        on "$h" "${cmd}awk '\$3 == \"=p\" && \$2 ~ /^\\[mxfs\\]/' /proc/dynamic_debug/control | wc -l" 30 | sed "s/^/  $h: probe sites on after $1: /"
    done
}
if [ -n "${PROBES:-}" ]; then
    trap 'probes -p' EXIT
    probes +p | tee -a "$SUM"
fi
TRACE_PID=
if [ "${TRACE:-0}" = 1 ]; then
    env PVE_PAIR="${HOSTS[*]}" FIO=0 LOAD_S=$(( BUILD_BUDGET + 600 )) \
        STOP_FILE="$EVID/trace.stop" EXTRA_FNS="${TRACE_FNS:-}" \
        "$REPO/tests/pve_pair_write_bound.sh" > "$EVID/trace.out" 2>&1 &
    TRACE_PID=$!
    tp=$(date +%s)
    until grep -q -E 'observing only|ABORT' "$EVID/trace.out" 2>/dev/null; do
        [ $(( $(date +%s) - tp )) -ge 120 ] && break
        sleep 2
    done
    grep -q 'observing only' "$EVID/trace.out" 2>/dev/null \
        || { say "ABORT: the trace did not start: $(tail -2 "$EVID/trace.out" | tr '\n' ' ')"; kill "$TRACE_PID" 2>/dev/null; exit 1; }
    say "tracing every swap on both hosts: $EVID/trace.out"
fi
# One sample of every running VM's drives: "<ts> <vmid> <drive> rd_bytes rd_ops
# rd_ns wr_bytes wr_ops wr_ns flush_ops flush_ns", from `qm status --verbose`;
# and of the host's own disks: "<ts> DISK <dev> <the 17 fields of its stat>",
# whose last two are the flushes completed and the milliseconds spent on them.
BLK=$(cat <<'EOF'
for d in /sys/block/sd*; do echo "$(date +%s) DISK ${d##*/} $(cat "$d/stat")"; done
for id in $(qm list 2>/dev/null | awk '$3 == "running" {print $1}'); do
    hn=$(timeout 5 qm agent "$id" get-host-name 2>/dev/null | sed -n 's/.*"host-name" *: *"\([^"]*\)".*/\1/p')
    echo "$(date +%s) AGENT $id ${hn:--}"
    qm status "$id" --verbose 2>/dev/null | awk -v id="$id" -v ts="$(date +%s)" '
        /^blockstat:/ {on = 1; next}
        /^[^\t]/ {on = 0}
        on && /^\t[^\t]+:$/ {d = $1; sub(/:$/, "", d); seen[d] = 1; next}
        on && /^\t\t(rd_bytes|rd_operations|rd_total_time_ns|wr_bytes|wr_operations|wr_total_time_ns|flush_operations|flush_total_time_ns):/ {k = $1; sub(/:$/, "", k); v[d, k] = $2}
        END {for (d in seen) print ts, id, d, v[d, "rd_bytes"] + 0, v[d, "rd_operations"] + 0, v[d, "rd_total_time_ns"] + 0, v[d, "wr_bytes"] + 0, v[d, "wr_operations"] + 0, v[d, "wr_total_time_ns"] + 0, v[d, "flush_operations"] + 0, v[d, "flush_total_time_ns"] + 0}'
done
EOF
)
BLK64=$(base64 -w0 <<<"$BLK")
SAMPLE_S=${SAMPLE_S:-60}
(
    while [ ! -e "$EVID/builds.done" ]; do
        for h in "${HOSTS[@]}"; do
            out=$(on "$h" "echo $BLK64 | base64 -d | bash" 40 | sed "s/^/$h /")
            echo "$out" >> "$EVID/blockstat.txt"
            # a build whose guest answers with its own hostname is installed
            for n in $(awk '$3 == "AGENT" {sub(/\..*/, "", $5); print $5}' <<<"$out"); do
                [[ " ${NAMES[*]} " == *" $n "* ]] || continue
                [ -e "$EVID/$n.installed" ] && continue
                date +%s > "$EVID/$n.installed"
                if [ "${STOP_INSTALLED:-0}" = 1 ] && [ -s "$EVID/$n.pid" ]; then
                    kill -TERM "$(cat "$EVID/$n.pid")" 2>/dev/null
                    say "$n installed; its build stopped (STOP_INSTALLED=1)"
                else
                    say "$n installed"
                fi
            done
        done
        for t in $(seq 1 "$SAMPLE_S"); do [ -e "$EVID/builds.done" ] && break; sleep 1; done
    done
) &
BLK_PID=$!

say "starting ${#NAMES[@]} builds of $SPEC: ${CNT[*]} on ${LOCS[*]}, disks on storage ${STORAGE:-shared}, budget ${BUILD_BUDGET}s each"
T0=$(date +%s)
BPIDS=()
for i in "${!NAMES[@]}"; do
    n=${NAMES[$i]}
    loc=${LOCS[${HIDX[$i]}]}
    (
        t0=$(date +%s)
        # timeout leads its own process group and passes a SIGTERM sent to it
        # on to mkosimage and packer, so packer's own cleanup runs
        defs=${STORAGE:+vm_storage_pool=$STORAGE}
        [ -n "${DEFINES:-}" ] && defs=${defs:+$defs,}$DEFINES
        timeout "$BUILD_BUDGET" mkosimage ${MKOS_FLAGS:-} ${defs:+-D "$defs"} "proxmox/$loc/$SPEC" "$n" > "$EVID/$n.log" 2>&1 </dev/null &
        echo $! > "$EVID/$n.pid"
        wait $!
        rc=$?
        echo "$n $loc rc=$rc wall=$(( $(date +%s) - t0 ))s" > "$EVID/$n.result"
    ) &
    BPIDS+=($!)
    tc=$(date +%s)
    until grep -a -q -E 'Starting VM|Error creating VM' "$EVID/$n.log" 2>/dev/null || [ -e "$EVID/$n.result" ]; do
        if [ $(( $(date +%s) - tc )) -ge "$CREATE_BUDGET" ]; then
            say "$n had not created its VM ${CREATE_BUDGET}s after its start (budget exceeded); starting the next build anyway"
            break
        fi
        sleep 2
    done
    if grep -a -q 'Starting VM' "$EVID/$n.log" 2>/dev/null; then
        date +%s > "$EVID/$n.vmstart"
        # its VM: the packer-* VM on its host whose configuration holds the
        # kickstart ISO this build uploaded (the log's colour codes end the name)
        iso=$(grep -a -o -m1 -E 'Uploaded ISO to [[:alnum:]_:/.-]+' "$EVID/$n.log" | awk '{print $4}')
        h=${HOSTS[${HIDX[$i]}]}
        vm=
        [ -n "$iso" ] && vm=$(on "$h" "for id in \$(qm list 2>/dev/null | awk '\$2 ~ /^packer-/ {print \$1}'); do qm config \$id 2>/dev/null | grep -qF '$iso' && echo \"\$id \$(qm config \$id | sed -n 's/^name: //p')\"; done" 60 | head -1)
        if [ -n "$vm" ]; then
            echo "$h $vm" | tee "$EVID/$n.vm" >> "$OWNED"
        else
            say "$n: its VM was not found by its ISO (${iso:-none}); a later run will not clean it up"
        fi
    fi
done
# the builds only: a bare wait would also wait for the profile, which runs
# until it is told to stop below
wait "${BPIDS[@]}"
for n in "${NAMES[@]}"; do
    r=$(cat "$EVID/$n.result" 2>/dev/null || echo "$n no result")
    say "$r"
done
say "all builds done in $(( $(date +%s) - T0 ))s"
touch "$EVID/builds.done"
wait "$BLK_PID"
# Each build disk's last sample (a VM packer deleted keeps the totals of its
# last minute), and the ISO drive's reads beside it.
python3 -I - "$EVID/blockstat.txt" "$EVID" "${NAMES[@]}" <<'PY' | tee -a "$SUM"
import os, sys
last, disk, up = {}, {}, {}
names = sys.argv[3:]
try:
    for line in open(sys.argv[1]):
        f = line.split()
        if len(f) == 5 and f[2] == "AGENT":
            hn = f[4].split(".")[0]          # the agent answers with the FQDN
            if hn in names and hn not in up:
                up[hn] = (int(f[1]), f[0], f[3])
        elif len(f) == 21 and f[2] == "DISK":
            host, ts, dev = f[0], int(f[1]), f[3]
            first = disk.get((host, dev), (None, None))[0]
            row = (ts, list(map(int, f[4:])))
            disk[(host, dev)] = (first or row, row)
        elif len(f) == 12:
            host, ts, vmid, drv = f[0], int(f[1]), f[2], f[3]
            last[(host, vmid, drv)] = (ts, *map(int, f[4:]))
except FileNotFoundError:
    print("guest block counters: none sampled")
    sys.exit(0)
# A build's install is done when its guest's agent answers with the build's
# own hostname: the installed system set it; the installer did not.
print(f"installed and booted (the guest agent answers with the build's hostname), from the VM's start, to within the {os.environ.get('SAMPLE_S', '60')} s sampling:")
for n in names:
    try:
        t0 = int(open(f"{sys.argv[2]}/{n}.vmstart").read())
    except (OSError, ValueError):
        print(f"  {n}: its VM never started")
        continue
    if n in up:
        ts, host, vmid = up[n]
        print(f"  {n}: VM {vmid} on {host} installed after {ts - t0} s")
    else:
        print(f"  {n}: never answered as installed")
print("guest block counters at each VM's last sample: host vm drive | read GiB, mean ms | write GiB, ops, mean ms | flushes, mean ms, total s")
for (host, vmid, drv), (ts, rb, ro, rns, wb, wo, wns, fo, fns) in sorted(last.items()):
    if not (rb or wb or fo):
        continue
    print(f"  {host} {vmid} {drv:8s} | {rb / 2**30:6.2f} {rns / max(ro, 1) / 1e6:7.2f} | {wb / 2**30:6.2f} {wo:8d} {wns / max(wo, 1) / 1e6:7.2f} | {fo:6d} {fns / max(fo, 1) / 1e6:8.2f} {fns / 1e9:8.1f}")
# /sys/block/<dev>/stat: 0 rd ios, 2 rd sectors, 4 wr ios, 6 wr sectors,
# 7 wr ticks ms, 9 io_ticks ms (busy), 15 flush ios, 16 flush ticks ms
print("host disks over the run: host dev | s | written MiB/s, writes/s, mean write ms | flushes/s, mean flush ms | busy %")
for (host, dev), ((t0, a), (t1, b)) in sorted(disk.items()):
    s = max(t1 - t0, 1)
    d = [y - x for x, y in zip(a, b)]
    if not (d[4] or d[15]):
        continue
    print(f"  {host} {dev} | {s:5d} | {d[6] * 512 / 2**20 / s:7.1f} {d[4] / s:8.1f} {d[7] / max(d[4], 1):7.1f} | {d[15] / s:7.1f} {d[16] / max(d[15], 1):8.1f} | {100 * d[9] / (s * 1000):5.1f}")
PY
if [ -n "$PROF_PID" ]; then
    touch "$EVID/profile.stop"
    # its last snapshot and the slow-call trace: two ssh reads per host
    for try in $(seq 1 60); do kill -0 "$PROF_PID" 2>/dev/null || break; sleep 5; done
    if kill -0 "$PROF_PID" 2>/dev/null; then
        say "the profile had not finished 300s after it was told to stop; stopped it"
        kill "$PROF_PID" 2>/dev/null
    fi
    sed -n '/: function, calls/,$p' "$EVID/profile/summary.txt" | tee -a "$SUM"
fi
if [ -n "$TRACE_PID" ]; then
    touch "$EVID/trace.stop"
    # it removes its trace instances and copies both kernel logs: a few ssh
    # round trips per host
    for try in $(seq 1 60); do kill -0 "$TRACE_PID" 2>/dev/null || break; sleep 5; done
    if kill -0 "$TRACE_PID" 2>/dev/null; then
        say "the trace had not finished 300s after it was told to stop; stopped it"
        kill "$TRACE_PID" 2>/dev/null
    fi
    say "the trace (tests/pve_pair_write_bound.sh FIO=0):"
    grep -a -E '^\[|mxfs_|kernel log since|FAIL|PASS|lost events' "$EVID/trace.out" | sed 's/^/  /' | tee -a "$SUM"
fi
for h in "${HOSTS[@]}"; do
    on "$h" "hostname; qm list 2>/dev/null" 30 | sed "s/^/  /" | tee -a "$SUM"
done
# With STOP_INSTALLED=1 a build succeeds when its guest installed within its
# budget (the harness stopped it there, so its exit status is the stop's).
if [ "${STOP_INSTALLED:-0}" = 1 ]; then
    fails=0
    for n in "${NAMES[@]}"; do [ -e "$EVID/$n.installed" ] || fails=$(( fails + 1 )); done
    [ "$fails" = 0 ] && { say "PASS: every build installed within its budget; evidence $EVID"; exit 0; }
    say "FAIL: $fails build(s) never answered as installed; evidence $EVID"
    exit 1
fi
fails=$(grep -L ' rc=0 ' "$EVID"/*.result 2>/dev/null | wc -l)
missing=$(( ${#NAMES[@]} - $(ls "$EVID"/*.result 2>/dev/null | wc -l) ))
if [ "$fails" = 0 ] && [ "$missing" = 0 ]; then
    say "PASS: every build succeeded; evidence $EVID"
    exit 0
fi
say "FAIL: $fails build(s) did not succeed, $missing without a result; evidence $EVID"
exit 1
