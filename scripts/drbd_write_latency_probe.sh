#!/bin/bash
# drbd_write_latency_probe.sh — how long one small replicated write takes on a
# DRBD protocol-C pair while bulk writes from both nodes load it, and where the
# time goes: DRBD's own queues (/proc/drbd ap/pe/lo/ua) or the backing disks
# (iostat).  MXFS's coordination (its bakery registers, its heartbeat) is
# exactly such a write, issued behind whatever the guests are writing.
#
# It runs on a scratch resource of its own — a thick LV on each host, its own
# minor and port, no handlers — so a pair carrying MXFS keeps its data, and the
# scratch resource is torn down at the end (also on failure).
#
# Usage: scripts/drbd_write_latency_probe.sh <hostA> <hostB> <outdir> [phase ...]
#   phases: idle | bulk | bulk-none (bulk with the backing disks' scheduler set
#   to none for the phase, restored after) | seqdio | seqdio-xfs (one writer
#   on hostA: 256 KiB O_DIRECT sequential writes at QD8 on the raw device, or
#   on XFS made on it and mounted on hostA alone; SEQ_S seconds, default 30).
#   Default: idle bulk.
# Env: VG (pve)  LV_SIZE (4G)  MINOR (1)  PORT (7790)  DISK (sda: the backing
#      disk iostat watches and bulk-none switches)  IDLE_S (20)  BULK_S (90)
#      BULK_JOBS (4)  BULK_QD (16)  BULK_BS (1M)
# Probes, on each node, one 512-byte write every 0.5 s after the previous one
# completes: "reg" (O_DIRECT, REQ_SYNC, like an MXFS register) and "fua"
# (O_DIRECT|O_SYNC, so REQ_FUA, like an MXFS compare-and-write target).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
[ "$#" -ge 3 ] || { echo "usage: $0 <hostA> <hostB> <outdir> [phase ...]"; exit 2; }
HA=$1; HB=$2; OUT=$3; shift 3
PHASES=("$@"); [ "${#PHASES[@]}" = 0 ] && PHASES=(idle bulk)
VG=${VG:-pve}; LV_SIZE=${LV_SIZE:-4G}; MINOR=${MINOR:-1}; PORT=${PORT:-7790}
DISK=${DISK:-sda}; IDLE_S=${IDLE_S:-20}; BULK_S=${BULK_S:-90}
BULK_JOBS=${BULK_JOBS:-4}; BULK_QD=${BULK_QD:-16}; BULK_BS=${BULK_BS:-1M}
RES=mxfsprobe; DEV=/dev/drbd$MINOR
mkdir -p "$OUT" || exit 1

on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>/dev/null | grep -avE '^Warning:|^Unauthorized|^If you'; }
log() { echo "[$(date +%T)] $*" | tee -a "$OUT/probe.log"; }

NA=$(on "$HA" 'uname -n'); NB=$(on "$HB" 'uname -n')
[ -n "$NA" ] && [ -n "$NB" ] || { log "cannot reach $HA or $HB"; exit 1; }
for h in "$HA" "$HB"; do
    st=$(on "$h" "[ -e /etc/drbd.d/$RES.res ] && echo HAVE_RES; grep -q '^ *$MINOR:' /proc/drbd && echo MINOR_USED; lvs $VG/$RES >/dev/null 2>&1 && echo HAVE_LV")
    [ -z "$st" ] || { log "$h already has: $(echo $st) — tear it down first (this script leaves nothing behind when it finishes)"; exit 1; }
done

teardown() {
    for h in "$HA" "$HB"; do
        on "$h" "[ -s /run/$RES.sched ] && cat /run/$RES.sched > /sys/block/$DISK/queue/scheduler; rm -f /run/$RES.sched
                 if grep -q ' /mnt/$RES ' /proc/mounts; then timeout 60 umount /mnt/$RES; fi; rmdir /mnt/$RES 2>/dev/null
                 timeout 20 drbdadm secondary $RES >/dev/null 2>&1; timeout 30 drbdadm down $RES >/dev/null 2>&1
                 rm -f /etc/drbd.d/$RES.res; lvremove -y $VG/$RES >/dev/null 2>&1; echo \"\$(uname -n): torn down, minor $MINOR \$(grep -c '^ *$MINOR:' /proc/drbd) left, lv \$(lvs $VG/$RES >/dev/null 2>&1 && echo LEFT || echo gone)\"" 90
    done | tee -a "$OUT/probe.log"
}
trap teardown EXIT

CONF="resource $RES {
    net { protocol C; allow-two-primaries yes; }
    disk { c-fill-target 4M; c-max-rate 110M; c-min-rate 20M; }
    on $NA { device $DEV minor $MINOR; disk /dev/$VG/$RES; address $HA:$PORT; meta-disk internal; }
    on $NB { device $DEV minor $MINOR; disk /dev/$VG/$RES; address $HB:$PORT; meta-disk internal; }
}"
log "scratch resource $RES ($LV_SIZE LV in $VG, $DEV, port $PORT) on $NA ($HA) and $NB ($HB)"
for h in "$HA" "$HB"; do
    r=$(on "$h" "lvcreate -y -W y -L $LV_SIZE -n $RES $VG >/dev/null 2>&1 || { echo LV_FAIL; exit; }
                 cat > /etc/drbd.d/$RES.res <<'EOF'
$CONF
EOF
                 drbdadm -- --force create-md $RES >/dev/null 2>&1 || { echo MD_FAIL; exit; }
                 drbdadm up $RES >/dev/null 2>&1 || { echo UP_FAIL; exit; }
                 echo UP" 90)
    log "$h: $r"
    [ "$r" = UP ] || exit 1
done
r=$(on "$HA" "for i in \$(seq 1 30); do [ \"\$(drbdadm cstate $RES)\" = Connected ] && break; sleep 1; done
             drbdadm -- --clear-bitmap new-current-uuid $RES >/dev/null 2>&1; sleep 1
             drbdadm primary $RES 2>&1 | tail -1; echo \"\$(drbdadm cstate $RES) \$(drbdadm dstate $RES)\"" 60)
log "$HA: $r"
r=$(on "$HB" "drbdadm primary $RES 2>&1 | tail -1; drbdadm role $RES" 30)
log "$HB: $r"
case "$r" in *Primary/Primary*) ;; *) log "both nodes are not Primary"; exit 1 ;; esac

# Each node gets half of the device: probes at its start, bulk after them.
SZ=$(on "$HA" "blockdev --getsize64 $DEV")
HALF=$(( SZ / 2 / 1048576 ))           # MiB
SLICE=$(( (HALF - 64) / BULK_JOBS ))   # MiB per bulk job

# run_phase <name> <seconds> <bulk 0|1>
run_phase() {
    local name=$1 secs=$2 bulk=$3 h base
    log "== phase $name: ${secs}s, bulk=$bulk (jobs=$BULK_JOBS qd=$BULK_QD bs=$BULK_BS, slice ${SLICE}MiB per job)"
    for h in "$HA" "$HB"; do
        if [ "$h" = "$HA" ]; then base=0; else base=$HALF; fi
        on "$h" "rm -f /tmp/$RES-*
            setsid bash -c 'for i in \$(seq 1 $((secs + 5))); do echo \"\$(date +%s.%N | cut -c1-14) \$(grep -A1 \"^ *$MINOR:\" /proc/drbd | tr -s \" \n\" \" \")\"; sleep 1; done > /tmp/$RES-drbd.log' >/dev/null 2>&1 </dev/null &
            setsid iostat -x -d -t $DISK 1 $((secs + 5)) > /tmp/$RES-iostat.log 2>/dev/null </dev/null &
            if [ $bulk = 1 ]; then
                setsid fio --name=bulk --filename=$DEV --rw=randwrite --bs=$BULK_BS --direct=1 --ioengine=libaio --iodepth=$BULK_QD \
                    --numjobs=$BULK_JOBS --offset=$((base + 64))M --offset_increment=${SLICE}M --size=${SLICE}M \
                    --time_based --runtime=$secs --group_reporting --output-format=json --output=/tmp/$RES-bulk.json >/dev/null 2>&1 </dev/null &
            fi
            for p in reg fua; do
                if [ \$p = reg ]; then off=$((base + 4)); sync=0; else off=$((base + 8)); sync=1; fi
                setsid fio --name=\$p --filename=$DEV --rw=write --bs=512 --direct=1 --sync=\$sync --ioengine=psync \
                    --thinktime=500ms --thinktime_blocks=1 --offset=\${off}M --size=256K --time_based --runtime=$secs \
                    --write_lat_log=/tmp/$RES-\$p --log_avg_msec=0 --output-format=json --output=/tmp/$RES-\$p.json >/dev/null 2>&1 </dev/null &
            done
            echo started" 30 >/dev/null &
    done
    wait
    sleep $((secs + 8))
    for h in "$HA" "$HB"; do
        local n; n=$(on "$h" 'uname -n')
        for f in drbd.log iostat.log bulk.json reg.json fua.json reg_clat.1.log fua_clat.1.log; do
            on "$h" "cat /tmp/$RES-$f 2>/dev/null" 30 > "$OUT/$name.$n.$f"
            [ -s "$OUT/$name.$n.$f" ] || rm -f "$OUT/$name.$n.$f"
        done
    done
    python3 - "$OUT" "$name" "$NA" "$NB" <<'PY' | tee -a "$OUT/probe.log"
import json, os, sys, re
out, phase, hosts = sys.argv[1], sys.argv[2], sys.argv[3:]
def jload(p):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return None
for h in hosts:
    pre = os.path.join(out, "%s.%s." % (phase, h))
    line = [h]
    for p in ("reg", "fua"):
        j = jload(pre + p + ".json")
        if not j: line.append("%s=none" % p); continue
        w = j["jobs"][0]["write"]; c = w["clat_ns"]; pc = c.get("percentile", {})
        line.append("%s n=%d p50=%.1fms p99=%.1fms max=%.1fms" % (p, w["total_ios"], pc.get("50.000000", 0) / 1e6,
                    pc.get("99.000000", 0) / 1e6, c["max"] / 1e6))
    j = jload(pre + "bulk.json")
    if j:
        w = j["jobs"][0]["write"]
        line.append("bulk %.0fMB/s clat_max=%.0fms" % (w["bw_bytes"] / 1e6, w["clat_ns"]["max"] / 1e6))
    mx = {}
    try:
        for l in open(pre + "drbd.log"):
            for k, v in re.findall(r"\b(lo|pe|ua|ap|ep):(\d+)", l):
                mx[k] = max(mx.get(k, 0), int(v))
    except Exception: pass
    line.append("drbd max " + " ".join("%s=%d" % (k, mx[k]) for k in sorted(mx)))
    aw = []
    try:
        hdr = None
        for l in open(pre + "iostat.log"):
            f = l.split()
            if f and f[0] == "Device": hdr = f; continue
            if hdr and f and f[0] not in ("Device",) and len(f) == len(hdr) and not f[0][0].isdigit():
                d = dict(zip(hdr, f))
                aw.append((float(d.get("w_await", 0)), float(d.get("aqu-sz", 0)), float(d.get("wkB/s", 0)), float(d.get("%util", 0))))
    except Exception: pass
    if aw:
        line.append("disk max w_await=%.0fms aqu=%.1f wMB/s=%.0f util=%.0f%%" % (max(a[0] for a in aw), max(a[1] for a in aw),
                    max(a[2] for a in aw) / 1024, max(a[3] for a in aw)))
    print("  " + " | ".join(line))
PY
}

# run_seqdio <name> <raw|xfs>: one writer on $HA alone, the pattern of
# tests/pve_dio_alloc_cost.sh and tests/pve_unaligned_dio.sh (sequential
# 256 KiB O_DIRECT writes at queue depth 8, io_uring, SEQ_S seconds), on the
# raw device (its own half) or on a sparse file in an XFS made on the device
# and mounted on $HA only: the same writes on DRBD itself and on XFS on DRBD,
# to set beside MXFS on DRBD and a local filesystem.
run_seqdio() {
    local name=$1 target=$2 out
    log "== phase $name: one writer on $NA, 256 KiB O_DIRECT sequential writes at QD8 for ${SEQ_S}s on the $target device"
    if [ "$target" = raw ]; then
        out=$(on "$HA" "fio --name=$name --filename=$DEV --rw=write --bs=256k --direct=1 --ioengine=io_uring --iodepth=8 \
                --offset=64M --size=1g --time_based --runtime=$SEQ_S --output-format=json > /tmp/$RES-seq.json 2>/tmp/$RES-seq.err
            echo FIO_RC=\$?" $((SEQ_S + 60)))
    else
        out=$(on "$HA" "mkfs.xfs -f -q -K $DEV && mkdir -p /mnt/$RES && mount $DEV /mnt/$RES && truncate -s 4G /mnt/$RES/f || { echo XFS_FAIL; exit; }
            fio --name=$name --filename=/mnt/$RES/f --rw=write --bs=256k --direct=1 --ioengine=io_uring --iodepth=8 \
                --size=4g --time_based --runtime=$SEQ_S --output-format=json > /tmp/$RES-seq.json 2>/tmp/$RES-seq.err
            echo FIO_RC=\$?; timeout 60 umount /mnt/$RES; rmdir /mnt/$RES" $((SEQ_S + 120)))
    fi
    on "$HA" "cat /tmp/$RES-seq.json" 30 > "$OUT/$name.$NA.seq.json"
    case "$out" in
        *FIO_RC=0*) ;;
        *) log "  $name failed: $(tr '\n' ' ' <<<"$out") $(on "$HA" "tail -2 /tmp/$RES-seq.err" | tr '\n' ' ')"; return 1 ;;
    esac
    python3 - "$OUT/$name.$NA.seq.json" "$name" <<'PY' | tee -a "$OUT/probe.log"
import json, sys
w = json.load(open(sys.argv[1]))["jobs"][0]["write"]
c = w["clat_ns"]
print(f"  {sys.argv[2]}: writes={w['total_ios']} MiB/s={w['bw_bytes'] / 2**20:.1f} lat_mean_ms={c['mean'] / 1e6:.1f} lat_max_ms={c['max'] / 1e6:.1f}")
PY
}
SEQ_S=${SEQ_S:-30}

for ph in "${PHASES[@]}"; do
    case "$ph" in
        idle) run_phase idle "$IDLE_S" 0 ;;
        bulk) run_phase bulk "$BULK_S" 1 ;;
        seqdio) run_seqdio seqdio raw ;;
        seqdio-xfs) run_seqdio seqdio-xfs xfs ;;
        bulk-none)
            # the scheduler in force is kept in /run on the host; teardown restores it too
            for h in "$HA" "$HB"; do
                on "$h" "sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/block/$DISK/queue/scheduler > /run/$RES.sched; echo none > /sys/block/$DISK/queue/scheduler; cat /sys/block/$DISK/queue/scheduler" | sed "s/^/$h scheduler: /" | tee -a "$OUT/probe.log"
            done
            run_phase bulk-none "$BULK_S" 1
            for h in "$HA" "$HB"; do
                on "$h" "cat /run/$RES.sched > /sys/block/$DISK/queue/scheduler; rm -f /run/$RES.sched; cat /sys/block/$DISK/queue/scheduler" | sed "s/^/$h scheduler restored: /" | tee -a "$OUT/probe.log"
            done ;;
        *) log "unknown phase $ph" ;;
    esac
done
