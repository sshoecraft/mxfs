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
#   on XFS made on it and mounted on hostA alone; SEQ_S seconds, default 30)
#   | vmio-mxfs | vmio-xfs | vmio-local (one writer on hostA writing as an
#   installing guest's disk does, below, VMIO_S seconds: into a sparse file on
#   the MXFS mount MNT, on XFS made on the scratch DRBD device and mounted on
#   hostA alone, or on XFS made on a scratch LV of hostA's own with no DRBD).
#   Default: idle bulk.
# Env: VG (pve)  LV_SIZE (4G)  MINOR (1)  PORT (7790)  DISK (sda: the backing
#      disk iostat watches and bulk-none switches)  IDLE_S (20)  BULK_S (90)
#      BULK_JOBS (4)  BULK_QD (16)  BULK_BS (1M)  VMIO_S (60)  MNT (/mnt/shared)
#      LV_THIN (empty: thick LVs; a thin pool's name, e.g. data, puts both
#      scratch LVs in that pool, as the MXFS resource's own LV may be, and
#      writes them in full first so no write of a phase provisions a chunk)
#      DISK_WCE (empty: as found; 0 or 1 sets DISK's write cache on both hosts
#      for the run and restores it at the end, see below)
# The vmio writer: O_DIRECT random writes (io_uring, queue depth 4) of 4/64/128/
# 256 KiB in the proportion 35/25/20/20 (126 KiB on average, as an AlmaLinux
# install's virtio disk wrote: 3.5 GiB in 29.5k writes) with an fdatasync
# after every 3 writes (it issued 12k flushes), into a 3 GiB sparse file, so
# writes allocate and every sync forces the log, as a guest filling its image.
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
VMIO_S=${VMIO_S:-60}; MNT=${MNT:-/mnt/shared}; LV_THIN=${LV_THIN:-}
RES=mxfsprobe; DEV=/dev/drbd$MINOR
# a scratch LV of hostA's own for vmio-local, beside the resource's
LOCAL_LV=${RES}l
mkdir -p "$OUT" || exit 1

on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>/dev/null | grep -avE '^Warning:|^Unauthorized|^If you'; }
log() { echo "[$(date +%T)] $*" | tee -a "$OUT/probe.log"; }

NA=$(on "$HA" 'uname -n'); NB=$(on "$HB" 'uname -n')
[ -n "$NA" ] && [ -n "$NB" ] || { log "cannot reach $HA or $HB"; exit 1; }
for h in "$HA" "$HB"; do
    st=$(on "$h" "[ -e /etc/drbd.d/$RES.res ] && echo HAVE_RES; grep -q '^ *$MINOR:' /proc/drbd && echo MINOR_USED; lvs $VG/$RES >/dev/null 2>&1 && echo HAVE_LV; lvs $VG/$LOCAL_LV >/dev/null 2>&1 && echo HAVE_LOCAL_LV")
    [ -z "$st" ] || { log "$h already has: $(echo $st) — tear it down first (this script leaves nothing behind when it finishes)"; exit 1; }
done

teardown() {
    for h in "$HA" "$HB"; do
        on "$h" "[ -s /run/$RES.sched ] && cat /run/$RES.sched > /sys/block/$DISK/queue/scheduler; rm -f /run/$RES.sched
                 if [ -s /run/$RES.wce ]; then hdparm -W\$(cat /run/$RES.wce) /dev/$DISK >/dev/null 2>&1; rm -f /run/$RES.wce
                     for i in \$(seq 1 20); do grep -q 'write back' /sys/block/$DISK/queue/write_cache && break; sleep 1; done
                     echo \"\$(uname -n): $DISK write cache restored: \$(cat /sys/block/$DISK/queue/write_cache)\"; fi
                 if grep -q ' /mnt/$RES ' /proc/mounts; then timeout 60 umount /mnt/$RES; fi; rmdir /mnt/$RES 2>/dev/null
                 if grep -q ' /mnt/$LOCAL_LV ' /proc/mounts; then timeout 60 umount /mnt/$LOCAL_LV; fi; rmdir /mnt/$LOCAL_LV 2>/dev/null
                 rm -f $MNT/pvevmio/vmio.\$(uname -n); rmdir $MNT/pvevmio 2>/dev/null
                 timeout 20 drbdadm secondary $RES >/dev/null 2>&1; timeout 30 drbdadm down $RES >/dev/null 2>&1
                 rm -f /etc/drbd.d/$RES.res; lvremove -y $VG/$RES >/dev/null 2>&1; lvremove -y $VG/$LOCAL_LV >/dev/null 2>&1
                 echo \"\$(uname -n): torn down, minor $MINOR \$(grep -c '^ *$MINOR:' /proc/drbd) left, lv \$(lvs $VG/$RES >/dev/null 2>&1 && echo LEFT || echo gone), local lv \$(lvs $VG/$LOCAL_LV >/dev/null 2>&1 && echo LEFT || echo gone)\"" 90
    done | tee -a "$OUT/probe.log"
}
trap teardown EXIT

# DISK_WCE=0: both backing disks run with their volatile write cache off for
# the run (hdparm -W0; the drive writes its cache out first), restored at the
# end.  A disk with no volatile cache has nothing a flush must persist, so the
# kernel drops every flush the layers above it send: DRBD's flush at each
# epoch on the receiver, the filesystem's at each log force.  It is safe by
# construction, the opposite of telling DRBD not to flush.  The kernel learns
# the drive's new state from the revalidation libata runs after the command;
# the run starts only once /sys/block/<disk>/queue/write_cache says so.
if [ -n "${DISK_WCE:-}" ]; then
    case "$DISK_WCE" in 0) want="write through" ;; 1) want="write back" ;; *) log "DISK_WCE is 0 or 1"; exit 2 ;; esac
    for h in "$HA" "$HB"; do
        r=$(on "$h" "hdparm -W /dev/$DISK 2>/dev/null | sed -n 's/.*write-caching = *\([01]\).*/\1/p' > /run/$RES.wce; [ -s /run/$RES.wce ] || { rm -f /run/$RES.wce; echo NO_STATE; exit; }
                     hdparm -W$DISK_WCE /dev/$DISK >/dev/null 2>&1 || { echo SET_FAIL; exit; }
                     for i in \$(seq 1 20); do grep -q '$want' /sys/block/$DISK/queue/write_cache && break; sleep 1; done
                     echo \"was=\$(cat /run/$RES.wce) now=\$(cat /sys/block/$DISK/queue/write_cache)\"" 60)
        log "$h: $DISK write cache $r"
        case "$r" in *"now=$want") ;; *) log "$h: the kernel does not see $DISK's write cache as '$want'"; exit 1 ;; esac
    done
fi

CONF="resource $RES {
    net { protocol C; allow-two-primaries yes; }
    disk { c-fill-target 4M; c-max-rate 110M; c-min-rate 20M; }
    on $NA { device $DEV minor $MINOR; disk /dev/$VG/$RES; address $HA:$PORT; meta-disk internal; }
    on $NB { device $DEV minor $MINOR; disk /dev/$VG/$RES; address $HB:$PORT; meta-disk internal; }
}"
# mklv <name>: the shell that makes one scratch LV on a host, thick or in the
# thin pool LV_THIN; a thin one is then written in full, so a phase's writes
# find every chunk provisioned (and zeroed) already, as on a long-used LV
mklv() {
    if [ -n "$LV_THIN" ]; then
        # count, not the device's end: dd that runs into the end exits 1
        echo "lvcreate -y -W y -V $LV_SIZE -T $VG/$LV_THIN -n $1 >/dev/null 2>&1 && dd if=/dev/zero of=/dev/$VG/$1 bs=4M count=$(( ${LV_SIZE%[Gg]} * 256 )) oflag=direct status=none"
    else
        echo "lvcreate -y -W y -L $LV_SIZE -n $1 $VG >/dev/null 2>&1"
    fi
}
log "scratch resource $RES ($LV_SIZE ${LV_THIN:+thin }LV in $VG${LV_THIN:+/$LV_THIN}, $DEV, port $PORT) on $NA ($HA) and $NB ($HB)"
# writing a thin LV in full takes about 10 s a GiB on these disks
LVTIME=0; [ -n "$LV_THIN" ] && LVTIME=$(( ${LV_SIZE%[Gg]} * 20 ))
for h in "$HA" "$HB"; do
    r=$(on "$h" "$(mklv "$RES") || { echo LV_FAIL; exit; }
                 cat > /etc/drbd.d/$RES.res <<'EOF'
$CONF
EOF
                 drbdadm -- --force create-md $RES >/dev/null 2>&1 || { echo MD_FAIL; exit; }
                 drbdadm up $RES >/dev/null 2>&1 || { echo UP_FAIL; exit; }
                 echo UP" $(( 90 + LVTIME )))
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

# run_vmio <name> <mxfs|xfs|local>: one writer on $HA, the vmio pattern (see
# the top) into a sparse 3 GiB file on the MXFS mount, on XFS made on the
# scratch DRBD device and mounted on $HA alone, or on XFS made on a scratch LV
# of $HA's own (no DRBD).  Both hosts' backing disk is sampled by iostat
# meanwhile, and /proc/drbd, so the peer's share of the cost shows too.
VMIO_JOB="--rw=randwrite --bssplit=4k/35:64k/25:128k/20:256k/20 --direct=1 --ioengine=io_uring --iodepth=4 --fdatasync=3 --size=3g --time_based --runtime=$VMIO_S"
run_vmio() {
    local name=$1 target=$2 out dir pre="" post="" h n f
    case "$target" in
        mxfs)  dir=$MNT/pvevmio
               pre="awk '\$2 == \"$MNT\" && \$3 == \"mxfs\"' /proc/mounts | grep -q . || { echo NOT_MXFS; exit; }; mkdir -p $dir" ;;
        xfs)   dir=/mnt/$RES
               pre="mkfs.xfs -f -q -K $DEV && mkdir -p $dir && mount $DEV $dir || { echo XFS_FAIL; exit; }"
               post="timeout 60 umount $dir; rmdir $dir" ;;
        local) dir=/mnt/$LOCAL_LV
               pre="{ $(mklv "$LOCAL_LV"); } && mkfs.xfs -f -q -K /dev/$VG/$LOCAL_LV && mkdir -p $dir && mount /dev/$VG/$LOCAL_LV $dir || { echo LOCAL_FAIL; exit; }"
               post="timeout 60 umount $dir; rmdir $dir; lvremove -y $VG/$LOCAL_LV >/dev/null 2>&1" ;;
        *) log "unknown vmio target $target"; return 1 ;;
    esac
    log "== phase $name: one writer on $NA writing as an installing guest's disk, ${VMIO_S}s, on $target"
    for h in "$HA" "$HB"; do
        on "$h" "rm -f /tmp/$RES-iostat.log /tmp/$RES-drbd.log
            setsid bash -c 'for i in \$(seq 1 $((VMIO_S + LVTIME + 30))); do echo \"\$(date +%s.%N | cut -c1-14) \$(grep -E \"^ *[0-9]+: |ns:\" /proc/drbd | tr -s \" \n\" \" \")\"; sleep 1; done > /tmp/$RES-drbd.log' >/dev/null 2>&1 </dev/null &
            setsid iostat -x -d -t $DISK 1 $((VMIO_S + LVTIME + 30)) > /tmp/$RES-iostat.log 2>/dev/null </dev/null &
            echo started" 30 >/dev/null
    done
    out=$(on "$HA" "$pre
        f=$dir/vmio.\$(uname -n); rm -f \$f; truncate -s 3G \$f || { echo TRUNC_FAIL; exit; }
        fio --name=$name --filename=\$f $VMIO_JOB --output-format=json > /tmp/$RES-vmio.json 2>/tmp/$RES-vmio.err
        echo FIO_RC=\$?; rm -f \$f; $post" $((VMIO_S + LVTIME + 180)))
    on "$HA" "cat /tmp/$RES-vmio.json" 30 > "$OUT/$name.$NA.vmio.json"
    for h in "$HA" "$HB"; do
        n=$(on "$h" 'uname -n')
        for f in iostat.log drbd.log; do
            on "$h" "cat /tmp/$RES-$f 2>/dev/null" 30 > "$OUT/$name.$n.$f"
        done
    done
    case "$out" in
        *FIO_RC=0*) ;;
        *) log "  $name failed: $(tr '\n' ' ' <<<"$out") $(on "$HA" "tail -2 /tmp/$RES-vmio.err" | tr '\n' ' ')"; return 1 ;;
    esac
    python3 -I - "$OUT" "$name" "$NA" "$NB" <<'PY' | tee -a "$OUT/probe.log"
import json, os, sys
out, name, ha, hb = sys.argv[1:5]
j = json.load(open(os.path.join(out, "%s.%s.vmio.json" % (name, ha))))["jobs"][0]
w = j["write"]; c = w["clat_ns"]; pc = c.get("percentile", {})
s = j.get("sync", {}); sl = s.get("lat_ns", {}); spc = sl.get("percentile", {})
print(f"  {name}: writes={w['total_ios']} MiB/s={w['bw_bytes'] / 2**20:.1f} write_ms mean={c['mean'] / 1e6:.1f} "
      f"p99={pc.get('99.000000', 0) / 1e6:.1f} max={c['max'] / 1e6:.1f} | syncs={s.get('total_ios', 0)} "
      f"sync_ms mean={sl.get('mean', 0) / 1e6:.1f} p99={spc.get('99.000000', 0) / 1e6:.1f} max={sl.get('max', 0) / 1e6:.1f}")
for h in (ha, hb):
    rows = []
    hdr = None
    try:
        for l in open(os.path.join(out, "%s.%s.iostat.log" % (name, h))):
            f = l.split()
            if f and f[0] == "Device": hdr = f; continue
            if hdr and f and len(f) == len(hdr) and not f[0][0].isdigit():
                rows.append(dict(zip(hdr, f)))
    except OSError:
        pass
    # the samples while the writer ran: those with any write
    rows = [r for r in rows if float(r.get("w/s", 0)) > 0]
    if not rows:
        print(f"    {h} disk: no samples"); continue
    def avg(k): return sum(float(r.get(k, 0)) for r in rows) / len(rows)
    print(f"    {h} disk over {len(rows)} s: util={avg('%util'):.0f}% w/s={avg('w/s'):.0f} wMB/s={avg('wkB/s') / 1024:.1f} "
          f"w_await={avg('w_await'):.1f}ms f/s={avg('f/s'):.1f} f_await={avg('f_await'):.1f}ms aqu={avg('aqu-sz'):.2f}")
PY
}

for ph in "${PHASES[@]}"; do
    case "$ph" in
        idle) run_phase idle "$IDLE_S" 0 ;;
        bulk) run_phase bulk "$BULK_S" 1 ;;
        seqdio) run_seqdio seqdio raw ;;
        seqdio-xfs) run_seqdio seqdio-xfs xfs ;;
        vmio-mxfs) run_vmio vmio-mxfs mxfs ;;
        vmio-xfs) run_vmio vmio-xfs xfs ;;
        vmio-local) run_vmio vmio-local local ;;
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
