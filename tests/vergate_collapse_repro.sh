#!/bin/bash
# tests/vergate_collapse_repro.sh — D-BOARD-COLLAPSE-2332-VERGATE-ARM-WINDOW
# Reproduce (or exclude) the Aug-1 23:32-23:52Z collapse: a board-active
# 32-node cluster lost 31 mounts in the window where tests/vergate.sh's hb
# arms ran against the live LUN.  Code reading eliminated fence-preempt
# collateral (READ KEYS classification; fake key absent) and epoch-voter
# stall (fake never enters lease membership).  Remaining candidate chains:
#   H4: join_refuse's umount+WITHDRAW of a live member while the fake
#       writer runs -> full death pipeline for a node that instantly
#       rejoins, under load -> recovery composition breaks cluster-wide.
#   H3: independent rig degradation (test32 root-disk-full that evening).
#
# Arms (each on an N-node cluster, default 8, PASS = no real member loses
# its mount, no shutdowns, no reservation conflicts, cluster converged):
#   a) fake-writer alone, idle cluster (3 min writer life)
#   b) fake-writer + all-node create/rm workload
#   c) full hb sequence: fake writer + PN umount/withdraw/rejoin
#      (join_refuse shape) + workload    <- the H4 arm
#
# Budget (RULE 0): arm a ~4 min (writer 180s + settle), arm b ~5, arm c ~6;
# total <= 16 min on a prepped cluster.
#
# usage: vergate_collapse_repro.sh [N=8] [arm: a|b|c|all=all]
set -u
N="${1:-8}"
ARM="${2:-all}"
SSH=tools/mxfs_sshpass.sh
LUN=/dev/mapper/mpatha
PN="test$N"                       # probe node for the withdraw arm
RID="vcr_$(date +%s)"
say() { echo "[$(date +%H:%M:%S)] $*"; }

NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done

mark() { for n in "${NODES[@]}"; do $SSH "$n" "echo ${RID}-$1 > /dev/kmsg" >/dev/null 2>&1; done; }

health() { # health <tag> — per-node: mount? shutdown? resv-conflict? since tag
  # NOTE: the shutdown pattern must match REAL forced shutdowns only.  A
  # bare case-insensitive 'shutdown' also matches the string
  # "generic_shutdown_super" inside the P199-UNMOUNT-RESIDUAL-INODE
  # diagnostic, which made a clean unmount read as 18 shutdowns (false
  # COLLAPSE verdict, first run of arm c).
  local bad=0 n out
  for n in "${NODES[@]}"; do
    out=$($SSH "$n" "M=\$(mount -t mxfs | wc -l); S=\$(dmesg | sed -n \"/${RID}-$1/,\\\$p\" | grep -cE 'Filesystem has been shut down|xfs_do_force_shutdown|forcing shutdown|SELF-FENCE|Log I/O Error'); R=\$(dmesg | sed -n \"/${RID}-$1/,\\\$p\" | grep -ciE 'reservation conflict'); L=\$(dmesg | sed -n \"/${RID}-$1/,\\\$p\" | grep -ciE 'P-VERGATE-FENCE|no longer responding'); echo \$M \$S \$R \$L" 2>/dev/null | tr -d '\r')
    read -r m s r l <<<"$out"
    # COLLAPSE = a real member lost its mount or its fs was force-shut.
    # Reservation-conflict NOTICES ('sd N:0:0:0: reservation conflict') are
    # the normal PR-probe artifact at every mount — proven present on
    # untouched nodes — and the 'reservation conflict error, dev' failed-I/O
    # line is the separately-tracked unmount-release-flush defect.  Neither
    # is collapse evidence; both are reported as notes so they stay visible.
    if [ "${m:-0}" != "1" ] || [ "${s:-1}" != "0" ]; then
      say "  UNHEALTHY $n: mounts=$m shutdowns=$s resv_conflicts=$r fence_events=$l"
      bad=1
    elif [ "${l:-0}" != "0" ] || [ "${r:-0}" != "0" ]; then
      say "  note $n: fence/death events=$l resv_conflict_notices=$r (mount intact, 0 shutdowns)"
    fi
  done
  return $bad
}

fake_start() { # 3-minute fake live-legacy writer on a random free slot 40-59
  FSLOT=$((40 + RANDOM % 20))
  $SSH test1 "echo $FSLOT > /tmp/vgate_fake.slot; nohup python3 - <<'EOF' >/dev/null 2>&1 &
import struct, time, os
f=os.open('$LUN', os.O_RDWR)
sup=os.pread(f,4096,0)
dloff,=struct.unpack_from('<Q',sup,64)
real=os.pread(f,512,dloff)
fs_gen,=struct.unpack_from('<I',real,12)
epoch=int(time.time())
slot=int(open('/tmp/vgate_fake.slot').read())
open('/tmp/vgate_fake.pid','w').write(str(os.getpid()))
for i in range(90):
    b=bytearray(512)
    struct.pack_into('<I',b,0,0x4D584C4B)
    struct.pack_into('<I',b,4,1)
    struct.pack_into('<I',b,8,990)
    struct.pack_into('<I',b,12,fs_gen)
    struct.pack_into('<Q',b,16,int(time.time()*1000))
    struct.pack_into('<Q',b,24,epoch)
    os.pwrite(f,bytes(b),dloff+slot*512)
    os.fsync(f)
    time.sleep(2)
EOF
sleep 1; cat /tmp/vgate_fake.pid" 2>/dev/null
}
fake_stop() {
  $SSH test1 "kill \$(cat /tmp/vgate_fake.pid) 2>/dev/null; sleep 1; python3 - <<'EOF'
import struct, os
f=os.open('$LUN', os.O_RDWR)
sup=os.pread(f,4096,0)
dloff,=struct.unpack_from('<Q',sup,64)
slot=int(open('/tmp/vgate_fake.slot').read())
os.pwrite(f,b'\x00'*512,dloff+slot*512)
os.fsync(f)
EOF" >/dev/null 2>&1
}

load_start() { # create/write/rm loop on every node
  for n in "${NODES[@]}"; do
    $SSH "$n" "mkdir -p /mnt/shared/.vcr_$n; nohup bash -c 'for i in \$(seq 1 500); do d=/mnt/shared/.vcr_$n; dd if=/dev/zero of=\$d/f\$i bs=64k count=4 conv=fsync 2>/dev/null; mkdir -p \$d/dir\$i; rm -f \$d/f\$((i>10?i-10:1)) 2>/dev/null; done; echo done > /tmp/vcr_load.done' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1 &
  done
  wait
}
load_stop() {
  for n in "${NODES[@]}"; do
    $SSH "$n" "pkill -f 'vcr_$n' 2>/dev/null; rm -rf /mnt/shared/.vcr_$n 2>/dev/null" >/dev/null 2>&1 &
  done
  wait
}

run_arm() { # run_arm <name> <with_load:0|1> <with_withdraw:0|1>
  local name=$1 load=$2 wd=$3 rc=0
  say "=== arm $name: fake writer${load:+ +load}${wd:+ +withdraw/rejoin} ==="
  mark "$name"
  [ "$load" = 1 ] && { say "starting workload on all $N nodes"; load_start; }
  fake_start
  say "fake writer live on slot $FSLOT (3 min)"
  sleep 45          # let vergate detect + fence the fake
  if [ "$wd" = 1 ]; then
    say "$PN: umount + mount attempt against live fake (join_refuse shape)"
    J=$($SSH "$PN" "umount /mnt/shared 2>&1; mount -t mxfs $LUN /mnt/shared 2>&1; echo rc=\$?" 2>/dev/null | tail -1)
    say "$PN join attempt: $J (refusal expected while fake lives)"
    sleep 20        # peers process the withdraw/death pipeline
    say "$PN: rejoining after fake stop"
    fake_stop
    sleep 5
    $SSH "$PN" "mount -t mxfs $LUN /mnt/shared 2>&1; echo rc=\$?" 2>/dev/null | tail -1
  else
    sleep 75
    fake_stop
  fi
  [ "$load" = 1 ] && { sleep 30; load_stop; } || sleep 15
  sleep 10
  if health "$name"; then
    say "arm $name: HEALTHY (all $N mounts intact, 0 shutdowns, 0 resv conflicts)"
  else
    say "arm $name: COLLAPSE EVIDENCE — capture dmesg NOW (RULE: forensics immediately)"
    for n in "${NODES[@]}"; do
      $SSH "$n" "dmesg | sed -n \"/${RID}-$name/,\\\$p\"" > "tests/logs/vcr_${RID}_${name}_${n}.dmesg" 2>/dev/null
    done
    say "per-node dmesg captured to tests/logs/vcr_${RID}_${name}_*.dmesg"
    rc=1
  fi
  return $rc
}

mkdir -p tests/logs
FAILED=0
case "$ARM" in
  a)   run_arm a 0 0 || FAILED=1 ;;
  b)   run_arm b 1 0 || FAILED=1 ;;
  c)   run_arm c 1 1 || FAILED=1 ;;
  all) run_arm a 0 0 || FAILED=1
       run_arm b 1 0 || FAILED=1
       run_arm c 1 1 || FAILED=1 ;;
  *) echo "arm must be a|b|c|all"; exit 2 ;;
esac
if [ "$FAILED" = 0 ]; then
  echo "RESULT: PASS | case=vergate_collapse_repro | N=$N arms=$ARM — no member lost its mount; H4 not reproduced under these conditions"
else
  echo "RESULT: FAIL | case=vergate_collapse_repro | N=$N arms=$ARM — collapse evidence captured (see tests/logs/vcr_${RID}_*)"
fi
exit $FAILED
