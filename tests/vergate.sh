#!/bin/bash
# tests/vergate.sh — C7 version-gate verification arms (sess42).
# Ledger: D-CROSSNODE-OPEN-UNLINK-DATA-LOSS / D-AGI-UNLINKED, item C7.
#
# Arms (default: all):
#   legacy_refuse — a loop-device fs with the gate STRIPPED must be refused
#                   RW by a gate-aware kernel (EPROTONOSUPPORT path), and
#                   must mount once mxfs.legacy_rw=1 is set (explicit unsafe
#                   opt-out), then refuse again at legacy_rw=0.
#   upgrade       — chk_mxfs -U on the stripped fs restores the gate
#                   (envelope first, sb copies primary-last); the fs then
#                   mounts with legacy_rw=0.  -U is idempotent.
#   hb_intruder   — a fake LIVE pre-gate member (ACTIVE HB record, zero
#                   feature block, advancing timestamps, free slot 63) on
#                   the SHARED LUN must trip P-VERGATE + P-VERGATE-FENCE on
#                   established members within ~3 monitor passes, exactly
#                   once for its epoch, with the cluster staying healthy.
#   join_refuse   — while the fake live-legacy writer runs, a fresh mount
#                   on the probe node must be REFUSED by the join gate
#                   (P-VERGATE-JOIN, -EPROTO); after the writer stops (and
#                   its record is zeroed) the same mount succeeds.
#   mixed_build   — B4 of D-MIXED-VERSION-UNGATED-REPLAY: a build whose
#                   MXFS_PROTO_GEN is older than the volume's
#                   cluster_proto_gen must be refused BEFORE any log
#                   recovery starts.  This build plays the old node; the
#                   volume is stamped gen+1.  Proof of "before recovery":
#                   the log is left DIRTY (forced shutdown w/o log flush),
#                   the refused mount logs zero recovery lines, and once
#                   the gen is restored the SAME dirty log replays
#                   ("Starting recovery"), i.e. the refusal touched nothing.
#
# The loop arms run on PROBE (default test32) with its shared mount taken
# down for the duration (one mxfs mount at a time), restored at the end.
# derived time budgets: loop arms ~90s; hb arms ~120s.
#
# usage: vergate.sh [probe_node=test32] [arm...]
set -u
PN="${1:-test32}"
shift 2>/dev/null || true
ONLY=("$@")
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$PN"; LUN=$MXFS_DEV_RESOLVED
IMG=/tmp/vergate_loop.img
# sess435: VG_DEV=/dev/mapper/mpatha runs the "loop arms" on the SHARED LUN instead
# (CAW-capable; fleet must be unmounted; a prep re-mkfs's it afterwards) — needed
# because 0.41.3 refuses CAW-less devices at admission (D-0359 step 1).
DEV=${VG_DEV:-/dev/loop7}
FAILS=0; PASSES=0
RUN=$$   # unique per-run dmesg tag suffix — the kernel ring buffer keeps
         # prior runs' tags, and sed anchors on the FIRST match (sess191)

want() { [ ${#ONLY[@]} -eq 0 ] && return 0; local c; for c in "${ONLY[@]}"; do [ "$c" = "$1" ] && return 0; done; return 1; }
verdict() { if [ "$2" -eq 0 ]; then PASSES=$((PASSES+1)); echo "RESULT: PASS | $1 | $3"; else FAILS=$((FAILS+1)); echo "RESULT: FAIL | $1 | $3"; fi; }

# strip_gate <node> <dev>: python zeroes envelope PROTOGATE flag+proto_gen and
# clears sb bit 30 on every AG sb copy, fixing all CRCs — synthesizes a
# legacy-format fs from a gated one.
strip_gate() {
  $SSH "$1" "python3 - <<'EOF'
import struct, sys
dev='$2'
f=open(dev,'r+b')
sup=bytearray(f.read(4096))
# crc32c seeded ~0, NO final complement — matches tools' crc32c(~0U, buf, len).
# MXFS envelope stores it directly; XFS sb stores its complement.
def mxfs_crc(buf):
    c=0xFFFFFFFF
    tab=[]
    for i in range(256):
        x=i
        for _ in range(8): x=(x>>1)^0x82F63B78 if x&1 else x>>1
        tab.append(x)
    for b in buf: c=tab[(c^b)&0xFF]^(c>>8)
    return c
flags,=struct.unpack_from('<I',sup,8)
struct.pack_into('<I',sup,8,flags & ~1)      # clear PROTOGATE
struct.pack_into('<I',sup,104,0)             # cluster_proto_gen=0
struct.pack_into('<I',sup,12,0)              # crc=0
struct.pack_into('<I',sup,12,mxfs_crc(bytes(sup)))
f.seek(0); f.write(sup)
xoff,=struct.unpack_from('<Q',sup,88)
f.seek(xoff); sb=bytearray(f.read(512))
bsz,=struct.unpack_from('>I',sb,4)
agb,=struct.unpack_from('>I',sb,0x54)
agc,=struct.unpack_from('>I',sb,0x58)
for ag in range(agc):
    off=xoff+ag*agb*bsz
    f.seek(off); s=bytearray(f.read(512))
    inc,=struct.unpack_from('>I',s,0xD8)
    struct.pack_into('>I',s,0xD8,inc & ~(1<<30))
    struct.pack_into('<I',s,0xE0,0)
    c=mxfs_crc(bytes(s))
    struct.pack_into('<I',s,0xE0,c ^ 0xFFFFFFFF)   # XFS: final complement
    f.seek(off); f.write(s)
f.flush(); f.close()
print('stripped agc=%d'%agc)
EOF" 2>/dev/null
}

# stamp_gen <node> <dev> <delta>: add <delta> to the envelope's
# cluster_proto_gen (PROTOGATE flag untouched), refresh the envelope CRC,
# print "old->new".  Only the 4K envelope super is touched — the XFS sb
# region (and its dirty log) is left byte-identical.
# sess433: md5 of one per-node XFS log slice on a raw device.  $3 = the
# kernel's log daddr (XFS 512 B units, already includes the slice offset),
# $4 = bblks; raw byte range = envelope xfs_data_offset (super byte 88) +
# daddr*512.
slice_md5() {
  [ "$4" -gt 0 ] 2>/dev/null || { echo ""; return; }
  $SSH "$1" "python3 - <<'EOF'
import struct, hashlib
f=open('$2','rb'); s=f.read(4096)
xo=struct.unpack_from('<Q', s, 88)[0]
f.seek(xo + $3*512); print(hashlib.md5(f.read($4*512)).hexdigest())
EOF" 2>/dev/null | tr -d '\r\n '
}
stamp_gen() {
  $SSH "$1" "python3 - <<'EOF'
import struct
dev='$2'; delta=$3
f=open(dev,'r+b')
sup=bytearray(f.read(4096))
def mxfs_crc(buf):
    c=0xFFFFFFFF
    tab=[]
    for i in range(256):
        x=i
        for _ in range(8): x=(x>>1)^0x82F63B78 if x&1 else x>>1
        tab.append(x)
    for b in buf: c=tab[(c^b)&0xFF]^(c>>8)
    return c
old,=struct.unpack_from('<I',sup,104)
struct.pack_into('<I',sup,104,old+delta)
struct.pack_into('<I',sup,12,0)
struct.pack_into('<I',sup,12,mxfs_crc(bytes(sup)))
f.seek(0); f.write(sup); f.flush(); f.close()
print('%d->%d'%(old,old+delta))
EOF" 2>/dev/null
}

# ── loop arms ──────────────────────────────────────────────────────────────
if want legacy_refuse || want upgrade || want mixed_build || want noncaw_refuse; then
  # SPARSE image (truncate, NOT fallocate): node root disks are ~6 GB; a
  # preallocated 4 GB image fills them (sess42: test32 hit 100% and every
  # later ko copy truncated — a whole prep cascade).  mkfs writes little.
  # Stale-residue guard (sess191): a pre-sess187 harness incident could leave
  # /mnt/vgate/b4/marker on the node's ROOT fs; it poisons any later
  # marker-existence check, so clear it while nothing is mounted there.
  # sess432: since 0.15.0 (sess378 fence-capability admission) a device with
  # no SCSI PR is REFUSED at mount (P303-FENCECAP-NOCAPS, -95) unless the
  # operator states the rig cannot fence: mxfs.fence_capability_override=1.
  # A loop device has no PR, so every loop arm needs the override for the
  # duration (restored to 0 at teardown).  Without it the three s419-s421
  # mixed_build runs failed at their own setup mount with ENOTCONN.
  case "$DEV" in
  /dev/loop*)
    $SSH "$PN" "umount /mnt/shared 2>/dev/null; umount /mnt/vgate 2>/dev/null; rm -f /mnt/vgate/b4/marker; rmdir /mnt/vgate/b4 2>/dev/null; mkdir -p /mnt/vgate; rm -f /tmp/vergate_loop.img; truncate -s 4G $IMG && losetup -D 2>/dev/null; losetup $DEV $IMG 2>/dev/null || true; echo 1 > /sys/module/mxfs/parameters/fence_capability_override; losetup -l | grep -c loop7" >/dev/null 2>&1
    ;;
  *)
    # shared LUN: nobody may be mounted anywhere (sess435 LUN port)
    VGD=$(mktemp -d)
    for i in $(seq 1 32); do
      ( timeout 12 $SSH "test$i" "umount /mnt/shared 2>/dev/null; mount -t mxfs | grep -c shared" > "$VGD/test$i" 2>/dev/null ) &
    done
    wait
    STILL=$(grep -l '^1' "$VGD"/test* 2>/dev/null | wc -l)
    [ "$STILL" = "0" ] || { echo "RESULT: FAIL | vergate | precondition: $STILL node(s) still mounted on $DEV"; exit 1; }
    $SSH "$PN" "umount /mnt/vgate 2>/dev/null; rm -f /mnt/vgate/b4/marker; rmdir /mnt/vgate/b4 2>/dev/null; mkdir -p /mnt/vgate" >/dev/null 2>&1
    ;;
  esac
  MK=$($SSH "$PN" "/src/mxfs/tools/mkfs_mxfs -f $DEV 2>&1 | tail -1" 2>/dev/null)
  ST=
  # sess435 (D-0359 step 1, ruling arm 1/14): a loop device has no SCSI
  # COMPARE AND WRITE, so the CAW-transport mount must be REFUSED at
  # admission (P311-CAW-CAP UNSUPPORTED -> P311-CAW-ADMISSION-REFUSED), with
  # or without single_node_exclusive=1, and must NOT print 'DLM initialized
  # (CAW' or start any lock traffic.  Until the SNLOCAL_EXCLUSIVE mode lands
  # (D-0359 step 2) the three loop arms below cannot mount at all and FAIL
  # by design — run them on the LUN, or wait for step 2.
  if want noncaw_refuse; then
    # sess453 (0.60.0, review-#3 D5): with fence_capability_override=1 and
    # single_node_exclusive=0 the mount is now refused EARLIER, at the
    # fence-capability admission (P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED),
    # before the slot claim where the CAW capability is proved — so the first
    # attempt asserts that refusal and only the second (snx=1) reaches P311.
    NR=$($SSH "$PN" "echo VG-NR-$RUN > /dev/kmsg; echo 0 > /sys/module/mxfs/parameters/single_node_exclusive; mount -t mxfs /dev/loop7 /mnt/vgate 2>&1 >/dev/null; echo rc=\$?; echo 1 > /sys/module/mxfs/parameters/single_node_exclusive; mount -t mxfs /dev/loop7 /mnt/vgate 2>&1 >/dev/null; echo rc2=\$?; echo 0 > /sys/module/mxfs/parameters/single_node_exclusive; umount /mnt/vgate 2>/dev/null; D=\$(dmesg | sed -n '/VG-NR-$RUN/,\$p'); echo ovr=\$(echo \"\$D\" | grep -c 'P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED'); echo cap=\$(echo \"\$D\" | grep -c 'P311-CAW-CAP.*UNSUPPORTED'); echo refused=\$(echo \"\$D\" | grep -c 'P311-CAW-ADMISSION-REFUSED'); echo init=\$(echo \"\$D\" | grep -c 'DLM initialized (CAW'); echo caw95=\$(echo \"\$D\" | grep -c 'caw_slot .* I/O error -95'); echo vg=\$(grep -c ' /mnt/vgate ' /proc/mounts)" 2>/dev/null | tr '\n' ' ')
    OK=1
    case "$NR" in *"rc=32 "*"rc2=32 "*"ovr=1 cap=1 refused=1 init=0 caw95=0 vg=0"*) OK=0;; esac
    verdict noncaw_refuse $OK "$NR"
  fi
  if want legacy_refuse || want upgrade; then
    ST=$(strip_gate "$PN" $DEV)
  fi
  if want legacy_refuse; then
    R1=$($SSH "$PN" "echo 0 > /sys/module/mxfs/parameters/legacy_rw; echo VG-LR1-$RUN > /dev/kmsg; mount -t mxfs $DEV /mnt/vgate 2>&1; echo rc=\$?; dmesg | sed -n '/VG-LR1-$RUN/,\$p' | grep -c 'legacy (pre-protogate)'" 2>/dev/null | tr '\n' ' ')
    R2=$($SSH "$PN" "echo 1 > /sys/module/mxfs/parameters/legacy_rw; mount -t mxfs $DEV /mnt/vgate 2>&1; echo rc=\$?; mount -t mxfs | grep -c vgate; umount /mnt/vgate 2>/dev/null; echo 0 > /sys/module/mxfs/parameters/legacy_rw" 2>/dev/null | tr '\n' ' ')
    case "$R1" in *"rc=32 1"*) LR1=0;; *) LR1=1;; esac
    case "$R2" in *"rc=0 1"*) LR2=0;; *) LR2=1;; esac
    verdict legacy_refuse $((LR1|LR2)) "strip=$ST refuse='$R1' legacyrw_mount='$R2'"
  fi
  if want upgrade; then
    U1=$($SSH "$PN" "/src/mxfs/tools/chk_mxfs -U $DEV 2>&1 | tail -1" 2>/dev/null)
    U2=$($SSH "$PN" "/src/mxfs/tools/chk_mxfs -U $DEV 2>&1 | tail -1" 2>/dev/null)   # idempotence
    R3=$($SSH "$PN" "mount -t mxfs $DEV /mnt/vgate 2>&1; echo rc=\$?; mount -t mxfs | grep -c vgate; umount /mnt/vgate 2>/dev/null" 2>/dev/null | tr '\n' ' ')
    OK=1
    case "$U1" in *COMPLETE*) case "$R3" in *"rc=0 1"*) OK=0;; esac;; esac
    verdict upgrade $OK "u1='$U1' u2='$U2' mount='$R3'"
  fi
  if want mixed_build; then
    # Ensure the gate is present (idempotent; restores it if the strip arms
    # ran first, no-op on a fresh gated mkfs).
    $SSH "$PN" "/src/mxfs/tools/chk_mxfs -U $DEV >/dev/null 2>&1" 2>/dev/null
    # Dirty the log: mount, fsync a file into the journal, force shutdown
    # WITHOUT a log flush (XFS_IOC_GOINGDOWN, NOLOGFLUSH=2), umount.  The
    # unmount record is never written, so the next mount needs recovery.
    # sess191: single_node_exclusive=1 for the whole arm — this is a
    # host-private loop device, so the operator assertion is TRUE, and since
    # the dirty-slice work (sess184-190) the shutdown umount leaves a
    # WITHDRAWN slot whose slice MB3 must fence-certify and replay before
    # admission; without the assertion a loop device (no PR) cannot certify
    # and the MB3 mount correctly fails -EBUSY after the admission wait.
    # The victim mount needs it too (write-time snlocal marker at claim).
    # sess432: the GOINGDOWN ioctl number (0x8004587d) is SHARED with
    # EXT4_IOC_SHUTDOWN.  When the loop mount failed (s419-s421, ENOTCONN)
    # /mnt/vgate was a plain directory on the node's ext4 ROOT fs and this
    # ioctl SHUT DOWN THE ROOT FILESYSTEM ('EXT4-fs (dm-0): shut down
    # requested (2)', root-fs EIO, ssh reset) — the harness, not MXFS, killed
    # test32.  The ioctl now runs only after /proc/mounts proves /mnt/vgate is
    # an mxfs mount.
    # sess433 (D-0355 loop arm, sess432 ruling): a loop device has no CAW, so
    # a recovery can NEVER publish (purge_cas_zero -EOPNOTSUPP by design) and
    # MB3's old "replayed + file present" oracle is unreachable here.  The C7
    # proof MB3 exists for is "the refusal happened before recovery touched
    # the log", so it is now a BYTE-COMPARE of the dirty per-node log slice
    # before and after the refused MB2 mount (slice geometry from the kernel's
    # 'per-node log slice N/M offset= bblks=' line, raw range =
    # xfs_data_offset + daddr*512), plus 'Starting recovery' on MB3 after the
    # gen is restored (replay ATTEMPTED on the same, untouched log).
    MB1=$($SSH "$PN" "echo VG-MB1-$RUN > /dev/kmsg; echo 1 > /sys/module/mxfs/parameters/single_node_exclusive; mount -t mxfs $DEV /mnt/vgate 2>&1; echo rc=\$?; python3 - <<'EOF'
import os, fcntl, struct, sys
mounted=False
for line in open('/proc/mounts'):
    f=line.split()
    if len(f)>=3 and f[1]=='/mnt/vgate' and f[2]=='mxfs':
        mounted=True
if not mounted:
    print('NOT-MXFS-MOUNT: refusing GOINGDOWN (ioctl is shared with EXT4_IOC_SHUTDOWN)')
    sys.exit(0)
os.makedirs('/mnt/vgate/b4', exist_ok=True)
fd=os.open('/mnt/vgate/b4/marker', os.O_CREAT|os.O_WRONLY, 0o644)
os.write(fd, b'B4-mixed-build')
os.fsync(fd)
os.close(fd)
dfd=os.open('/mnt/vgate', os.O_RDONLY)
fcntl.ioctl(dfd, 0x8004587d, struct.pack('I', 2))   # GOINGDOWN NOLOGFLUSH
os.close(dfd)
print('shutdown-ok')
EOF
umount /mnt/vgate 2>&1; echo urc=\$?; dmesg | sed -n '/VG-MB1-$RUN/,\$p' | grep -o 'per-node log slice [0-9]*/[0-9]* offset=[0-9]* bblks=[0-9]*' | tail -1" 2>/dev/null | tr '\n' ' ')
    SOFF=$(echo "$MB1" | grep -o 'offset=[0-9]*' | tail -1 | cut -d= -f2); SBB=$(echo "$MB1" | grep -o 'bblks=[0-9]*' | tail -1 | cut -d= -f2)
    SL1=$(slice_md5 "$PN" $DEV "${SOFF:-0}" "${SBB:-0}")
    # Stamp the volume one generation AHEAD of this build and try to mount:
    # must be refused (-EPROTONOSUPPORT, rc=32) with ZERO recovery lines.
    G1=$(stamp_gen "$PN" $DEV 1)
    MB2=$($SSH "$PN" "echo VG-MB2-$RUN > /dev/kmsg; mount -t mxfs $DEV /mnt/vgate 2>&1 >/dev/null; echo rc=\$?; dmesg | sed -n '/VG-MB2-$RUN/,\$p' | grep -c 'refusing mount (upgrade the mismatched side)'; dmesg | sed -n '/VG-MB2-$RUN/,\$p' | grep -c 'recovery'" 2>/dev/null | tr '\n' ' ')
    # Restore the gen: the SAME log must now replay — proof the refusal
    # happened before recovery touched anything.
    SL2=$(slice_md5 "$PN" $DEV "${SOFF:-0}" "${SBB:-0}")
    G2=$(stamp_gen "$PN" $DEV -1)
    MB3=$($SSH "$PN" "echo VG-MB3-$RUN > /dev/kmsg; mount -t mxfs $DEV /mnt/vgate 2>&1 >/dev/null; echo rc=\$?; dmesg | sed -n '/VG-MB3-$RUN/,\$p' | grep -c 'Starting recovery'; grep -aq B4-mixed-build /mnt/vgate/b4/marker 2>/dev/null && echo file=1 || echo file=0; umount /mnt/vgate 2>/dev/null; echo 0 > /sys/module/mxfs/parameters/single_node_exclusive" 2>/dev/null | tr '\n' ' ')
    OK=1
    case "$MB1" in *"rc=0 shutdown-ok"*"per-node log slice"*)
      case "$MB2" in *"rc=32 1 0"*)
        if [ -n "$SL1" ] && [ "$SL1" = "$SL2" ]; then
          MB3N=$(echo "$MB3" | grep -o 'rc=[0-9]* [0-9]*' | tail -1 | awk '{print $2}')
          [ "${MB3N:-0}" -ge 1 ] 2>/dev/null && OK=0
          # sess435: on a CAW device (LUN port) the replay can PUBLISH, so the
          # original B4 durability leg is asserted again: the fsync'd marker
          # must be present after the post-restore replay.  A loop device
          # cannot publish (-95 by design) and keeps the byte-compare oracle.
          case "$DEV" in /dev/loop*) ;; *) case "$MB3" in *"file=1"*) ;; *) OK=1;; esac;; esac
        fi;; esac;; esac
    verdict mixed_build $OK "dirty='$MB1' slice=${SOFF:-?}+${SBB:-?}bb md5_before=$SL1 md5_after=$SL2 gen=$G1 refused='$MB2' restore=$G2 replay_attempt='$MB3'"
  fi
  $SSH "$PN" "echo 0 > /sys/module/mxfs/parameters/single_node_exclusive; echo 0 > /sys/module/mxfs/parameters/fence_capability_override; case $DEV in /dev/loop*) losetup -d $DEV 2>/dev/null; rm -f /tmp/vergate_loop.img;; esac; mount -t mxfs $LUN /mnt/shared 2>&1 | tail -1" >/dev/null 2>&1
  sleep 3
  RB=$($SSH "$PN" "mount -t mxfs | grep -c shared" 2>/dev/null | tr -d ' \r\n')
  [ "${RB:-0}" = "1" ] || echo "WARN: $PN shared remount says '$RB' (rejoin manually if needed)"
fi

# ── hb arms (shared LUN, live cluster) ─────────────────────────────────────
fake_hb_start() { # fake_hb_start <node> <slot> — background fake-legacy writer
  $SSH "$1" "echo ${2:-63} > /tmp/vgate_fake.slot; nohup python3 - <<'EOF' >/dev/null 2>&1 &
import struct, time, os
dev='$LUN'
f=os.open(dev, os.O_RDWR)
sup=os.pread(f,4096,0)
dloff,=struct.unpack_from('<Q',sup,64)
real=os.pread(f,512,dloff)          # slot 0's record for fs_gen
fs_gen,=struct.unpack_from('<I',real,12)
epoch=int(time.time())
slot=int(open('/tmp/vgate_fake.slot').read())
open('/tmp/vgate_fake.pid','w').write(str(os.getpid()))
for i in range(90):
    b=bytearray(512)
    struct.pack_into('<I',b,0,0x4D584C4B)       # MXLK
    struct.pack_into('<I',b,4,1)                # ACTIVE
    struct.pack_into('<I',b,8,990)              # node_id
    struct.pack_into('<I',b,12,fs_gen)
    struct.pack_into('<Q',b,16,int(time.time()*1000))
    struct.pack_into('<Q',b,24,epoch)
    os.pwrite(f,bytes(b),dloff+slot*512)
    os.fsync(f)
    time.sleep(2)
EOF
sleep 1; cat /tmp/vgate_fake.pid" 2>/dev/null
}
fake_hb_stop() { # fake_hb_stop <node> — kill writer + zero slot 63
  $SSH "$1" "kill \$(cat /tmp/vgate_fake.pid) 2>/dev/null; sleep 1; python3 - <<'EOF'
import struct, os
f=os.open('$LUN', os.O_RDWR)
sup=os.pread(f,4096,0)
dloff,=struct.unpack_from('<Q',sup,64)
slot=int(open('/tmp/vgate_fake.slot').read())
os.pwrite(f,b'\x00'*512,dloff+slot*512)
os.fsync(f)
os.close(f)
print('zeroed')
EOF" 2>/dev/null
}

hbcounts() { # hbcounts <node> <slot> — "vergate fence mounts shutdowns", one ssh, one retry
  local out try
  for try in 1 2; do
    out=$($SSH "$1" "R=$HBRID; V=\$(dmesg | sed -n \"/\$R/,\\\$p\" | grep -c 'P-VERGATE slot=$2 '); F=\$(dmesg | sed -n \"/\$R/,\\\$p\" | grep -c 'P-VERGATE-FENCE slot=$2 '); M=\$(mount -t mxfs | wc -l); S=\$(dmesg | grep -c SHUTDOWN); echo \$V \$F \$M \$S" 2>/dev/null | tr -d '\r')
    [ -n "$out" ] && { echo "$out"; return 0; }
    sleep 2
  done
  echo ""
}

if want hb_intruder; then
  HBRID="VGHB$(date +%s)"
  # Fresh random free slot (40-59): a FIRST-join intruder (last_epoch==0)
  # takes the direct live-transition -> vergate path.  Reusing one slot
  # across runs instead exercises the epoch-change -> fire_dead -> recovery
  # resolution first, which legitimately delays (not defeats) the fence.
  FSLOT=$((40 + RANDOM % 20))
  for n in test1 test2; do $SSH "$n" "echo $HBRID > /dev/kmsg" >/dev/null 2>&1; done
  PID=$(fake_hb_start test1 "$FSLOT")
  V1=0; F1=0; WAITED=0
  while [ $WAITED -lt 60 ]; do
    sleep 5; WAITED=$((WAITED+5))
    C1=$(hbcounts test2 "$FSLOT")
    V1=$(echo "$C1" | awk '{print $1}'); F1=$(echo "$C1" | awk '{print $2}')
    [ "${V1:-0}" -ge 1 ] && [ "${F1:-0}" -ge 1 ] && break
  done
  sleep 10
  C2=$(hbcounts test2 "$FSLOT"); V2=$(echo "$C2" | awk '{print $1}'); M2=$(echo "$C2" | awk '{print $3}'); S2=$(echo "$C2" | awk '{print $4}')
  OK=1
  [ "${V1:-0}" -ge 1 ] && [ "${F1:-0}" -ge 1 ] && [ "${V2:-0}" = "${V1:-0}" ] && \
      [ "${M2:-0}" = "1" ] && [ "${S2:-1}" = "0" ] && OK=0
  verdict hb_intruder $OK "slot=$FSLOT detect<=${WAITED}s vergate=$V1 fence=$F1 after10s=$V2 (once-per-epoch) mounts=$M2 shutdowns=$S2 pid=$PID"
  [ -z "${KEEP_FAKE:-}" ] && want join_refuse || fake_hb_stop test1 >/dev/null
fi

if want join_refuse; then
  JRID="VGJN$(date +%s)"
  # writer may still be running from hb_intruder; ensure it is
  RUN=$($SSH test1 "kill -0 \$(cat /tmp/vgate_fake.pid) 2>/dev/null && echo yes || echo no" 2>/dev/null | tr -d ' \r\n')
  [ "$RUN" = "yes" ] || PID=$(fake_hb_start test1)
  J1=$($SSH "$PN" "R=$JRID; umount /mnt/shared 2>/dev/null; echo \$R > /dev/kmsg; mount -t mxfs $LUN /mnt/shared 2>&1; echo rc=\$?; dmesg | sed -n \"/\$R/,\\\$p\" | grep -c 'withdrawing (join refused)'" 2>/dev/null | tr '\n' ' ')
  fake_hb_stop test1 >/dev/null
  sleep 2
  J2=$($SSH "$PN" "mount -t mxfs $LUN /mnt/shared 2>&1; echo rc=\$?; mount -t mxfs | grep -c shared" 2>/dev/null | tr '\n' ' ')
  OK=1
  case "$J1" in *"rc=32 1"*) case "$J2" in *"rc=0 1"*) OK=0;; esac;; esac
  verdict join_refuse $OK "refused='$J1' after_stop='$J2'"
fi

echo "SUMMARY: vergate pass=$PASSES fail=$FAILS"
[ $FAILS -eq 0 ]
