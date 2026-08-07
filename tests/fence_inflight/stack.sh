#!/bin/bash
# stack.sh — build/tear down the isolated delayed LUN used by the
# D-PR-FENCE-PREEMPT-WITHOUT-ABORT step-4 in-flight exclusion harness.
#
# Everything here is DELIBERATELY separate from the production 32-node rig:
# its own backing file, its own dm device, its own SCST device, its own IQN,
# and two purpose-made open-iscsi ifaces.  The 64 production sessions on
# iqn.2026-05.local.mxfs:shared are never touched.
#
# TWO MODES.  MXFS_FENCE_MODE=blockio (default) is stage (i) of the ruled plan
# — the feasibility harness that validates the METHOD.  MXFS_FENCE_MODE=fileio
# is stage (ii), and it is the one that carries closure weight: the SHIPPED
# production LUN is vdisk_fileio (device "mxfs", filename /home/steve/disk.img
# on ext4, o_direct=1, blocksize=512, nv_cache=0, write_through=0), and the
# ruling is explicit that agreement between the two handlers' code does not
# substitute for measuring the one that ships.
#
# Stage (i) stack, bottom to top:
#   /var/lib/mxfs-fence/blk-backing.img   preallocated, initialized
#     -> /dev/loopN                       losetup --direct-io=on (VERIFIED on)
#        -> /dev/mapper/mxfsfence         dm-delay, write delay switchable
#           -> SCST vdisk_blockio "fencedelay"
#              -> iqn.2026-08.mxfs.fence:inflight LUN 0
#                 -> two local iSCSI sessions, distinct iface.initiatorname:
#                      fnc_v -> iqn.2026-08.mxfs.fence:victim
#                      fnc_s -> iqn.2026-08.mxfs.fence:survivor
#
# Stage (ii) stack adds the two layers the shipped handler really has:
#   /var/lib/mxfs-fence/fio-backing.gN.img  preallocated, initialized
#     -> /dev/loopN                       losetup --direct-io=on (VERIFIED on)
#        -> /dev/mapper/mxfsfencefN       dm-delay, write delay switchable
#           -> ext4 (mkfs defaults, same fs type as production), noatime
#              -> /var/lib/mxfs-fence/fiomnt.gN/disk.img
#                                         preallocated AND zero-initialized, so
#                                         every tested extent is already
#                                         written: an O_DIRECT overwrite needs
#                                         no allocation, no unwritten-extent
#                                         conversion and no journal transaction
#                 -> SCST vdisk_fileio "fencedelayf" o_direct=1 blocksize=512
#                    -> iqn.2026-08.mxfs.fence:inflightf LUN 0 -> same 2 ifaces
#
# The OBSERVATION POINT in BOTH modes is /dev/loopN — the device immediately
# BELOW dm-delay.  Buffered reads of it are unsound (five cache aliases between
# target and backing file), so the harness only ever reads it with aligned
# O_DIRECT.  In blockio mode a LUN LBA is that device's sector directly; in
# fileio mode it is wherever disk.img's extent map puts it, which is why
# `stack.sh fiemap` exists and why the map is re-recorded around every run.
#
# The two modes are mutually exclusive by construction — separate backing
# image, dm name, SCST device and target — so bringing one up cannot silently
# reuse the other's leftovers, but only one should be up at a time.
#
# ── GENERATIONS AND THE QUARANTINE (sess142) ────────────────────────────────
#
# The stage-(ii) stack used to build on ONE fixed image path, and `down`
# deliberately KEPT the image.  That turned out to be load-bearing in the worst
# way: sess136's GPF (the SCST fileio bvec UAF, since fixed) killed the loop
# worker INSIDE __iomap_dio_rw(), so inode_dio_end() never ran and the backing
# file's inode was left with i_dio_count=1 — measured, not inferred, with
# scripts/inode_dio_probe.  Every exclusive-path O_DIRECT write to that inode
# then blocks forever in inode_dio_wait(), while reads keep working.  Because
# the image was kept, EVERY later `up` re-attached the same poisoned inode, and
# stage (ii) never once ran.  A fresh loop device does not help; only a fresh
# INODE does.
#
# So the fileio stack is now GENERATIONAL.  Generation N owns its own image, dm
# name and mount point, and `newgen` moves to a brand-new inode.  The original
# unnumbered names (fio-backing.img / mxfsfencef / fiomnt) are generation 0 and
# are PERMANENTLY QUARANTINED: its loop worker still sleeps in
# wait_var_event(&inode->i_dio_count), so detaching the loop or deleting the
# image would free an inode a live kernel task is waiting on.  Nothing here ever
# touches generation 0 again — not `down`, not `purge`.
#
# `up` will not build on a poisoned inode: it reads i_dio_count directly before
# attaching, and then proves the attached loop can complete a write+flush inside
# a RULE-0 budget, using a scratch area at the end of the image that is outside
# the dm-delay mapping (so the gate is non-destructive and can run on every up,
# including a re-up of an already-built generation).
#
# Usage:
#   stack.sh up            build everything and log in both sessions
#   stack.sh down          log out, remove target/device/fs/dm/loop (image kept)
#   stack.sh newgen        move the fileio stack to a fresh generation (fresh
#                          inode); required after a wedge, refused while up
#   stack.sh purge         delete torn-down, non-quarantined generations' images
#   stack.sh quarantine    show the quarantine list
#   stack.sh status        print the resolved device map
#   stack.sh delay <ms>    set the dm-delay WRITE delay (0 = pass through)
#   stack.sh devmap        machine-readable map: LOOP/DM/VICTIM/SURVIVOR devices
#   stack.sh fiemap <byteoff> <len>
#                          fileio mode: physical byte offset ON THE LOOP DEVICE
#                          of a LUN byte range (blockio mode: identity)
#   stack.sh relogin <victim|survivor>
#                          log one nexus out and back in — the only way to fail
#                          a command PREEMPT AND ABORT dropped without a response

set -u

DIR=/var/lib/mxfs-fence
# The LIVE stack records which mode it was built in.  Consumers (inflight_ab.sh
# resolves the device map with `sudo bash stack.sh devmap`, which drops the
# caller's environment) must see the mode of the stack that is actually up, not
# the compiled-in default — otherwise a fileio stack is reported "not up" and,
# worse, an arm could measure the wrong handler.  Explicit MXFS_FENCE_MODE still
# wins, so `MXFS_FENCE_MODE=fileio stack.sh up` selects the mode as before.
MODESTATE=$DIR/mode
MODE=${MXFS_FENCE_MODE:-$( [ -r "$MODESTATE" ] && cat "$MODESTATE" || echo blockio )}
PORTAL=127.0.0.1:3260
IFV=fnc_v
IFS_=fnc_s
IQN_V=iqn.2026-08.mxfs.fence:victim
IQN_S=iqn.2026-08.mxfs.fence:survivor
TROOT=/sys/kernel/scst_tgt/targets/iscsi
DISK_MB=${MXFS_FENCE_DISK_MB:-1024}

# Generation state.  Generation 0 is the QUARANTINED original (unnumbered
# names); a live generation is always >= 1.  MXFS_FENCE_GEN overrides for
# inspection of an older generation, but `up` refuses to build on a quarantined
# one regardless.
GENSTATE=$DIR/fiogen
QFILE=$DIR/quarantine
GEN=${MXFS_FENCE_GEN:-$( [ -r "$GENSTATE" ] && cat "$GENSTATE" || echo 1 )}
case "$GEN" in ''|*[!0-9]*) echo "FATAL: bad generation '$GEN'" >&2; exit 2 ;; esac

# The last MiB of every image is a SCRATCH AREA deliberately left OUTSIDE the
# dm-delay mapping, so the `up` admission gate can prove the loop device really
# completes a write+flush without touching a single byte the LUN can see.
RESERVE_SECTORS=2048

case "$MODE" in
  blockio)
    IMG=$DIR/blk-backing.img
    IMG_MB=${MXFS_FENCE_IMG_MB:-1024}
    DM=mxfsfence
    DEV=fencedelay
    TGT=iqn.2026-08.mxfs.fence:inflight
    H=/sys/kernel/scst_tgt/handlers/vdisk_blockio
    DEVPARAMS="filename=/dev/mapper/mxfsfence"
    MNT=
    DISK=
    ;;
  fileio)
    if [ "$GEN" = 0 ]; then
      IMG=$DIR/fio-backing.img; DM=mxfsfencef; MNT=$DIR/fiomnt
    else
      IMG=$DIR/fio-backing.g$GEN.img; DM=mxfsfencef$GEN; MNT=$DIR/fiomnt.g$GEN
    fi
    DISK=$MNT/disk.img
    IMG_MB=${MXFS_FENCE_IMG_MB:-2048}
    DEV=fencedelayf
    TGT=iqn.2026-08.mxfs.fence:inflightf
    H=/sys/kernel/scst_tgt/handlers/vdisk_fileio
    # Mirrors the production device attribute for attribute.  async=1 is not
    # optional decoration: SCST refuses o_direct without it ("using o_direct
    # without setting async is not supported", vdisk_attach), production runs
    # async=1, and AIO submission is exactly the case the ruling singled out —
    # a handler must not report a command complete while a detached AIO still
    # capable of modifying storage is live.
    DEVPARAMS="filename=$DISK;blocksize=512;o_direct=1;async=1;nv_cache=0;write_through=0"
    ;;
  *) echo "FATAL: MXFS_FENCE_MODE must be blockio or fileio, got '$MODE'" >&2; exit 2 ;;
esac

die() { echo "FATAL: $*" >&2; exit 1; }

loopdev() { losetup -j "$IMG" 2>/dev/null | cut -d: -f1 | head -1; }

# Resolve the /dev/sdX belonging to the session opened on a given iface.
# Two sessions to the same target+portal collide on /dev/disk/by-path, so the
# mapping MUST come from the session tree, not from a by-path symlink.
sd_for_iface() {
  local want="$1" s ifn sd
  for s in /sys/class/iscsi_session/session*; do
    [ -e "$s/targetname" ] || continue
    [ "$(cat "$s/targetname" 2>/dev/null)" = "$TGT" ] || continue
    ifn=$(cat "$s/ifacename" 2>/dev/null)
    [ "$ifn" = "$want" ] || continue
    sd=$(ls "$s/device"/target*/*/block 2>/dev/null | head -1)
    [ -n "$sd" ] && { echo "/dev/$sd"; return 0; }
  done
  return 1
}

iface_iqn() {   # target-side check helper: what initiatorname did the session use
  local want="$1" s
  for s in /sys/class/iscsi_session/session*; do
    [ "$(cat "$s/targetname" 2>/dev/null)" = "$TGT" ] || continue
    [ "$(cat "$s/ifacename" 2>/dev/null)" = "$want" ] || continue
    cat "$s/initiatorname" 2>/dev/null; return 0
  done
  return 1
}

# Sectors MAPPED BY dm-delay — the image minus the reserved scratch tail.
sectors() { echo $((IMG_MB * 1024 * 1024 / 512 - RESERVE_SECTORS)); }
# Byte offset of the scratch area, i.e. the first byte the LUN cannot reach.
probe_off() { echo $(( $(sectors) * 512 )); }

# ── the `up` admission gate ─────────────────────────────────────────────────
#
# is_quarantined <gen>  — 0 if that generation has been condemned.
is_quarantined() {
  [ "$1" = 0 ] && return 0            # generation 0 is condemned by definition
  [ -r "$QFILE" ] || return 1
  grep -q "^gen=$1 " "$QFILE" 2>/dev/null
}

quarantine_gen() {   # <gen> <reason>
  sudo mkdir -p "$DIR"
  printf 'gen=%s img=%s dm=%s loop=%s when=%s reason=%s\n' \
    "$1" "$IMG" "$DM" "$(loopdev)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$2" \
    | sudo tee -a "$QFILE" >/dev/null
  echo "QUARANTINED generation $1: $2" >&2
  echo "  its loop device, dm device, image and mount are now off-limits to" >&2
  echo "  every subcommand — nothing will detach, remove or delete them." >&2
  echo "  Move on with: sudo bash $0 newgen" >&2
}

# Direct read of the in-core inode's i_dio_count.  A nonzero value means an
# earlier O_DIRECT operation on this inode died without its inode_dio_end(), and
# every exclusive-path write to it will block forever in inode_dio_wait().  This
# is a MEASUREMENT and it cannot hang — unlike actually attempting the write.
DIO_PROBE_DIR=$(cd "$(dirname "$0")/../../scripts/inode_dio_probe" 2>/dev/null && pwd)
dio_count() {   # <path> -> prints the integer, or "unknown"
  local p="$1" tok ko="$DIO_PROBE_DIR/inode_dio_probe.ko"
  [ -f "$ko" ] || { echo unknown; return; }
  tok="DIOPROBE-$$-$(date -u +%s%N)"
  echo "$tok" | sudo tee /dev/kmsg >/dev/null
  sudo insmod "$ko" path="$p" 2>/dev/null && sudo rmmod inode_dio_probe 2>/dev/null
  sudo dmesg | sed -n "/$tok/,\$p" | grep -o 'i_dio_count=[0-9]*' | head -1 \
    | cut -d= -f2 | grep -E '^[0-9]+$' || echo unknown
}

# Prove the attached loop device can complete a write AND a flush inside a
# RULE-0 budget.  Non-destructive: it writes only in the reserved tail, which
# dm-delay does not map, so no LUN byte and no filesystem block is touched.
# Budget 5 s against a measured 4-5 ms healthy path — three orders of headroom.
loop_admission_probe() {   # <loopdev>
  local dev="$1" off t0 t1 ms
  off=$(probe_off)
  t0=$(date +%s%N)
  sudo timeout 5 dd if=/dev/zero of="$dev" bs=4096 count=1 seek=$((off / 4096)) \
      oflag=direct conv=fsync,notrunc status=none >/dev/null 2>&1 || return 1
  t1=$(date +%s%N); ms=$(( (t1 - t0) / 1000000 ))
  echo "loop_admission_probe ${dev} write+flush ${ms}ms (budget 5000ms)"
  return 0
}

# ── stage (ii) only: the ext4 + preallocated disk.img between dm-delay and the
# SCST fileio handler.  Built once and then left alone; a re-run must never
# re-mkfs, because that would silently move disk.img's extents out from under
# an in-progress A/B and invalidate every offset the harness recorded.
fio_layers() {
  local dmdev=/dev/mapper/$DM fstype
  fstype=$(sudo blkid -o value -s TYPE "$dmdev" 2>/dev/null || true)
  if [ -z "$fstype" ]; then
    echo "mkfs.ext4 on $dmdev (first build)"
    # Defaults, like production's /home/steve/disk.img filesystem.  No
    # encryption, no compression, no reflink — ext4 has none of the three, so
    # the ruled exclusions hold by construction rather than by option.
    sudo mkfs.ext4 -q -F -L mxfsfence "$dmdev" || die "mkfs.ext4 failed"
  elif [ "$fstype" != ext4 ]; then
    die "$dmdev already holds a '$fstype' filesystem — refusing to overwrite"
  fi
  sudo mkdir -p "$MNT"
  if ! mountpoint -q "$MNT"; then
    sudo mount -o noatime "$dmdev" "$MNT" || die "mount $dmdev failed"
  fi
  echo "ext4 mounted: $(findmnt -no SOURCE,FSTYPE,OPTIONS "$MNT")"

  if [ ! -f "$DISK" ]; then
    echo "creating $DISK (${DISK_MB} MiB, preallocated + zero-initialized)"
    sudo fallocate -l "${DISK_MB}M" "$DISK" || die "fallocate $DISK failed"
    # Initialization is not cosmetic.  fallocate leaves UNWRITTEN extents,
    # which read back as zeroes whatever the target wrote and would make
    # "pattern absent" meaningless; writing real zeroes converts them, so
    # every later O_DIRECT overwrite touches an already-initialized extent and
    # needs no ext4 metadata change at all.
    sudo dd if=/dev/zero of="$DISK" bs=1M count="$DISK_MB" conv=notrunc \
        oflag=direct status=none || die "disk.img init failed"
    sudo sync -f "$DISK" || die "sync of $DISK failed"
  fi
  echo "disk=$DISK bytes=$(sudo stat -c %s "$DISK")"
}

# Translate a LUN byte offset into the byte offset of the SAME data on the loop
# device below dm-delay.  blockio: the LUN IS the dm device, so it is identity.
# fileio: the LUN is disk.img, so it is that file's extent map — obtained from
# FIEMAP programmatically, and refused unless the range lies wholly inside one
# initialized, unshared, directly-mapped extent.
fiemap_off() {
  local off="$1" len="${2:-4096}"
  if [ "$MODE" = blockio ]; then
    echo "fiemap mode=blockio byteoff=$off len=$len phys=$off identity=1"
    return 0
  fi
  sudo "$(dirname "$0")/prprobe" fiemap "$DISK" "$off" "$len"
}

up() {
  sudo modprobe dm-delay 2>/dev/null
  sudo mkdir -p "$DIR"

  if [ "$MODE" = fileio ] && is_quarantined "$GEN"; then
    die "fileio generation $GEN is QUARANTINED — run 'newgen' and try again"
  fi

  if [ ! -f "$IMG" ]; then
    echo "creating $IMG (${IMG_MB} MiB, preallocated + initialized)"
    # O_CREAT|O_EXCL, so a generation can never silently adopt a file that
    # already existed under its name (the ruling: "use a genuinely new file
    # created with O_CREAT|O_EXCL; do not recycle names").
    sudo bash -c "set -C; : > '$IMG'" || die "image $IMG already exists — refusing to recycle"
    sudo fallocate -l "${IMG_MB}M" "$IMG" || die "fallocate failed"
    # Initialize: a preallocated-but-unwritten extent can read back as a hole
    # and would make "pattern absent" ambiguous.  Write real zeros.
    sudo dd if=/dev/zero of="$IMG" bs=1M count="$IMG_MB" conv=notrunc \
        oflag=direct status=none || die "image init failed"
  fi

  # ADMISSION GATE 1 — the inode.  Read the counter that decides whether an
  # exclusive-path write can ever complete on this file, BEFORE attaching
  # anything to it.  This measurement cannot itself hang.
  local dc; dc=$(dio_count "$IMG")
  echo "admission: $IMG i_dio_count=$dc"
  if [ "$dc" != 0 ] && [ "$dc" != unknown ]; then
    quarantine_gen "$GEN" "i_dio_count=$dc on $IMG before attach (leaked DIO)"
    die "refusing to build on a poisoned inode"
  fi

  local LOOP; LOOP=$(loopdev)
  if [ -z "$LOOP" ]; then
    # Bounded: attaching a backing file whose inode still carries a leaked
    # i_dio_count (sess141) can block here, and an unbounded block is unkillable.
    LOOP=$(timeout 60 sudo losetup --find --show --direct-io=on "$IMG") \
      || die "losetup did not attach $IMG within 60s — backing inode may still hold a leaked i_dio_count"
  fi
  # The ruling requires CONFIRMING direct-io did not silently fall back.
  local dio; dio=$(cat "/sys/block/$(basename "$LOOP")/loop/dio" 2>/dev/null)
  [ "$dio" = "1" ] || die "loop $LOOP direct-io is '$dio', not 1 — observation path unsound"
  echo "loop=$LOOP direct_io=$dio"

  # ADMISSION GATE 2 — the attached device.  A healthy loop completes this in
  # 4-5 ms; a poisoned one never completes it at all.  Runs on EVERY up, and is
  # non-destructive because the target sector is outside the dm-delay mapping.
  if ! loop_admission_probe "$LOOP"; then
    quarantine_gen "$GEN" "loop $LOOP did not complete a 4KiB write+flush within 5s"
    die "loop $LOOP is wedged — NOT detaching it (it may still own stranded work)"
  fi

  if ! sudo dmsetup ls 2>/dev/null | grep -q "^$DM"; then
    echo "0 $(sectors) delay $LOOP 0 0 $LOOP 0 0" | timeout 30 sudo dmsetup create "$DM" \
      || die "dmsetup create $DM did not return within 30s"
  fi
  echo "dm=/dev/mapper/$DM"

  [ "$MODE" = fileio ] && fio_layers

  if [ ! -d /sys/kernel/scst_tgt/devices/$DEV ]; then
    echo "add_device $DEV $DEVPARAMS" | sudo tee $H/mgmt >/dev/null \
      || die "SCST add_device failed"
  fi
  if [ "$MODE" = fileio ]; then
    # The ruling requires CONFIRMING o_direct is actually in force rather than
    # assuming the parameter took: a buffered fileio LUN would let a write be
    # reported complete while its bytes were still only in clyde's page cache,
    # which is precisely the ambiguity the whole measurement exists to remove.
    # SCST appends a "[key]" marker line to attributes it persists — take the
    # value line only.
    local od; od=$(sudo cat /sys/kernel/scst_tgt/devices/$DEV/o_direct 2>/dev/null | head -1)
    [ "$od" = "1" ] || die "SCST device $DEV o_direct='$od', not 1 — fileio path unsound"
    local bs; bs=$(sudo cat /sys/kernel/scst_tgt/devices/$DEV/blocksize 2>/dev/null | head -1)
    [ "$bs" = "512" ] || die "SCST device $DEV blocksize='$bs', not 512"
    local as; as=$(sudo cat /sys/kernel/scst_tgt/devices/$DEV/async 2>/dev/null | head -1)
    [ "$as" = "1" ] || die "SCST device $DEV async='$as', not 1 — not the production submission path"
    echo "scst o_direct=$od async=$as blocksize=$bs (production mxfs: 1/1/512)"
  fi
  [ -d "$TROOT/$TGT" ] || echo "add_target $TGT" | sudo tee $TROOT/mgmt >/dev/null
  [ -d "$TROOT/$TGT/luns/0" ] || echo "add $DEV 0" | sudo tee $TROOT/$TGT/luns/mgmt >/dev/null
  echo 1 | sudo tee "$TROOT/$TGT/enabled" >/dev/null
  echo "scst_device=$DEV target=$TGT enabled"

  # Two ifaces with DISTINCT initiator names -> two distinct I_T nexuses.
  # Node records are created explicitly (no discovery) so no other target on
  # this portal — least of all the production one — is ever touched.
  local i n
  for i in "$IFV:$IQN_V" "$IFS_:$IQN_S"; do
    n=${i%%:*}; local q=${i#*:}
    sudo iscsiadm -m iface -I "$n" -o new >/dev/null 2>&1
    sudo iscsiadm -m iface -I "$n" -o update -n iface.initiatorname -v "$q" >/dev/null \
      || die "iface $n initiatorname update failed"
    sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$n" -o new >/dev/null 2>&1
    # SG_IO carries its own timeout, but keep the block-layer one well clear of W.
    sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$n" -o update \
      -n node.session.timeo.replacement_timeout -v 300 >/dev/null 2>&1
    sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$n" --login >/dev/null 2>&1
  done
  udevadm settle 2>/dev/null

  local SDV SDS
  SDV=$(sd_for_iface "$IFV") || die "no session/disk for iface $IFV"
  SDS=$(sd_for_iface "$IFS_") || die "no session/disk for iface $IFS_"
  [ "$SDV" != "$SDS" ] || die "victim and survivor resolved to the SAME device $SDV"

  # Raise the block-layer command timeout well above W (belt and braces).
  for d in "$SDV" "$SDS"; do
    echo 300 | sudo tee "/sys/block/$(basename "$d")/device/timeout" >/dev/null 2>&1
  done
  echo "victim=$SDV ($(iface_iqn "$IFV"))"
  echo "survivor=$SDS ($(iface_iqn "$IFS_"))"
  # Record the mode and generation of the stack that is now live, so an env-less
  # `devmap` (how inflight_ab.sh resolves the devices) reports THIS stack.
  echo "$MODE" | sudo tee "$MODESTATE" >/dev/null
  echo "$GEN"  | sudo tee "$GENSTATE"  >/dev/null
  status
}

# Move to a brand-new generation: a NEW inode, which is the only thing that
# clears a leaked i_dio_count.  Refused while a stack is up, because the live
# stack's devices are resolved from the generation file.
newgen() {
  [ "$MODE" = fileio ] || die "newgen applies to fileio mode only"
  [ -r "$MODESTATE" ] && die "a stack is still up (mode=$(cat "$MODESTATE")) — run 'down' first"
  local next=$((GEN + 1))
  while [ -e "$DIR/fio-backing.g$next.img" ]; do next=$((next + 1)); done
  echo "$next" | sudo tee "$GENSTATE" >/dev/null
  echo "fileio generation $GEN -> $next"
  echo "next up will build: img=$DIR/fio-backing.g$next.img dm=mxfsfencef$next mnt=$DIR/fiomnt.g$next"
}

# Delete the images of generations that are PROVEN safe to delete: torn down
# (no loop attachment, no dm device, not mounted) and never quarantined.  Named
# in full, one at a time — never a glob, never losetup -D, never
# dmsetup remove_all, and NEVER generation 0.
purge() {
  local g img
  for g in $(seq 1 "$GEN"); do
    [ "$g" = "$GEN" ] && continue          # keep the current generation
    img=$DIR/fio-backing.g$g.img
    [ -f "$img" ] || continue
    if is_quarantined "$g"; then
      echo "gen $g: QUARANTINED — left untouched"; continue
    fi
    if losetup -j "$img" 2>/dev/null | grep -q .; then
      echo "gen $g: still has a loop attachment — left untouched"; continue
    fi
    if sudo dmsetup ls 2>/dev/null | grep -q "^mxfsfencef$g[[:space:]]"; then
      echo "gen $g: dm device mxfsfencef$g still present — left untouched"; continue
    fi
    if mountpoint -q "$DIR/fiomnt.g$g" 2>/dev/null; then
      echo "gen $g: $DIR/fiomnt.g$g still mounted — left untouched"; continue
    fi
    sudo rm -f "$img" && echo "gen $g: image deleted"
    sudo rmdir "$DIR/fiomnt.g$g" 2>/dev/null
  done
  echo "purge complete (generation 0 and the current generation $GEN are never purged)"
}

show_quarantine() {
  echo "current fileio generation: $GEN"
  echo "--- quarantine (permanently off-limits) ---"
  echo "gen=0 img=$DIR/fio-backing.img dm=mxfsfencef loop=$(losetup -j "$DIR/fio-backing.img" 2>/dev/null | cut -d: -f1) reason=leaked-i_dio_count-sess136-GPF"
  [ -r "$QFILE" ] && cat "$QFILE"
  return 0
}

down() {
  if [ "$MODE" = fileio ] && is_quarantined "$GEN"; then
    echo "generation $GEN is QUARANTINED — tearing down only the SCST/iSCSI layers." >&2
    echo "Its mount, dm device and loop device are left in place on purpose: a" >&2
    echo "parked kernel task may still hold references into them." >&2
  fi
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$IFV" -u >/dev/null 2>&1
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$IFS_" -u >/dev/null 2>&1
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$IFV" -o delete >/dev/null 2>&1
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$IFS_" -o delete >/dev/null 2>&1
  sudo iscsiadm -m iface -I "$IFV" -o delete >/dev/null 2>&1
  sudo iscsiadm -m iface -I "$IFS_" -o delete >/dev/null 2>&1
  echo 0 | sudo tee "$TROOT/$TGT/enabled" >/dev/null 2>&1
  echo "del 0" | sudo tee "$TROOT/$TGT/luns/mgmt" >/dev/null 2>&1
  echo "del_target $TGT" | sudo tee $TROOT/mgmt >/dev/null 2>&1
  echo "del_device $DEV" | sudo tee $H/mgmt >/dev/null 2>&1
  if [ "$MODE" = fileio ] && is_quarantined "$GEN"; then
    sudo rm -f /var/lib/mxfs-fence/mode
    echo "SCST/iSCSI layers removed; quarantined generation $GEN left standing"
    return 0
  fi
  # Teardown order matters and every step is bounded.  An unbounded umount of a
  # wedged ext4 hangs UNKILLABLE holding the superblock; a `dmsetup remove` that
  # follows it then wedges too (remove needs the same suspend path), and the
  # second wedge is what removes any chance of recovering the device without a
  # host reset.  So: bound the umount, and if it does not return, STOP — do not
  # proceed to touch dm.
  if [ "$MODE" = fileio ] && mountpoint -q "$MNT"; then
    if ! timeout 60 sudo umount "$MNT"; then
      quarantine_gen "$GEN" "umount $MNT did not return within 60s — fs wedged, dm left untouched"
      die "umount $MNT is wedged. NOT touching $DM: a dmsetup remove would block on
     the same superblock and add a second unkillable task. Leaving the stack
     standing so the device stays recoverable."
    fi
  fi
  local infl; infl=$(dm_inflight || true)
  if [ -n "$infl" ] && [ "$(echo "$infl" | awk '{print $1+$2}')" -gt 0 ]; then
    quarantine_gen "$GEN" "IO still in flight below $DM at teardown (inflight='$infl')"
    die "$DM still has IO in flight ('$infl') — a remove would wait on it forever. Left standing."
  fi
  if ! dm_try 60 remove "$DM" 2>/dev/null; then
    quarantine_gen "$GEN" "dmsetup remove $DM did not return within 60s"
    die "$DM removal is wedged and UNKILLABLE. Do NOT retry and do NOT attempt an
     error-target swap — see ccmemory never-pgrep-f-on-clyde-mmap-lock-wedge."
  fi
  local LOOP; LOOP=$(loopdev)
  [ -n "$LOOP" ] && { timeout 30 sudo losetup -d "$LOOP" \
    || echo "WARN: losetup -d $LOOP did not return within 30s — loop left attached" >&2; }
  sudo rm -f /var/lib/mxfs-fence/mode
  echo "torn down (image $IMG kept)"
}

# Release a command the target will never answer.
#
# PREEMPT AND ABORT with TAS off is REQUIRED to abort the victim's command
# "without delivery or notification" (SAM); SCST does exactly that --
# iscsi_xmit_response logs "aborted", req_cmnd_release_force frees the request,
# and no PDU is sent.  libiscsi's eh_cmd_timed_out then keeps returning
# BLK_EH_RESET_TIMER for as long as the connection is healthy, so the initiator
# NEVER times the command out: the SG_IO caller sits in blk_execute_rq
# indefinitely (measured: still in D state 261 s after a 120 s SG_IO timeout).
# The only thing that fails such a command is session teardown.  Log the nexus
# out and back in; sd_for_iface re-resolves the (possibly new) /dev/sdX.
relogin() {
  local which="$1" ifn
  case "$which" in
    victim)   ifn="$IFV" ;;
    survivor) ifn="$IFS_" ;;
    *) die "relogin: want 'victim' or 'survivor', got '$which'" ;;
  esac
  local before; before=$(sd_for_iface "$ifn" || true)
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$ifn" -u >/dev/null 2>&1
  # The logout can drop the iface binding on the node record, after which
  # --login -I <iface> reports "No records found".  Recreate it unconditionally.
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$ifn" -o new >/dev/null 2>&1
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$ifn" -o update \
    -n node.session.timeo.replacement_timeout -v 300 >/dev/null 2>&1
  sudo iscsiadm -m node -T "$TGT" -p "$PORTAL" -I "$ifn" --login >/dev/null 2>&1
  udevadm settle 2>/dev/null
  local after i
  for i in $(seq 1 60); do
    after=$(sd_for_iface "$ifn") && [ -b "$after" ] && break
    after=""; sleep 0.5
  done
  [ -n "$after" ] || die "relogin $which: no disk after login"
  echo 300 | sudo tee "/sys/block/$(basename "$after")/device/timeout" >/dev/null 2>&1
  echo "relogin $which iface=$ifn dev=$before -> $after"
}

# --------------------------------------------------------------- dm safety
# A dm control ioctl that hangs is UNKILLABLE (uninterruptible sleep) and holds
# md->suspend_lock for the device forever, so every LATER suspend/resume/remove
# blocks behind it.  The attempt CONSUMES THE ESCAPE HATCH: once one is stuck,
# no error-target swap can rescue the device and only a host reset clears it
# (clyde 2026-08-04 -> loadavg 583, manual reset).  Therefore: bound every call,
# and on timeout QUARANTINE AND STOP — never retry, never escalate.
dm_try() {   # <timeout_s> <dmsetup args...>
  local t="$1"; shift
  timeout "$t" sudo dmsetup "$@"
}

# "<reads> <writes>" in flight below $DM, or "" if the device is not resolvable.
dm_inflight() {
  local real
  [ -e "/dev/mapper/$DM" ] || return 1
  real=$(readlink -f "/dev/mapper/$DM" 2>/dev/null) || return 1
  [ -n "$real" ] || return 1
  cat "/sys/block/$(basename "$real")/inflight" 2>/dev/null
}

# Current dm-delay write delay in ms (last field of the table), 0 if unreadable.
dm_write_delay_ms() {
  local v; v=$(timeout 10 sudo dmsetup table "$DM" 2>/dev/null | awk '{print $NF}')
  case "${v:-}" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac
}

set_delay() {
  local ms="$1" LOOP; LOOP=$(loopdev)
  [ -n "$LOOP" ] || die "no loop device for $IMG"
  is_quarantined "$GEN" \
    && die "generation $GEN is quarantined — refusing any table op on $DM"

  # PREFLIGHT.  A bio already stuck below us makes suspend wait forever, and
  # that wait is the unkillable one.  Refuse rather than create it.
  local infl; infl=$(dm_inflight || true)
  local inflw; inflw=$(echo "${infl:-0 0}" | awk '{print $2+0}')
  local prev; prev=$(dm_write_delay_ms)
  if [ "$inflw" -gt 0 ] && [ "$prev" -eq 0 ]; then
    quarantine_gen "$GEN" "stuck bio below $DM (inflight='$infl') with delay already 0 — never completing"
    die "$DM has $inflw write(s) in flight at delay=0: they are stuck, not slow. Refusing to suspend."
  fi

  # RULE 0 budget: suspend must drain bios ALREADY QUEUED at the CURRENT write
  # delay, so derive the bound from that delay instead of a round number.
  local budget=$(( prev / 1000 * 2 + 20 ))

  # --nolockfs is REQUIRED.  In fileio mode an ext4 is mounted on $DM, and a
  # freezing suspend deadlocks against it: __dm_suspend -> bdev_freeze ->
  # fs_bdev_freeze -> super_lock, blocking on the superblock a wedged mount
  # holds.  Only the delay parameter changes here — same loop, same offset, no
  # data moves — so there is nothing for an fs freeze to protect.
  if ! dm_try "$budget" suspend --nolockfs "$DM"; then
    quarantine_gen "$GEN" "dmsetup suspend exceeded ${budget}s (prev_delay=${prev}ms inflight='${infl:-?}')"
    die "suspend of $DM did not return within ${budget}s — it is now wedged and UNKILLABLE.
     Do NOT retry, and do NOT attempt a dmsetup error-target swap: the swap
     itself needs this same suspend lock and will only add another stuck task.
     See tools/mxfs_pgrep.sh header and ccmemory never-pgrep-f-on-clyde-mmap-lock-wedge."
  fi

  if ! echo "0 $(sectors) delay $LOOP 0 0 $LOOP 0 $ms" | timeout 20 sudo dmsetup reload "$DM"; then
    # NEVER leave it suspended — every IO above it would block forever.
    dm_try 30 resume "$DM" \
      || die "reload failed AND $DM could not be resumed — it is suspended and wedged"
    die "reload of $DM failed (device successfully resumed, delay left at ${prev}ms)"
  fi

  if ! dm_try 30 resume "$DM"; then
    quarantine_gen "$GEN" "dmsetup resume did not return within 30s after a successful reload"
    die "$DM is SUSPENDED and its resume is wedged — all IO above it is blocked"
  fi
  echo "write_delay_ms=$ms $(timeout 10 sudo dmsetup table "$DM")"
}

devmap() {
  local LOOP DMDEV SDV SDS
  LOOP=$(loopdev)
  # Only resolve the dm device if it actually exists: readlink -f happily
  # returns a path for a nonexistent name, and a bogus DM_DEVNO=0 would be
  # installed into inflight_ab.sh's block-tracepoint filter.
  DMDEV=$( [ -e "/dev/mapper/$DM" ] && readlink -f "/dev/mapper/$DM" 2>/dev/null || true )
  SDV=$(sd_for_iface "$IFV")
  SDS=$(sd_for_iface "$IFS_")
  echo "MODE=$MODE"
  echo "GEN=$GEN"
  echo "IMG=$IMG"
  echo "SCSTDEV=$DEV"
  echo "TARGET=$TGT"
  echo "LOOP=$LOOP"
  echo "DM=/dev/mapper/$DM"
  echo "DMREAL=$DMDEV"
  echo "VICTIM=$SDV"
  echo "SURVIVOR=$SDS"
  if [ "$MODE" = fileio ]; then
    echo "DISK=$DISK"
    echo "MNT=$MNT"
  fi
  echo "VICTIM_IQN=$(iface_iqn "$IFV")"
  echo "SURVIVOR_IQN=$(iface_iqn "$IFS_")"
  [ -n "$LOOP" ]  && echo "LOOP_DEVNO=$(( 0x$(stat -c '%t' "$LOOP") * 1048576 + 0x$(stat -c '%T' "$LOOP") ))"
  [ -n "$DMDEV" ] && echo "DM_DEVNO=$(( 0x$(stat -c '%t' "$DMDEV") * 1048576 + 0x$(stat -c '%T' "$DMDEV") ))"
  [ -n "$DMDEV" ] && echo "DM_SYSFS=/sys/block/$(basename "$DMDEV")"
}

status() {
  echo "--- devmap ---"; devmap
  echo "--- dm table ---"; sudo dmsetup table "$DM" 2>/dev/null
  echo "--- loop ---"; losetup -l -O NAME,SIZELIMIT,DIO,BACK-FILE 2>/dev/null | grep -E "NAME|$IMG"
  echo "--- scst sessions on $TGT ---"
  ls "$TROOT/$TGT/sessions/" 2>/dev/null
  echo "--- production target sessions (must stay 64) ---"
  echo "count=$(ls $TROOT/iqn.2026-05.local.mxfs:shared/sessions/ 2>/dev/null | wc -l)"
}

case "${1:-status}" in
  up)     up ;;
  down)   down ;;
  newgen) newgen ;;
  purge)  purge ;;
  quarantine) show_quarantine ;;
  status) status ;;
  devmap) devmap ;;
  delay)  set_delay "${2:?usage: stack.sh delay <ms>}" ;;
  fiemap) fiemap_off "${2:?usage: stack.sh fiemap <byteoff> [len]}" "${3:-4096}" ;;
  relogin) relogin "${2:?usage: stack.sh relogin <victim|survivor>}" ;;
  *) echo "usage: stack.sh {up|down|newgen|purge|quarantine|status|devmap|delay <ms>|fiemap <byteoff> [len]|relogin <victim|survivor>}" >&2; exit 2 ;;
esac
