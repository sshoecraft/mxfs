#!/usr/bin/env python3
"""disklock_hb_dump.py — the 64 heartbeat records of the disklock table as
they sit on the platter, read with an O_DIRECT pread (no SG_IO, no FUA).

tools/recov_forge dump reads each record through a READ(16) FUA CDB, which
the QNAP TS-453 Pro refuses (sense 05/24/00), so on that rig the slot table
could not be inspected at all.  This reads the same 512-byte records through
the block device's ordinary read path, bypassing the device's page cache: a
buffered read on a node whose module holds the device open returns the image
cached at the first read for as long as the device stays open (measured
s67e).  It is a census tool for a quiescent or read-only look: nothing here
writes.

Usage:  disklock_hb_dump.py <dev> [disklock_offset_bytes] [--all]
        disklock_offset_bytes is the 'disklock_offset=' value chk_mxfs -v
        prints for the device (the heartbeat region starts there, one
        512-byte record per slot, 64 slots); default 67117056, the offset every
        mkfs_mxfs of this era has produced.  Without --all only non-EMPTY
        records are printed.

Layout (dlm/disklock.h struct mxfs_disklock_heartbeat, 512 B):
  0 magic u32   4 flags u32   8 node_id u32   12 fs_gen u32
  16 timestamp_ms u64   24 epoch u64   32 lock_count u64
  360 struct mxfs_hb_identity: magic u32, ver u16, key_gen u16,
      host_uuid[16] @368, boot_uuid[16] @384, pr_key u64 @400, host_src u32 @408
  40 (flags == RECOVERY_GUARD only) struct mxfs_recov_desc, 120 B:
      magic u32 @40  version u16 @44  stage u16 @46  victim_epoch u64 @48
      owner_epoch u64 @56  recovery_gen u64 @64  owner_stamp_ms u64 @72
      victim_node u32 @80  owner_node u32 @84  victim_fs_gen u32 @88
      flags u32 @92  victim_slot u16 @96  owner_slot u16 @98  slice_idx u16 @100
      slice_count u16 @102  stage_seq u64 @104  owner_term u32 @112
      fence_kind u16 @116  fence_resv_type u16 @118  fence_victim_key u64 @120
      fence_prover_epoch u64 @128  fence_stamp_ms u64 @136
      fence_prover_node u32 @144  fence_pr_gen u32 @148  fence_term u32 @152
  A guard record prints a second, indented line with the descriptor: who is
  recovering the victim (owner), who holds or proved the fence (prover), and
  the stage.  That is the line that says why a slice is not takeable: a
  descriptor at stage FENCING names the prover whose incarnation must be
  revoked before anyone else may take the attempt over.
"""
import mmap
import os
import struct
import sys

RECORD = 512
SLOTS = 64
MAGIC = 0x4D584C4B
FLAGS = {0: "EMPTY", 1: "ACTIVE", 2: "WITHDRAWN", 3: "RECOVERY_GUARD",
         4: "RETIRE_PENDING"}
IDENT_OFF = 360
DESC_OFF = 40
DESC_MAGIC = 0x5643524D
STAGES = {0: "NONE", 1: "FENCING", 2: "SNAPSHOTTING", 3: "FENCED",
          4: "IMAGES_REPLAYED", 5: "OBLIGATIONS_DONE", 6: "GRANTS_RELEASED"}
FENCE_KINDS = {0: "NONE", 1: "ERROR", 2: "UNSUPPORTED", 3: "ADVISORY_TOPOLOGY",
               4: "NOT_REGISTERED", 5: "SELF_PREEMPTED",
               6: "KEY_ABSENT_UNPROVEN", 7: "RACE_LOST", 8: "NO_RESERVATION",
               9: "VIEW_TRUNCATED", 16: "PREEMPT_ABORT_DONE",
               17: "SINGLE_NODE_EXCLUSIVE", 18: "NO_VICTIM_KEY",
               19: "SELF_SUCCESSION_DONE", 20: "EXCLUSIVE_WRITE_GATE",
               21: "BOOT_SUCCESSION_ABSENT", 22: "KEY_HELD_BY_LIVE_MEMBER",
               23: "PREEMPT_ABORT_PROVEN_V1",
               24: "LU_RESET_WITNESSED_V1"}
# 16, 17 and 19 are no longer minted by any current build (16 and 19 retired in
# 0.89.16, 17 revoked in 0.89.18), but a record an older build left on the
# platter still carries them and a dumper that printed a bare number for such a
# record would be the least useful thing it could do.  23 is what the ordinary
# fence mints now; it was added to the kernel enum and not here, so every
# current certificate dumped as "23(23)" and a harness comparing against the
# NAME scored a correct certificate as wrong.
OWNER_NONE = 0xFFFFFFFF


def desc_line(rec):
    (dmagic, dver, stage, victim_epoch, owner_epoch, recovery_gen,
     owner_stamp_ms, victim_node, owner_node, victim_fs_gen, dflags,
     victim_slot, owner_slot, slice_idx, slice_count, stage_seq,
     owner_term, fence_kind, fence_resv_type, fence_victim_key,
     fence_prover_epoch, fence_stamp_ms, fence_prover_node, fence_pr_gen,
     fence_term) = struct.unpack_from("<IHHQQQQIIIIHHHHQIHHQQQIII", rec,
                                      DESC_OFF)
    if dmagic != DESC_MAGIC:
        return "    desc: magic=%#x (no descriptor)" % dmagic
    owner = "none" if owner_node == OWNER_NONE else "%u/%u" % (owner_node,
                                                                owner_epoch)
    return ("    desc v%u stage=%s(%u) victim=%u/%u fs_gen=%#x flags=%#x "
            "owner=%s owner_slot=%u owner_term=%u stage_seq=%u slice=%u/%u "
            "fence_kind=%s(%u) resv_type=%#x fence_key=%#x prover=%u/%u "
            "fence_term=%u pr_gen=%u"
            % (dver, STAGES.get(stage, str(stage)), stage, victim_node,
               victim_epoch, victim_fs_gen, dflags, owner, owner_slot,
               owner_term, stage_seq, slice_idx, slice_count,
               FENCE_KINDS.get(fence_kind, str(fence_kind)), fence_kind,
               fence_resv_type, fence_victim_key, fence_prover_node,
               fence_prover_epoch, fence_term, fence_pr_gen))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_all = "--all" in sys.argv
    if not args:
        sys.exit(__doc__)
    dev = args[0]
    base = int(args[1]) if len(args) > 1 else 67117056
    # O_DIRECT, never a buffered read.  On a node whose mxfs module holds the
    # device open, the block device's page cache outlives every read: the
    # module's heartbeat writes are bios that never touch that cache, so a
    # buffered read returns the image cached at the FIRST read for as long as
    # the device stays open (measured s67e on test2: the buffered dump showed
    # slot 2 ts_ms=167600 three times while direct reads of the same sector
    # advanced 332143 -> 336239 -> 338287).  An unmounted node's last close
    # flushes that cache, which is why the same buffered read looked fresh
    # there.  A dump that can be stale is not a measurement.
    size = RECORD * SLOTS
    if base % 512:
        sys.exit("base %d is not sector-aligned" % base)
    fd = os.open(dev, os.O_RDONLY | os.O_DIRECT)
    try:
        buf = mmap.mmap(-1, size)           # page-aligned, as O_DIRECT needs
        n = os.preadv(fd, [buf], base)
        table = bytes(buf[:n])
        buf.close()
    finally:
        os.close(fd)
    if len(table) != size:
        sys.exit("short read: %d bytes" % len(table))
    print("disklock heartbeat table @%d dev=%s" % (base, dev))
    for slot in range(SLOTS):
        rec = table[slot * RECORD:(slot + 1) * RECORD]
        magic, flags, node, fs_gen, ts, epoch, locks = struct.unpack_from(
            "<IIIIQQQ", rec, 0)
        imagic, iver, key_gen = struct.unpack_from("<IHH", rec, IDENT_OFF)
        boot_uuid = rec[IDENT_OFF + 24:IDENT_OFF + 40]
        pr_key, host_src = struct.unpack_from("<QI", rec, IDENT_OFF + 40)
        empty = (magic == 0 and flags == 0 and node == 0 and epoch == 0)
        if empty and not show_all:
            continue
        print("slot %2d magic=%s flags=%-14s node=%u fs_gen=%#x ts_ms=%u "
              "epoch=%u locks=%u pr_key=%#x boot=%s ident_magic=%#x key_gen=%u"
              % (slot, "MXLK" if magic == MAGIC else ("%#x" % magic),
                 FLAGS.get(flags, str(flags)), node, fs_gen, ts, epoch, locks,
                 pr_key, boot_uuid[:4].hex(), imagic, key_gen))
        if flags == 3:
            print(desc_line(rec))


if __name__ == "__main__":
    main()
