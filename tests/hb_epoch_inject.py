#!/usr/bin/env python3
"""hb_epoch_inject.py — rewrite the incarnation (epoch) of one disklock
heartbeat record on the backing store and RESEAL the two crcs that bind it.

D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN closure instrument (sess420).

Why the reseal matters (the ledger's recorded trap): the HB feature block's
crc32c (dlm/disklock.c hb_feature_crc) and the claim-provenance crc
(hb_prov_crc) both cover the record's identity triple {fs_gen, node_id,
EPOCH}.  A naive epoch rewrite makes hb_feature_state() read CORRUPT and a
DIFFERENT refusal arm fires, so the probe would measure the wrong thing.
This tool recomputes both crcs exactly as the kernel does (crc32c, seed ~0,
no output inversion — pal/linux/user.c mxfs_pal_crc32c).

Record layout (struct mxfs_disklock_heartbeat, 512 B, little-endian):
  0 magic u32 | 4 flags u32 | 8 node_id u32 | 12 fs_gen u32 | 16 timestamp u64
  24 epoch u64 | 32 lock_count u64 | 40 body union (320 B)
  360 ident {magic u32, ver u16, key_gen u16, host_uuid[16], boot_uuid[16],
             pr_key u64, host_src u32, crc32c u32, reserved[8]} (64 B, sess438;
             crc binds {slot, flags, fs_gen, node_id, epoch} too)
  424 prov {magic u32, prev_node u32, prev_epoch u64, slot_seq u64,
            chain_len u32, crc32c u32} (32 B)
  456 mepoch (44 B, own crc, does not cover epoch)
  500 feat {magic u32, proto_gen u16, feat_flags u16, crc32c u32} (12 B)
The disklock region offset is the u64 at byte 64 of sector 0 (envelope
header), as tests/recov_takeover_doublefault_probe.sh reads it.

Usage:
  hb_epoch_inject.py <img> <slot> show
  hb_epoch_inject.py <img> <slot> set <epoch>       (decimal or 0x...)
  hb_epoch_inject.py <img> <slot> setowner <owner_epoch>
      (GUARD records only: rewrite the recovery descriptor's owner_epoch and
       reseal the descriptor crc — D-RECOV-ADVANCE ruling item 4's
       "same node, later incarnation" negative arm)
Prints the record's fields before and (for set) after; exit 0 on success,
2 on a record that is not a valid MXLK record.
"""
import mmap
import os
import struct
import sys

MAGIC = 0x4D584C4B
FEAT_MAGIC = 0x47465846
PROV_MAGIC = 0x5650584D
IDENT_MAGIC = 0x4449584D
IDENT_OFF = 360
FLAGS = {0: "EMPTY", 1: "ACTIVE", 2: "WITHDRAWN", 3: "GUARD"}

_tbl = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    _tbl.append(c)


def crc32c(crc, data):
    for b in data:
        crc = (crc >> 8) ^ _tbl[(crc & 0xFF) ^ b]
    return crc & 0xFFFFFFFF


def feat_crc(fs_gen, node_id, epoch, magic, proto_gen, feat_flags):
    return crc32c(0xFFFFFFFF, struct.pack("<IHHIIQ", magic, proto_gen,
                                          feat_flags, fs_gen, node_id, epoch))


def prov_crc(fs_gen, node_id, epoch, magic, prev_node, prev_epoch, slot_seq,
             chain_len):
    return crc32c(0xFFFFFFFF, struct.pack("<IIQQIIIQ", magic, prev_node,
                                          prev_epoch, slot_seq, chain_len,
                                          fs_gen, node_id, epoch))


def ident_crc(slot, flags, fs_gen, node_id, epoch, r):
    """hb_ident_crc: packed {magic,ver,key_gen,host[16],boot[16],pr_key,
    host_src, slot, flags, fs_gen, node_id, epoch}."""
    im, iv, ig = struct.unpack_from("<IHH", r, IDENT_OFF)
    host = bytes(r[IDENT_OFF + 8:IDENT_OFF + 24])
    boot = bytes(r[IDENT_OFF + 24:IDENT_OFF + 40])
    key, src = struct.unpack_from("<QI", r, IDENT_OFF + 40)
    return crc32c(0xFFFFFFFF, struct.pack("<IHH", im, iv, ig) + host + boot +
                  struct.pack("<QIIIIIQ", key, src, slot, flags, fs_gen,
                              node_id, epoch))


def ident_reseal(r, slot):
    im, = struct.unpack_from("<I", r, IDENT_OFF)
    if im != IDENT_MAGIC:
        return
    flags, nid, fs_gen = struct.unpack_from("<III", r, 4)
    epoch, = struct.unpack_from("<Q", r, 24)
    struct.pack_into("<I", r, IDENT_OFF + 52,
                     ident_crc(slot, flags, fs_gen, nid, epoch, r))


DESC_OFF = 40                 # struct mxfs_recov_body.desc inside the record
DESC_MAGIC = 0x5643524D
DESC_CRC_OFF = DESC_OFF + 116  # offsetof(struct mxfs_recov_desc, crc32c)


def desc_crc(r, fs_gen, nid, epoch):
    """recov_desc_crc: crc32c(~0, desc bytes 0..115) folded with the record's
    victim identity {fs_gen, node_id, epoch}."""
    c = crc32c(0xFFFFFFFF, bytes(r[DESC_OFF:DESC_CRC_OFF]))
    return crc32c(c, struct.pack("<IIQ", fs_gen, nid, epoch))


def describe(r, slot=None):
    magic, flags, nid, fs_gen, ts, epoch = struct.unpack_from("<IIIIQQ", r, 0)
    pm, pn, pe, ps, pc, pcrc = struct.unpack_from("<IIQQII", r, 424)
    fm, fpg, fff, fcrc = struct.unpack_from("<IHHI", r, 500)
    feat_ok = fm == FEAT_MAGIC and fcrc == feat_crc(fs_gen, nid, epoch, fm, fpg, fff)
    prov_ok = pm == PROV_MAGIC and pcrc == prov_crc(fs_gen, nid, epoch, pm, pn, pe, ps, pc)
    s = ("magic=%s flags=%s node=%u fs_gen=0x%08x epoch=%u feat{magic=%s "
         "proto_gen=%u crc_ok=%d} prov{magic=%s slot_seq=%u crc_ok=%d}"
         % ("MXLK" if magic == MAGIC else hex(magic), FLAGS.get(flags, flags),
            nid, fs_gen, epoch, "ok" if fm == FEAT_MAGIC else hex(fm), fpg,
            feat_ok, "ok" if pm == PROV_MAGIC else hex(pm), ps, prov_ok))
    im, iv, ig = struct.unpack_from("<IHH", r, IDENT_OFF)
    if im == IDENT_MAGIC:
        key, src, icrc = struct.unpack_from("<QII", r, IDENT_OFF + 40)
        iok = (slot is not None and
               icrc == ident_crc(slot, flags, fs_gen, nid, epoch, r))
        s += " ident{key=0x%x gen=%u src=%u crc_ok=%d}" % (key, ig, src, iok)
    dm, = struct.unpack_from("<I", r, DESC_OFF)
    if flags == 3 and dm == DESC_MAGIC:
        stage, = struct.unpack_from("<H", r, DESC_OFF + 6)
        vepoch, oepoch, gen = struct.unpack_from("<QQQ", r, DESC_OFF + 8)
        vnode, onode = struct.unpack_from("<II", r, DESC_OFF + 40)
        term, = struct.unpack_from("<I", r, DESC_OFF + 72)
        dcrc, = struct.unpack_from("<I", r, DESC_CRC_OFF)
        s += (" desc{stage=%u victim=%u/%u owner=%u/%u gen=%u term=%u crc_ok=%d}"
              % (stage, vnode, vepoch, onode, oepoch, gen, term,
                 dcrc == desc_crc(r, fs_gen, nid, epoch)))
    return s


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    img, slot, op = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    fd = os.open(img, os.O_RDWR | os.O_DIRECT)
    buf = mmap.mmap(-1, 4096)
    mv = memoryview(buf)

    def dread(off, n):
        os.preadv(fd, [mv[:n]], off)
        return bytes(mv[:n])

    sup = dread(0, 4096)
    dloff, = struct.unpack_from("<Q", sup, 64)
    off = dloff + slot * 512
    r = bytearray(dread(off, 512))
    print("slot=%d off=%d before: %s" % (slot, off, describe(r, slot)))
    magic, = struct.unpack_from("<I", r, 0)
    if magic != MAGIC:
        print("not an MXLK record; refusing")
        sys.exit(2)
    if op == "show":
        return
    nid, fs_gen = struct.unpack_from("<II", r, 8)
    if op == "setowner":
        # D-RECOV-ADVANCE ruling item 4 (sess91): make the descriptor read as
        # owned by a DIFFERENT incarnation of the same owner node.  Only the
        # descriptor crc binds owner_epoch; the record's own identity triple
        # (victim) is untouched, so feat/prov stay valid.
        flags, = struct.unpack_from("<I", r, 4)
        dm, = struct.unpack_from("<I", r, DESC_OFF)
        if flags != 3 or dm != DESC_MAGIC:
            print("slot is not a GUARD record with a descriptor; refusing")
            sys.exit(2)
        epoch, = struct.unpack_from("<Q", r, 24)
        new_owner_epoch = int(sys.argv[4], 0)
        struct.pack_into("<Q", r, DESC_OFF + 16, new_owner_epoch)
        struct.pack_into("<I", r, DESC_CRC_OFF, desc_crc(r, fs_gen, nid, epoch))
    elif op == "set":
        new_epoch = int(sys.argv[4], 0)
        struct.pack_into("<Q", r, 24, new_epoch)
        fm, fpg, fff, _ = struct.unpack_from("<IHHI", r, 500)
        if fm == FEAT_MAGIC:
            struct.pack_into("<I", r, 508, feat_crc(fs_gen, nid, new_epoch, fm, fpg, fff))
        pm, pn, pe, ps, pc, _ = struct.unpack_from("<IIQQII", r, 424)
        if pm == PROV_MAGIC:
            struct.pack_into("<I", r, 452, prov_crc(fs_gen, nid, new_epoch, pm, pn, pe, ps, pc))
        ident_reseal(r, slot)       # sess438: the identity crc binds epoch too
    else:
        print("unknown op %s" % op)
        sys.exit(1)
    mv[:512] = bytes(r)
    os.pwritev(fd, [mv[:512]], off)
    os.fsync(fd)
    chk = dread(off, 512)
    print("slot=%d off=%d after:  %s" % (slot, off, describe(chk, slot)))
    if chk != bytes(r):
        print("readback mismatch")
        sys.exit(3)


if __name__ == "__main__":
    main()
