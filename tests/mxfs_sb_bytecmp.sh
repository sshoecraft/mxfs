#!/bin/bash
# mxfs_sb_bytecmp.sh — snapshot and byte-compare the XFS superblock sector of an
# MXFS envelope image (sess474, D-0133 design-consult verification bar: the SB summary
# lock's whole-sector home write must change NOTHING outside the three summary
# counters, the CRC and the LSN).
#
#   tests/mxfs_sb_bytecmp.sh snap <img> <out.bin> [xfs_data_offset]
#       dd the 512-byte sb sector at xfs_data_offset (chk_mxfs -v prints it;
#       default 793497600 = the current ~/disk.img mkfs) into out.bin.
#   tests/mxfs_sb_bytecmp.sh cmp <label> <pre.bin> <post.bin>
#       print one line:
#         SB-BYTECMP lap=<label> magic_ok=1 diff_total=N diff_outside_counters_crc_lsn=M offsets_outside=[..] pre_*/post_* counters and lsn
#       M must be 0 for the fix's verification; N>0 is expected (counters/crc/lsn).
# Excluded ranges (struct xfs_dsb, xfs/libxfs/xfs_format.h): sb_icount 128..135,
# sb_ifree 136..143, sb_fdblocks 144..151, sb_crc 224..227, sb_lsn 240..247.
set -u
mode=${1:?usage: snap <img> <out> [off] | cmp <label> <pre> <post>}
case "$mode" in
snap)
  img=${2:?img}; out=${3:?out}; off=${4:-793497600}
  [ $(( off % 512 )) -eq 0 ] || { echo "SB-BYTECMP-ABORT off=$off not sector aligned"; exit 2; }
  # iflag=direct: the sector under comparison is the one the module rewrites,
  # and a buffered read of a device the module holds open returns the page
  # cache's first image, not the platter (measured 0.89.4)
  dd if="$img" of="$out" bs=512 skip=$(( off / 512 )) count=1 iflag=direct status=none || { echo "SB-BYTECMP-ABORT dd rc=$?"; exit 2; }
  ;;
cmp)
  label=${2:?label}; pre=${3:?pre}; post=${4:?post}
  python3 - "$label" "$pre" "$post" <<'EOF'
import sys, struct
label, pre, post = sys.argv[1:4]
a = open(pre, 'rb').read(); b = open(post, 'rb').read()
if len(a) != 512 or len(b) != 512:
    print(f"  SB-BYTECMP lap={label} ABORT pre_len={len(a)} post_len={len(b)}"); sys.exit(2)
def fields(x):
    ic, ifr, fdb = struct.unpack('>QQQ', x[128:152])
    crc = struct.unpack('<I', x[224:228])[0]
    lsn = struct.unpack('>Q', x[240:248])[0]
    return ic, ifr, fdb, crc, lsn
excl = set(range(128, 152)) | set(range(224, 228)) | set(range(240, 248))
diff = [i for i in range(512) if a[i] != b[i]]
out = [i for i in diff if i not in excl]
magic = a[:4] == b'XFSB' and b[:4] == b'XFSB'
pa = fields(a); pb = fields(b)
print(f"  SB-BYTECMP lap={label} magic_ok={int(magic)} diff_total={len(diff)} "
      f"diff_outside_counters_crc_lsn={len(out)} offsets_outside={out[:48]} "
      f"pre_icount={pa[0]} pre_ifree={pa[1]} pre_fdblocks={pa[2]} pre_lsn={pa[4]:#x} "
      f"post_icount={pb[0]} post_ifree={pb[1]} post_fdblocks={pb[2]} post_lsn={pb[4]:#x} post_crc={pb[3]:#x}")
sys.exit(0 if (magic and not out) else 1)
EOF
  ;;
*) echo "usage: snap <img> <out> [off] | cmp <label> <pre> <post>"; exit 2 ;;
esac
