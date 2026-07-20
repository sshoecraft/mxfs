#!/bin/bash
# dblalloc_repro.sh — one iteration of the AG free-space double-allocation
# reproducer (sess3 ccloop 8ba7ae5c, GPT probe plan).
#
# Sequence mirrors the failing 32/caw ladder segment (minus fio): fresh prep
# (mkfs + remount, module reload → probe counters reset), then
# precond_readiness + cache_coherency, then strong_consistency + posix_multi.
# Afterwards: pull probe-filtered kernel journals from every node (beating
# journald rotation), and run a static cross-fork overlap check directly on
# the SCST backing file (clyde-local, no cluster interaction).
#
# Detection channels (any hit = reproduction):
#   - P130-FALSE-FRESH        fresh CAW grant with lineage still open
#   - P131-INVAL-DISCARD      acquire-invalidation staled unresolved AG-meta
#   - P75 cil_resident        release handed AG over with CIL-resident bno/cnt
#   - P-DBLALLOC(+AGF)        foreign-live content at alloc + read/write side
#   - fork overlap            unlink_visibility vs posix_multi extents collide
#   - uv block foreign owner  uv-dir block content owned by another inode
#   - test FAIL               cache_coherency/posix_multi verdicts
#
# Usage: scripts/dblalloc_repro.sh <iter-label>
# Exit: 0 = iteration ran, no reproduction; 10 = REPRODUCED (see log dir);
#       2 = infra failure (prep/test harness broke).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

ITER="${1:?usage: dblalloc_repro.sh <iter-label>}"
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
N="${DBLALLOC_NODES:-32}"
BACKING="${DBLALLOC_BACKING:-/home/steve/disk.img}"
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
LOGROOT="$REPO/tests/logs/dblalloc_repro"
LOGDIR="$LOGROOT/iter_${ITER}"
mkdir -p "$LOGDIR"

PROBE_RE='P130-FALSE-FRESH|P131-INVAL-DISCARD|P-DBLALLOC|P75-INSTR|P55-STUCKMETA|P79-INSTR|PROBE-A|P125-AG-DIVERGE|P88|P121-COLDREAD|P3-SKIP-DBLFREE|P47-INVAL|Metadata corruption|Internal error|P70-INSTR|P74-INSTR'

T0_UTC=$(date -u '+%Y-%m-%d %H:%M:%S')
echo "=== iter $ITER start $T0_UTC (nodes=$N dev=$DEV) ===" | tee "$LOGDIR/summary.txt"

# 1. fresh prep (forced; resets module → probe caps/counters reset)
MXFS_DEV="$DEV" MXFS_EXTRA_MODARGS="${MXFS_EXTRA_MODARGS:-dblalloc_probe=1}" \
    ./run.sh "$N" caw prep_cluster > "$LOGDIR/prep.log" 2>&1
rc=$?
if [ $rc -ne 0 ]; then
    echo "PREP FAILED rc=$rc (see prep.log)" | tee -a "$LOGDIR/summary.txt"
    exit 2
fi

# 2. the failing segment (two batches, each well inside a 600s wrapper).
# RULE0_CALIBRATE=1 matches the ladder's criteria-recording semantics: the
# suite's flat budget_s values are miscalibrated for 32 nodes (posix_multi
# needs ~80s vs budget 30s; scaling 4/6/14/35s at 2/4/8/16 nodes), and an
# enforced kill mid-create-storm reads as NO_TERMINAL_RECORD=32 — a false
# "reproduction" that masks the real corruption channels.  Functional check
# failures still FAIL under calibration; only budget overruns are tolerated.
MXFS_DEV="$DEV" RULE0_CALIBRATE=1 ./run.sh "$N" caw precond_readiness cache_coherency \
    > "$LOGDIR/batch1.log" 2>&1
MXFS_DEV="$DEV" RULE0_CALIBRATE=1 ./run.sh "$N" caw strong_consistency posix_multi \
    > "$LOGDIR/batch2.log" 2>&1
grep -E '^  (PASS|FAIL)' "$LOGDIR"/batch1.log "$LOGDIR"/batch2.log | tee -a "$LOGDIR/summary.txt"

# 3. pull probe-filtered journals from every node since T0 (parallel)
for i in $(seq 1 "$N"); do
    ( timeout 50 "$SSH" "test$i" "$PASS" \
        "journalctl -k --since '$T0_UTC' --no-pager 2>/dev/null | grep -E '$PROBE_RE'" \
        2>/dev/null | grep -vE '^Warning|^Unauthorized|^If you|^$' \
        > "$LOGDIR/probes_test$i.log" ) &
done
wait

# 4. static cross-fork overlap check on the backing file (authoritative)
UV_INO=$(timeout 20 "$SSH" test2 "$PASS" \
    "stat -c %i /mnt/shared/.cache_coherency/unlink_visibility 2>/dev/null" \
    2>/dev/null | grep -vE '^Warning|^Unauthorized|^If you' | tr -d '[:space:]')
PM_INO=$(timeout 20 "$SSH" test2 "$PASS" \
    "stat -c %i /mnt/shared/.posix_multi 2>/dev/null" \
    2>/dev/null | grep -vE '^Warning|^Unauthorized|^If you' | tr -d '[:space:]')
echo "uv_ino=$UV_INO pm_ino=$PM_INO" | tee -a "$LOGDIR/summary.txt"

if [ -n "$UV_INO" ] && [ -n "$PM_INO" ]; then
python3 - "$BACKING" "$UV_INO" "$PM_INO" <<'EOF' | tee -a "$LOGDIR/summary.txt"
import struct, sys
img, uv_ino, pm_ino = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
f = open(img, 'rb')
sb0 = f.read(96)
xfs_off, = struct.unpack_from('<Q', sb0, 88)
f.seek(xfs_off); sb = f.read(512)
blocksize, = struct.unpack_from('>I', sb, 4)
agblocks, = struct.unpack_from('>I', sb, 84)
inodesize, = struct.unpack_from('>H', sb, 104)
blocklog = sb[120]; inopblog = sb[123]; agblklog = sb[124]

def fsb_to_daddr(fsb):
    agno = fsb >> agblklog; agbno = fsb & ((1 << agblklog) - 1)
    return (agno * agblocks + agbno) * (blocksize // 512)

def read_dinode(ino):
    agno = ino >> (agblklog + inopblog)
    agbno = (ino >> inopblog) & ((1 << agblklog) - 1)
    slot = ino & ((1 << inopblog) - 1)
    f.seek(xfs_off + (agno * agblocks + agbno) * blocksize + slot * inodesize)
    return f.read(inodesize)

def fork_extents(ino):
    di = read_dinode(ino)
    fmt = di[5]
    nx, = struct.unpack_from('>I', di, 76)
    lit = 176
    exts = []
    if fmt == 2:
        for i in range(nx):
            hi, lo = struct.unpack_from('>QQ', di, lit + i * 16)
            startoff = (hi >> 9) & ((1 << 54) - 1)
            sb_ = ((hi & 0x1ff) << 43) | (lo >> 21)
            cnt = lo & ((1 << 21) - 1)
            exts.append((startoff, sb_, cnt))
    elif fmt == 3:
        forkoff = di[82]
        litsz = (inodesize - 176) if forkoff == 0 else forkoff * 8
        level, numrec = struct.unpack_from('>HH', di, lit)
        maxrec = (litsz - 4) // 16
        ptrs = [struct.unpack_from('>Q', di, lit + 4 + maxrec * 8 + i * 8)[0]
                for i in range(numrec)]
        def walk(fsb):
            f.seek(xfs_off + fsb_to_daddr(fsb) * 512)
            blk = f.read(blocksize)
            if blk[0:4] != b'BMA3':
                return
            lvl, nrec = struct.unpack_from('>HH', blk, 4)
            hdr = 72
            if lvl > 0:
                mx = (blocksize - hdr) // 16
                for i in range(nrec):
                    p, = struct.unpack_from('>Q', blk, hdr + mx * 8 + i * 8)
                    walk(p)
            else:
                for i in range(nrec):
                    hi, lo = struct.unpack_from('>QQ', blk, hdr + i * 16)
                    startoff = (hi >> 9) & ((1 << 54) - 1)
                    sb_ = ((hi & 0x1ff) << 43) | (lo >> 21)
                    cnt = lo & ((1 << 21) - 1)
                    exts.append((startoff, sb_, cnt))
        for p in ptrs:
            walk(p)
    return exts

uv = fork_extents(uv_ino)
pm = fork_extents(pm_ino)
overlap = []
for _, us, uc in uv:
    for _, ps, pc in pm:
        lo = max(us, ps); hi = min(us + uc, ps + pc)
        if lo < hi:
            overlap.append((lo, hi - lo))
print(f"uv extents={len(uv)} pm extents={len(pm)} OVERLAP={overlap if overlap else 'NONE'}")

foreign = []
for off, sfsb, cnt in uv:
    if off >= 8388608:
        continue  # leaf: content freed legitimately looks different
    f.seek(xfs_off + fsb_to_daddr(sfsb) * 512)
    blk = f.read(64)
    magic = blk[0:4]
    owner, = struct.unpack_from('>Q', blk, 40)
    if magic in (b'XDD3', b'XDB3') and owner != uv_ino:
        foreign.append((sfsb, owner))
    elif magic not in (b'XDD3', b'XDB3'):
        foreign.append((sfsb, f'nonmagic:{magic.hex()}'))
print(f"uv data-block foreign-content: {foreign if foreign else 'NONE'}")
print("REPRODUCED" if (overlap or foreign) else "CLEAN")
EOF
else
    echo "WARN: could not stat test dirs (uv=$UV_INO pm=$PM_INO)" | tee -a "$LOGDIR/summary.txt"
fi

# 5. verdict.  P-DBLALLOC(+AGF) content hits are EXCLUDED from the verdict:
# they fire 150-600×/iter on legitimate foreign-dead block reuse (holds=dir-
# block, magic XDD3) — proven false-positive family (iters 1b/3/5b all CLEAN
# on the static xref while logging 334-1148 of them).  They are still pulled
# into probes_test*.log for manual correlation; the authoritative double-alloc
# channels are the mechanism probes (P130/P131/cil_resident), the static
# fork-overlap/foreign-content check, and quiesced scripts/xref_owners.py.
dblnoise=$(cat "$LOGDIR"/probes_test*.log 2>/dev/null | grep -cE 'P-DBLALLOC |P-DBLALLOC-AGF' || true)
echo "dblalloc_content_hits=$dblnoise (FP-prone; not part of verdict)" | tee -a "$LOGDIR/summary.txt"
hits=$(cat "$LOGDIR"/probes_test*.log 2>/dev/null | grep -cE 'P130-FALSE-FRESH|P131-INVAL-DISCARD|cil_resident=[1-9]' || true)
fails=$(grep -cE '^  FAIL' "$LOGDIR"/batch1.log "$LOGDIR"/batch2.log 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
repro=$(grep -c '^REPRODUCED$' "$LOGDIR/summary.txt" || true)
echo "probe_hits=$hits test_fails=$fails static_repro=$repro" | tee -a "$LOGDIR/summary.txt"
if [ "${hits:-0}" -gt 0 ] || [ "${repro:-0}" -gt 0 ] || [ "${fails:-0}" -gt 0 ]; then
    echo "=== iter $ITER: REPRODUCED (hits=$hits fails=$fails static=$repro) ===" | tee -a "$LOGDIR/summary.txt"
    exit 10
fi
echo "=== iter $ITER: clean ===" | tee -a "$LOGDIR/summary.txt"
exit 0
