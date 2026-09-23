#!/bin/bash
# crash_audit — board criterion (coord=host, TERMINAL): the crash-recovery
# STRUCTURAL gate (ledger D-THE-CLUSTERED-STRUCTURAL-AUDIT-GATE-DOES-NOT-
# ESTABLISH-THAT, clause 2).
#
# WHY.  chk_clean audits the platter after a workload PLUS an orderly
# shutdown: unmount drains delayed allocation, commits metadata and writes the
# lazy counters, so an orderly CLEAN says nothing about the path a shared-LUN
# filesystem is actually for — a node dying with fsync-acknowledged work in
# its journal slice and the survivor replaying that slice onto the shared
# platter.  Until this row the board had no structural verdict over THAT
# platter; the two crash rows it had (crash_consistency, fence_during_write)
# never run the checker, and the harnesses that do are targeted probes off
# the board.  A gate cited as covering crash recovery must have examined a
# platter that went through one.
#
# SHAPE (2 nodes: W = survivor and elected replayer, V = victim):
#   1. tests/tcp_death_replay.sh, the proven death oracle, plain arm: V
#      streams fsynced files, is virsh-destroyed mid-stream; W's heartbeat
#      expiry -> fence -> sealed manifest -> foreign replay -> recovery
#      complete, every step asserted by its probe line; every file V had
#      acknowledged before the kill reads on W with its md5.  The oracle
#      restarts V (unmounted) and leaves W mounted.  Its PASS with acked >= 1
#      is the non-vacuity witness: the replayed slice demonstrably carried
#      that many inode allocations and their data.
#   2. On W, still mounted: the inode numbers of every file in the oracle's
#      directory (>= acked), recorded outside the filesystem.
#   3. W unmounts (bounded; the last member's unmount writes the counters),
#      and the offline checker runs cold on W against its resolved LUN:
#      structural CLEAN (rc 0, zero error lines), the chunk/free-space
#      aliasing pass OK, the superblock icount/ifree equal to the inobt sums,
#      and every recorded replayed inode still allocated in the inobt the
#      checker walked.
#   4. The row ends with the fleet UNMOUNTED (W out, V freshly rebooted): it
#      is TERMINAL and must be the last row of the matrix (it lives in the
#      "death" category, appended last); the next board run's prep_cluster
#      re-forms the cluster.
#
# WHAT THE PASS CLAIMS: after one dirty node death and the survivor's
# foreign replay of its slice, the shared platter is structurally intact,
# its inode accounting reconciles, and the replayed files' inodes are
# allocated on it.  It does not claim crash coverage of any other cut (the
# fence crash cuts are their own record), nor coverage of the allocator
# transitions (alloc_witness + chk_clean is that gate).
#
# derived time budget (from MEASURED walls, not padded):
#   oracle: setup ~10 s + 6 s writing + ~62 s death detection + fence/
#     seal/replay ~15-25 s + verify ~10 s + V restart ~60 s = ~170 s
#     (measured 167-169 s at 2/tcp, tests/criteria/TIMEOUT_BUDGETS.md);
#     its own caller bound 240 s
#   stat of the replayed files ~3 s; W's lone unmount typ 3 s, bound 120 s;
#     chk_mxfs -v on the 50 G device 10-35 s, bound 120 s; geometry ~2 s
#   => ~225 s typical; criteria budget_s 440 = 240 + 120 + 60 + 20.  A row
#   that overruns FAILs; tighten toward measured after healthy PASSes.
set -u
N=${MXFS_NODES:?}
RUN=${MXFS_RUN_ID:-local}
MNT=${MXFS_MNT:-/mnt/shared}
cd /src/mxfs || { echo "RESULT: FAIL src=test | measured=setup | reason=not-on-clyde"; exit 1; }
# shellcheck source=tests/lib/rig.sh
. tests/lib/rig.sh
NODES_CSV=${MXFS_NODE_LIST:-test1,test2}
W=${NODES_CSV%%,*}
V=${NODES_CSV##*,}
OUT=tests/evidence/board_${RUN}_crash_audit
mkdir -p "$OUT"
LABEL="ca_$RUN"
t0=$(date +%s)
fails=0
why=""
ck() {  # <what> <got> <want>
    if [ "$2" = "$3" ]; then echo "  PASS $1"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails + 1)); why="${why}${why:+; }$1 (got $2)"; fi
}
finish() {  # <status> <measured>
    echo "RESULT: $1 src=test | measured=$2 | reason=${why} (evidence $OUT)"
}

[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }

# The kernel-log mark every count in this row is taken from.  Named for the RUN
# and not for the row, because a mark named for the row matches the PREVIOUS
# lap's copy of itself and replays that lap's verdict.  Written BEFORE the
# oracle, so the window covers the death, the fence and the replay.
CAMARK="CA-MARK-$RUN"
rs 20 "$W" "echo '$CAMARK' > /dev/kmsg" >/dev/null 2>&1

# ---- 1. the death oracle -----------------------------------------------------
echo "  INFO oracle: tests/tcp_death_replay.sh $LABEL $W $V (bound 240 s) at $(date -u +%T)"
timeout --kill-after=5 240 tests/tcp_death_replay.sh "$LABEL" "$W" "$V" > "$OUT/oracle.log" 2>&1
orc=$?
oline=$(grep -a '^RESULT:' "$OUT/oracle.log" | tail -1 | cut -c1-300)
acked=$(printf '%s' "$oline" | grep -ao 'acked=[0-9]*' | cut -d= -f2)
replay_s=$(printf '%s' "$oline" | grep -ao 'replay_s=[0-9]*' | cut -d= -f2)
oevid=$(printf '%s' "$oline" | grep -ao 'evidence=[^ ]*' | cut -d= -f2)
echo "  INFO oracle rc=$orc wall=$(( $(date +%s) - t0 ))s: ${oline:-<no RESULT line>}"
ck "the death oracle passed (V's slice fenced, sealed and replayed by W, every acknowledged file verified)" "$orc:$(printf '%s' "$oline" | awk '{print $2}')" "0:PASS"
ck "the replayed slice carried acknowledged files (acked >= 1)" "$([ "${acked:-0}" -ge 1 ] && echo yes || echo "no(${acked:-none})")" "yes"
if [ "$orc" != 0 ] || [ "${acked:-0}" -lt 1 ]; then
    # the platter after a FAILED replay is still worth a cold look, but the
    # row's verdict is already FAIL; do not mount anything back
    finish FAIL "oracle=FAIL acked=${acked:-0}"
    exit 1
fi

# ---- 2. the replayed files' inode numbers, from W while it is mounted --------
# the oracle's two directories: tdr_<label> (the victim's stream) and
# tdr_pre_<label> (W's pre-cached files the victim rewrote and added to);
# the acknowledged set spans both
D="$MNT/tdr_$LABEL"; PRE="$MNT/tdr_pre_$LABEL"
measure "$W" 40 "$OUT/replayed_inos.txt" '^INOS=[0-9]+$' "the replayed files' inode numbers on $W" \
    "for d in '$D' '$PRE'; do [ -d \"\$d\" ] && ( cd \"\$d\" && stat -c '%i %n' * 2>/dev/null | grep -aE '^[0-9]+ ' ); done > /root/ca_inos.txt; cat /root/ca_inos.txt; echo INOS=\$(grep -ac . /root/ca_inos.txt)"
ninos=$(grep -ao '^INOS=[0-9]*' "$OUT/replayed_inos.txt" | cut -d= -f2)
ck "W lists at least the acknowledged files across the oracle's directories (inodes recorded: ${ninos:-0}, acked: $acked)" "$([ "${ninos:-0}" -ge "$acked" ] && echo yes || echo no)" "yes"

# ---- 2b. the NAMESPACE, on the survivor, while it is still mounted -------------
# A replay that recovers every acknowledged file and still leaves the mount root
# unreachable has recovered nothing anybody can use, and that is not a
# hypothetical: measured on 2026-09-20 at 0.89.28, the victim mastered the ROOT
# INODE, so after the refused replay `ls /mnt/shared` returned "Stale file
# handle" and `mkdir` under it returned EIO, with the kernel naming the cause
# (P240-QUAR-NSOP-REFUSE op=lookup ino=128) for comm=ls, comm=md5sum and
# comm=mkdir alike.  Every acknowledged-file assertion above reads a path
# BENEATH that root, so each one of them can pass on a filesystem whose root is
# gone only because the row never asked.  This asks.
#
# Both operations are in the RECOVERED domain by design, which is the point: a
# lookup of the mount root and a create in it are what the dead node mastered.
# Asking after the replay completed is asking whether the recovery handed that
# mastery back, not whether a fail-fast refusal works.
NSDIR="ca_ns_${RUN}"
measure "$W" 40 "$OUT/namespace_$W.txt" '^NS_LS=[0-9]+ NS_MKDIR=[0-9]+$' \
    "the mount root's reachability on $W after the replay" \
    "ls $MNT >/dev/null 2>&1; l=\$?; mkdir $MNT/$NSDIR >/dev/null 2>&1; m=\$?; [ \$m = 0 ] && rmdir $MNT/$NSDIR >/dev/null 2>&1; \
     echo NS_LS=\$l NS_MKDIR=\$m"
nsline=$(grep -a '^NS_LS=' "$OUT/namespace_$W.txt" | head -1)
echo "  INFO namespace on $W: ${nsline:-<none>}"
ck "the mount root is readable on W after the replay (ls of the mount root succeeds)" \
   "$(printf '%s' "$nsline" | grep -ao 'NS_LS=[0-9]*' | cut -d= -f2)" "0"
ck "the mount root accepts a create on W after the replay (mkdir in the mount root succeeds)" \
   "$(printf '%s' "$nsline" | grep -ao 'NS_MKDIR=[0-9]*' | cut -d= -f2)" "0"
# Counted from THIS lap's own mark, never from the whole ring: the ring on a
# rig node carries earlier laps, and an unmarked count would charge this row
# with a refusal some previous session provoked.
window_count_into nsquar "$W" 40 "$CAMARK" 'P240-QUAR-NSOP-REFUSE' ca_quar
window_count_into nsshut "$W" 40 "$CAMARK" 'Shutting down filesystem' ca_shut
ck "no namespace operation on W was refused by a quarantine in this lap (P240-QUAR-NSOP-REFUSE)" \
   "$nsquar" "0"
ck "W never shut its filesystem down across the death and the replay" "$nsshut" "0"

# ---- 3. W unmounts and audits the platter cold --------------------------------
tu=$(date +%s)
measure "$W" 130 "$OUT/umount_$W.txt" '^UMOUNT_RC=[0-9]+ ms=[0-9]+ mounted=[01]$' "the last member's unmount on $W" \
    "sync; s=\$(date +%s%N); timeout 120 umount $MNT; rc=\$?; e=\$(date +%s%N); mountpoint -q $MNT && m=1 || m=0; echo UMOUNT_RC=\$rc ms=\$(( (e-s)/1000000 )) mounted=\$m"
uline=$(grep -a '^UMOUNT_RC=' "$OUT/umount_$W.txt" | head -1)
echo "  INFO $W unmount: $uline (wall $(( $(date +%s) - tu ))s)"
ck "W unmounted cleanly as the last member" "$(printf '%s' "$uline" | grep -ao 'UMOUNT_RC=[0-9]*.*mounted=[01]' | sed 's/ ms=[0-9]*//')" "UMOUNT_RC=0 mounted=0"
if ! printf '%s' "$uline" | grep -q 'mounted=0'; then
    finish FAIL "oracle=PASS acked=$acked umount=stuck"
    exit 1
fi

tc=$(date +%s)
mxfs_chk_on_node "$W" "$OUT/chk_$W.txt" "the cold structural audit on $W after the replay" -v
crc=$(mxfs_chk_rc "$OUT/chk_$W.txt")
grep -av "^${RS_STATUS_TAG:-__none__} " "$OUT/chk_$W.txt" > "$OUT/chk_$W.out"
errs=$(grep -ciE 'error|corrupt|bad magic|inconsistent' "$OUT/chk_$W.out")
alias_line=$(grep -a 'Chunk/free-space aliasing' "$OUT/chk_$W.out" | head -1 | sed 's/^ *//;s/ \+/ /g')
icount=$(sed -n 's/.*Superblock icount: *//p' "$OUT/chk_$W.out" | tail -1 | tr -d ' \r')
inobt_sum=$(sed -n 's/.*Total inodes (inobt sum): *//p' "$OUT/chk_$W.out" | tail -1 | tr -d ' \r')
ifree=$(sed -n 's/.*Superblock ifree: *//p' "$OUT/chk_$W.out" | tail -1 | tr -d ' \r')
ifree_sum=$(sed -n 's/.*Total free inodes (inobt sum): *//p' "$OUT/chk_$W.out" | tail -1 | tr -d ' \r')
echo "  INFO cold audit on $W: rc=${crc:-?} errs=$errs icount=${icount:-?} inobt_sum=${inobt_sum:-?} ifree=${ifree:-?} ifree_sum=${ifree_sum:-?} ${alias_line:-aliasing=not-reported} (wall $(( $(date +%s) - tc ))s)"
ck "the checker completed and found no structural violation (rc 0, zero error lines)" "${crc:-none}:$errs" "0:0"
ck "the chunk/free-space aliasing pass ran and is OK" "$(printf '%s' "$alias_line" | grep -ac 'OK')" "1"
ck "the checker reported the cold inode accounting" "$([ -n "$icount" ] && [ -n "$inobt_sum" ] && [ -n "$ifree" ] && [ -n "$ifree_sum" ] && echo yes || echo no)" "yes"
ck "superblock icount equals the inobt sum after the replay" "${icount:-?}" "${inobt_sum:-!}"
ck "superblock ifree equals the inobt free sum after the replay" "${ifree:-?}" "${ifree_sum:-!}"

# the replayed inodes are allocated in the cold inobt the checker walked
measure "$W" 30 "$OUT/geometry.txt" 'agcount=[0-9]+' "the geometry on $W" \
    "/src/mxfs/tools/chk_mxfs --geometry $MXFS_DEV_RESOLVED 2>&1 | grep -ao 'agcount=[0-9]*\|agblocks=[0-9]*\|agblklog=[0-9]*\|inopblog=[0-9]*' | tr '\n' ' '; echo"
python3 - "$OUT/replayed_inos.txt" "$OUT/chk_$W.out" "$OUT/geometry.txt" > "$OUT/replayed_alloc.txt" 2>&1 <<'PY'
import re, sys
inos_f, chk_f, geo_f = sys.argv[1:4]
geo = open(geo_f, errors="replace").read()
def gval(k):
    m = re.search(r"\b%s=(\d+)" % k, geo); return int(m.group(1)) if m else None
agblocks, inopblog, agblklog = gval("agblocks"), gval("inopblog"), gval("agblklog")
if agblocks is None or inopblog is None:
    print("ALLOC checked=0 allocated=0 missing=0 reason=no-geometry"); sys.exit(0)
if agblklog is None: agblklog = max(1, (agblocks - 1).bit_length())
shift = agblklog + inopblog; mask = (1 << shift) - 1
recs = {}
pat = re.compile(r"AG (\d+) inobt rec \d+: startino=(\d+) count=(\d+) freecount=(\d+) holemask=0x([0-9A-Fa-f]+) free=0x([0-9A-Fa-f]+)")
for ln in open(chk_f, errors="replace"):
    m = pat.search(ln)
    if m: recs.setdefault(int(m.group(1)), []).append((int(m.group(2)), int(m.group(6), 16)))
if not recs:
    print("ALLOC checked=0 allocated=0 missing=0 reason=no-inobt-records"); sys.exit(0)
inos = [int(l.split()[0]) for l in open(inos_f, errors="replace") if re.match(r"^\d+ ", l)]
missing = []
for ino in inos:
    ag, agino = ino >> shift, ino & mask
    ok = False
    for start, free in recs.get(ag, []):
        if start <= agino < start + 64:
            ok = not (free >> (agino - start)) & 1; break
    if not ok: missing.append(ino)
print("ALLOC checked=%d allocated=%d missing=%d %s" % (len(inos), len(inos) - len(missing), len(missing), ",".join(map(str, missing[:8]))))
PY
aline=$(grep -a '^ALLOC' "$OUT/replayed_alloc.txt" | head -1)
echo "  INFO replayed inodes in the cold inobt: ${aline:-<none>}"
ck "every replayed file's inode is allocated in the cold inobt (checked >= acked, missing 0)" \
    "$(printf '%s' "$aline" | grep -ao 'checked=[0-9]*' | cut -d= -f2 | awk -v a="$acked" '{print ($1>=a)?"ok":"short("$1")"}'):$(printf '%s' "$aline" | grep -ao 'missing=[0-9]*' | cut -d= -f2)" "ok:0"

wall=$(( $(date +%s) - t0 ))
m="oracle=PASS acked=$acked replay_s=${replay_s:-?} ns_ls=$(printf '%s' "$nsline" | grep -ao 'NS_LS=[0-9]*' | cut -d= -f2) ns_mkdir=$(printf '%s' "$nsline" | grep -ao 'NS_MKDIR=[0-9]*' | cut -d= -f2) quar=$nsquar shut=$nsshut umount_ms=$(printf '%s' "$uline" | grep -ao 'ms=[0-9]*' | cut -d= -f2) chk_rc=${crc:-?} errs=$errs icount=${icount:-?} ${alias_line:-aliasing=not-reported} ${aline:-alloc=none} wall=${wall}s oracle_evidence=${oevid:-?}"
if [ "$fails" = 0 ]; then finish PASS "$m"; else finish FAIL "$m"; fi
exit $(( fails > 0 ))
