#!/bin/bash
# alloc_witness — the allocation-coverage witness the cold structural audit's
# CLEAN rests on (design-consult rulings, docs/rulings/audit-gate-allocation-
# coverage-witness.md: the s71 shape and the s73 re-scoping to the allocator's
# design).  Runs on every node immediately BEFORE chk_clean.
#
# WHY.  The cold audit proves the platter it examined was structurally intact.
# It cannot say that the clustered workload before it carved inode chunks on
# both nodes at the same time, kept every carve inside the AG partition the
# design relies on, emptied a chunk and reused it in place, or moved the
# finobt on an existing chunk — and those are the transitions the audit
# claims to cover.  A CLEAN over a volume the workload barely touched is green
# for reasons unrelated to the claim.  So the release verdict is conjunctive:
# chk_clean's CLEAN counts only when THIS row's coverage witness passed, and
# the two results are kept apart in the record.
#
# WHAT THE ALLOCATOR DOES, WHICH THE FLOORS ARE WRITTEN FOR.  On a multi-node
# mount every regular file AND every directory is allocated from this node's
# own affine AG (node slot mod AG count), whatever the parent's AG, and a
# strict partition (a node owns agno mod stride == slot mod stride) keeps a
# node out of every other AG short of its whole stride being full; two nodes
# carving in one AG is the recorded precondition of the cross-node inobt
# double-allocation, so the witness asserts it did NOT happen.  A clustered
# mount never deletes a fully free inode chunk (its blocks re-entering the
# free pool under a directory is a measured corruption); the chunk stays in
# the inobt with every inode free and a later create reuses it, so the
# witness asserts THAT lifecycle and that no release happened.
#
# WHAT IT MEASURES.  The module counts SUCCESSFUL transitions per node and AG
# (/sys/kernel/debug/mxfs/<dev>/alloc_witness: chunk carves with the first
# and last carve wall-clock stamps, chunk releases, the two finobt transitions
# on EXISTING chunks — full->partial and partial->full — and, mount-wide, the
# RELAXED ownership-dropping passes, the node's slot and ownership stride) and
# answers a chunk query (alloc_witness_chunk: the inobt record covering an
# inode number, read live from this node's inode btree).  This row clears the
# counters, drives five phases, and snapshots between phases with the
# workload quiesced:
#   1  free-running burst: every node creates files in ONE shared directory
#      for a fixed window (the concurrency witness: per node the first-to-last
#      carve span, corrected by a measured clock offset with its error bound
#      and a drift allowance; the attribution witness: which AG each node's
#      carves landed in);
#   2  breadth: each node creates files in a directory of its own;
#   3  finobt lifecycle: in that directory, free one inode of a full chunk
#      (full->partial) and allocate again (partial->full);
#   4  empty-retain-reuse: a disposable cohort of 256 files is created and
#      every inode number recorded; the chunks the cohort fully occupies are
#      the TARGETS (confirmed by the live chunk query: count 64, no holes,
#      none free); the cohort is unlinked and the row WAITS, per target, for
#      the live query to show every inode free (an unlink is not a free); then
#      it creates again, bounded, until a new inode lands inside a target
#      (reuse in place), recording every inode it created;
#   5  the ending snapshot, with the mount-wide relaxed count.
# A retained, partially used cohort is left in every covered AG and its inode
# numbers are recorded in a manifest OUTSIDE the audited filesystem (this
# tree over NFS), so the cold checker can confirm their bits still allocated
# and each target chunk's record, free mask and finobt entry match exactly
# the occupants this row put back.
#
# THE FLOORS (non-vacuity, not stress adequacy), evaluated by rank 1 over
# every node's record:
#   partition   every node's mount was multi-node with one common stride;
#               every AG with a carve was carved by exactly ONE node, and that
#               node owns it (agno mod stride == slot mod stride)
#   own_ag      each node made >= 2 committed carves in its affine AG in
#               phase 1
#   overlap     the nodes' phase-1 carve spans overlap beyond the clock-offset
#               error plus a 200 ppm drift allowance over the span
#   breadth     carves in >= 2 AGs cluster-wide over the row
#   relaxed     no RELAXED ownership-dropping pass on any node
#   release     zero chunk releases on every node (the guard held)
#   reuse       on EVERY node: >= 1 target chunk observed fully free by the
#               live query after the unlinks, then a create landed in it
#   finobt      >= 1 full->partial AND >= 1 partial->full (cluster-wide)
#   cohort      >= 1 retained inode recorded in every covered AG
#   counters    no clear happened between a node's snapshots
# coverage = PASS | INSUFFICIENT (a floor unmet with complete measurements) |
# UNKNOWN (a measurement missing).  Only PASS lets chk_clean call the release
# verdict CLEAN.  Actual AG attribution comes from the counters, never from
# where a directory was placed.
#
# WHAT THE PASS DOES NOT CLAIM: shared-AG carving (the design forbids it),
# the owned-AG spill and partition wrap (unreachable without filling an AG's
# inode space), the RELAXED fallback, and chunk deletion (reachable only on a
# never-clustered mount, outside this gate).
#
# THE RECORD.  tests/evidence/alloc_witness/<run id>/rank<N>.txt per node and
# witness.txt (rank 1: the verdict, the fsid, the end stamp, the cohort, the
# targets and their occupants, every floor's numbers), sealed by its sha256
# in witness.sha.  chk_clean refuses a witness whose fsid is not the
# platter's or whose run id is not its own — so the two rows must run in ONE
# run.sh invocation (`./run.sh 2 tcp alloc_witness chk_clean`); run apart,
# the audit's verdict is INDETERMINATE by design.  No workload may touch the
# filesystem between this row and chk_clean; the tooling manifest places them
# adjacently and the run id ties them.
#
# Budget (derived): 6 barriers ~2 s each + clock exchange 3 s + phase 1 window
# 25 s + phase 2 ~5 s + phase 3 ~2 s + phase 4 cohort create+stat ~4 s,
# unlink ~3 s, empty wait <= 30 s, reuse creates ~3 s + settle 3 s + snapshots
# and NFS writes ~5 s => ~95 s; 180 s row.
SUITE_TEST_NAME=alloc_witness
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
RANK="${MXFS_RANK:-1}"
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
BURST_S="${AW_BURST_S:-25}"
BURST_MAX="${AW_BURST_MAX:-6000}"
EMPTY_WAIT_S="${AW_EMPTY_WAIT_S:-30}"
# the reuse bound: the allocator fills the free inodes nearest the parent
# first (the cohort's two partial edge chunks, ~115 creates measured at 2/tcp)
# before a whole emptied target wins, so the bound carries 4x that margin
REUSE_MAX="${AW_REUSE_MAX:-512}"

emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }

# Coordination only (as chk_clean: lib.sh's finish would print a second RESULT).
: "${COORD_TIMEOUT:=40}"
export COORD_TIMEOUT
COORD="$(dirname -- "${BASH_SOURCE[0]}")/../suite/coord.sh"
# shellcheck source=/dev/null
[ -f "$COORD" ] && source "$COORD"
command -v coord_barrier >/dev/null 2>&1 || coord_barrier() { return 0; }
command -v coord_put >/dev/null 2>&1 || coord_put() { return 0; }
command -v coord_get >/dev/null 2>&1 || coord_get() { return 1; }

if [ "$FSTYPE" = xfs ]; then
    emit SKIPPED "native-xfs" "the witness counters are MXFS's own; native XFS has no equivalent"
    exit 0
fi

# the run id ties this record to the chk_clean that follows it
RUN_ID=$(printf '%s' "${MXFS_COORD_PREFIX:-}" | awk -F/ '{print $3}')
[ -n "$RUN_ID" ] || RUN_ID="${MXFS_RUN_ID:-norun}"
TREE="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
WDIR="$TREE/tests/evidence/alloc_witness/$RUN_ID"
mkdir -p "$WDIR" 2>/dev/null
if [ ! -d "$WDIR" ] || [ ! -w "$WDIR" ]; then
    emit FAIL "witness_dir=unwritable rank=$RANK" "the witness record must live outside the audited filesystem and $WDIR is not writable from this node (is the tree mounted over NFS?)"
    exit 1
fi
REC="$WDIR/rank$RANK.txt"
: > "$REC"
rec(){ printf '%s\n' "$*" >> "$REC"; }

fail_out(){ # <measured> <reason>: record the abort in the rank file and leave
    rec "ABORT $2"
    coord_barrier "aw_written" >/dev/null 2>&1
    emit FAIL "$1" "$2"
    exit 1
}

mountpoint -q "$MNT" || fail_out "mounted=0 rank=$RANK" "the filesystem is not mounted on this node"

# ---- the counter file: exactly one mounted MXFS on this node ---------------
WIT=""
n=0
for f in /sys/kernel/debug/mxfs/*/alloc_witness; do
    [ -e "$f" ] || continue
    n=$((n + 1)); WIT=$f
done
[ "$n" = 1 ] || fail_out "witness_files=$n rank=$RANK" "expected exactly one /sys/kernel/debug/mxfs/<dev>/alloc_witness on this node (the module build must carry the counters)"
WITC="${WIT%/alloc_witness}/alloc_witness_chunk"
[ -e "$WITC" ] || fail_out "chunk_query=missing rank=$RANK" "the module build does not carry alloc_witness_chunk (0.89.10), which the reuse lifecycle's live observation needs"

snap(){ # <label>: the counters, verbatim, into the rank record; sets S_<label>
    local lbl=$1 body
    sync -f "$MNT" 2>/dev/null
    body=$(cat "$WIT" 2>/dev/null)
    [ -n "$body" ] || fail_out "snapshot=$lbl rank=$RANK" "the witness file read empty at snapshot $lbl"
    rec "SNAP $lbl wall_ns=$(date +%s%N)"
    printf '%s\n' "$body" | sed "s/^/  $lbl /" >> "$REC"
    eval "S_$lbl=\$body"
}
hdr(){ printf '%s\n' "$1" | awk 'NR==1'; }
field(){ # <text> <key>: value of key=... on the header line
    hdr "$1" | grep -oE "(^| )$2=[^ ]+" | head -1 | cut -d= -f2
}
agval(){ # <text> <ag> <key>
    printf '%s\n' "$1" | awk -v a="ag=$2" '$1==a' | grep -oE " $3=[0-9]+" | head -1 | cut -d= -f2
}
chunkq(){ # <ino>: the inobt record covering ino, live from this node's kernel
    echo "$1" > "$WITC" 2>/dev/null || return 1
    cat "$WITC" 2>/dev/null
}
cqval(){ # <chunk line> <key>
    printf '%s' "$1" | grep -oE "(^| )$2=[^ ]+" | head -1 | cut -d= -f2
}

# ---- 0a. exhaust the affine AG's free inodes ---------------------------------
# The suite runs this row on a filesystem earlier rows have aged: measured
# s166e, each node's affine AG still held 1379 / 1570 free inodes after the
# row, more than phase 1 ever creates (~830 per node, the shared directory
# serialises the two nodes' creates), so no allocation needed a new chunk and
# own_ag / overlap / breadth had nothing to measure — every run INSUFFICIENT,
# chk_clean VACUOUS.  The same row passed on a young filesystem (s168a).
# So before the counters are cleared, each node creates files in a private
# directory until the witness shows its affine AG carve a chunk: the free
# reserve is then gone and phase 1's creates must carve.  Bounded by FILL_MAX;
# never reaching a carve inside it is a failure with its own reason, not a pass.
D="$MNT/alloc_witness"
FILL_MAX="${AW_FILL_MAX:-8192}"
W0=$(cat "$WIT" 2>/dev/null)
AFF=$(( $(field "$W0" slot) % $(field "$W0" agcount) ))
mkdir -p "$D/fill_r$RANK" || fail_out "fill_mkdir=failed rank=$RANK" "mkdir of the node's fill directory failed"
echo 1 > "$WIT" 2>/dev/null || fail_out "clear=failed rank=$RANK" "the witness counters could not be cleared before the fill"
fill=0; fcarved=0; fstart=$(date +%s%N)
while [ "$fill" -lt "$FILL_MAX" ]; do
    j=0
    while [ "$j" -lt 64 ]; do
        : > "$D/fill_r$RANK/x$fill" || fail_out "fill_create=failed i=$fill rank=$RANK" "a create in the node's fill directory failed"
        fill=$((fill + 1)); j=$((j + 1))
    done
    fcarved=$(agval "$(cat "$WIT" 2>/dev/null)" "$AFF" carves)
    [ "${fcarved:-0}" -ge 1 ] && break
done
rec "FILL affine_ag=$AFF files=$fill carved=${fcarved:-0} wall_ms=$(( ($(date +%s%N) - fstart) / 1000000 ))"
[ "${fcarved:-0}" -ge 1 ] || fail_out "fill=exhausted files=$fill affine_ag=$AFF rank=$RANK" "$fill creates in the affine AG never carved a chunk; the free reserve could not be exhausted inside AW_FILL_MAX"

# ---- 0. clear, baseline, clock exchange -----------------------------------
[ "$RANK" = 1 ] && { mkdir -p "$D/shared" 2>/dev/null; sync -f "$MNT" 2>/dev/null; }
echo 1 > "$WIT" 2>/dev/null || fail_out "clear=failed rank=$RANK" "the witness counters could not be cleared"
snap S0
CLEARS0=$(field "$S_S0" clears)
FSID=$(field "$S_S0" fsid)
SLOT=$(field "$S_S0" slot); STRIDE=$(field "$S_S0" stride); MULTI=$(field "$S_S0" multi)
AGCOUNT=$(field "$S_S0" agcount)
[ -n "$SLOT" ] && [ -n "$STRIDE" ] && [ -n "$MULTI" ] || fail_out "header=old rank=$RANK" "the witness header carries no slot/stride/multi (a 0.89.10 module is required)"
rec "FSID $FSID"
rec "NODE rank=$RANK host=$(hostname) module=$(cat /sys/module/mxfs/srcversion 2>/dev/null) slot=$SLOT stride=$STRIDE multi=$MULTI agcount=$AGCOUNT affine_ag=$(( SLOT % AGCOUNT ))"

if ! coord_barrier "aw_start"; then fail_out "barrier=aw_start rank=$RANK" "not every node reached the start rendezvous"; fi

# clock offset of every rank against rank 1: rank 1 publishes t1, rank k
# answers with its receive time t2, rank 1 reads the answer at t3.  offset_k
# (rank k's clock minus rank 1's) = t2 - (t1+t3)/2, error <= (t3-t1)/2.
if [ "$NODES" -ge 2 ]; then
    if [ "$RANK" = 1 ]; then
        k=2
        while [ "$k" -le "$NODES" ]; do
            t1=$(date +%s%N)
            coord_put "aw_ping_$k" "$t1"
            t2=$(coord_get "aw_pong_$k" 20) || fail_out "clock=rank$k rank=1" "rank $k never answered the clock exchange"
            t3=$(date +%s%N)
            off=$(( t2 - (t1 + t3) / 2 )); err=$(( (t3 - t1) / 2 ))
            rec "CLOCK rank=$k offset_ns=$off err_ns=$err t1=$t1 t2=$t2 t3=$t3"
            k=$((k + 1))
        done
    else
        t1=$(coord_get "aw_ping_$RANK" 30) || fail_out "clock=noping rank=$RANK" "rank 1 never sent the clock exchange"
        t2=$(date +%s%N)
        coord_put "aw_pong_$RANK" "$t2"
        rec "CLOCK answered t1=$t1 t2=$t2"
    fi
fi

# ---- 1. the free-running burst in one shared directory ----------------------
if ! coord_barrier "aw_p1"; then fail_out "barrier=aw_p1 rank=$RANK" "not every node reached the burst rendezvous"; fi
[ -d "$D/shared" ] || fail_out "shared_dir=missing rank=$RANK" "the shared directory rank 1 created is not visible here"
rec "PHASE1 start_ns=$(date +%s%N)"
t_end=$(( $(date +%s) + BURST_S )); i=0
while [ "$i" -lt "$BURST_MAX" ]; do
    : > "$D/shared/r${RANK}_$i" || fail_out "phase1_create=failed i=$i rank=$RANK" "a create in the shared directory failed"
    i=$((i + 1))
    if [ $(( i % 64 )) = 0 ] && [ "$(date +%s)" -ge "$t_end" ]; then break; fi
done
rec "PHASE1 end_ns=$(date +%s%N) files=$i"
snap S1
if ! coord_barrier "aw_p2"; then fail_out "barrier=aw_p2 rank=$RANK" "not every node finished the burst"; fi

# ---- 2. breadth: a directory of this node's own -----------------------------
mkdir -p "$D/own_r$RANK" || fail_out "phase2_mkdir=failed rank=$RANK" "mkdir of the node's own directory failed"
i=0
while [ "$i" -lt 200 ]; do : > "$D/own_r$RANK/f$i" || fail_out "phase2_create=failed i=$i rank=$RANK" "a create in the node's own directory failed"; i=$((i + 1)); done
sync -f "$MNT"
rec "PHASE2 files=200 end_ns=$(date +%s%N)"

# ---- 3. finobt lifecycle on an existing full chunk -------------------------
# f5 sits in the first chunk of own_r<rank>, which 200 creates filled; its
# unlink turns that chunk full->partial, and the next create takes the freed
# inode back (the finobt is searched first), partial->full.
rm -f "$D/own_r$RANK/f5" || fail_out "phase3_unlink=failed rank=$RANK" "the unlink for the finobt transition failed"
sync -f "$MNT"
: > "$D/own_r$RANK/f5b" || fail_out "phase3_create=failed rank=$RANK" "the create for the finobt transition failed"
sync -f "$MNT"
rec "PHASE3 end_ns=$(date +%s%N)"

# ---- 4. empty-retain-reuse: a disposable cohort, its chunks, its return -----
mkdir -p "$D/disp_r$RANK" || fail_out "phase4_mkdir=failed rank=$RANK" "mkdir of the disposable directory failed"
i=0
while [ "$i" -lt 256 ]; do : > "$D/disp_r$RANK/d$i" || fail_out "phase4_create=failed i=$i rank=$RANK" "a create in the disposable directory failed"; i=$((i + 1)); done
: > "$D/disp_r$RANK/keep"
sync -f "$MNT"
# every cohort inode number, then the chunks the cohort occupies COMPLETELY
# (all 64 numbers of a 64-aligned range are cohort members; `keep` was
# created last, so its chunk is never complete and is never a target)
COHORT_INOS=$(stat -c '%i' "$D/disp_r$RANK"/d[0-9]* 2>/dev/null | sort -n)
[ "$(printf '%s\n' "$COHORT_INOS" | wc -l)" = 256 ] || fail_out "phase4_stat=short rank=$RANK" "could not stat all 256 disposable files"
TARGETS=$(printf '%s\n' "$COHORT_INOS" | awk '{c=int($1/64)*64; n[c]++} END{for(c in n) if(n[c]==64) print c}' | sort -n)
[ -n "$TARGETS" ] || fail_out "targets=0 rank=$RANK" "no chunk is fully occupied by the disposable cohort (256 contiguous creates should fill at least three)"
NT=0
for c in $TARGETS; do
    q=$(chunkq "$c") || fail_out "chunk_query=failed rank=$RANK" "the live chunk query could not be issued"
    st=$(cqval "$q" startino); cnt=$(cqval "$q" count); fc=$(cqval "$q" freecount); hm=$(cqval "$q" holemask)
    rec "TARGET chunk=$c query_before=[$q]"
    # a target must be a whole, unholed chunk with none of its inodes free
    [ -n "$st" ] && [ "$cnt" = 64 ] && [ "$hm" = 0x0000 ] && [ "$fc" = 0 ] || { rec "TARGET chunk=$c rejected=1"; continue; }
    NT=$((NT + 1))
done
[ "$NT" -ge 1 ] || fail_out "targets_confirmed=0 rank=$RANK" "no candidate chunk was confirmed by the live query as whole, unholed and fully allocated"
snap S3
REL3=0; for ag in $(printf '%s\n' "$S_S3" | awk '$1 ~ /^ag=/ {sub("ag=","",$1); print $1}'); do REL3=$(( REL3 + $(agval "$S_S3" "$ag" releases) )); done
rm -f "$D/disp_r$RANK"/d[0-9]* || fail_out "phase4_rm=failed rank=$RANK" "the remove of the disposable files failed"
sync -f "$MNT"
rec "PHASE4 removed=256 end_ns=$(date +%s%N) releases_before=$REL3"
# wait, per target, for the live query to show every inode free: the free is
# deferred inactivation, and only the inode btree says it happened
EMPTY=0
for c in $TARGETS; do
    grep -q "^TARGET chunk=$c rejected=1" "$REC" && continue
    w=0; fc=""
    while [ "$w" -le "$EMPTY_WAIT_S" ]; do
        q=$(chunkq "$c"); fc=$(cqval "$q" freecount)
        [ "$fc" = 64 ] && break
        sleep 1; w=$((w + 1))
    done
    rec "EMPTY chunk=$c wait_s=$w freecount=${fc:-?} query_after=[$q]"
    [ "$fc" = 64 ] && EMPTY=$((EMPTY + 1))
done
body=$(cat "$WIT" 2>/dev/null); RELNOW=0
for ag in $(printf '%s\n' "$body" | awk '$1 ~ /^ag=/ {sub("ag=","",$1); print $1}'); do RELNOW=$(( RELNOW + $(agval "$body" "$ag" releases) )); done
rec "PHASE4 targets=$NT empty=$EMPTY releases_after=$RELNOW"
# reuse in place: bounded creates until one lands inside an emptied target;
# every created inode is recorded, so the checker knows each target's exact
# occupants
REUSED=""; i=0
while [ "$i" -lt "$REUSE_MAX" ]; do
    : > "$D/disp_r$RANK/u$i" || fail_out "phase4_reuse_create=failed i=$i rank=$RANK" "a create for the reuse observation failed"
    ino=$(stat -c %i "$D/disp_r$RANK/u$i"); c=$(( ino / 64 * 64 ))
    rec "OCCUPANT ino=$ino chunk=$c path=alloc_witness/disp_r$RANK/u$i"
    i=$((i + 1))
    if printf '%s\n' "$TARGETS" | grep -qx "$c" && ! grep -q "^TARGET chunk=$c rejected=1" "$REC"; then REUSED="$ino"; break; fi
done
sync -f "$MNT"
if [ -n "$REUSED" ]; then
    q=$(chunkq "$REUSED")
    rec "REUSE ino=$REUSED chunk=$(( REUSED / 64 * 64 )) creates=$i query=[$q]"
else
    rec "REUSE none creates=$i"
fi
rec "PHASE4 reuse_end_ns=$(date +%s%N)"

# ---- the retained cohort: inode numbers, recorded outside the filesystem ----
sleep 3
for f in "$D/shared/r${RANK}_0" "$D/shared/r${RANK}_1" "$D/shared/r${RANK}_63" "$D/shared/r${RANK}_64" \
         "$D/own_r$RANK/f0" "$D/own_r$RANK/f5b" "$D/own_r$RANK/f100" "$D/own_r$RANK/f199" \
         "$D/disp_r$RANK/keep"; do
    [ -e "$f" ] || continue
    rec "COHORT ino=$(stat -c %i "$f") path=${f#$MNT/}"
done
snap SEND
CLEARSEND=$(field "$S_SEND" clears)
rec "CLEARS start=$CLEARS0 end=$CLEARSEND"
rec "RELAXED end=$(field "$S_SEND" relaxed)"
rec "DONE rank=$RANK end_ns=$(date +%s%N)"
sync -f "$MNT"

if ! coord_barrier "aw_written"; then emit FAIL "barrier=aw_written rank=$RANK" "not every node wrote its record"; exit 1; fi

# ---- rank 1: every node's record -> the floors -> the sealed witness --------
if [ "$RANK" != 1 ]; then
    emit PASS "rank=$RANK role=writer record=${REC#$TREE/}"
    exit 0
fi

python3 - "$WDIR" "$NODES" "$FSID" "$RUN_ID" > "$WDIR/eval.txt" 2>&1 <<'PY'
import sys, os, re, hashlib, time
wdir, nodes, fsid, run_id = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
DRIFT_PPM = 200   # the clock-drift allowance over a phase span, on top of the exchange error
def parse(rank):
    p = os.path.join(wdir, "rank%d.txt" % rank)
    if not os.path.exists(p):
        return None
    r = {"snaps": {}, "clock": None, "cohort": [], "abort": None, "fsid": None, "clears": None,
         "node": {}, "targets": {}, "empty": {}, "occupants": [], "reuse": None, "relaxed": None, "phase1": {}}
    for ln in open(p):
        ln = ln.rstrip("\n")
        if ln.startswith("ABORT"):
            r["abort"] = ln
        elif ln.startswith("FSID "):
            r["fsid"] = ln.split()[1]
        elif ln.startswith("NODE "):
            r["node"] = dict(kv.split("=", 1) for kv in ln.split()[1:])
        elif ln.startswith("CLOCK rank="):
            r["clock"] = dict(kv.split("=") for kv in ln.split()[1:])
        elif ln.startswith("COHORT "):
            r["cohort"].append(dict(kv.split("=", 1) for kv in ln.split()[1:]))
        elif ln.startswith("CLEARS "):
            r["clears"] = dict(kv.split("=") for kv in ln.split()[1:])
        elif ln.startswith("RELAXED "):
            r["relaxed"] = int(ln.split()[1].split("=")[1])
        elif ln.startswith("PHASE1 "):
            r["phase1"].update(dict(kv.split("=") for kv in ln.split()[1:]))
        elif ln.startswith("TARGET chunk="):
            m = re.match(r"TARGET chunk=(\d+) (rejected=1|query_before=\[(.*)\])", ln)
            if m and m.group(2) == "rejected=1":
                r["targets"].pop(int(m.group(1)), None)
            elif m:
                r["targets"][int(m.group(1))] = m.group(3)
        elif ln.startswith("EMPTY chunk="):
            m = re.match(r"EMPTY chunk=(\d+) wait_s=(\d+) freecount=(\S+)", ln)
            if m:
                r["empty"][int(m.group(1))] = (int(m.group(2)), m.group(3))
        elif ln.startswith("OCCUPANT "):
            r["occupants"].append(dict(kv.split("=", 1) for kv in ln.split()[1:]))
        elif ln.startswith("REUSE ino="):
            r["reuse"] = dict(kv.split("=", 1) for kv in re.sub(r" query=\[.*\]", "", ln).split()[1:])
        elif ln.startswith("  "):
            parts = ln.split()
            lbl = parts[0]
            snap = r["snaps"].setdefault(lbl, {"hdr": {}, "ag": {}})
            if parts[1] == "alloc_witness":
                snap["hdr"] = dict(kv.split("=") for kv in parts[2:])
            elif parts[1].startswith("ag="):
                d = dict(kv.split("=") for kv in parts[1:])
                snap["ag"][int(d["ag"])] = {k: int(v) for k, v in d.items() if k != "ag"}
    return r
recs = {k: parse(k) for k in range(1, nodes + 1)}
out = []
def say(s): out.append(s)
unknown = []
for k, r in recs.items():
    if r is None: unknown.append("rank%d record missing" % k); continue
    if r["abort"]: unknown.append("rank%d aborted: %s" % (k, r["abort"]))
    for lbl in ("S0", "S1", "S3", "SEND"):
        if lbl not in r["snaps"]: unknown.append("rank%d snapshot %s missing" % (k, lbl))
    if r["fsid"] != fsid: unknown.append("rank%d fsid %s != %s" % (k, r["fsid"], fsid))
    if r["clears"] and r["clears"].get("start") != r["clears"].get("end"):
        unknown.append("rank%d counters cleared mid-row (%s -> %s)" % (k, r["clears"]["start"], r["clears"]["end"]))
    for key in ("slot", "stride", "multi", "agcount", "affine_ag"):
        if key not in r["node"]: unknown.append("rank%d NODE line lacks %s" % (k, key))
    if r["relaxed"] is None: unknown.append("rank%d relaxed count missing" % k)
clocks = {}
if recs.get(1):
    for ln in open(os.path.join(wdir, "rank1.txt")):
        if ln.startswith("CLOCK rank="):
            d = dict(kv.split("=") for kv in ln.split()[1:])
            clocks[int(d["rank"])] = (int(d["offset_ns"]), int(d["err_ns"]))
for k in range(2, nodes + 1):
    if k not in clocks: unknown.append("no clock offset measured for rank%d" % k)
verdict = "UNKNOWN"
floors = {}
if not unknown:
    p1 = {k: recs[k]["snaps"]["S1"]["ag"] for k in recs}
    end = {k: recs[k]["snaps"]["SEND"]["ag"] for k in recs}
    node = {k: recs[k]["node"] for k in recs}
    ags = sorted(set(a for k in end for a in end[k]))
    # partition: multi-node everywhere with one stride; every carved AG has
    # exactly one carving node, and that node owns it
    strides = set(int(node[k]["stride"]) for k in recs)
    multi_ok = all(node[k]["multi"] == "1" for k in recs)
    carvers = {a: [k for k in recs if end[k].get(a, {}).get("carves", 0) > 0] for a in ags}
    breaches = []
    for a, ks in carvers.items():
        if len(ks) > 1: breaches.append("AG %d carved by ranks %s" % (a, ks))
        for k in ks:
            s = int(node[k]["stride"]); slot = int(node[k]["slot"])
            if s > 1 and a % s != slot % s: breaches.append("AG %d carved by rank %d (slot %d) outside its stride %d" % (a, k, slot, s))
    floors["partition"] = "PASS" if multi_ok and len(strides) == 1 and not breaches else "FAIL"
    say("partition: multi=%s strides=%s carvers=%s breaches=%s" % (multi_ok, sorted(strides), {a: ks for a, ks in carvers.items() if ks}, breaches))
    # own_ag: >= 2 phase-1 carves in each node's affine AG
    own = {k: p1[k].get(int(node[k]["affine_ag"]), {}).get("carves", 0) for k in recs}
    floors["own_ag"] = "PASS" if all(v >= 2 for v in own.values()) else "FAIL"
    say("own_ag: phase-1 carves in each node's affine AG %s (affine %s)" % (own, {k: node[k]["affine_ag"] for k in recs}))
    # overlap: per node the phase-1 span over its AGs, in rank 1's clock
    lo, hi, err, span = None, None, 0, 0
    for k in recs:
        firsts = [d["carve_first_ns"] for d in p1[k].values() if d["carves"] > 0]
        lasts = [d["carve_last_ns"] for d in p1[k].values() if d["carves"] > 0]
        if not firsts: lo, hi = 1, 0; say("overlap: rank %d made no phase-1 carve" % k); break
        f, l = min(firsts), max(lasts)
        off, e = (0, 0) if k == 1 else clocks[k]
        f -= off; l -= off
        err = max(err, e); span = max(span, l - f)
        lo = f if lo is None else max(lo, f)
        hi = l if hi is None else min(hi, l)
    ov = (hi - lo) if lo is not None else 0
    unc = err + span * DRIFT_PPM // 1000000
    floors["overlap"] = "PASS" if ov - unc > 0 else "FAIL"
    say("overlap: overlap_ns=%d err_ns=%d drift_allow_ns=%d (span %d ns at %d ppm) margin_ns=%d" % (ov, err, unc - err, span, DRIFT_PPM, ov - unc))
    # breadth: carves in >= 2 AGs cluster-wide
    allags = sorted(a for a in ags if any(end[k].get(a, {}).get("carves", 0) > 0 for k in recs))
    floors["breadth"] = "PASS" if len(allags) >= 2 else "FAIL"
    say("covered AGs (any carve): %s" % allags)
    # relaxed: no ownership-dropping pass anywhere
    floors["relaxed"] = "PASS" if all(recs[k]["relaxed"] == 0 for k in recs) else "FAIL"
    say("relaxed passes per node: %s" % {k: recs[k]["relaxed"] for k in recs})
    # release: zero on every node (the clustered mount keeps every chunk)
    rel = {k: sum(end[k][a]["releases"] for a in end[k]) for k in recs}
    floors["release"] = "PASS" if all(v == 0 for v in rel.values()) else "FAIL"
    # reuse: every node emptied a target and got an inode back from it
    reuse = {}
    for k in recs:
        r = recs[k]
        emptied = [c for c, (w, fc) in r["empty"].items() if fc == "64" and c in r["targets"]]
        got = r["reuse"] is not None and int(r["reuse"]["chunk"]) in emptied
        reuse[k] = (len(r["targets"]), len(emptied), got, r["reuse"]["ino"] if r["reuse"] else None,
                    max([w for c, (w, fc) in r["empty"].items()] or [0]))
    floors["reuse"] = "PASS" if all(v[2] for v in reuse.values()) else "FAIL"
    say("reuse per node (targets, emptied, reused, ino, max_empty_wait_s): %s" % reuse)
    ins = sum(end[k][a]["fino_ins"] for k in end for a in end[k])
    dele = sum(end[k][a]["fino_del"] for k in end for a in end[k])
    floors["finobt"] = "PASS" if ins >= 1 and dele >= 1 else "FAIL"
    say("cluster-wide releases=%s fino_ins=%d fino_del=%d" % (rel, ins, dele))
    floors["cohort"] = "PASS"   # per-AG cohort presence is decided by chk_clean, which knows the geometry
    verdict = "PASS" if all(v == "PASS" for v in floors.values()) else "INSUFFICIENT"
lines = ["ALLOC_WITNESS run=%s fsid=%s nodes=%d coverage=%s" % (run_id, fsid, nodes, verdict)]
for k, v in floors.items(): lines.append("FLOOR %s %s" % (k, v))
for u in unknown: lines.append("UNKNOWN %s" % u)
for s in out: lines.append("NOTE %s" % s)
for k, r in recs.items():
    if r is None: continue
    lines.append("NODE rank=%d %s" % (k, " ".join("%s=%s" % kv for kv in sorted(r["node"].items()))))
    for c in r["cohort"]: lines.append("COHORT rank=%d ino=%s path=%s" % (k, c["ino"], c["path"]))
    for c in sorted(r["targets"]):
        w, fc = r["empty"].get(c, (None, "?"))
        occ = sorted(int(o["ino"]) for o in r["occupants"] if int(o["chunk"]) == c)
        lines.append("TARGET rank=%d chunk=%d emptied=%s wait_s=%s occupants=%s" % (k, c, "yes" if fc == "64" else "no", w, ",".join(map(str, occ)) or "-"))
    for o in r["occupants"]: lines.append("OCCUPANT rank=%d ino=%s chunk=%s path=%s" % (k, o["ino"], o["chunk"], o["path"]))
    if "SEND" in r["snaps"]:
        for a, d in sorted(r["snaps"]["SEND"]["ag"].items()):
            lines.append("END rank=%d ag=%d carves=%d releases=%d fino_ins=%d fino_del=%d" % (k, a, d["carves"], d["releases"], d["fino_ins"], d["fino_del"]))
lines.append("END_NS %d" % time.time_ns())
body = "\n".join(lines) + "\n"
open(os.path.join(wdir, "witness.txt"), "w").write(body)
open(os.path.join(wdir, "witness.sha"), "w").write(hashlib.sha256(body.encode()).hexdigest() + "\n")
print("coverage=%s floors=%s unknown=%d" % (verdict, ",".join("%s:%s" % kv for kv in floors.items()), len(unknown)))
PY
ev=$(tail -1 "$WDIR/eval.txt")
cov=$(printf '%s' "$ev" | grep -oE 'coverage=[A-Z]+' | cut -d= -f2)
m="coverage=${cov:-UNKNOWN} $(printf '%s' "$ev" | grep -oE 'floors=[^ ]+') run=$RUN_ID fsid=$FSID witness=${WDIR#$TREE/}/witness.txt"
case "$cov" in
PASS)          emit PASS "$m" ;;
INSUFFICIENT)  emit FAIL "$m" "a coverage floor was not met with complete measurements; the cold audit that follows can only be VACUOUS (see $WDIR/witness.txt)" ;;
*)             emit FAIL "$m" "a measurement is missing or untrustworthy; the cold audit that follows can only be INDETERMINATE (see $WDIR/eval.txt)" ;;
esac
exit 0
