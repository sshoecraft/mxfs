#!/bin/bash
# caw_grant_wait_anatomy.sh [files_per_node] [participants]
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess24)
# ----------------------------------------
# tests/create_stall_stacks.sh read the stall site off the kernel rather than
# guessing it.  Of 1005 blocked samples taken during a 32-way create workload
# (256 creates, mean 288ms, p50 25ms, max 2614ms):
#
#     75.3%  mxfs_pal_cond_timedwait   <- caw_acquire_poll_sleep, waiting for an
#                                          INODE grant:
#              mxfs_dlm_inode_lock_routed -> mxfs_v5_dlm_inode_lock
#                -> mxfs_dlm_caw_lock -> caw_wait_for_grant
#                  -> caw_acquire_poll_sleep -> caw_nudge_wait
#     14.2%  blk_execute_rq            <- read_slot's SCSI READ(16) FUA, i.e.
#                                          the poll I/O for the same wait
#      4.2%  mxfs_dlm_ilock_begin
#
# So ~89% of the multi-second create tail is CAW inode-grant wait.  It is NOT
# the poll schedule: MXFS_CAW_POLL_INITIAL_MS=1, _MAX_MS=25,
# INODE_FASTPOLL_INTERVAL_MS=2 for the first 64ms, and the sleep is on a
# grant-nudge cond that a releaser's multicast wakes immediately.
#
# Which leaves two very different possibilities, needing opposite fixes:
#
#   HOLDER-BOUND   the grant genuinely was not available: a peer held the inode
#                  for seconds.  Fix = shorten the hold (tenure cap, release
#                  path cost).
#   CLAIM-BOUND    the slot became COMPATIBLE early and we still burned seconds
#                  before claiming it.  Fix = the claim path (fairness/ticket
#                  deferral, lost nudges, CAW retry livelock).
#
# MXFS already emits the discriminator, always-on:
#     P138-WAIT ino= mode= elapsed_ms= ffw_ms= ytd= poll= realms=
# where ffw_ms is the grantable->granted latency and ytd counts ticket
# deferrals taken WHILE ALREADY GRANTABLE.  ffw_ms/elapsed_ms is exactly the
# CLAIM-BOUND fraction.  P131-WAITLONG (>1s) names the resource.
#
# This harness runs the contended workload and harvests both probes clusterwide,
# scoped to a kmsg marker so nothing from an earlier run is counted (state.md:
# "never count a probe with a bare dmesg | grep -c -- the ring outlives the
# build").
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
F="${1:-8}"
P="${2:-32}"
MNT=/mnt/shared
STAMP=$(date -u +%H%M%S)
OUT=$(mktemp -d)
MARK="MXFS_CGWA_WINDOW_$STAMP"
# sess380: SHAPE selects which resource is contended.
#   shared  (default) — every node creates into ONE directory, which is the
#           shape D-32NODE-SHARED-DIR-CREATE-PACE is about.
#   private — per-node subdirectories; then the only contended inode is the
#           parent, and only for the mkdir.  That is what this harness used to
#           do unconditionally, which is why its census kept reporting the
#           parent inode rather than the directory under test.
# LOCKTOTAL_MS lowers the P139-LOCKTOTAL whole-acquire census floor (kernel
# default 800ms) on every node for the run and restores it afterwards.  Without
# that this harness is BLIND to the tail it exists to explain: measured 2026-08-20,
# a 32-node create tail of p95 424ms / max 471ms produced exactly 4 P138-WAIT
# lines fleet-wide and ZERO P139-LOCKTOTAL, because the acquire is many sub-5ms
# waits with outer retries between them and the whole-acquire probe floor sat
# above the entire distribution.
SHAPE="${SHAPE:-shared}"
LOCKTOTAL_MS="${LOCKTOTAL_MS:-50}"
PARM=/sys/module/mxfs/parameters/caw_locktotal_ms

W=$(cat <<'EOS'
set -u
D="$1"; F="$2"; R="$3"; MARK="$4"
echo "$MARK rank=$R" > /dev/kmsg 2>/dev/null || true
# sess380: the caller pre-creates every directory, so no mkdir runs inside the
# measured window (a 32-way mkdir on a shared parent is its own contention event
# and used to be silently folded into these numbers).
[ -d "$D" ] || { echo "MISSING_DIR $D"; exit 1; }
line="CGWA r$R"$'\n'
s="$line"; while [ "${#s}" -lt 4096 ]; do s="$s$s"; done
pat="${s:0:4096}"
prev=$(date +%s%N)
for i in $(seq 1 "$F"); do
    printf '%s' "$pat" > "$D/n${R}_$i"
    now=$(date +%s%N); echo "OP $i $(( (now - prev) / 1000000 ))"; prev=$now
done
EOS
)

echo "=== caw_grant_wait_anatomy: P=$P F=$F mark=$MARK ==="
DIRB="$MNT/.cgwa_${STAMP}"
echo "--- shape=$SHAPE locktotal_floor=${LOCKTOTAL_MS}ms"
"$SSH" test1 "mkdir -p '$DIRB'; [ '$SHAPE' = shared ] || for i in \$(seq 1 $P); do mkdir -p '$DIRB'/r\$i; done" >/dev/null 2>&1
armed=0
for i in $(seq 1 "$P"); do
    ( "$SSH" "test$i" "[ -w $PARM ] && echo $LOCKTOTAL_MS > $PARM && cat $PARM" \
        > "$OUT/arm$i.txt" 2>&1 ) &
done
wait
for i in $(seq 1 "$P"); do
    [ "$(grep -xE '[0-9]+' "$OUT/arm$i.txt" 2>/dev/null | tail -1)" = "$LOCKTOTAL_MS" ] &&
        armed=$((armed+1))
done
echo "--- P139-LOCKTOTAL floor armed on $armed/$P nodes"
[ "$armed" -eq "$P" ] || echo "    WARNING: nodes without the knob are running the 800ms default and will under-report"
for i in $(seq 1 "$P"); do
    if [ "$SHAPE" = shared ]; then d="$DIRB"; else d="$DIRB/r$i"; fi
    ( "$SSH" "test$i" "bash -s '$d' '$F' '$i' '$MARK'" <<< "$W" \
        > "$OUT/op$i.txt" 2>&1 ) &
done
wait
for i in $(seq 1 "$P"); do
    ( "$SSH" "test$i" "[ -w $PARM ] && echo 800 > $PARM" >/dev/null 2>&1 ) &
done
wait
echo "--- workload done, harvesting scoped probes ---"
for i in $(seq 1 "$P"); do
    ( "$SSH" "test$i" \
        "dmesg | awk '/$MARK/{f=1} f' | grep -E 'P138-WAIT|P131-WAITLONG|P138-BAST|P139-LOCKTOTAL|P139-TAILCENSUS|P34-ACQ-SLOW' | tail -8000" \
        > "$OUT/pr$i.txt" 2>/dev/null ) &
done
wait

python3 - "$OUT" "$P" <<'PY'
import sys, os, re, glob, statistics
from collections import Counter
out, P = sys.argv[1], int(sys.argv[2])

ops = []
for p in glob.glob(os.path.join(out, "op*.txt")):
    for ln in open(p, errors='replace'):
        f = ln.split()
        if len(f) == 3 and f[0] == 'OP':
            ops.append(int(f[2]))

W138 = re.compile(r'P138-WAIT ino=(\d+) mode=(\d+) elapsed_ms=(\d+) ffw_ms=(\d+) '
                  r'ytd=(-?\d+) poll=(\d+) caw_try=(\d+) caw_miss=(\d+) '
                  r'caw_err=(\d+) caw_svc_ms=(\d+) reads=(\d+)')
WLONG = re.compile(r'P131-WAITLONG type=(\d+) ino=(\d+) ag=(\d+) mode=(\d+) elapsed_ms=(\d+)')

waits, longs, nodes = [], [], 0
for i in range(1, P + 1):
    p = os.path.join(out, f"pr{i}.txt")
    if not os.path.exists(p):
        continue
    got = False
    for ln in open(p, errors='replace'):
        m = W138.search(ln)
        if m:
            waits.append(tuple([i] + [int(m.group(g)) for g in range(1, 12)]))
            got = True
        m = WLONG.search(ln)
        if m:
            longs.append((i, int(m.group(1)), int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5))))
            got = True
    nodes += 1 if got else 0

if ops:
    ops.sort()
    print(f"workload: creates={len(ops)} mean={statistics.fmean(ops):.1f}ms "
          f"p50={ops[len(ops)//2]} p95={ops[min(len(ops)-1,int(len(ops)*.95))]} max={max(ops)}")
print(f"probes: nodes_reporting={nodes} P138-WAIT={len(waits)} P131-WAITLONG={len(longs)}")

if not waits:
    print("\nNO P138-WAIT LINES IN WINDOW -- caw instrumentation may be off "
          "(caw_instr_on) or the ring rotated. Check /sys/module/mxfs/parameters.")
    sys.exit(2)

el = sorted(w[3] for w in waits)
print(f"\n=== all contended inode grants (>5ms) ===")
print(f"  n={len(el)} elapsed_ms mean={statistics.fmean(el):.1f} p50={el[len(el)//2]} "
      f"p95={el[min(len(el)-1,int(len(el)*.95))]} max={max(el)}")
print(f"  total wait across cluster = {sum(el)/1000.0:.1f} s")

# THE DISCRIMINATOR: how much of each wait was spent AFTER the slot was already
# compatible.  ffw_ms>0 means the resource was grantable and we did not take it.
big = [w for w in waits if w[3] >= 100]
print(f"\n=== CLAIM-BOUND vs HOLDER-BOUND ===")
for label, subset in (("all waits >5ms", waits), ("waits >=100ms", big)):
    if not subset:
        continue
    tot = sum(w[3] for w in subset)
    ffw = sum(w[4] for w in subset)
    ytd = sum(w[5] for w in subset)
    nz = sum(1 for w in subset if w[4] > 0)
    print(f"  {label:16s} n={len(subset):5d}  total={tot/1000.0:7.1f}s  "
          f"grantable-but-unclaimed(ffw)={ffw/1000.0:7.1f}s = {100.0*ffw/tot if tot else 0:5.1f}%  "
          f"ffw>0 on {nz} ({100.0*nz/len(subset):.0f}%)  ticket_defers={ytd}")

print(f"\n=== the {min(15,len(waits))} longest single grants ===")
print(f"  {'node':>5s} {'ino':>12s} {'mode':>4s} {'elapsed':>8s} {'ffw':>8s} {'ytd':>5s} {'poll':>5s}")
for w in sorted(waits, key=lambda x: -x[3])[:15]:
    print(f"  {w[0]:5d} {w[1]:12d} {w[2]:4d} {w[3]:8d} {w[4]:8d} {w[5]:5d} {w[6]:5d}")

print(f"\n=== which inodes absorb the wait (top 12 by total ms) ===")
tot_by_ino = Counter()
cnt_by_ino = Counter()
for w in waits:
    tot_by_ino[w[1]] += w[3]; cnt_by_ino[w[1]] += 1
for ino, ms in tot_by_ino.most_common(12):
    print(f"  ino={ino:12d}  total={ms:7d}ms  grants={cnt_by_ino[ino]:5d}  "
          f"mean={ms/cnt_by_ino[ino]:7.1f}ms")

# ccloop sess24 (GPT Q3): THE decisive histogram -- CAW attempts per logical
# grant, classified.  This is what separates admission-policy cost from
# single-sector CAS contention from block-path service time.
print(f"\n=== CAW ATTEMPT CENSUS per logical grant (n={len(waits)}) ===")
tries = [w[7] for w in waits]; miss = [w[8] for w in waits]
errs  = [w[9] for w in waits]; svc  = [w[10] for w in waits]
rds   = [w[11] for w in waits]
def st(nm, v):
    v = sorted(v)
    print(f"  {nm:22s} total={sum(v):8d}  mean={statistics.fmean(v):8.2f}  "
          f"p50={v[len(v)//2]:6d}  p95={v[min(len(v)-1,int(len(v)*.95))]:6d}  max={max(v):6d}")
st("CAW submissions", tries); st("CAW miscompares", miss)
st("CAW io errors", errs);    st("CAW service ms", svc)
st("slot poll READs", rds)
tot_wait = sum(w[3] for w in waits)
print(f"  CAW service time is {100.0*sum(svc)/tot_wait if tot_wait else 0:.1f}% of total grant wait "
      f"({sum(svc)/1000.0:.1f}s of {tot_wait/1000.0:.1f}s)")
import collections
h = collections.Counter(min(w[8], 20) for w in waits)
print("  miscompares-per-grant histogram (20=20+):")
for k in sorted(h): print(f"    {k:3d} miscompares : {h[k]:5d} grants")
# VERDICT MUST BE KEYED ON TIME, NOT ON COUNTS.  The first cut of this block
# branched on mean miscompares >= 5 and duly announced "SINGLE-SECTOR CAS
# CONTENTION dominates" on a run where CAW work -- service time for EVERY
# submission including all miscompares -- was 1.5% of the grant wait.  A count
# is not a cost: each CAW here completes in ~0.65ms, so even 32 miscompares buy
# only ~21ms of a multi-second wait.  Attribute by seconds.
print("\n  ATTRIBUTION BY TIME (a count is not a cost):")
svc_pct = 100.0*sum(svc)/tot_wait if tot_wait else 0.0
per_caw = (sum(svc)/sum(tries)) if sum(tries) else 0.0
miss_ms = per_caw*sum(miss)
miss_pct = 100.0*miss_ms/tot_wait if tot_wait else 0.0
poll_ms = tot_wait - sum(svc)
print(f"    CAW service (all submissions)  {sum(svc)/1000.0:8.1f}s  {svc_pct:5.1f}%   "
      f"per-CAW {per_caw:.2f}ms, io_errors={sum(errs)}")
print(f"      of which miscompare retries  {miss_ms/1000.0:8.1f}s  {miss_pct:5.1f}%   "
      f"({sum(miss)} miscompares)")
print(f"    NOT in CAW (poll sleeps/waits) {poll_ms/1000.0:8.1f}s  {100.0-svc_pct:5.1f}%   "
      f"{statistics.fmean(rds):.0f} poll READs per grant")
if svc_pct < 10 and sum(errs) == 0:
    print("    => NOT the block/target/multipath path, and NOT CAS throughput.")
    print("       The wait is poll cycles on a genuinely contended lock: admission")
    print("       policy plus real holder turnover.  Note ffw_ms measures time since")
    print("       the FIRST compatible sighting, not CONTINUOUS compatibility, so a")
    print("       high ffw share does NOT prove the lock stayed grantable.")
elif svc_pct > 40:
    print("    => block/target/multipath service time dominates.")
else:
    print("    => mixed; read the two lines above rather than the histogram.")

if longs:
    print(f"\n=== P131-WAITLONG (>1s) : {len(longs)} occurrences ===")
    LT = {0: 'AG', 1: 'INODE', 2: 'SB', 3: 'DIR'}
    byt = Counter(LT.get(l[1], f'type{l[1]}') for l in longs)
    print("  by resource type: " + ", ".join(f"{k}={v}" for k, v in byt.most_common()))
    for l in sorted(longs, key=lambda x: -x[5])[:10]:
        print(f"  node{l[0]:<3d} type={LT.get(l[1],l[1]):6s} ino={l[2]:12d} ag={l[3]:4d} "
              f"mode={l[4]} elapsed_ms={l[5]}")
# ---------------------------------------------------------------- sess380 ---
# WHOLE-ACQUIRE census.  P138-WAIT times ONE wait_for_grant call; an acquire
# that loses a claim race re-registers and waits again, so a 400ms acquire can
# be twenty sub-5ms waits and appear NOWHERE in the per-wait census.
# P139-LOCKTOTAL brackets the whole acquire including every retry, and its
# `retries` field is the discriminator:
#   retries ~0 and total large  -> HOLDER-BOUND, a peer really held it
#   retries large               -> CLAIM-BOUND, we keep losing the race
LOCKTOT = re.compile(
    r'P139-LOCKTOTAL ino=(\d+) req=(\d+) rc=(-?\d+) total_ms=(\d+) retries=(\d+) '
    r'ea_claim=(\d+) ea_compat=(\d+) ea_regwait=(\d+)')
acqs = []
for p_ in sorted(glob.glob(os.path.join(out, "pr*.txt"))):
    node = os.path.basename(p_)[2:-4]
    for ln in open(p_, errors='replace'):
        m = LOCKTOT.search(ln)
        if m:
            ino, req, rc, tot, rtr, eac, eacm, ear = (int(x) for x in m.groups())
            acqs.append(dict(node=node, ino=ino, req=req, rc=rc, total=tot,
                             retries=rtr, ea_claim=eac, ea_compat=eacm,
                             ea_regwait=ear))

print(f"\n=== WHOLE-ACQUIRE census (P139-LOCKTOTAL, floor set by the harness) ===")
if not acqs:
    print("  NONE. Either no acquire crossed the floor, or the floor knob is not")
    print("  present in this build (mxfs.caw_locktotal_ms, added 0.15.5) and the")
    print("  kernel default of 800ms sat above the whole distribution.")
else:
    tots = sorted(a['total'] for a in acqs)
    rtrs = sorted(a['retries'] for a in acqs)
    n = len(tots)
    print(f"  n={n}  total_ms mean={statistics.fmean(tots):.1f} p50={tots[n//2]} "
          f"p95={tots[min(n-1,int(n*.95))]} max={tots[-1]}")
    print(f"  retries  mean={statistics.fmean(rtrs):.2f} p50={rtrs[n//2]} "
          f"p95={rtrs[min(n-1,int(n*.95))]} max={rtrs[-1]}")
    print(f"  aggregate acquire wait across cluster = {sum(tots)/1000.0:.1f}s")
    zero = sum(1 for r in rtrs if r == 0)
    print(f"  acquires with ZERO retries: {zero}/{n} ({100.0*zero/n:.1f}%)  "
          f"-> {'HOLDER-BOUND dominates' if zero > n/2 else 'CLAIM-BOUND dominates'}")
    by_ino = {}
    for a in acqs:
        d_ = by_ino.setdefault(a['ino'], [0, 0, 0])
        d_[0] += a['total']; d_[1] += 1; d_[2] += a['retries']
    print("  by inode (top 8 by total ms):")
    for ino, (t, c, r) in sorted(by_ino.items(), key=lambda kv: -kv[1][0])[:8]:
        print(f"    ino={ino:<12d} total={t:7d}ms grants={c:5d} "
              f"mean={t/c:7.1f}ms retries/grant={r/c:5.2f}")
    ea = [(sum(a['ea_claim'] for a in acqs), 'ea_claim  (lost the SLOT-CLAIM race)'),
          (sum(a['ea_compat'] for a in acqs), 'ea_compat (lost the COMPATIBLE-admit CAS)'),
          (sum(a['ea_regwait'] for a in acqs), 'ea_regwait(lost the WAITER-REGISTER CAS)')]
    print("  where the retries were spent (total -EAGAIN by site):")
    for v, lab in sorted(ea, reverse=True):
        print(f"    {lab:48s} {v}")

PY
rc=$?
echo "=== cleanup ==="
"$SSH" test1 "rm -rf '$DIRB'" >/dev/null 2>&1
echo "=== raw in $OUT ==="
exit $rc
