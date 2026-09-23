#!/bin/bash
# cc_grantwait.sh — harvest + attribute the CAW inode grant wait (P138-WAIT).
#
# WHY (ccloop c7ee71c6 sess126): tests/cc_stackprof.sh PROVED, by wall-clock
# stack sampling of a virgin-fs crash_consistency run, that essentially all of
# the workload's blocking wall is
#     mxfs_pal_cond_timedwait < caw_nudge_wait < caw_wait_for_grant
#       < mxfs_dlm_caw_lock < mxfs_v5_dlm_inode_lock
# i.e. the CAW grant wait on an INODE resource (26.3% of all samples; the
# 16.6% md5sum/bash `open_last_lookups` are queued behind it on the local
# dir i_rwsem, and the 39.6% `do_wait` / 13.6% `pipe_read` are the parent
# shells waiting on those same children).
#
# P138-WAIT is the existing per-grant record inside that wait, gated by the
# `instr` module param.  It carries the attribution split the ledger needs:
#   elapsed_ms  total grant wait
#   ffw_ms      wait REMAINING after the slot first read mode-COMPATIBLE
#               (compatible-but-not-admitted = admission POLICY cost)
#   ytd         fair-handoff ticket deferrals taken while compatible
#   caw_try/miss/err + caw_svc_ms   CAS attempt census + device service time
#   reads       slot re-reads
# Classification (sess24 design-consult): long wait + 0-1 attempts -> admission POLICY;
# long wait + tens of miscompares -> single-sector CAS contention; few attempts
# + slow caw_svc_ms -> block/target/multipath path.
#
# P138-WAIT IS UNCONDITIONAL (dlm_caw.c:5917, `if (p138_n++ < 4000)`), so the
# `arm` mode's instr=1 is NOT needed to collect it and costs a great deal:
# instr=1 turns an 86 s run into >240 s, which changes the very pace being
# measured.  Use `mark` for any pace measurement; `arm` only when a probe that
# really is instr-gated (P13-INSTR, P204-YT-DEFER) is also wanted.  The 4000/
# boot cap is per module load, so a prep_cluster (which rmmods) resets it.
#
# usage:
#   cc_grantwait.sh mark   [N]     # kmsg boundary mark ONLY — no instr (default choice)
#   cc_grantwait.sh arm    [N]     # instr=1 on every node + kmsg boundary mark
#   cc_grantwait.sh disarm [N]     # instr=0
#   cc_grantwait.sh report [N]     # harvest since the mark, per-ino attribution
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
cd "$REPO"
MODE="${1:-}"; N="${2:-32}"
MARK="mxfs-GWMARK"
# shellcheck source=quiet_console.sh
. "$REPO/tests/quiet_console.sh"

case "$MODE" in
mark)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "$QUIET_CONSOLE \
             echo '$MARK begin' > /dev/kmsg; \
             cat /sys/module/mxfs/parameters/instr" 2>/dev/null \
          | tr -d '\n' | sed "s/^/test$i:instr=/;s/\$/ /" ) &
    done
    wait; echo
    ;;
arm)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "echo 1 > /sys/module/mxfs/parameters/instr; \
             $QUIET_CONSOLE \
             echo '$MARK begin' > /dev/kmsg; \
             cat /sys/module/mxfs/parameters/instr" 2>/dev/null \
          | tr -d '\n' | sed "s/^/test$i:instr=/;s/\$/ /" ) &
    done
    wait; echo
    ;;
disarm)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "echo 0 > /sys/module/mxfs/parameters/instr" >/dev/null 2>&1 ) &
    done
    wait; echo "instr=0 on $N nodes"
    ;;
report)
    OUT=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        ( tools/mxfs_sshpass.sh "test$i" \
            "dmesg | awk '/$MARK begin/{f=1;next} f' | grep -a 'P138-WAIT\\|P138-AGWAIT\\|P138-ACQ'" \
            2>/dev/null > "$OUT/test$i" ) &
    done
    wait
    OUT="$OUT" python3 - <<'PYEOF'
import os, re, statistics, collections
OUT = os.environ["OUT"]
FIELD = re.compile(r"(\w+)=(-?\d+)")
rows = []
agrows = []   # sess435: AG-class waits (P138-AGWAIT), same fields keyed by ag=
acq = []      # sess435: acquire-level P138-ACQ (>5 ms whole acquires)
acqsum = {}   # (node,type) -> last P138-ACQSUM dict (cumulative per module load)
pernode = collections.Counter()
for name in sorted(os.listdir(OUT)):
    for line in open(os.path.join(OUT, name)):
        if "P138-ACQSUM" in line:
            d = dict((k, int(v)) for k, v in FIELD.findall(line.split("P138-ACQSUM", 1)[1]))
            if "type" in d: acqsum[(name, d["type"])] = d
            continue
        if "P138-ACQ " in line:
            d = dict((k, int(v)) for k, v in FIELD.findall(line.split("P138-ACQ", 1)[1]))
            if "elapsed_ms" in d:
                d["node"] = name; acq.append(d)
            continue
        if "P138-AGWAIT" in line:
            d = dict((k, int(v)) for k, v in FIELD.findall(line.split("P138-AGWAIT", 1)[1]))
            if "elapsed_ms" in d:
                d["node"] = name; agrows.append(d)
            continue
        if "P138-WAIT" not in line:
            continue
        d = dict((k, int(v)) for k, v in FIELD.findall(line.split("P138-WAIT", 1)[1]))
        if "elapsed_ms" not in d:
            continue
        d["node"] = name
        rows.append(d)
        pernode[name] += 1

TYPEN = {1:"INODE",2:"EXTENT",3:"AG",4:"JOURNAL",5:"SUPER",6:"ICLUSTER"}
if acqsum:
    print("P138-ACQSUM (cumulative per node since module load, last line per node/type; fleet sums)")
    bytype = collections.defaultdict(lambda: [0,0,0,0])
    for (node, ty), d in acqsum.items():
        a = bytype[ty]; a[0]+=d.get("n",0); a[1]+=d.get("sum_ms",0); a[2]+=d.get("gt5",0); a[3]+=1
    for ty, a in sorted(bytype.items()):
        print("   type=%d %-8s nodes=%d n=%d sum_ms=%d mean_ms=%.2f gt5=%d" % (ty, TYPEN.get(ty,"?"), a[3], a[0], a[1], a[1]/max(a[0],1), a[2]))
if acq:
    el = [r["elapsed_ms"] for r in acq]
    v = sorted(el)
    print("P138-ACQ (whole acquires >5 ms) n=%d nodes=%d TOTAL=%d ms p50=%d p90=%d p99=%d max=%d"
          % (len(acq), len(set(r["node"] for r in acq)), sum(el), v[len(v)//2], v[min(len(v)-1,int(len(v)*0.9))], v[min(len(v)-1,int(len(v)*0.99))], max(el)))
    byt = collections.defaultdict(lambda: [0,0])
    for r in acq:
        a = byt[r.get("type",0)]; a[0]+=r["elapsed_ms"]; a[1]+=1
    for ty, a in sorted(byt.items(), key=lambda kv: -kv[1][0]):
        print("   type=%d %-8s n=%d sum_ms=%d mean_ms=%.1f" % (ty, TYPEN.get(ty,"?"), a[1], a[0], a[0]/a[1]))
    byres = collections.defaultdict(lambda: [0,0])
    for r in acq:
        k = (r.get("type",0), r.get("ino",0), r.get("ag",0))
        a = byres[k]; a[0]+=r["elapsed_ms"]; a[1]+=1
    print("   top resources by summed acquire ms:")
    for k, a in sorted(byres.items(), key=lambda kv: -kv[1][0])[:8]:
        print("     type=%d ino=%d ag=%d sum_ms=%d n=%d" % (k[0], k[1], k[2], a[0], a[1]))
    print()
def pct0(vals, p):
    if not vals: return 0
    v = sorted(vals); return v[min(len(v) - 1, int(len(v) * p / 100.0))]
if agrows:
    el = [r["elapsed_ms"] for r in agrows]
    print("P138-AGWAIT (AG-class grants >5 ms) grants=%d nodes=%d TOTAL=%d ms  p50=%d p90=%d p99=%d max=%d mean=%.1f"
          % (len(agrows), len(set(r["node"] for r in agrows)), sum(el),
             pct0(el,50), pct0(el,90), pct0(el,99), max(el), statistics.mean(el)))
    byag = collections.defaultdict(lambda: [0,0,0,0,0,0,0])
    for r in agrows:
        a = byag[r.get("ag",-1)]
        a[0]+=r["elapsed_ms"]; a[1]+=1; a[2]+=r.get("ffw_ms",0); a[3]+=r.get("ytd",0)
        a[4]+=r.get("caw_try",0); a[5]+=r.get("caw_miss",0); a[6]+=r.get("reads",0)
    print("   %-4s %10s %8s %8s %9s %7s %8s %9s %7s" % ("ag","sum_ms","grants","mean_ms","ffw_share","ytd","caw_try","caw_miss","reads"))
    for ag, a in sorted(byag.items(), key=lambda kv: -kv[1][0])[:16]:
        print("   %-4d %10d %8d %8.1f %8.0f%% %7d %8d %9d %7d" % (ag, a[0], a[1], a[0]/a[1], 100.0*a[2]/max(a[0],1), a[3], a[4], a[5], a[6]))
    pn = collections.Counter(r["node"] for r in agrows)
    print("   per-node AG grants: " + " ".join("%s=%d" % (k.replace("test","t"), v) for k, v in sorted(pn.items(), key=lambda kv: int(kv[0][4:]))))
    print()
else:
    print("P138-AGWAIT: no AG-class waits >5 ms recorded")
if not rows:
    print("no P138-WAIT records — was `arm` run before the workload?")
    raise SystemExit(0)

tot = sum(r["elapsed_ms"] for r in rows)
print("P138-WAIT grants=%d nodes=%d  TOTAL grant-wait=%d ms (sum over nodes)"
      % (len(rows), len(pernode), tot))

def pct(vals, p):
    if not vals: return 0
    v = sorted(vals); return v[min(len(v) - 1, int(len(v) * p / 100.0))]

el = [r["elapsed_ms"] for r in rows]
print("  elapsed_ms  p50=%d p90=%d p99=%d max=%d mean=%.1f"
      % (pct(el,50), pct(el,90), pct(el,99), max(el), statistics.mean(el)))

# --- where does the WALL live: per-inode, by summed elapsed_ms ---
byino = collections.defaultdict(lambda: [0, 0, 0, 0, 0, 0])  # ms,n,ffw,ytd,try,miss
for r in rows:
    a = byino[r.get("ino", 0)]
    a[0] += r["elapsed_ms"]; a[1] += 1
    a[2] += r.get("ffw_ms", 0); a[3] += r.get("ytd", 0)
    a[4] += r.get("caw_try", 0); a[5] += r.get("caw_miss", 0)
print("\n## WALL BY INODE  (top 12 by summed grant wait)")
print("   %-12s %10s %8s %8s %9s %7s %8s %9s" %
      ("ino", "sum_ms", "grants", "mean_ms", "ffw_share", "ytd", "caw_try", "caw_miss"))
for ino, a in sorted(byino.items(), key=lambda kv: -kv[1][0])[:12]:
    print("   %-12d %10d %8d %8.1f %8.0f%% %7d %8d %9d"
          % (ino, a[0], a[1], a[0] / a[1], 100.0 * a[2] / max(a[0], 1),
             a[3], a[4], a[5]))

# --- classification of the dominant inode's grants ---
top_ino = max(byino.items(), key=lambda kv: -(-kv[1][0]))[0]
sub = [r for r in rows if r.get("ino") == top_ino]
print("\n## DOMINANT INODE %d — %d grants, %d ms" % (top_ino, len(sub), byino[top_ino][0]))
for label, key in (("elapsed_ms", "elapsed_ms"), ("ffw_ms", "ffw_ms"),
                   ("caw_svc_ms", "caw_svc_ms"), ("caw_try", "caw_try"),
                   ("caw_miss", "caw_miss"), ("reads", "reads"), ("ytd", "ytd")):
    v = [r.get(key, 0) for r in sub]
    print("   %-11s p50=%-7d p90=%-7d p99=%-7d max=%-7d sum=%d"
          % (label, pct(v,50), pct(v,90), pct(v,99), max(v), sum(v)))
n_policy  = sum(1 for r in sub if r.get("caw_try",0) <= 1 and r["elapsed_ms"] >= 5)
n_cas     = sum(1 for r in sub if r.get("caw_miss",0) >= 5)
n_dev     = sum(1 for r in sub if r.get("caw_svc_ms",0) >= r["elapsed_ms"]/2 and r["elapsed_ms"] >= 5)
print("   CLASSIFY(>=5ms waits): admission-POLICY=%d  CAS-contention=%d  device-path=%d"
      % (n_policy, n_cas, n_dev))
print("\n## PER-NODE grant counts")
print("   " + "  ".join("%s=%d" % (k.replace("test", "t"), v)
                        for k, v in sorted(pernode.items(),
                                           key=lambda kv: int(kv[0][4:]))))
PYEOF
    ;;
*)
    sed -n '2,30p' "$0"; exit 2 ;;
esac
