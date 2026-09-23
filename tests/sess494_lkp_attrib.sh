#!/bin/bash
# sess494: WHAT IS THE SHARED-DIRECTORY LOOKUP TERM MADE OF?
# (D-32NODE-SHARED-DIR-CREATE-PACE, sess487 ruling item 3 — the icr split)
#
# Chain 137 split the in-tenure create; the 0.70.2 A/B (s490g) then showed the
# whole "icr" excess is the EXISTENCE LOOKUP: lkp_ms 4.4 ms (persig on) / 7.9
# (off) per create in the 3200-entry shared directory, icr_ms 0.0, against 0.3
# in a private directory.  Hypothesis H-L1: the lookup cost is synchronous
# cold directory-block reads (FUA passthrough, ~1 ms each) issued because the
# tenure-start evict cleared the cached blocks and each lookup touches blocks
# not yet re-read in this tenure; predicted lkp_fua ~2-3 per create with
# lkp_fua_ms ~= lkp_ms.  Refuted if lkp_fua is ~0 while lkp_ms stays ~4 (the
# cost is elsewhere: hash walk, lock waits, plain bios -> lkp_rd).
#
# 0.70.13 prints lkp_fua= lkp_fua_ms= lkp_rd= on every P132-CREATE line.  One
# armed crash_consistency row (create_cost_ms=1) per leg on a FRESH prep:
#   shared    the board row (mxfs.dir_persig_flush default)
#   private   CC_PRIVATE=1 (the control: per-node directories)
# derived time budgets: prep 300 (measured 106-146 s); cc row 160 (manifest 90 +
# harness); sweep 90.  ~8 min per leg.
#
# Usage: KO=<0.70.13 ko> GATE=<log> setsid nohup bash tests/sess494_lkp_attrib.sh s494h &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s494h}
GATE=${GATE:-tests/evidence/sess487_chain139_persig_ab_s494g.log}
KO=${KO:-tests/evidence/sess494_frozen_07013/mxfs.ko}
RESTORE_KO=${RESTORE_KO:-}          # empty = leave KO installed in the tree
LEGS=${LEGS:-shared private}
THRESH=${THRESH:-1}
LKP_TRACE=${LKP_TRACE:-0}           # sess495: 1 = arm mxfs.lkp_trace (0.70.15+): P495-LKP-RD read trace inside the lookup window
LOG=tests/evidence/sess494_lkp_attrib_$LABEL.log
O=tests/evidence/sess494_lkp_attrib_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"
nodes() { seq 1 32 | sed 's/^/test/'; }

arm() { # <param> <value>
    local p=$1 v=$2 ok=0 bad="" n
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "echo $v > /sys/module/mxfs/parameters/$p 2>/dev/null; cat /sys/module/mxfs/parameters/$p 2>/dev/null" > "$O/.arm.$p.$n" 2>/dev/null ) &
    done
    wait
    for n in $(nodes); do
        [ "$(tr -d '[:space:]' < "$O/.arm.$p.$n" 2>/dev/null)" = "$v" ] && ok=$((ok + 1)) || bad="$bad $n"
    done
    echo "  arm $p=$v: $ok/32 confirmed${bad:+ ; NOT ARMED:$bad}"
    [ "$ok" -eq 32 ]
}

sweep() { # <since> <dir>
    local since=$1 d=$2 n c hit=0 tot=0
    mkdir -p "$d"
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -aE 'P132-CREATE|P483-DIRTENURE|P495-LKP-|mxfs-cc-FAIL|mxfs-cc-COUNT'" 2>/dev/null | gzip > "$d/kernlog_$n.gz" ) &
    done
    wait
    for n in $(nodes); do
        c=$(zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -ac 'P132-CREATE'); c=${c:-0}
        [ "$c" -gt 0 ] && hit=$((hit + 1)); tot=$((tot + c))
    done
    echo "  STAGE sweep dir=$d nodes_with_P132=$hit/32 P132_lines=$tot cc_FAIL=$(zcat "$d"/kernlog_*.gz 2>/dev/null | grep -ac 'mxfs-cc-FAIL') cc_COUNT=$(zcat "$d"/kernlog_*.gz 2>/dev/null | grep -ac 'mxfs-cc-COUNT')"
}

{
  echo "=== sess494 lkp_attrib START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO LEGS='$LEGS' ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$KO" mxfs.ko
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_ko sv=$sv lkp_fua_marker=$(strings -a mxfs.ko | grep -ac 'lkp_fua=')"
  for leg in $LEGS; do
      echo "--- leg=$leg $(date -u +%FT%TZ) ---"
      t0=$(date +%s)
      timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep_$leg.out" 2>&1; prc=$?
      echo "STAGE prep_$leg rc=$prc wall=$(( $(date +%s) - t0 ))s budget=300s build=$(grep -ao 'build [0-9A-F]*' "$O/prep_$leg.out" | tail -1)"
      [ "$prc" = 0 ] || { echo "LEG $leg NOT RUN: prep rc=$prc"; continue; }
      idok=0
      for n in $(nodes); do ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -dc 'A-F0-9' > "$O/.sv.$n" ) & done; wait
      for n in $(nodes); do [ "$(cat "$O/.sv.$n" 2>/dev/null)" = "$sv" ] && idok=$((idok + 1)); done
      echo "  STAGE fleet_identity match=$idok/32 sv=$sv"
      [ "$idok" -eq 32 ] || { echo "LEG $leg NOT RUN: fleet identity mismatch"; continue; }
      arm create_cost_ms "$THRESH" || { echo "LEG $leg NOT RUN: probe not armed on all 32"; continue; }
      if [ "$LKP_TRACE" = 1 ]; then
          arm lkp_trace 1 || { echo "LEG $leg NOT RUN: lkp_trace not armed on all 32 (needs 0.70.15+)"; continue; }
      fi
      SINCE=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
      if [ "$leg" = private ]; then
          MXFS_TEST_ENV="CC_PRIVATE=1" timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$leg.out" 2>&1
      else
          timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$leg.out" 2>&1
      fi
      echo "STAGE cc_$leg rc=$? wall=$(( $(date +%s) - t0 ))s budget=160s"
      grep -aE 'crash_consistency' "$O/cc_$leg.out" | grep -a 'nodes_pass' | cut -c1-320 | sed "s/^/  $leg ROW: /"
      sweep "$SINCE" "$O/$leg"
      echo "  --- phase summary, leg=$leg (all creates, then in-tenure dlk_ms<5) ---"
      python3 tools/p132_phase_summary.py "$O/$leg" 2>&1 | grep -aE 'field|lkp_|icr_ms|rfr_ms|dirsig_ms|total_ms|IN-TENURE|in-tenure|creates' | head -40 | sed 's/^/  /'
      # the discriminator: per-create lkp_fua and lkp_fua_ms against lkp_ms, in-tenure only
      python3 - "$O/$leg" <<'EOF' 2>&1 | sed 's/^/  /'
import sys, gzip, glob, re, statistics as st
d = sys.argv[1]; rows = []
for f in glob.glob(d + '/kernlog_*.gz'):
    for line in gzip.open(f, 'rt', errors='replace'):
        if 'P132-CREATE' not in line: continue
        kv = dict(re.findall(r'(\w+)=(-?\d+)', line))
        if 'lkp_fua' not in kv: continue
        rows.append({k: int(v) for k, v in kv.items()})
it = [r for r in rows if r.get('dlk_ms', 0) < 5]
def q(xs, p): xs = sorted(xs); return xs[min(len(xs) - 1, int(p * len(xs)))] if xs else 0
print('LKP-ATTRIB rows=%d in_tenure=%d' % (len(rows), len(it)))
for name, sel in (('all', rows), ('in-tenure', it)):
    if not sel: continue
    lk = [r['lkp_ms'] for r in sel]; fu = [r['lkp_fua'] for r in sel]; fm = [r['lkp_fua_ms'] for r in sel]; rd = [r['lkp_rd'] for r in sel]
    print('  %-9s lkp_ms mean=%.2f p50=%d p90=%d | lkp_fua mean=%.2f p50=%d p90=%d max=%d | lkp_fua_ms mean=%.2f p90=%d | lkp_rd mean=%.2f p90=%d | fua_share=%.0f%%' % (
        name, st.mean(lk), q(lk, .5), q(lk, .9), st.mean(fu), q(fu, .5), q(fu, .9), max(fu), st.mean(fm), q(fm, .9), st.mean(rd), q(rd, .9),
        100.0 * sum(fm) / max(1, sum(lk))))
    by = {}
    for r in sel: by.setdefault(r['lkp_fua'], []).append(r['lkp_ms'])
    print('  %-9s lkp_ms by lkp_fua: ' % name + ' '.join('%d->n=%d,mean=%.1f' % (k, len(v), st.mean(v)) for k, v in sorted(by.items())[:8]))
EOF
      # sess495: the read trace, when armed — who reads what inside the lookup window
      python3 - "$O/$leg" <<'EOF' 2>&1 | sed 's/^/  /'
import sys, gzip, glob, re, collections
d = sys.argv[1]
wins = 0; bio = collections.Counter(); fua = collections.Counter(); comm = collections.Counter(); daddr = collections.Counter(); per = []
fresh = collections.Counter(); done = collections.Counter()
for f in glob.glob(d + '/kernlog_*.gz'):
    cur = None
    for line in gzip.open(f, 'rt', errors='replace'):
        if 'P495-LKP-WIN open' in line:
            cur = [0, 0]; wins += 1
        elif 'P495-LKP-WIN close' in line:
            if cur is not None: per.append(tuple(cur)); cur = None
        elif 'P495-LKP-RD kind=bio' in line:
            kv = dict(re.findall(r'(\w+)=(\S+)', line))
            bio[kv.get('ops', '?')] += 1; comm[kv.get('comm', '?')] += 1; daddr[kv.get('daddr', '?')] += 1
            fresh[kv.get('fresh', '?')] += 1; done[kv.get('done', '?')] += 1
            if cur is not None: cur[0] += 1
        elif 'P495-LKP-RD kind=fua' in line:
            kv = dict(re.findall(r'(\w+)=(\S+)', line))
            fua[kv.get('comm', '?')] += 1
            if cur is not None: cur[1] += 1
if wins == 0:
    print('LKP-TRACE not armed (no P495-LKP-WIN lines)')
else:
    print('LKP-TRACE windows=%d closed=%d bio_total=%d fua_total=%d' % (wins, len(per), sum(bio.values()), sum(fua.values())))
    print('  bio by ops : ' + ' '.join('%s=%d' % kv for kv in bio.most_common(8)))
    print('  bio by comm: ' + ' '.join('%s=%d' % kv for kv in comm.most_common(8)))
    print('  bio done=  : ' + ' '.join('%s=%d' % kv for kv in done.most_common(3)) + ' | fresh= ' + ' '.join('%s=%d' % kv for kv in fresh.most_common(3)))
    print('  fua by comm: ' + ' '.join('%s=%d' % kv for kv in fua.most_common(8)))
    print('  top daddr  : ' + ' '.join('%s=%d' % kv for kv in daddr.most_common(10)))
    if per:
        bs = sorted(p[0] for p in per); fs = sorted(p[1] for p in per)
        print('  per-window bio p50=%d p90=%d max=%d | fua p50=%d p90=%d max=%d' % (bs[len(bs)//2], bs[int(.9*len(bs))], bs[-1], fs[len(fs)//2], fs[int(.9*len(fs))], fs[-1]))
EOF
  done
  if [ -n "$RESTORE_KO" ]; then cp "$RESTORE_KO" mxfs.ko; echo "STAGE restore_tree_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"; fi
  echo "--- VERDICT ---"
  echo "  H-L1 holds if the shared leg's in-tenure lkp_fua mean is >= 1 with fua_share >= 70% and lkp_ms grows with lkp_fua; refuted if lkp_fua ~0 or fua_share < 30%."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
