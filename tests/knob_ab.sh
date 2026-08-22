#!/bin/bash
# Generic paired-A/B harness for a runtime module knob  (sess382)
#
# WHY THIS EXISTS
#   This project's standard evidence for a behavioural change is a PAIRED A/B
#   ON ONE BUILD with the knob flipped at runtime -- that removes "different
#   build" and "different workload" as explanations in one step.  Every session
#   was hand-rolling the same fan-out; this is it, once, in the tree.
#
# USAGE
#   tests/knob_ab.sh <nodes> <dlm> <knob> <value> <probe,probe,...> <criteria...>
#
#   e.g. tests/knob_ab.sh 32 caw relog_holds_version 0 \
#          P34F-RELOAD-SELFAHEAD-SKIP,P146V-UNLANDED dir_reuse_coherency
#
#   Run it once per arm, same criteria, and diff the two tables.
#
# RULE 0: no outer timeout is wrapped around run.sh -- run.sh already enforces
# each criterion's manifest budget as a hard timeout and flips PASS->FAIL on
# overrun.  Wrapping it again only delays the evidence.
# RULE 9: the fleet sweeps are one call each, per-node output file, per-node rc,
# per-node inner timeout.
set -u
cd "$(dirname "$0")/.."

N=${1:?nodes}; DLM=${2:?dlm}; KNOB=${3:?knob}; VAL=${4:?value}
PROBES=${5:?comma-separated probe list}; shift 5
CRIT=${*:?criteria}
NODES=$(seq 1 "$N" | sed 's/^/test/')

echo "=== knob A/B: mxfs.$KNOB=$VAL   criteria: $CRIT ==="

d=$(mktemp -d); fail=0
for h in $NODES; do
  ( timeout 15 tools/mxfs_sshpass.sh "$h" \
      "echo $VAL > /sys/module/mxfs/parameters/$KNOB && cat /sys/module/mxfs/parameters/$KNOB" \
      > "$d/$h" 2>&1; echo "rc=$?" >> "$d/$h" ) &
done
wait 2>/dev/null
for h in $NODES; do
  if ! grep -q '^rc=0$' "$d/$h" || ! grep -qx "$VAL" "$d/$h"; then
    echo "  !! $h: $KNOB did not take"; fail=1
  fi
done
[ $fail -eq 0 ] || { echo "ABORT: knob not uniform across the fleet"; exit 1; }
echo "  $KNOB=$VAL on all $N nodes"

echo "--- clearing rings so counts belong to THIS arm ---"
d=$(mktemp -d)
for h in $NODES; do ( timeout 15 tools/mxfs_sshpass.sh "$h" "dmesg -C" >"$d/$h" 2>&1 ) & done
wait 2>/dev/null

./run.sh "$N" "$DLM" $CRIT 2>&1 | grep -E "  (PASS|FAIL|ABORT) "

d=$(mktemp -d)
for h in $NODES; do
  ( timeout 25 tools/mxfs_sshpass.sh "$h" \
      "for p in \$(echo $PROBES | tr ',' ' '); do echo \"\$p=\$(dmesg|grep -c \$p || true)\"; done; \
       mountpoint -q /mnt/shared && echo MOUNT=1 || echo MOUNT=0; echo SCANOK" \
      > "$d/$h" 2>&1 ) &
done
wait 2>/dev/null

python3 - "$d" "$N" "$KNOB" "$VAL" <<'PY'
import sys,os,re,collections
d,n,knob,val=sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4]
tot=collections.Counter(); bad=[]; nomount=[]
for i in range(1,n+1):
    h="test%d"%i; p=os.path.join(d,h)
    if not os.path.exists(p): bad.append(h); continue
    t=open(p).read()
    if 'SCANOK' not in t: bad.append(h+" incomplete"); continue
    for k,v in re.findall(r'(P[\w-]+)=(\d+)',t): tot[k]+=int(v)
    if 'MOUNT=0' in t: nomount.append(h)
print("--- ARM %s=%s : fleet totals over %d nodes ---"%(knob,val,n))
for k in sorted(tot): print("  %-32s %8d"%(k,tot[k]))
print("  NOMOUNT: %s"%(", ".join(nomount) if nomount else "none"))
print("  scan failures: %s"%(bad or "none"))
PY
