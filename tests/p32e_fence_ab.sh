#!/bin/bash
# P32E dir-epoch flush-fence paired A/B  (sess382)
#
# WHAT THIS TESTS
#   xfs_iflush's P32E-DIREPOCH-FENCE decides whether a peer superseded this
#   node's in-core directory image.  sess28 introduced
#   mxfs_dir_epoch_superseded() because the raw `cur_ep > i_dlm_dir_valid_epoch`
#   compare pits a DEAD incarnation's handoff lineage against a LIVE
#   incarnation's baseline.  include/xfs_mxfs_dlm.h names this fence as one of
#   the two consumers that MUST use the predicate -- but until sess382 this
#   site still compared raw (it even extern-declared the predicate and never
#   called it).
#
#   The fence abandons the flush with error=0 and WITHOUT stamping
#   i_mxfs_pub_flush_seq, so the publication obligation (pending != durable)
#   never closes.  The release drain then re-logs the "clean-but-unlanded"
#   core (P146V) every attempt, and xfs_trans_log_inode bumps pending_seq each
#   time -- the drain's own repair feeds the counter it waits on -- until the
#   release-defer episode's no-progress bound fires P-INODE-WEDGE and force-
#   shuts down the whole mount.
#
# THE TWO KNOBS (both already in the tree, both runtime-writable 0644)
#   mxfs.dir_adopt_at_acquire  0 = pre-fix sentinels; leaves dirs in the
#                                  valid_epoch=0 "no baseline" precursor
#                                  state, which is the fence's precondition.
#                                  This is the CONDITION FORCER.
#   mxfs.dir_epoch_incarn_gate 1 = incarnation-qualified predicate (fixed)
#                              0 = raw compare (pre-fix negative control)
#                                  This is the ARM SELECTOR.
#
# USAGE
#   tests/p32e_fence_ab.sh <nodes> <dlm> <gate> [criteria...]
#     gate = 1 (fixed arm) | 0 (pre-fix raw-compare control)
#
# RULE 0: this script sets NO timeout of its own around run.sh -- run.sh
# already enforces each criterion's manifest budget as a hard timeout and
# flips PASS->FAIL on overrun.  Wrap the CALL, not the callee.
set -u
cd "$(dirname "$0")/.."

N=${1:?nodes}; DLM=${2:?dlm}; GATE=${3:?gate 0|1}; shift 3
CRIT=${*:-ag_strand_repair}
NODES=$(seq 1 "$N" | sed 's/^/test/')

setknob() {   # setknob <name> <value> -- fleet-wide, per-node rc, inner timeout
  local k=$1 v=$2 d rc=0
  d=$(mktemp -d)
  for h in $NODES; do
    ( timeout 15 tools/mxfs_sshpass.sh "$h" \
        "echo $v > /sys/module/mxfs/parameters/$k && cat /sys/module/mxfs/parameters/$k" \
        > "$d/$h" 2>&1; echo "rc=$?" >> "$d/$h" ) &
  done
  wait 2>/dev/null
  for h in $NODES; do
    if ! grep -q '^rc=0$' "$d/$h" || ! grep -qx "$v" "$d/$h"; then
      echo "  !! $h: $k did not take: $(grep -vE 'Unauthor|not an auth|Warning' "$d/$h" | tr '\n' ' ')"
      rc=1
    fi
  done
  [ $rc -eq 0 ] && echo "  $k=$v on all $N nodes"
  return $rc
}

echo "=== P32E A/B: gate=$GATE (1=fixed predicate, 0=raw-compare control) ==="
setknob dir_adopt_at_acquire 0 || exit 1     # force the precondition
setknob dir_epoch_incarn_gate "$GATE" || exit 1

echo "--- clearing rings so counts belong to THIS arm ---"
d=$(mktemp -d)
for h in $NODES; do ( timeout 15 tools/mxfs_sshpass.sh "$h" "dmesg -C" >"$d/$h" 2>&1 ) & done
wait 2>/dev/null

echo "--- running: $CRIT ---"
./run.sh "$N" "$DLM" $CRIT
RUNRC=$?

echo "--- per-node evidence ---"
d=$(mktemp -d)
for h in $NODES; do
  ( timeout 25 tools/mxfs_sshpass.sh "$h" \
      "mountpoint -q /mnt/shared && echo MOUNT=1 || echo MOUNT=0; \
       for p in P32E-DIREPOCH-FENCE P32E-RAWDIVERGE P146V-UNLANDED \
                P176-OBLIGATION-OPEN P-INODE-WEDGE P228-RELBAR-DEFER \
                P211-EPOCH-REBASE P211-EPOCH-NOGRANT P211-EPOCH-FOREIGN \
                P216-B-DIRTY-SKIP P189-RELOG-BEHIND-DISK P177-OBLIGATION-DROPPED-AT-ADOPT; do \
         echo \"\$p=\$(dmesg|grep -c \$p)\"; done; \
       echo '---samples---'; \
       dmesg | grep -m3 'P-INODE-WEDGE\|P216-B-DIRTY-SKIP' || true" \
      > "$d/$h" 2>&1; echo "rc=$?" >> "$d/$h" ) &
done
wait 2>/dev/null

python3 - "$d" "$N" <<'PY'
import sys,os,re,collections
d,n=sys.argv[1],int(sys.argv[2]); tot=collections.Counter(); nomount=[]; bad=[]; samples=[]
for i in range(1,n+1):
    h="test%d"%i; p=os.path.join(d,h)
    if not os.path.exists(p): bad.append((h,"NOFILE")); continue
    t=open(p).read()
    if 'rc=0' not in t: bad.append((h,"rc!=0"))
    kv=dict(re.findall(r'(P[\w-]+)=(\d+)',t))
    for k,v in kv.items(): tot[k]+=int(v)
    if 'MOUNT=0' in t: nomount.append(h)
    body=t.split('---samples---',1)
    if len(body)==2:
        for ln in body[1].splitlines():
            if 'mxfs:' in ln:
                samples.append("%s: %s"%(h,ln.strip()[:190]))
print("--- fleet totals over %d nodes ---"%n)
for k in sorted(tot): print("  %-24s %d"%(k,tot[k]))
print("  NOMOUNT nodes: %s"%(", ".join(nomount) if nomount else "none"))
print("  collection failures: %s"%(bad or "none"))
for s in samples[:6]: print("  "+s)
PY
echo "=== run.sh rc=$RUNRC ==="
