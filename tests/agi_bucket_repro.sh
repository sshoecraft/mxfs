#!/bin/bash
# tests/agi_bucket_repro.sh — deterministic reproducer for
# D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (ledger, opened sess38).
#
# ROOT UNDER TEST: XFS AGI unlinked buckets are shared cluster state, but the
# in-core unlinked list design assumes (a) every bucket member is in THIS
# node's icache ("existence guarantee") and (b) any on-disk member NOT in
# cache is abandoned garbage ("Found unrecovered unlinked inode ... Initiating
# recovery").  Both premises are false across nodes.  A peer's live
# open-unlinked inode in the same bucket (agino % 64 collision) is reloaded by
# xfs_iunlink_reload_next (P83-UNL-RELOAD), stitched with possibly-stale
# in-core next/prev (P83-UNL-REMCHK STALE=1), and its cross-node inactivation
# is only held off by the heuristic B1-B5 guards in xfs_inactive.
#
# METHOD: held-open unlinked files are persistent zombies.  Two nodes place
# zombies with CONGRUENT inode numbers (same AG, ino mod 64 equal) in ONE
# bucket, then close them in adversarial (mid-chain-first) order, forcing
# cross-node reloads and stitches on demand instead of waiting for a 32-node
# aged-mount race.
#
# usage: agi_bucket_repro.sh [pair|chain|stress] [nodeA=test1] [nodeB=test2]
# Exit 0 = harness ran; grep the report for REPRO= lines.  This is a
# diagnostic reproducer, not a criterion.
set -u
PHASE="${1:-pair}"
NA="${2:-test1}"
NB="${3:-test2}"
SSH=tools/mxfs_sshpass.sh
RUNID="$(date +%s)_$$"
BASE="/mnt/shared/.agirepro_${RUNID}"
POOL="$BASE/pool"
AGSHIFT=21          # from sb: agblklog=18 + inopblog=3 (chk_mxfs verified)
NPOOL=280
say(){ echo "[agirepro] $*"; }

mark(){ # mark <node> <tag>
  $SSH "$1" "echo AGIREPRO-${RUNID}-$2 > /dev/kmsg" >/dev/null 2>&1
}
scan(){ # scan <node> <tag>  -> prints scoped dmesg probe hits
  $SSH "$1" "dmesg | sed -n \"/AGIREPRO-${RUNID}-$2/,\\\$p\" | grep -E 'P83-UNL|P82-ADD|P71-INSTR|P47-INACT|P2L|P19-B3DEC|IFREE-REVALIDATE|rc=-117|EFSCORRUPTED|Internal error|Corruption|corrupt|shutdown|sync-inactive' | grep -v 'AGIREPRO'" 2>/dev/null
}

# unlink the held file -> zombie enters AGI bucket (P82-ADD fires)
zombify(){ local node="$1" path="$2"; $SSH "$node" "rm $path && echo UNLINKED" 2>/dev/null | grep -q UNLINKED; }

say "run=$RUNID phase=$PHASE A=$NA B=$NB base=$BASE"
say "prep: instr on (P83-UNL-REMCHK is instr-gated), pool of ${NPOOL}+${NPOOL} inos in one shared dir"
$SSH "$NA" "echo 1 > /sys/module/mxfs/parameters/instr; mkdir -p $POOL" >/dev/null 2>&1
$SSH "$NB" "echo 1 > /sys/module/mxfs/parameters/instr" >/dev/null 2>&1

# --- pool creation: ALL by node A (one AG — mxfs shards allocation per node,
# so cross-node bucket cohabitation comes from B unlinking A-created files,
# the shared-tree rm case, not from concurrent creates) ---
$SSH "$NA" "cd $POOL && for i in \$(seq 1 $NPOOL); do echo x > f\$i; done" >/dev/null 2>&1
FINOS=$($SSH "$NA" "cd $POOL && stat -c '%n %i' f*" 2>/dev/null | grep -E '^f[0-9]+ [0-9]+$')
[ -z "$FINOS" ] && { say "ABORT pool listing failed"; exit 1; }
# A takes the first two of a congruence class, B the next two
AINOS=$FINOS
BINOS=$FINOS

# --- host-side congruence pick: need >=2 A and >=2 B files, same agno, same bucket ---
PICK=$(python3 - "$AGSHIFT" <<PYEOF
import sys, collections
agshift=int(sys.argv[1])
pool="""$FINOS"""
byk=collections.defaultdict(list)
for ln in pool.strip().splitlines():
    n,i=ln.split(); i=int(i)
    byk[(i>>agshift,(i&((1<<agshift)-1))%64)].append((n,i))
best=None
for k,l in sorted(byk.items(), key=lambda kv:-len(kv[1])):
    if len(l)>=4: best=(k,l[:4]); break
if not best:
    print("NONE"); sys.exit(0)
(ag,bk),l=best
# a1,a2 for node A; b1,b2 for node B — all A-created, one bucket
print(f"AG={ag} BUCKET={bk} "+" ".join(f"{t}:{n}:{i}" for t,(n,i) in zip(("a1","a2","b1","b2"),l)))
PYEOF
)
say "pick: $PICK"
echo "$PICK" | grep -q NONE && { say "ABORT no congruent quad found"; exit 1; }
getf(){ echo "$PICK" | grep -o "$1:f[0-9]*:[0-9]*" | cut -d: -f2; }
geti(){ echo "$PICK" | grep -o "$1:f[0-9]*:[0-9]*" | cut -d: -f3; }
A1N=$(getf a1); A1I=$(geti a1); A2N=$(getf a2); A2I=$(geti a2)
B1N=$(getf b1); B1I=$(geti b1); B2N=$(getf b2); B2I=$(geti b2)

mark "$NA" P1; mark "$NB" P1

# holders write their own pidfile so closes are exact (no pattern kills)
holdp(){ # holdp <node> <name> <id>
  local node="$1" name="$2" id="$3"
  $SSH "$node" "rm -f /tmp/agihold.${id}.ready /tmp/agihold.${id}.pid; nohup bash -c 'exec 9<>$POOL/$name; echo \$\$ > /tmp/agihold.${id}.pid; touch /tmp/agihold.${id}.ready; sleep 900' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  for i in $(seq 1 50); do
    $SSH "$node" "test -f /tmp/agihold.${id}.ready" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  say "ERROR holder $id/$name on $node not ready"; return 1
}
closep(){ # closep <node> <id>
  local node="$1" id="$2"
  $SSH "$node" "kill \$(cat /tmp/agihold.${id}.pid) 2>/dev/null; echo CLOSED" 2>/dev/null | grep -q CLOSED
  sleep 2
}

case "$PHASE" in
pair)
  say "== PAIR: zombie A:$A1N($A1I) then B:$B1N($B1I) — expect P83-UNL-RELOAD on $NB at insert =="
  holdp "$NA" "$A1N" a1 && zombify "$NA" "$POOL/$A1N" && say "A zombie in"
  sleep 1
  holdp "$NB" "$B1N" b1 && zombify "$NB" "$POOL/$B1N" && say "B zombie in (chain: $B1I -> $A1I)"
  sleep 2
  say "--- $NB scoped probes after B-insert:"; scan "$NB" P1
  say "--- $NA scoped probes after B-insert:"; scan "$NA" P1
  mark "$NA" P2; mark "$NB" P2
  say "close order: A first (tail remove; prev=$B1I is B's zombie -> reload on $NA)"
  closep "$NA" a1
  say "--- $NA after its close:"; scan "$NA" P2
  closep "$NB" b1
  say "--- $NB after its close:"; scan "$NB" P2
  ;;
chain)
  say "== CHAIN: interleave a1,b1,a2,b2 (head b2->a2->b1->a1), close mid-chain first =="
  holdp "$NA" "$A1N" a1 && zombify "$NA" "$POOL/$A1N"
  holdp "$NB" "$B1N" b1 && zombify "$NB" "$POOL/$B1N"
  holdp "$NA" "$A2N" a2 && zombify "$NA" "$POOL/$A2N"
  holdp "$NB" "$B2N" b2 && zombify "$NB" "$POOL/$B2N"
  say "chain on disk (head->tail): $B2I -> $A2I -> $B1I -> $A1I"
  sleep 2
  say "--- insert-phase probes A:"; scan "$NA" P1
  say "--- insert-phase probes B:"; scan "$NB" P1
  mark "$NA" P2; mark "$NB" P2
  say "close a2 (MID-chain on $NA: stitch prev=$B2I next=$B1I, both B's zombies)"
  closep "$NA" a2
  say "--- $NA:"; scan "$NA" P2; say "--- $NB:"; scan "$NB" P2
  mark "$NA" P3; mark "$NB" P3
  say "close b1 (MID-chain on $NB: prev/next views may be stale now)"
  closep "$NB" b1
  say "--- $NB:"; scan "$NB" P3; say "--- $NA:"; scan "$NA" P3
  mark "$NA" P4; mark "$NB" P4
  say "close b2 then a1 (drain)"
  closep "$NB" b2; closep "$NA" a1
  say "--- $NB:"; scan "$NB" P4; say "--- $NA:"; scan "$NA" P4
  ;;
stress)
  say "== STRESS: 3 rounds of chain pattern over distinct buckets =="
  say "(not implemented in v1 — run chain repeatedly)"
  ;;
esac

# --- verdict ---
say "== health checks =="
HA=$($SSH "$NA" "touch $BASE/probe_a && ls $BASE >/dev/null && rm $BASE/probe_a && echo OK" 2>/dev/null | grep -c OK)
HB=$($SSH "$NB" "touch $BASE/probe_b && ls $BASE >/dev/null && rm $BASE/probe_b && echo OK" 2>/dev/null | grep -c OK)
CORR_A=$($SSH "$NA" "dmesg | sed -n \"/AGIREPRO-${RUNID}-P1/,\\\$p\" | grep -cE 'rc=-117|EFSCORRUPTED|Internal error|Corruption of in-memory data|shutdown'" 2>/dev/null)
CORR_B=$($SSH "$NB" "dmesg | sed -n \"/AGIREPRO-${RUNID}-P1/,\\\$p\" | grep -cE 'rc=-117|EFSCORRUPTED|Internal error|Corruption of in-memory data|shutdown'" 2>/dev/null)
RELOADS=$($SSH "$NA" "dmesg | sed -n \"/AGIREPRO-${RUNID}-P1/,\\\$p\" | grep -c P83-UNL-RELOAD" 2>/dev/null)
RELOADS_B=$($SSH "$NB" "dmesg | sed -n \"/AGIREPRO-${RUNID}-P1/,\\\$p\" | grep -c P83-UNL-RELOAD" 2>/dev/null)
say "REPRO: reloads A=$RELOADS B=$RELOADS_B corruption A=$CORR_A B=$CORR_B fs_ops A=$HA B=$HB"
if [ "${CORR_A:-0}" -gt 0 ] || [ "${CORR_B:-0}" -gt 0 ]; then say "REPRO=CORRUPTION"; else
  if [ "${RELOADS:-0}" -gt 0 ] || [ "${RELOADS_B:-0}" -gt 0 ]; then
    say "REPRO=RELOAD-ONLY (P83 reload fired, no corruption)."
    say "  READ THIS BEFORE TREATING IT AS A REGRESSION: since per-slot buckets"
    say "  (0.11.332) a node only ever walks its OWN bucket, so an OWNER-LOCAL"
    say "  reload is expected and benign — it is how a node re-stitches a zombie"
    say "  of its own that has since been evicted from its cache.  Deferred-reap"
    say "  zombies (0.11.333+, P87-OPEN-DEFER: a peer holds the unlinked file"
    say "  open) live in the owner's bucket for as long as the peer keeps it"
    say "  open, so they make owner-local reloads MORE likely, not less."
    say "  The defect signature is a reload whose node_slot does NOT own the"
    say "  bucket being walked, or any corruption count above — compare the"
    say "  P83 line's node_slot against the bucket in the P82-ADD/P87 lines."
  else say "REPRO=NONE"; fi
fi
say "cleanup"
$SSH "$NA" "rm -rf $BASE; echo 0 > /sys/module/mxfs/parameters/instr" >/dev/null 2>&1
$SSH "$NB" "echo 0 > /sys/module/mxfs/parameters/instr" >/dev/null 2>&1
say "done"
