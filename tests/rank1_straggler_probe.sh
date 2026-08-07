#!/bin/bash
# rank1_straggler_probe.sh — is the coordinator (rank 1 / test1) structurally
# slower than its peers, and does the gap widen with mount age?
#
# WHY THIS EXISTS
#   D-MOUNT-DEGRADES-WITH-USE was localised in sess26: two independent
#   240s/240s dirent_durability truncations on an aged mount, BOTH on test1 and
#   never on any other node. The token differential named the same two probes
#   each time:
#       P1-AGWAIT          110-200  vs peer median 3-7    (x25-28)
#       P128-INACT-DEFER   153-176  vs peer median 0      (x154-177)
#   plus P-DIRFLUSH ~x18-24, while test1 did NONE of the ordinary eviction work
#   its peers did (EVICT-RING-FLAG 0 vs median 30-33).
#
#   That was measured on FAILING runs, where cause and consequence are
#   inseparable. This measures the same ratios on a PASSING run, so the question
#   "is rank 1 always elevated and merely crosses a threshold when aged?" can be
#   answered separately from "did the failure make it elevated?".
#
# Run it right after a dirent_durability run. Compare a fresh-prep run against
# an aged-mount run: if the ratio is already high when fresh, rank 1 carries a
# structural asymmetry (it also performs the teardown work); if the ratio only
# grows with age, the backlog is what accumulates.
#
# Source selection is PER NODE — retention varies ~60x and neither dmesg nor
# journalctl -k is reliably longer (see ccmemory
# kernel-log-retention-varies-per-node-pick-best-source).
#
# Usage: tests/rank1_straggler_probe.sh [n_nodes] [label]

set -u
cd "$(dirname "$0")/.." || exit 1
N="${1:-32}"
LABEL="${2:-probe}"
SSH=tools/mxfs_sshpass.sh
PROBES="P1-AGWAIT P128-INACT-DEFER P-DIRFLUSH P-DIRDW P12-WORK EVICT-RING-FLAG P-CR63-SHELL P128-REARM-UNPUB P-BLOCK0-CONVGATE P-IGET-ENOENT P6-MIDTENURE-RELOAD-SKIP"
td=$(mktemp -d)
# Keep the FULL per-node census, not just the printed subset.  A first cut
# deleted it and printed 11 named probes, so a later "failing vs passing" diff
# compared the failing census against ABSENT baseline entries and read them as
# measured zeros -- inventing +1388/+1190 deltas for probes never baselined.
KEEP="${MXFS_R1_OUT:-$(mktemp -d)}"

for i in $(seq 1 "$N"); do
    (
      timeout 90 "$SSH" "test$i" "
        dmesg > /tmp/r1_dm.txt 2>/dev/null
        journalctl -k --no-pager > /tmp/r1_jk.txt 2>/dev/null
        for f in /tmp/r1_dm.txt /tmp/r1_jk.txt; do
            awk -v f=\$f '/MXFS_DIRENT_WINDOW/{n=NR} END{print f, (n?NR-n:0)}' \$f
        done | sort -k2,2nr | head -1 | awk '{print \$1}' > /tmp/r1_best.txt
        B=\$(cat /tmp/r1_best.txt)
        awk '/MXFS_DIRENT_WINDOW/{n=NR} {l[NR]=\$0} END{for(j=n+1;j<=NR;j++) print l[j]}' \$B \
          | grep -oE 'mxfs: [A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)+' | sed 's/^mxfs: //' \
          | sort | uniq -c | awk '{print \$2, \$1}'
      " 2>/dev/null | grep -vE '^(Warning|If you)' > "$td/test$i"
    ) &
done
wait

python3 - "$td" "$N" "$LABEL" <<'PY'
import sys, os, statistics
td, n, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
PROBES = os.environ.get("PROBES", "").split() or [
    "P1-AGWAIT","P128-INACT-DEFER","P-DIRFLUSH","P-DIRDW","P12-WORK",
    "EVICT-RING-FLAG","P-CR63-SHELL","P128-REARM-UNPUB",
    "P-BLOCK0-CONVGATE","P-IGET-ENOENT","P6-MIDTENURE-RELOAD-SKIP"]

def load(i):
    p = os.path.join(td, f"test{i}")
    d = {}
    if os.path.exists(p):
        for line in open(p):
            t = line.split()
            if len(t) == 2 and t[1].isdigit():
                d[t[0]] = int(t[1])
    return d

r1 = load(1)
peers = {i: load(i) for i in range(2, n + 1)}
peers = {i: d for i, d in peers.items() if d}
print(f"=== rank1 (test1) vs {len(peers)} peers [{label}] ===")
if not peers:
    print("  no peer data"); sys.exit(1)
print(f"  {'PROBE':<30} {'rank1':>7} {'peer_med':>9} {'peer_max':>9}  ratio")
for pr in PROBES:
    a = r1.get(pr, 0)
    vals = [d.get(pr, 0) for d in peers.values()]
    med, mx = statistics.median(vals), max(vals)
    ratio = (a + 1) / (med + 1)
    flag = "  <-- ABOVE EVERY PEER" if a > mx and a > 0 else ""
    print(f"  {pr:<30} {a:>7} {med:>9} {mx:>9}  x{ratio:>5.1f}{flag}")
PY
cp "$td"/test* "$KEEP"/ 2>/dev/null
echo "  full per-node censuses kept in: $KEEP"
rm -rf "$td"
