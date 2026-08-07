#!/bin/bash
#
# tests/auth_counters.sh — read the inode-authority population counters
# (/sys/kernel/debug/mxfs/<dev>/inode_authority) from every node and print a
# per-node table plus a cluster aggregate.  Optionally diffs against a saved
# snapshot so a workload's contribution can be isolated.
#
# The counters answer the sess96 RULE-5 ruling's question for
# D-FOREIGN-REPLAY-UNGATED-IMAGES: what fraction of the live acquire
# population can actually PROVE a durable EX tenure, and when it cannot,
# WHICH refusal reason applies.  A gate that refuses nearly every image is a
# no-op dressed as safety, so this fraction decides whether step 5.3 is worth
# shipping in its current shape.
#
# Usage:
#   tests/auth_counters.sh <nnodes> [snapshot-file]
#     no snapshot-file      -> print current absolute values
#     snapshot-file absent  -> print current values AND save them there
#     snapshot-file present -> print the DELTA since that snapshot
#
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:?usage: auth_counters.sh <nnodes> [snapshot-file]}"
SNAP="${2:-}"

# Field order is fixed by the kernel's seq_printf; keep in sync with
# mxfs_inode_authority_show() in xfs/xfs_mxfs_dlm.c.
FIELDS="installs installs_advance refusals novalid nogres notvalid noepoch shared stalegen releasing unpublished routing reclaim no_snapshot judged revoke release_begin backstop unpublished_noted"

RAW="$(mktemp -d)/raw"
for i in $(seq 1 "$N"); do
    (
        v="$("$SSH" "test$i" \
            "cat /sys/kernel/debug/mxfs/*/inode_authority 2>/dev/null" 2>/dev/null |
            grep -E "^ *[a-z_]+ +[0-9]+$" | awk '{print $1"="$2}' | tr '\n' ' ')"
        [ -n "$v" ] && echo "test$i $v"
    ) >> "$RAW" &
done
wait

sort -V "$RAW" -o "$RAW"

python3 - "$RAW" "$SNAP" "$FIELDS" <<'PY'
import sys, os, json
raw, snapfile, fields = sys.argv[1], sys.argv[2], sys.argv[3].split()

cur = {}
for line in open(raw):
    parts = line.split()
    if not parts:
        continue
    node = parts[0]
    cur[node] = {k: int(v) for k, v in (p.split('=', 1) for p in parts[1:])}

base = {}
mode = "ABSOLUTE"
if snapfile:
    if os.path.exists(snapfile):
        base = json.load(open(snapfile))
        mode = "DELTA since snapshot"
    else:
        json.dump(cur, open(snapfile, 'w'))
        mode = "ABSOLUTE (snapshot saved)"

def val(node, f):
    c = cur.get(node, {}).get(f, 0)
    b = base.get(node, {}).get(f, 0) if base else 0
    return c - b

show = ["installs", "installs_advance", "novalid", "nogres", "notvalid",
        "noepoch", "shared", "stalegen",
        "releasing", "unpublished", "routing", "reclaim", "no_snapshot",
        "revoke", "release_begin", "backstop", "unpublished_noted"]
hdr = ["inst", "adv", "noval", "nogres", "notval", "noep", "shared", "stale", "rel'ng", "unpub", "route",
       "recl", "nosnap", "revoke", "relbeg", "bkstop", "unpubN"]

print(f"inode-authority counters — {mode} — {len(cur)} node(s) reporting")
print("node    " + " ".join(f"{h:>7}" for h in hdr))
tot = dict.fromkeys(show, 0)
for node in sorted(cur, key=lambda s: int(s[4:])):
    row = [val(node, f) for f in show]
    for f, v in zip(show, row):
        tot[f] += v
    print(f"{node:<8}" + " ".join(f"{v:>7}" for v in row))
print("-" * (8 + 8 * len(show)))
print(f"{'TOTAL':<8}" + " ".join(f"{tot[f]:>7}" for f in show))

inst = tot["installs"] + tot["installs_advance"]
ref = sum(tot[f] for f in ("novalid", "shared", "stalegen", "releasing",
                           "unpublished", "routing", "reclaim"))
judged = inst + ref
print()
print(f"judged acquires (install-eligible) : {judged}")
print(f"  installed a durable tenure       : {inst}"
      + (f"  ({inst*100//judged}%)" if judged else ""))
print(f"  refused                          : {ref}"
      + (f"  ({ref*100//judged}%)" if judged else ""))
if ref:
    for f, h in (("novalid", "no CAS result at all"),
                 ("shared", "PR/CR grant — correctly non-proving"),
                 ("stalegen", "gen moved (guard fired)"),
                 ("releasing", "tenure being released"),
                 ("unpublished", "no durable slot yet"),
                 ("routing", "backing mismatch"),
                 ("reclaim", "inode reclaiming/shutdown")):
        if tot[f]:
            print(f"    {f:<12} {tot[f]:>9}  ({tot[f]*100//ref}% of refusals)"
                  f"  — {h}")
print(f"no-snapshot acquires (probe/nudge)  : {tot['no_snapshot']}")
PY
