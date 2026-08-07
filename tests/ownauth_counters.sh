#!/bin/bash
#
# tests/ownauth_counters.sh — collect the P239-OWNAUTH histogram from every
# node and aggregate it.
#
# P239-OWNAUTH (pal/linux/xfs_buf_item.c, sess101) answers the question step
# 5.3 of D-FOREIGN-REPLAY-UNGATED-IMAGES turns on: for every logged buffer
# image whose authority is NOT the containing AG grant — the population a
# foreign replayer would apply unchecked — what authority state is the OWNING
# inode actually in at format time?
#
#   durable   the owner holds a DURABLE_EX grant with a nonzero epoch.  The
#             formatter can name real authority; no delegation is needed.
#   unpub     UNPUBLISHED_EX — created under an AG tenure, never published.
#             This is the population the sess101 ruling designed an AG-minted
#             unpublished-child delegation for.
#   uncached  the owning inode is not in the AG's radix tree at all.
#   none/stale/durnoep/noowner/badag/nopag  capture or state failures; a gate
#             must fail CLOSED on every one of them.
#
# The report is emitted to dmesg every 8192 authority tokens, so each line is
# CUMULATIVE SINCE MODULE LOAD.  Pass a snapshot file to difference two
# workload windows; without one the absolute totals are printed.
#
# Usage:
#   tests/ownauth_counters.sh <nnodes> [snapshot-file]
#     no snapshot-file      -> print current absolute values
#     snapshot-file absent  -> print current values AND save them there
#     snapshot-file present -> print the DELTA since that snapshot
#
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:?usage: ownauth_counters.sh <nnodes> [snapshot-file]}"
SNAP="${2:-}"

RAW="$(mktemp -d)/raw"
for i in $(seq 1 "$N"); do
    (
        # One whole report block, emitted in this order by mxfs_tokcls_report:
        # P228-TOKCLASS, P239-OWNAUTH n=, P239-OWNAUTH-NONDURABLE, P240-AUTHCAP.
        v="$("$SSH" "test$i" \
            "dmesg | grep -E 'P239-OWNAUTH n=|P239-OWNAUTH-NONDURABLE|P228-TOKCLASS n=|P240-AUTHCAP' | tail -4" \
            2>/dev/null)"
        [ -n "$v" ] && echo "test$i|$(echo "$v" | tr '\n' '|')"
    ) >> "$RAW" &
done
wait

sort -V "$RAW" -o "$RAW"

python3 - "$RAW" "$SNAP" <<'PY'
import sys, os, json, re

raw, snapfile = sys.argv[1], sys.argv[2]

OUTCOMES = ["noowner", "badag", "nopag", "uncached", "stale",
            "none", "unpub", "releasing", "durable", "durnoep"]

BLFT = {0: "unknown", 1: "udquot", 2: "pdquot", 3: "gdquot", 4: "btree",
        5: "agf", 6: "agfl", 7: "agi", 8: "dino", 9: "symlink",
        10: "dir_block", 11: "dir_data", 12: "dir_free", 13: "dir_leaf1",
        14: "dir_leafn", 15: "da_node", 16: "attr_leaf", 17: "attr_rmt",
        18: "sb", 19: "rtbitmap", 20: "rtsummary"}


def parse(node_blob):
    """Return (outcomes, nondurable_blft, tokcls, authcap, capmode)."""
    out, nd, tok, cap, cmode = {}, {}, {}, {}, {}
    for seg in node_blob:
        if "P239-OWNAUTH n=" in seg:
            for k, v in re.findall(r"(\w+)=(\d+)", seg):
                out[k] = int(v)
        elif "P239-OWNAUTH-NONDURABLE" in seg:
            for k, v in re.findall(r"t(\d+)=(\d+)", seg):
                nd[int(k)] = int(v)
        elif "P228-TOKCLASS n=" in seg:
            head = seg.split("mis_blft:")[0]
            for k, v in re.findall(r"(\w+)=(\d+)", head):
                tok[k] = int(v)
        elif "P240-AUTHCAP" in seg:
            # head: win/relog/mismatch/noblft/blftchg/nocap
            # tail after 'pw_by_outcome:': per-outcome count of images dirtied
            # while this node held mode >= PW on the derived owner.
            head, _, tail = seg.partition("pw_by_outcome:")
            for k, v in re.findall(r"(\w+)=(\d+)", head):
                cap[k] = int(v)
            for k, v in re.findall(r"(\w+)=(\d+)", tail):
                cmode[k] = int(v)
    return out, nd, tok, cap, cmode


cur = {}
for line in open(raw):
    parts = [p for p in line.rstrip("\n").split("|") if p.strip()]
    if len(parts) < 2:
        continue
    node = parts[0]
    cur[node] = parse(parts[1:])

base, mode = {}, "ABSOLUTE"
if snapfile:
    if os.path.exists(snapfile):
        base = json.load(open(snapfile))
        mode = "DELTA"
    else:
        json.dump({n: [c[0], {str(k): v for k, v in c[1].items()}, c[2],
                       c[3], c[4]]
                   for n, c in cur.items()}, open(snapfile, "w"))
        mode = "ABSOLUTE (snapshot saved)"

if not cur:
    print("no P239-OWNAUTH reports on any node — the 8192-token report "
          "modulus has not been reached since module load")
    sys.exit(1)

agg_out = {k: 0 for k in OUTCOMES}
agg_nd, agg_tok, agg_cap, agg_cmode = {}, {}, {}, {}
rows = []
caprows = []

for node in sorted(cur, key=lambda s: int(s[4:])):
    out, nd, tok, cap, cmode = cur[node]
    if mode == "DELTA" and node in base:
        b = base[node] + [{}, {}]          # tolerate a pre-P240 snapshot
        b_out, b_nd, b_tok, b_cap, b_cmode = b[0], b[1], b[2], b[3], b[4]
        out = {k: out.get(k, 0) - b_out.get(k, 0) for k in out}
        nd = {k: nd.get(k, 0) - int(b_nd.get(str(k), 0)) for k in nd}
        tok = {k: tok.get(k, 0) - b_tok.get(k, 0) for k in tok}
        cap = {k: cap.get(k, 0) - b_cap.get(k, 0) for k in cap}
        cmode = {k: cmode.get(k, 0) - b_cmode.get(k, 0) for k in cmode}
    n = sum(out.get(k, 0) for k in OUTCOMES)
    rows.append((node, n, out))
    caprows.append((node, cap, cmode))
    for k in OUTCOMES:
        agg_out[k] += out.get(k, 0)
    for k, v in nd.items():
        agg_nd[k] = agg_nd.get(k, 0) + v
    for k, v in tok.items():
        agg_tok[k] = agg_tok.get(k, 0) + v
    for k, v in cap.items():
        agg_cap[k] = agg_cap.get(k, 0) + v
    for k, v in cmode.items():
        agg_cmode[k] = agg_cmode.get(k, 0) + v

print("=== P239-OWNAUTH — inode-owned image authority at format time "
      "(%s, %d nodes) ===" % (mode, len(rows)))
hdr = "%-8s %8s " % ("node", "n") + " ".join("%9s" % k for k in OUTCOMES)
print(hdr)
for node, n, out in rows:
    print("%-8s %8d " % (node, n) +
          " ".join("%9d" % out.get(k, 0) for k in OUTCOMES))
print("-" * len(hdr))
tot = sum(agg_out.values())
print("%-8s %8d " % ("TOTAL", tot) +
      " ".join("%9d" % agg_out[k] for k in OUTCOMES))
if tot:
    print("%-8s %8s " % ("pct", "") +
          " ".join("%8.2f%%" % (100.0 * agg_out[k] / tot) for k in OUTCOMES))

print()
print("non-durable BLFT mix (the images a gate would have to REFUSE):")
if agg_nd:
    for k in sorted(agg_nd, key=lambda k: -agg_nd[k]):
        if agg_nd[k]:
            print("   t%-2d %-10s %8d" % (k, BLFT.get(k, "?"), agg_nd[k]))
else:
    print("   none")

print()
print("P228-TOKCLASS totals (whole authority-token population):")
for k in ("n", "ag", "sb", "mislabel", "noepoch", "unknown", "incomplete"):
    if k in agg_tok:
        print("   %-12s %10d" % (k, agg_tok[k]))

print()
print("=== P240-AUTHCAP — capture-point health (sess103) ===")
if not agg_cap:
    print("   no P240-AUTHCAP line on any node — the (win & 1023) report "
          "trigger has not been reached since module load")
else:
    NOTE = {
        "win":      "capture windows opened (first protected dirty per txn)",
        "relog":    "re-logs of an already-captured buffer in the same window",
        "mismatch": "one buffer, two authorities -> downgraded to MIXED",
        "noblft":   "captured before xfs_trans_buf_set_type ran (MUST be low)",
        "blftchg":  "BLFT changed after capture",
        "nocap":    "formatted with NO capture -- MUST BE 0 (plumbing hole)",
    }
    for k in ("win", "relog", "mismatch", "noblft", "blftchg", "nocap"):
        flag = ""
        if k == "nocap" and agg_cap.get(k, 0):
            flag = "   <== PLUMBING HOLE: a dirty path bypasses " \
                   "xfs_trans_dirty_buf"
        print("   %-10s %12d   %s%s" % (k, agg_cap.get(k, 0), NOTE[k], flag))
    nz = [(n, c["nocap"]) for n, c, _ in caprows if c.get("nocap", 0)]
    if nz:
        print("   nocap by node: " +
              " ".join("%s=%d" % (n, v) for n, v in nz))

    print()
    print("   cross-tab: of each outcome, how many were dirtied while this")
    print("   node held mode >= PW on the derived owner")
    # mxfs_buf_owner_authority sets *dlm_mode = 0 up front and only writes the
    # real mode at the i_flags_lock section that decides the switch.  Every
    # outcome that returns BEFORE that point therefore reports mode 0 by
    # construction, and its cross-tab is vacuous -- not evidence of an
    # unauthorized write.  NOOWNER does not even call the function.
    VACUOUS = ("noowner", "badag", "nopag", "uncached", "stale")
    print("   %-10s %10s %10s %8s   %s" %
          ("outcome", "captured", "held>=PW", "pct", "reading"))
    for k in OUTCOMES:
        tot_k = agg_out.get(k, 0)
        pw_k = agg_cmode.get(k, 0)
        if not tot_k and not pw_k:
            continue
        pct = (100.0 * pw_k / tot_k) if tot_k else 0.0
        if k == "durable":
            reading = "expected"
        elif k in VACUOUS:
            reading = "n/a -- mode never read on this arm (vacuous)"
        elif pct >= 50.0:
            reading = "RECORDER is broken (state-machine gap)"
        else:
            reading = "UNAUTHORIZED modification -- live coherency defect"
        print("   %-10s %10d %10d %7.2f%%   %s" %
              (k, tot_k, pw_k, pct, reading))
PY
