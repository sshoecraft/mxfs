#!/usr/bin/env python3
"""Tabulate the replay transactions a survivor judged and how the victim ended
the tenure of every inode-class owner their tokens name.

Input: one gzip text file per node, klog_test<N>.txt.gz, captured with
`journalctl -k -f -o short-unix`, one record per line:

    <epoch>.<usec> <host> kernel: <message>

What it reads

  on every node that is not a victim (a replayer prints these):
    P227-TOKEN      one line per buffer image of a replayed transaction, in
                    item order: blkno blft class st res gepoch slot lineage
    P227-TOKENSUM   one line per transaction, after its images: lsn buf_items
                    ino wapply redundant wskip
    ATOMIC-SKIP     a transaction skipped whole (lsn items)
    P273-SHADOW-EVAL  the evaluator's totals for one slice

  on every victim:
    every line that names one of the inode-class owners found above
    (ino=<res>, owner=<res>, dp=<res>, ip=<res>), counted by message tag, with
    the time of the first and the last such line measured back from the
    victim's own last line.

Sections

  1  per node: line count, first and last timestamp
  2  per replayer: the transactions in log order.  The images of a
     transaction are the P227-TOKEN lines between the previous P227-TOKENSUM
     and its own.  The P227-TOKEN print is capped by the module (400 per
     load), so a transaction past the cap lists no image; it is marked.
  3  per replayer: P273-SHADOW-EVAL fields of each slice
  4  per inode-class owner named in a transaction with wskip > 0: which
     transactions name it, and per victim the tags of the lines that name it
  5  the same owners on the survivors: the tags of the lines that name them

Nothing here prints a raw log line.  A field value is printed as the log
carries it; a tag is the first token of the form P<digits or letters>-<NAME>.

usage:
  python3 tools/klog_tenure_table.py --dir EVIDENCE_DIR --victims 2,7 \
      [--nodes 1,2,3,4,5,6,7,8] [--all-owners] [--out FILE]

--all-owners tabulates the owners of every transaction, not only of those
with wskip > 0.  Exit status: 0 when every node file was read to its end, 3
when a node file was missing or unreadable (the node is named).
"""

import argparse
import collections
import gzip
import os
import re
import sys
import zlib

TS_RE = re.compile(rb"^(\d{10}\.\d{6}) ")
PAIR_RE = re.compile(r"(\w+)=(\S+)")
TAG_RE = re.compile(r"\bP[0-9A-Za-z]*-[A-Z0-9][A-Z0-9-]*")
LSN_RE = re.compile(r"lsn=(0x[0-9a-fA-F]+)")
ITEMS_RE = re.compile(r"items=(\d+)")

TOKEN = b"P227-TOKEN "
TOKENSUM = b"P227-TOKENSUM"
ATOMIC = b"ATOMIC-SKIP whole transaction"
SHADOW = b"P273-SHADOW-EVAL"

CLASS_NAMES = {"0": "none", "1": "ag", "2": "sb", "3": "inode", "4": "iclus"}
TOKEN_FIELDS = ("blkno", "len", "blft", "v", "class", "st", "res", "gepoch",
                "oepoch", "slot", "lineage")
SUM_FIELDS = ("buf_items", "tokened", "ag", "ino", "iclus", "classless",
              "untagged", "wapply", "redundant", "wskip")
SHADOW_FIELDS = ("victim_slot", "capable", "buf", "untagged", "classless",
                 "badst", "fowner", "winc", "manerr", "wlineage", "notheld",
                 "staleep", "WOULD_APPLY", "REDUNDANT_CLEAN", "txn",
                 "all_apply", "relmarks", "relmark_overflow")


def fields_of(text):
    return dict(PAIR_RE.findall(text))


def tag_of(text):
    m = TAG_RE.search(text)
    return m.group(0) if m else "(untagged)"


def read_lines(path):
    """Yield (timestamp or None, decoded text) for every line; raise on a bad file."""
    with gzip.open(path, "rb") as fh:
        for raw in fh:
            m = TS_RE.match(raw)
            ts = float(m.group(1)) if m else None
            yield ts, raw.decode("utf-8", "replace").rstrip("\n")


def scan_replayer(path):
    """One pass over a survivor's log: transactions, atomic skips, slice totals."""
    out = {"lines": 0, "first": None, "last": None, "txns": [], "skips": {},
           "shadow": [], "error": None}
    pending = []
    try:
        for ts, text in read_lines(path):
            out["lines"] += 1
            if ts is not None:
                if out["first"] is None:
                    out["first"] = ts
                out["last"] = ts
            raw = text.encode("utf-8", "replace")
            if TOKENSUM in raw:
                f = fields_of(text)
                m = LSN_RE.search(text)
                out["txns"].append({
                    "ts": ts, "lsn": m.group(1) if m else "?",
                    "sum": {k: f.get(k, "-") for k in SUM_FIELDS},
                    "images": pending,
                })
                pending = []
            elif TOKEN in raw:
                f = fields_of(text)
                pending.append({k: f.get(k, "-") for k in TOKEN_FIELDS})
            elif ATOMIC in raw:
                m = LSN_RE.search(text)
                n = ITEMS_RE.search(text)
                if m:
                    out["skips"][m.group(1)] = n.group(1) if n else "?"
            elif SHADOW in raw:
                f = fields_of(text)
                out["shadow"].append({"ts": ts,
                                      "f": {k: f.get(k, "-") for k in SHADOW_FIELDS}})
    except (OSError, EOFError, zlib.error) as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    out["orphans"] = len(pending)
    return out


def scan_for_owners(path, owners):
    """Count, per owner and tag, the lines of one log that name the owner."""
    out = {"lines": 0, "first": None, "last": None, "hits": {}, "error": None}
    if not owners:
        return out
    alt = "|".join(sorted(re.escape(o) for o in owners))
    pat = re.compile(r"\b(?:ino|owner|dp|ip|res)=(%s)\b" % alt)
    quick = [o.encode() for o in owners]
    try:
        for ts, text in read_lines(path):
            out["lines"] += 1
            if ts is not None:
                if out["first"] is None:
                    out["first"] = ts
                out["last"] = ts
            raw = text.encode("utf-8", "replace")
            if not any(q in raw for q in quick):
                continue
            seen = set()
            for m in pat.finditer(text):
                seen.add(m.group(1))
            if not seen:
                continue
            tag = tag_of(text)
            extra = ""
            if tag == "P975-TENURE-END-EVICT":
                f = fields_of(text)
                extra = " why=%s mode=%s" % (f.get("why", "-"), f.get("mode", "-"))
            elif tag == "P-H22-CALL":
                f = fields_of(text)
                extra = " site=%s" % f.get("site", "-")
            elif tag == "P-FREEPUB-CLAIM-CLEAR":
                f = fields_of(text)
                extra = " why=%s" % f.get("why", "-")
            for owner in seen:
                slot = out["hits"].setdefault(owner, collections.OrderedDict())
                rec = slot.setdefault(tag + extra, [0, ts, ts])
                rec[0] += 1
                rec[2] = ts
    except (OSError, EOFError, zlib.error) as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def image_text(img):
    cls = CLASS_NAMES.get(img["class"], "class" + img["class"])
    return "%s/blft%s/res%s/blk%s/ge%s/st%s" % (
        cls, img["blft"], img["res"], img["blkno"], img["gepoch"], img["st"])


def rel(ts, base):
    if ts is None or base is None:
        return "-"
    return "%+.2f" % (ts - base)


def main():
    ap = argparse.ArgumentParser(description="Replay transactions and the tenure "
                                 "end of the owners they name, from per-node kernel logs")
    ap.add_argument("--dir", required=True, help="directory holding klog_test<N>.txt.gz")
    ap.add_argument("--victims", required=True, help="comma list of victim node numbers")
    ap.add_argument("--nodes", default="1,2,3,4,5,6,7,8", help="comma list of node numbers")
    ap.add_argument("--all-owners", action="store_true",
                    help="tabulate the owners of every transaction")
    ap.add_argument("--out", help="also write the report to this file")
    args = ap.parse_args()

    nodes = [n.strip() for n in args.nodes.split(",") if n.strip()]
    victims = [n.strip() for n in args.victims.split(",") if n.strip()]
    survivors = [n for n in nodes if n not in victims]
    rep = []
    bad = []

    def path_of(node):
        return os.path.join(args.dir, "klog_test%s.txt.gz" % node)

    scans = {}
    for node in survivors:
        if not os.path.exists(path_of(node)):
            bad.append("test%s: no file" % node)
            continue
        scans[node] = scan_replayer(path_of(node))
        if scans[node]["error"]:
            bad.append("test%s: %s" % (node, scans[node]["error"]))

    owners = collections.OrderedDict()
    for node, sc in scans.items():
        for txn in sc["txns"]:
            wskip = txn["sum"].get("wskip", "0")
            if not args.all_owners and wskip in ("0", "-"):
                continue
            for img in txn["images"]:
                if img["class"] == "3":
                    owners.setdefault(img["res"], []).append(
                        "test%s lsn=%s blft%s blk%s ge%s" % (
                            node, txn["lsn"], img["blft"], img["blkno"], img["gepoch"]))

    vscans = {}
    for node in victims:
        if not os.path.exists(path_of(node)):
            bad.append("test%s: no file" % node)
            continue
        vscans[node] = scan_for_owners(path_of(node), list(owners))
        if vscans[node]["error"]:
            bad.append("test%s: %s" % (node, vscans[node]["error"]))
    sscans = {}
    for node in survivors:
        if node in scans and owners:
            sscans[node] = scan_for_owners(path_of(node), list(owners))

    rep.append("# replay transactions and tenure ends: %s" % args.dir)
    rep.append("victims: %s   survivors: %s" % (
        " ".join("test" + v for v in victims), " ".join("test" + s for s in survivors)))
    rep.append("")
    rep.append("## 1 files")
    rep.append("node | lines | first | last")
    for node in nodes:
        sc = scans.get(node) or vscans.get(node)
        if not sc:
            rep.append("test%s | - | - | -" % node)
            continue
        rep.append("test%s | %d | %s | %s" % (
            node, sc["lines"],
            "%.2f" % sc["first"] if sc["first"] else "-",
            "%.2f" % sc["last"] if sc["last"] else "-"))

    rep.append("")
    rep.append("## 2 transactions judged, per replayer (log order)")
    for node, sc in scans.items():
        if not sc["txns"]:
            continue
        rep.append("### test%s: %d transactions, %d skipped whole, %d image lines after the last sum" % (
            node, len(sc["txns"]), len(sc["skips"]), sc["orphans"]))
        rep.append("lsn | buf_items | ino | wapply | redundant | wskip | whole-skip | images")
        for txn in sc["txns"]:
            s = txn["sum"]
            imgs = txn["images"]
            shown = "; ".join(image_text(i) for i in imgs if i["class"] != "1")
            nag = sum(1 for i in imgs if i["class"] == "1")
            if not imgs:
                shown = "(no image line: past the module's print cap)"
            else:
                shown = ("%d ag" % nag) + ("; " + shown if shown else "")
            rep.append("%s | %s | %s | %s | %s | %s | %s | %s" % (
                txn["lsn"], s["buf_items"], s["ino"], s["wapply"], s["redundant"],
                s["wskip"], "yes items=%s" % sc["skips"][txn["lsn"]]
                if txn["lsn"] in sc["skips"] else "no", shown))

    rep.append("")
    rep.append("## 3 slice totals (P273-SHADOW-EVAL), per replayer")
    for node, sc in scans.items():
        for sh in sc["shadow"]:
            rep.append("test%s | %s" % (node, " ".join(
                "%s=%s" % (k, sh["f"][k]) for k in SHADOW_FIELDS)))

    rep.append("")
    rep.append("## 4 inode-class owners of %s, and the victim's lines that name them" % (
        "every transaction" if args.all_owners else "transactions with wskip > 0"))
    if not owners:
        rep.append("(none)")
    for owner, where in owners.items():
        rep.append("### owner %s: %d image(s)" % (owner, len(where)))
        for w in where:
            rep.append("  image: %s" % w)
        for node, vs in vscans.items():
            hits = vs["hits"].get(owner)
            if not hits:
                rep.append("  test%s (victim): no line names it" % node)
                continue
            rep.append("  test%s (victim), last line of its log = 0:" % node)
            rep.append("  tag | lines | first | last   (seconds before the victim's last line)")
            for tag, (n, first, last) in hits.items():
                rep.append("  %s | %d | %s | %s" % (
                    tag, n, rel(first, vs["last"]), rel(last, vs["last"])))

    rep.append("")
    rep.append("## 5 the same owners on the survivors")
    for owner in owners:
        for node, ss in sscans.items():
            hits = ss["hits"].get(owner)
            if not hits:
                continue
            rep.append("owner %s on test%s: %s" % (owner, node, ", ".join(
                "%s x%d" % (tag, rec[0]) for tag, rec in hits.items())))

    if bad:
        rep.append("")
        rep.append("## unreadable")
        rep.extend(bad)

    text = "\n".join(rep) + "\n"
    sys.stdout.write(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    return 3 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
