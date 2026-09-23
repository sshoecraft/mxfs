#!/usr/bin/env python3
"""alloc_witness_verdict.py — the cold audit's half of the allocation-coverage
witness (design-consult rulings docs/rulings/audit-gate-allocation-coverage-
witness.md).  chk_clean runs it on the auditing node after chk_mxfs -v, with
every node unmounted, and prints ONE line the row folds into its verdict:

    release=CLEAN|VACUOUS|INDETERMINATE coverage=... cohort=... finobt=... \
    targets=... accounting=... witness=<path> reason=<text>

It never says CORRUPT: that is the structural checker's word, and chk_clean
takes it first.  This decides only whether a structural CLEAN may be called
a release CLEAN:

  INDETERMINATE  the witness is missing, unsealed (sha mismatch), for another
                 run or filesystem, its coverage is UNKNOWN, or the checker
                 output lacks what the confirmation needs (geometry, the
                 per-record inobt/finobt lines with free masks, the inode
                 accounting totals)
  VACUOUS        every measurement is present and a floor is unmet: the stress
                 row's coverage was INSUFFICIENT, a retained-cohort inode is no
                 longer allocated, a covered AG has no genuinely partial
                 chunk in its finobt, an emptied-and-reused target chunk's
                 inobt record, free mask, freecount or finobt entry does not
                 match exactly the occupants the row put back, or the
                 superblock inode counts do not reconcile with the inobt
  CLEAN          coverage PASS, every cohort inode still allocated in the inobt
                 the checker walked, every covered AG shows a partial chunk
                 in the finobt, every target chunk matches its occupants, and
                 the superblock icount/ifree equal the inobt sums

usage: alloc_witness_verdict.py <witness dir> <chk_mxfs -v output> <chk_mxfs
       --geometry output> <run id> [<expected fsid>]
The expected fsid is the checker's own "UUID:" line when the caller has it;
the witness's fsid must equal it.
"""
import hashlib
import os
import re
import sys

INODES_PER_CHUNK = 64


def out(release, coverage="?", cohort="?", finobt="?", targets="?", accounting="?", witness="none", reason=""):
    print("release=%s coverage=%s cohort=%s finobt=%s targets=%s accounting=%s witness=%s reason=%s"
          % (release, coverage, cohort, finobt, targets, accounting, witness, reason.replace("|", "_")))
    sys.exit(0)


def main():
    if len(sys.argv) < 5:
        out("INDETERMINATE", reason="usage")
    wdir, chkout, geoout, run_id = sys.argv[1:5]
    want_fsid = sys.argv[5].strip().lower() if len(sys.argv) > 5 else ""
    wpath = os.path.join(wdir, "witness.txt")
    spath = os.path.join(wdir, "witness.sha")
    if not os.path.exists(wpath) or not os.path.exists(spath):
        out("INDETERMINATE", witness=wpath, reason="no sealed witness for run %s" % run_id)
    body = open(wpath, "rb").read()
    if hashlib.sha256(body).hexdigest() != open(spath).read().strip():
        out("INDETERMINATE", witness=wpath, reason="witness seal (sha256) does not match its body")
    text = body.decode(errors="replace")
    head = text.splitlines()[0] if text else ""
    m = re.match(r"ALLOC_WITNESS run=(\S+) fsid=(\S+) nodes=(\d+) coverage=(\S+)", head)
    if not m:
        out("INDETERMINATE", witness=wpath, reason="witness header unreadable")
    w_run, w_fsid, w_nodes, coverage = m.group(1), m.group(2).lower(), int(m.group(3)), m.group(4)
    if w_run != run_id:
        out("INDETERMINATE", coverage, witness=wpath,
            reason="witness belongs to run %s, this audit is run %s" % (w_run, run_id))
    if want_fsid and w_fsid != want_fsid:
        out("INDETERMINATE", coverage, witness=wpath,
            reason="witness fsid %s is not the platter's %s" % (w_fsid, want_fsid))
    cohort = []
    covered = set()
    targets = []     # (rank, chunk start ino, occupants)
    for ln in text.splitlines():
        if ln.startswith("COHORT "):
            d = dict(kv.split("=", 1) for kv in ln.split()[1:])
            cohort.append((int(d["ino"]), d.get("path", "?"), int(d.get("rank", 0))))
        elif ln.startswith("END "):
            d = dict(kv.split("=", 1) for kv in ln.split()[1:])
            if int(d["carves"]) > 0:
                covered.add(int(d["ag"]))
        elif ln.startswith("TARGET "):
            d = dict(kv.split("=", 1) for kv in ln.split()[1:])
            if d.get("emptied") == "yes":
                occ = [int(x) for x in d.get("occupants", "-").split(",") if x not in ("", "-")]
                targets.append((int(d.get("rank", 0)), int(d["chunk"]), occ))
    if coverage == "UNKNOWN":
        out("INDETERMINATE", coverage, witness=wpath, reason="the stress row's coverage is UNKNOWN")

    # geometry: agblocks and inopblog give the inode number split
    geo = open(geoout, errors="replace").read()
    def gval(key):
        mm = re.search(r"\b%s\s*[=:]\s*(\d+)" % key, geo)
        return int(mm.group(1)) if mm else None
    agblocks, inopblog, agcount = gval("agblocks"), gval("inopblog"), gval("agcount")
    agblklog = gval("agblklog")
    if agblocks is None or inopblog is None or agcount is None:
        out("INDETERMINATE", coverage, witness=wpath, reason="geometry (agblocks/inopblog/agcount) not readable from the checker")
    if agblklog is None:
        agblklog = max(1, (agblocks - 1).bit_length())
    ino_shift = agblklog + inopblog
    agino_mask = (1 << ino_shift) - 1

    # the checker's per-record lines (verbose): inobt for allocation, finobt for
    # the partial-chunk floor and the target confirmation; the accounting totals
    recs = {"inobt": {}, "finobt": {}}
    pat = re.compile(r"AG (\d+) (inobt|finobt) rec \d+: startino=(\d+) count=(\d+) freecount=(\d+) holemask=0x([0-9A-Fa-f]+) free=0x([0-9A-Fa-f]+)")
    totals = {}
    tpat = re.compile(r"(Total inodes \(inobt sum\)|Superblock icount|Total free inodes \(inobt sum\)|Superblock ifree):\s+(\d+)")
    for ln in open(chkout, errors="replace"):
        mm = pat.search(ln)
        if mm:
            ag = int(mm.group(1)); tree = mm.group(2)
            recs[tree].setdefault(ag, []).append((int(mm.group(3)), int(mm.group(4)), int(mm.group(5)),
                                                  int(mm.group(6), 16), int(mm.group(7), 16)))
            continue
        mt = tpat.search(ln)
        if mt:
            totals[mt.group(1)] = int(mt.group(2))
    if not recs["inobt"]:
        out("INDETERMINATE", coverage, witness=wpath, reason="the checker output carries no per-record inobt lines with free masks (chk_mxfs -v of a build that prints them is required)")
    if len(totals) < 4:
        out("INDETERMINATE", coverage, witness=wpath, reason="the checker output lacks the inode accounting totals (inobt sums and superblock icount/ifree)")

    # cohort: every recorded inode still allocated
    missing = []
    for ino, path, rank in cohort:
        ag = ino >> ino_shift; agino = ino & agino_mask
        ok = False
        for (start, count, freecount, holemask, free) in recs["inobt"].get(ag, []):
            if start <= agino < start + INODES_PER_CHUNK:
                bit = agino - start
                ok = not (free >> bit) & 1
                break
        if not ok:
            missing.append("%d(%s)" % (ino, path))
    cohort_v = "PASS" if cohort and not missing else ("FAIL" if cohort else "NONE")
    # every covered AG has a retained cohort inode and a genuinely partial chunk
    cohort_ags = set((ino >> ino_shift) for ino, _, _ in cohort)
    ag_without_cohort = sorted(a for a in covered if a not in cohort_ags)
    partial_missing = []
    for ag in sorted(covered):
        if not any(0 < fc < c for (_, c, fc, _, _) in recs["finobt"].get(ag, [])):
            partial_missing.append(ag)
    finobt_v = "PASS" if covered and not partial_missing else ("FAIL" if covered else "NONE")

    # the emptied-and-reused targets: each is still a whole inobt record whose
    # free mask, freecount and finobt entry are exactly the occupants the row
    # put back (its blocks not being free space is the checker's own aliasing
    # pass, taken by chk_clean before this)
    target_bad = []
    for rank, chunk, occ in targets:
        ag = chunk >> ino_shift; start = chunk & agino_mask
        rec = next(((s, c, fc, hm, fr) for (s, c, fc, hm, fr) in recs["inobt"].get(ag, []) if s == start), None)
        if rec is None:
            target_bad.append("rank%d chunk %d: no inobt record at AG %d startino %d" % (rank, chunk, ag, start)); continue
        s, c, fc, hm, fr = rec
        want_alloc = 0
        for o in occ:
            if (o >> ino_shift) != ag or not (start <= (o & agino_mask) < start + INODES_PER_CHUNK):
                target_bad.append("rank%d chunk %d: occupant %d is outside the chunk" % (rank, chunk, o)); continue
            want_alloc |= 1 << ((o & agino_mask) - start)
        want_free = ((1 << INODES_PER_CHUNK) - 1) & ~want_alloc
        want_fc = INODES_PER_CHUNK - bin(want_alloc).count("1")
        if c != INODES_PER_CHUNK or hm != 0:
            target_bad.append("rank%d chunk %d: count %d holemask 0x%x, not a whole chunk" % (rank, chunk, c, hm))
        if fr != want_free or fc != want_fc:
            target_bad.append("rank%d chunk %d: inobt free=0x%016x freecount=%d, occupants say free=0x%016x freecount=%d" % (rank, chunk, fr, fc, want_free, want_fc))
        frec = next(((s2, c2, fc2, hm2, fr2) for (s2, c2, fc2, hm2, fr2) in recs["finobt"].get(ag, []) if s2 == start), None)
        if want_fc > 0 and (frec is None or frec[2] != want_fc or frec[4] != want_free):
            target_bad.append("rank%d chunk %d: finobt %s, want freecount %d free=0x%016x" % (rank, chunk, "absent" if frec is None else "freecount %d free=0x%016x" % (frec[2], frec[4]), want_fc, want_free))
        if want_fc == 0 and frec is not None:
            target_bad.append("rank%d chunk %d: full but still in the finobt" % (rank, chunk))
    targets_v = "PASS" if targets and not target_bad else ("FAIL" if targets else "NONE")

    # the superblock inode accounting reconciles with every AG's inobt
    acc_bad = []
    if totals["Total inodes (inobt sum)"] != totals["Superblock icount"]:
        acc_bad.append("inobt sum %d != sb icount %d" % (totals["Total inodes (inobt sum)"], totals["Superblock icount"]))
    if totals["Total free inodes (inobt sum)"] != totals["Superblock ifree"]:
        acc_bad.append("inobt free sum %d != sb ifree %d" % (totals["Total free inodes (inobt sum)"], totals["Superblock ifree"]))
    accounting_v = "PASS" if not acc_bad else "FAIL"

    reasons = []
    if coverage != "PASS":
        reasons.append("stress-row coverage %s" % coverage)
    if cohort_v != "PASS":
        reasons.append("retained cohort: %s" % (("not allocated: " + ",".join(missing)) if missing else "none recorded"))
    if ag_without_cohort:
        reasons.append("covered AGs without a retained inode: %s" % ag_without_cohort)
    if finobt_v != "PASS":
        reasons.append("covered AGs without a partial chunk in the finobt: %s" % (partial_missing or "no covered AG"))
    if targets_v != "PASS":
        reasons.append("target chunks: %s" % ("; ".join(target_bad) if target_bad else "none emptied"))
    if accounting_v != "PASS":
        reasons.append("inode accounting: %s" % "; ".join(acc_bad))
    if reasons:
        out("VACUOUS", coverage, cohort_v, finobt_v, targets_v, accounting_v, wpath, "; ".join(reasons))
    out("CLEAN", coverage, cohort_v, finobt_v, targets_v, accounting_v, wpath,
        "coverage PASS, %d cohort inodes allocated, partial chunks in AGs %s, %d target chunks match their occupants, sb icount %d = inobt sum, ifree %d = inobt free sum"
        % (len(cohort), sorted(covered), len(targets), totals["Superblock icount"], totals["Superblock ifree"]))


if __name__ == "__main__":
    main()
