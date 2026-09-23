#!/usr/bin/env python3
"""Triage the project's .ccmemory store back to lessons only.

The store accumulated session records — handoffs, run states, next-step plans,
campaign summaries — alongside the durable lessons it exists to hold.  A memory
named for a session or a run is a record, and a record does not belong in
memory.  This tool sorts every file into one of four fates and executes the
move, so nothing that is still load-bearing leaves with the records.

  KEEP      a lesson: what already bit us, what the user corrected, what a turn
            should have known.  Stays in .ccmemory.
  RULING    a design-consult ruling.  The defect queue cites these by name as
            the evidence behind open defects, so they become documents under
            docs/rulings/ and every citation is rewritten to the new path.
  HISTORY   a compiled campaign article, or a record the defect queue or the
            awareness docs still point at.  Becomes a document under
            docs/history/, citations rewritten the same way.
  DELETE    everything else: the session record with nothing left to teach.

Nothing is deleted while a pointer to it survives.  A name cited anywhere in
the tree is either preserved as a document, or redirected to the compiled
article that absorbed it — so a citation always lands on the material.

  triage.py plan [--out FILE]   classify everything, write the plan, change nothing
  triage.py apply PLAN          execute a plan: export, rewrite citations, delete
"""

import json
import os
import re
import shutil
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEM_DIR = os.path.join(ROOT, ".ccmemory")
DB = os.path.join(MEM_DIR, "index.db")
HISTORY_DIR = os.path.join(ROOT, "docs", "history")
RULINGS_DIR = os.path.join(ROOT, "docs", "rulings")

# Directories whose contents are not part of the tree's own text.
SKIP_DIRS = {".git", ".ccmemory", ".ccloop", "node_modules", ".state", "linux"}

# A ruling is a design consult: the queue cites it as the reason a fix has the
# shape it has, so it outlives the session that asked the question.
RULING_RE = re.compile(r"(gpt-ruling|gpt-verdict|gpt-consult|astra-ruling|fable-ruling"
                       r"|-ruling-|-ruling$|ruling\d*-|gpt-fence-design|gpt-plan-review"
                       r"|-verdict$|architectural-review|design-blueprint)", re.I)

# Lessons keep their place by name.
LESSON_PREFIXES = ("trap-", "feedback-", "technique-", "reference-", "user-")

# Lessons whose names do not carry one of those prefixes.  Each is something a
# future session on a different task would be wrong without.
KEEP_NAMES = {
    "never-mountpoint-q-on-a-quarantined-mxfs-mount",
    "never-find-root-nfs-mounts",
    "vacuous-pass-the-dominant-evidence-failure-in-this-project",
    "timing-is-first-class",
    "reuse-existing-criteria-tests",
    "convention-statemd-fresh-history-in-changelog",
    "rule10-and-agents-pulled-2026-08-22-flag-ab-arm-restore-text",
    "state-md-deprecated-do-not-maintain",
    "handoff-md-removed-context-is-auto-derived",
    "astra-consult-was-used-once-and-was-substantive-but-has-not-yet-closed-a-defect",
    "fable-safeguard-refusal-fallback-to-opus-mechanism",
    "clyde-taint-512-is-a-boot-time-dma-direct-map-page-warn-not-campaign-induced",
    "dmesg-follow-ringbuffer-staleness-trap-drc-cap2-fix",
    "kernel-log-retention-varies-per-node-pick-best-source",
    "libvirt-domain-deadlock-recovery-without-host-reset",
    "rig-prep-spurious-powercycle-under-host-load",
    "rig-recovery-after-clyde-reboot-scst-mpath",
    "env-cluster-bringup-after-host-reboot",
    "env-test1-needs-a-static-dhcp-reservation",
    "probe-counts-are-per-module-load-and-capped",
    "mkfs-mxfs-vs-mkfs-xfs-agcount-geometry-difference",
    "demoter-predicate-self-exemption-invariant",
    "differential-invalid-when-loser-is-rank1",
    "dirent-durability-failure-mode-discriminator",
    "aged-mount-coherency-repro-recipe",
    "unmount-leak-global-refcount-balance-cannot-work",
    "infra-src-mxfs-is-nfs-root-squash",
    "infra-src-is-qnap-nfs-do-not-touch-exports",
    "infra-sshpass-2arg-litters-repo-with-password-files",
    "infra-sshpass-wrapper-flattens-args-no-complex-scripts",
    "infra-node-root-disks-fill-and-fabricate-victim-failures",
    "infra-timeout-orphans-hold-run-lock-not-rival-session",
    "infra-mpath-up-sh-quoting-regression-fixed",
    "infra-lio-for-tcp-scst-for-caw-rationale",
    "infra-ccloop-leaves-stale-sessions-alive-KILL-AT-START",
    "project-caw-priority-enterprise-vmware-proxmox-san",
    "github-public-repo-mxfs",
    "mxfs1-vs-v5-not-mirror-images",
    "subagents-DO-inherit-claude-md-session-start-snapshot",
    "trap-killing-a-harness-run-midflight-leaks-the-module-refcount",
    "MXFS mount path",
    "Make clean before rebuild for multi-file changes",
    "Test VMs are disposable",
    "Use test1/test2, not T1/T2",
    "Commits only when work is done/working",
    "feedback_kill_builds",
    "feedback_sudo_virsh",
    # Compiled articles whose subject is how to work here, not what happened to
    # the code.  These are the lesson layer in collected form and stay put; the
    # campaign articles beside them are records and become documents.
    "compiled-rig-harness-measurement-traps",
    "compiled-rig-host-build-traps",
    "compiled-rig-operational-traps",
    "compiled-rig-infra-physrig-and-project-decisions",
    "compiled-test-environment-infra-reference",
    "compiled-matrix-enforcement-and-perf-measurement-methodology",
    "compiled-request-economics-delegation-and-safeguard-flags",
}

# Documents that belong in docs/ under their own name, or appended to the doc
# that already owns the subject.
DOC_MOVES = {
    "docs/xfs-native-format-plan.md": "docs/xfs-native-format-plan.md",
    "docs/rulings/dir-reuse-32-architectural-review.md": "docs/rulings/dir-reuse-32-architectural-review.md",
    "docs/net2-plan-of-record.md": "docs/net2-plan-of-record.md",
    "docs/rulings/net2-plan-review-verdict.md": "docs/rulings/net2-plan-review-verdict.md",
    "docs/net2-plan-of-record.md": "docs/net2-plan-of-record.md",
    "docs/ag-metadata-coherency.md": "docs/ag-metadata-coherency.md",
    "docs/pr-fencing-departure.md": "docs/pr-fencing-departure.md",
    "docs/sole-survivor-sweep.md": "docs/sole-survivor-sweep.md",
    "docs/sole-survivor-sweep.md": "docs/sole-survivor-sweep.md",
    "docs/sole-survivor-sweep.md": "docs/sole-survivor-sweep.md",
}

# Project history: what this and its predecessors were, kept as narrative.
HISTORY_APPEND = {
    "docs/project-history.md": "docs/project-history.md",
    "v5-history": "docs/project-history.md",
    "docs/project-history.md": "docs/project-history.md",
    "docs/project-history.md": "docs/project-history.md",
    "docs/project-history.md": "docs/project-history.md",
    "docs/project-history.md": "docs/project-history.md",
    "docs/project-history.md": "docs/project-history.md",
    "reference_prior_mxfs_versions": "docs/project-history.md",
}

# Measurement and process audits: the doc that already carries the subject.
COST_APPEND = [
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
    "docs/cost-audit.md",
]

# The source version log this tree never got into its changelog.
CHANGELOG_MOVES = ["v3-version-history"]


def slugify(name):
    """A document name for a memory: drop the run and session it was written in."""
    s = name
    s = re.sub(r"^AAA?[A-C]?-", "", s)
    s = re.sub(r"^ccloop-?[0-9a-f]{4,}-", "", s)
    s = re.sub(r"^sess[0-9]+[a-z]?[-_]", "", s)
    s = re.sub(r"^sess[0-9]+[a-z]?$", name, s)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    s = re.sub(r"^(gpt|astra|fable)-(ruling|verdict|consult)-?", "", s)
    return s or re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()


def load():
    con = sqlite3.connect(DB)
    rows = [dict(name=r[0], type=r[1], description=r[2] or "", body=r[3] or "")
            for r in con.execute("select name, type, description, body from mem")]
    folds = {}
    for src, dst in con.execute(
            "select src_name, dst_name from mem_edges where src_name like 'compiled-%'"):
        folds.setdefault(dst, src)
    con.close()
    return rows, folds


def tree_citations(names):
    """Every file outside the store that names a memory, and which names.

    Fixed-string grep, not a per-file Python scan: 2,800 patterns against a
    211k-LOC tree is an Aho-Corasick job, and doing it in Python takes tens of
    minutes instead of two.
    """
    import subprocess
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(names) + "\n")
        patterns = fh.name
    cmd = ["grep", "-rFo", "-f", patterns]
    cmd += ["--exclude-dir=%s" % d for d in sorted(SKIP_DIRS)]
    cmd += ["."]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    os.unlink(patterns)
    nameset = set(names)
    hits = {}
    for line in proc.stdout.splitlines():
        path, sep, match = line.partition(":")
        if not sep or match not in nameset:
            continue
        if path.startswith("./"):
            path = path[2:]
        hits.setdefault(path, set()).add(match)
    return hits


def classify(rows, folds, cited):
    plan = {}
    for r in rows:
        name = r["name"]
        if name in KEEP_NAMES:
            plan[name] = ("KEEP", "")
        elif name.startswith("compiled-"):
            plan[name] = ("HISTORY", "docs/history/%s.md" % slugify(name))
        elif name in DOC_MOVES:
            plan[name] = ("DOC", DOC_MOVES[name])
        elif name in HISTORY_APPEND:
            plan[name] = ("DOC", HISTORY_APPEND[name])
        elif name in COST_APPEND:
            plan[name] = ("DOC", "docs/cost-audit.md")
        elif name in CHANGELOG_MOVES:
            plan[name] = ("CHANGELOG", "CHANGELOG.md")
        elif name.startswith(LESSON_PREFIXES) or name in KEEP_NAMES:
            plan[name] = ("KEEP", "")
        elif RULING_RE.search(name):
            plan[name] = ("RULING", "docs/rulings/%s.md" % slugify(name))
        elif name in cited:
            plan[name] = ("HISTORY", "docs/history/%s.md" % slugify(name))
        else:
            plan[name] = ("DELETE", "")

    # Nothing leaves while a pointer to it survives: a cited name that is being
    # deleted is redirected to the compiled article that absorbed it, and
    # promoted to a document of its own when no article did.
    for name, (fate, dest) in list(plan.items()):
        if fate != "DELETE" or name not in cited:
            continue
        article = folds.get(name)
        if article and plan.get(article, ("", ""))[0] == "HISTORY":
            continue
        plan[name] = ("HISTORY", "docs/history/%s.md" % slugify(name))

    # Resolve destination collisions.
    seen = {}
    for name in sorted(plan):
        fate, dest = plan[name]
        if fate not in ("HISTORY", "RULING") or not dest:
            continue
        if dest in seen:
            base, ext = os.path.splitext(dest)
            n = 2
            while "%s-%d%s" % (base, n, ext) in seen:
                n += 1
            dest = "%s-%d%s" % (base, n, ext)
            plan[name] = (fate, dest)
        seen[dest] = name
    return plan


def redirect_map(plan, folds):
    """memory name -> the path a citation to it should now point at."""
    m = {}
    for name, (fate, dest) in plan.items():
        if fate in ("HISTORY", "RULING", "DOC"):
            m[name] = dest
        elif fate == "CHANGELOG":
            m[name] = "CHANGELOG.md"
    for name, (fate, _dest) in plan.items():
        if fate != "DELETE":
            continue
        article = folds.get(name)
        if article and article in m:
            m[name] = m[article]
    return m


def write_plan(path):
    rows, folds = load()
    hits = tree_citations([r["name"] for r in rows])
    cited = set()
    for names in hits.values():
        cited |= names
    plan = classify(rows, folds, cited)
    redir = redirect_map(plan, folds)
    bodies = {r["name"]: r for r in rows}
    out = {
        "plan": {n: {"fate": f, "dest": d} for n, (f, d) in plan.items()},
        "redirect": redir,
        "citing_files": {f: sorted(ns) for f, ns in hits.items()},
        "counts": {},
    }
    for f, _d in plan.values():
        out["counts"][f] = out["counts"].get(f, 0) + 1
    dangling = sorted(n for n in cited if plan[n][0] == "DELETE" and n not in redir)
    out["dangling"] = dangling
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print("plan: %s" % path)
    for k in sorted(out["counts"]):
        print("  %-9s %d" % (k, out["counts"][k]))
    print("  cited anywhere in tree: %d" % len(cited))
    print("  citations that would dangle: %d" % len(dangling))
    for n in dangling[:10]:
        print("    %s" % n)
    _ = bodies
    return out


def body_of(row):
    """The markdown body, with the store's frontmatter stripped."""
    return row["body"].strip() + "\n"


def rewrite_exported_docs(redir):
    """The exported documents cite each other by memory name; resolve those too."""
    names = sorted((n for n in redir), key=len, reverse=True)
    changed = 0
    for d in (HISTORY_DIR, RULINGS_DIR):
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            path = os.path.join(d, fn)
            with open(path, "r", errors="ignore") as fh:
                text = fh.read()
            original = text
            for name in names:
                if name in text:
                    text = text.replace(name, redir[name])
            text = tidy_pointers(text)
            if text != original:
                with open(path, "w") as fh:
                    fh.write(text)
                changed += 1
    return changed


def tidy_pointers(text):
    """A rewritten pointer reads as a path, not as a memory that no longer exists."""
    text = re.sub(r"\[\[(docs/[^\]]+?)\]\]", r"`\1`", text)
    text = re.sub(r"(?i)\bccmemory\s+(?:as\s+|note\s+)?(?=`?docs/)", "", text)
    text = re.sub(r"(?i)\bccmemory:\s+(?=`?docs/)", "", text)
    text = re.sub(r"(?i)\bmemory\s+`(docs/[^`]+)`", r"`\1`", text)
    return text


def apply(plan_path):
    with open(plan_path) as fh:
        p = json.load(fh)
    rows, _folds = load()
    byname = {r["name"]: r for r in rows}
    plan, redir = p["plan"], p["redirect"]

    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(RULINGS_DIR, exist_ok=True)

    written = appended = deleted = 0
    appends = {}
    for name, spec in sorted(plan.items()):
        fate, dest = spec["fate"], spec["dest"]
        row = byname.get(name)
        if row is None or fate in ("KEEP", "DELETE"):
            continue
        path = os.path.join(ROOT, dest)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if fate in ("HISTORY", "RULING") and not os.path.exists(path):
            with open(path, "w") as fh:
                fh.write("<!-- %s -->\n" % row["description"].strip())
                fh.write(body_of(row))
            written += 1
        else:
            appends.setdefault(dest, []).append(name)

    for dest, names in sorted(appends.items()):
        path = os.path.join(ROOT, dest)
        with open(path, "a") as fh:
            for name in names:
                row = byname[name]
                fh.write("\n\n---\n\n")
                fh.write(body_of(row))
                appended += 1

    # Every pointer at a moved memory now points at the document.
    rewritten_files = 0
    for relpath in sorted(p["citing_files"]):
        path = os.path.join(ROOT, relpath)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        original = text
        for name in sorted(p["citing_files"][relpath], key=len, reverse=True):
            target = redir.get(name)
            if target and name in text:
                text = text.replace(name, target)
        if text != original:
            text = tidy_pointers(text)
            with open(path, "w") as fh:
                fh.write(text)
            rewritten_files += 1

    rewritten_files += rewrite_exported_docs(redir)

    con = sqlite3.connect(DB)
    for name, spec in sorted(plan.items()):
        if spec["fate"] == "KEEP":
            continue
        path = os.path.join(MEM_DIR, name + ".md")
        if os.path.exists(path):
            os.remove(path)
            deleted += 1
        con.execute("delete from mem where name = ?", (name,))
        con.execute("delete from mem_edges where src_name = ? or dst_name = ?", (name, name))
    con.commit()
    con.close()

    print("documents written=%d  sections appended=%d  files rewritten=%d  memories removed=%d"
          % (written, appended, rewritten_files, deleted))


def relink(plan_path):
    """Point every surviving citation at wherever its memory went.

    Run after `apply`.  A name still in the store is left alone; every other
    name is replaced by the document that now holds it.  Finding the files is a
    fixed-string grep, not a scan of the tree per name -- the difference is
    minutes against tens of them.
    """
    with open(plan_path) as fh:
        redir = json.load(fh)["redirect"]
    con = sqlite3.connect(DB)
    live = {n for (n,) in con.execute("select name from mem")}
    con.close()
    redir = {n: d for n, d in redir.items() if n not in live}
    hits = tree_citations(sorted(redir))
    touched = 0
    for relpath in sorted(hits):
        fp = os.path.join(ROOT, relpath)
        if not os.path.exists(fp):
            print("  MISSING %s" % relpath)
            continue
        text = open(fp, errors="ignore").read()
        original = text
        for name in sorted(hits[relpath], key=len, reverse=True):
            text = text.replace(name, redir[name])
        if text != original:
            text = tidy_pointers(text)
            open(fp, "w").write(text)
            touched += 1
            print("  %s (%d names)" % (relpath, len(hits[relpath])))
    print("relinked %d files" % touched)


def rename(pairs):
    """Rename a memory to what it teaches, and follow its citations.

    A name that says WHEN something happened marks a record.  These are
    lessons, so the session they came from belongs in the description, never in
    the name.
    """
    con = sqlite3.connect(DB)
    for old, new in pairs:
        oldp = os.path.join(MEM_DIR, old + ".md")
        newp = os.path.join(MEM_DIR, new + ".md")
        if not os.path.exists(oldp):
            print("  missing: %s" % old)
            continue
        text = open(oldp, errors="ignore").read()
        text = re.sub(r"^name:\s*.*$", "name: " + new, text, count=1, flags=re.M)
        with open(newp, "w") as fh:
            fh.write(text)
        os.remove(oldp)
        con.execute("update mem set name = ?, path = ? where name = ?", (new, newp, old))
        con.execute("update mem_edges set src_name = ? where src_name = ?", (new, old))
        con.execute("update mem_edges set dst_name = ? where dst_name = ?", (new, old))
        touched = 0
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                if os.path.getsize(fp) > 12 * 1024 * 1024:
                    continue
                try:
                    t = open(fp, errors="ignore").read()
                except OSError:
                    continue
                if old in t:
                    open(fp, "w").write(t.replace(old, new))
                    touched += 1
        print("  %-64s -> %-52s (%d citing files)" % (old, new, touched))
    con.commit()
    con.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    if sys.argv[1] == "plan":
        write_plan(sys.argv[2] if len(sys.argv) > 2 else "/tmp/ccmemory-plan.json")
    elif sys.argv[1] == "relink":
        relink(sys.argv[2])
    elif sys.argv[1] == "rename":
        rename([tuple(a.split("=", 1)) for a in sys.argv[2:]])
    elif sys.argv[1] == "apply":
        apply(sys.argv[2])
    else:
        raise SystemExit(__doc__)
