#!/usr/bin/env python3
"""Does the text a user reads say what the release data says?

    tools/release_text_check.py            exit 0 iff every check passes
    tools/release_text_check.py --list     the files read and the claims derived

WHY THIS EXISTS.  What is released lives in data (`data/configurations.json`: the
release matrix and the configurations verified by a rig of their own;
`data/platforms.json`; `VERSION`; `data/defects.json`).  The README, the manual
pages, the installed module-options file, the storage guide and the module's
own parameter descriptions repeat it in prose, and prose does not update
itself.  Measured on 2026-10-04, two releases after sixteen nodes shipped and
with multipath and DRBD verified: the README still called DRBD a "trial ... not
in any release", `mxfs(5)` listed DRBD as unsupported and dm-multipath as not
verified, four places said the lock managers were released up to eight nodes on
one path, `modinfo` described disk/caw as "in development", and the README
quoted a defect count that was two records old.  Readers, and the tools that
read for them, concluded the released product was not ready.

WHAT IT CHECKS.  Derived from the data, never from a second list kept here:

  1. The README's "Released" table names exactly the released configurations.
  2. The README names the tree's VERSION as the current release, in the table's
     closing sentence and in its first news heading.
  3. The count in the README's "Released: <n> configurations" heading.
  4. The README's open-defect numbers (total, and how many reach a released
     configuration) equal what tools/defects.py reports now.
  5. Every released platform's name is in the README.
  6. No public file describes a released thing as unreleased: the phrases in
     STALE below.  Each is a statement that was true once.
  7. No public file gives the released cluster sizes as a list that stops
     short of the largest one.
  8. The files that state released cluster sizes name the largest one.

A phrase that is right where it stands (history that names its own version, a
statement about something genuinely unreleased) is listed in ALLOWED with the
reason, by file and by the exact text of its line.  Nothing else is exempt.

WHERE IT RUNS.  scripts/release.sh runs it before it builds a package and again
before it publishes, and stops on a failure; tests/full_verify.sh records its
result with the build's other audits.  It reads the tree only.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The text a user, or a tool reading for one, meets: the front page, what the
# packages install, the guides the front page sends them to, and what modinfo
# prints.  Design notes, rulings and history are not release claims.
PUBLIC = [
    "README.md",
    "docs/man/man5/mxfs.5",
    "docs/man/man8/chk_mxfs.8",
    "docs/man/man8/mkfs.mxfs.8",
    "docs/man/man8/mxfs_admin.8",
    "docs/man/man8/resize_mxfs.8",
    "docs/iscsi_setup.md",
    "docs/attachment-methods.md",
    "docs/mpath-verification.md",
    "packaging/mxfs-modprobe.conf",
    "packaging/mkdeb.sh",
    "packaging/mkdeb_pve.sh",
    "packaging/mkrpm.sh",
    "packaging/packaging.md",
    "frontend/proxmox/MXFSPlugin.pm",
    "frontend/proxmox/mxfs-storage.js",
]
# Source files: only their MODULE_DESCRIPTION / MODULE_PARM_DESC text is public.
MODULE_TEXT = ["dlm/v5_mount.c", "pal/linux/kern.c", "pal/linux/xfs_super.c"]

# Files that state the released cluster sizes and must name the largest.
SIZES_STATED_IN = ["README.md", "docs/man/man5/mxfs.5", "docs/iscsi_setup.md",
                   "packaging/mxfs-modprobe.conf"]

NUMBER_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
                "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
                "seventeen", "eighteen", "nineteen", "twenty", "twenty-one", "twenty-two",
                "twenty-three", "twenty-four", "twenty-five", "twenty-six", "twenty-seven",
                "twenty-eight", "twenty-nine", "thirty", "thirty-one", "thirty-two"]

# (pattern, what it wrongly says).  Matched per line, case-insensitively.
STALE = [
    (r"\btrial\b", "calls something a trial; a released attachment is not one"),
    (r"not (yet )?recommended for production", "recommends against production use"),
    (r"(CAW|disk/caw)[^.\n]{0,60}\bin development\b|\bin development\b[^.\n]{0,60}(CAW|disk/caw)",
     "calls the disk/caw lock manager in development"),
    (r"\bthe released (transport|configuration)\b", "implies one lock manager is the released one"),
    (r"\b(not in|outside) the release matrix\b", "places a configuration outside the release"),
]

# How prose names an attachment.  A public file must not call a RELEASED
# attachment unverified, unsupported or unreleased; which ones are released
# comes from the data.  DRBD was released in 0.90.41 and withdrawn on
# 2026-10-06, and the text that says so is right.
ATTACH_WORDS = {"mpath": r"dm-multipath|multipath|\bmpath\b", "drbd": r"DRBD"}


def attach_rule(rel: list[str]) -> tuple[str, str] | None:
    names = sorted({c.split("/")[3] for c in rel} & set(ATTACH_WORDS))
    if not names:
        return None
    return (r"(" + "|".join(ATTACH_WORDS[n] for n in names) + r")[^.\n]{0,120}"
            r"\b(not verified|unverified|not supported|not released|not in any release)\b",
            "calls a released attachment (" + ", ".join(names) + ") unverified, unsupported or unreleased")

# (file, exact stripped line, reason).  The line must still be in the file: a
# stale exemption fails the check, so this list cannot outlive what it excuses.
ALLOWED = [
    ("README.md",
     "a released thing a trial, unverified, unsupported or in development.",
     "the README's description of this check"),
    ("docs/attachment-methods.md",
     "attachment carries a flag named `trial` and is parsed only for a caller that",
     "names the tooling flag and says, two lines on, that it is not release status"),
    ("README.md",
     "> the 2-, 4- and 8-node configurations and all four platforms were verified",
     "the 0.90.42 news item: the smaller sizes re-verified when sixteen nodes shipped"),
]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(errors="replace")


def released() -> list[str]:
    d = json.loads(read("data/configurations.json"))
    own = [k for k in d.get("released_by_own_rig", {}) if k != "_"]
    return list(d["release_matrix"]) + own


def matrix_sizes() -> list[int]:
    d = json.loads(read("data/configurations.json"))
    return sorted({int(k.split("/")[0]) for k in d["release_matrix"]})


def defect_counts(cfgs: list[str]) -> tuple[int, int]:
    """(open records, records that reach at least one released configuration)."""
    total = len(json.loads(read("data/defects.json")).get("defects", []))
    out = subprocess.run([sys.executable, str(ROOT / "tools/defects.py")],
                         capture_output=True, text=True).stdout
    m = re.search(r"^Total: (\d+) open", out, re.M)
    if m:
        total = int(m.group(1))
    ids: set[str] = set()
    for c in cfgs:
        o = subprocess.run([sys.executable, str(ROOT / "tools/defects.py"), "--at", c],
                           capture_output=True, text=True).stdout
        ids |= set(re.findall(r"\bD-[A-Z0-9][A-Z0-9-]+", o))
    return total, len(ids)


def module_text(rel: str) -> list[tuple[int, str]]:
    """The lines of MODULE_DESCRIPTION / MODULE_PARM_DESC statements in a source file."""
    out, inside = [], False
    for i, line in enumerate(read(rel).splitlines(), 1):
        if re.search(r"\bMODULE_(PARM_DESC|DESCRIPTION)\s*\(", line):
            inside = True
        if inside:
            out.append((i, line))
            if ");" in line:
                inside = False
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true", help="print the files and the derived claims")
    args = ap.parse_args()

    fails: list[str] = []
    rel = released()
    sizes = matrix_sizes()
    top = sizes[-1]
    version = read("VERSION").strip()
    readme = read("README.md")

    # 1. the Released table
    section = readme.split("### Released", 1)[1].split("###", 1)[0] if "### Released" in readme else ""
    rows = re.findall(r"^> \| `(\d+/[a-z]+/[a-z]+/[a-z]+)` \|", section, re.M)
    for c in rel:
        if c not in rows:
            fails.append(f"README.md: the Released table has no row for {c}")
    for c in rows:
        if c not in rel:
            fails.append(f"README.md: the Released table lists {c}, which the release data does not")

    # 2. the current release
    m = re.search(r"verified on the current release, ([0-9.]+[0-9])", readme)
    if not m or m.group(1) != version:
        fails.append(f"README.md: 'verified on the current release, <v>' says "
                     f"{m.group(1) if m else 'nothing'}; VERSION is {version}")
    m = re.search(r"^> ## ([0-9]+\.[0-9]+\.[0-9]+):", readme, re.M)
    if not m or m.group(1) != version:
        fails.append(f"README.md: the first news heading is for {m.group(1) if m else 'no version'}; "
                     f"VERSION is {version}")

    # 3. the count in the heading
    m = re.search(r"^> ## .*Released: ([a-z-]+|\d+) configurations", readme, re.M)
    want = NUMBER_WORDS[len(rel)] if len(rel) < len(NUMBER_WORDS) else str(len(rel))
    if not m or m.group(1) not in (want, str(len(rel))):
        fails.append(f"README.md: the 'Released: <n> configurations' heading says "
                     f"{m.group(1) if m else 'nothing'}; the data has {len(rel)} ({want})")

    # 4. defect numbers
    total, reach = defect_counts(rel)
    m = re.search(r"holds (\d+) open records", readme)
    if not m or int(m.group(1)) != total:
        fails.append(f"README.md: 'holds <n> open records' says {m.group(1) if m else 'nothing'}; "
                     f"tools/defects.py counts {total}")
    m = re.search(r"The (\d+) that reach a released\s+(?:>\s*)?configuration", readme)
    if not m or int(m.group(1)) != reach:
        fails.append(f"README.md: 'The <n> that reach a released configuration' says "
                     f"{m.group(1) if m else 'nothing'}; tools/defects.py counts {reach}")
    m = re.search(r"(\d+) of them reach only", readme)
    if not m or int(m.group(1)) != total - reach:
        fails.append(f"README.md: '<n> of them reach only ...' says {m.group(1) if m else 'nothing'}; "
                     f"the data gives {total - reach}")

    # 5. released platforms
    plats = json.loads(read("data/platforms.json"))
    plats = plats.get("platforms", plats)
    for key, p in plats.items():
        if isinstance(p, dict) and p.get("status") == "released":
            name = re.split(r"\s*\(", p.get("name", key))[0].split(" / ")[0].strip()
            if name and name not in readme:
                fails.append(f"README.md: released platform '{name}' ({key}) is not named")

    # 6 and 7. stale phrases
    allowed_seen = set()
    short = [n for n in sizes if n < top]
    word = lambda n: NUMBER_WORDS[n]
    stops_short = []
    if len(short) >= 2:
        a, b = short[:-1], short[-1]
        stops_short = [
            ", ".join(word(n) for n in a) + " and " + word(b),
            ", ".join(str(n) for n in a) + " and " + str(b),
            ", ".join(f"{n}-" for n in a) + f" and {b}-node",
        ]
    texts = [(f, list(enumerate(read(f).splitlines(), 1))) for f in PUBLIC if (ROOT / f).exists()]
    texts += [(f, module_text(f)) for f in MODULE_TEXT if (ROOT / f).exists()]
    stale = STALE + [r for r in [attach_rule(rel)] if r]
    for f, lines in texts:
        for i, line in lines:
            hit = None
            for pat, why in stale:
                if re.search(pat, line, re.I):
                    hit = why
                    break
            if not hit:
                low = line.lower()
                for s in stops_short:
                    if s in low and str(top) not in low and word(top) not in low:
                        hit = f"lists the released cluster sizes and stops at {short[-1]}; {top} is released"
                        break
            if not hit:
                continue
            # a line that names a configuration the data does not release is
            # talking about that configuration (`32/disk/caw/mpath ... not released`)
            keys = re.findall(r"\b\d+/[a-z]+/[a-z]+/[a-z]+\b", line)
            if keys and any(k not in rel for k in keys):
                continue
            ok = [a for a in ALLOWED if a[0] == f and a[1] == line.strip()]
            if ok:
                allowed_seen.add((f, ok[0][1]))
                continue
            fails.append(f"{f}:{i}: {hit}: {line.strip()[:150]}")
    for f, text, _ in ALLOWED:
        if (f, text) not in allowed_seen:
            fails.append(f"tools/release_text_check.py: the exemption for {f} ('{text[:60]}...') "
                         f"matches no line any more; remove it")

    # 8. the largest released size is named where sizes are stated
    for f in SIZES_STATED_IN:
        t = read(f).lower()
        if not re.search(rf"\b{top}\b|\b{word(top)}\b", t):
            fails.append(f"{f}: states released cluster sizes and never names {top}")

    if args.list:
        print("released:", " ".join(rel))
        print("version:", version, "| open defects:", total, "| reaching a released configuration:", reach)
        print("files:", " ".join(f for f, _ in texts))
    for line in fails:
        print("FAIL", line)
    print(f"release_text_check: {len(fails)} failure(s) over {len(texts)} files, "
          f"{len(rel)} released configurations, version {version}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
