#!/usr/bin/env python3
"""One-time migration of the files that name a rig condition code but have no writer tool.

    scripts/migrate_configuration_keys.py            show what would change, write nothing
    scripts/migrate_configuration_keys.py --write    apply it

Until 0.90.37 the rig keyed what it measured by condition codes -- tcp, cawd, cawp, caw --
which fused the DLM with how the LUN is attached. A configuration now names both:
<nodes>/<class>/<method>/<attach> (tools/configuration.py). The board and the defect queue
migrate through their own writers (`tools/criteria.py migrate-keys`, `tools/defects.py
migrate-config`); this handles the rest:

    bench.json             each entry's `dlm` becomes `configuration` (with its node count),
                           an `fs` label that was a code becomes the configuration's slug, and
                           a fio_perf/fio_vs_xfs label's `<N>n_<code>` becomes the slug
    .xfs_fio_baseline.<code>[.<rig>].json and .raw_fio_ceiling.<code>[.<rig>].json
                           renamed to <class-method-attach>, one file per code as before
    .cluster_marker.json, .last_run.json
                           `dlm` becomes `configuration`

Evidence logs are history and keep their names. Refuses to run while a run.sh holds the run
lock, because run.sh rewrites the marker and bench.json as it goes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import configuration  # noqa: E402

RUNLOCK = Path("/tmp/mxfs_run.lock")
CODES = tuple(sorted(configuration.RETIRED, key=len, reverse=True))
LABEL = re.compile(r"^(fio_perf|fio_vs_xfs)_(\d+)n_(%s|xfs)_(\d+)$" % "|".join(CODES))
YARDSTICK = re.compile(r"^\.(xfs_fio_baseline|raw_fio_ceiling)\.(%s)((?:\.[A-Za-z0-9_-]+)?)\.json$"
                       % "|".join(CODES))


def lock_held() -> str:
    try:
        pid = RUNLOCK.read_text().split()[0]
    except (OSError, IndexError):
        return ""
    try:
        if Path("/proc/%s/comm" % pid).read_text().strip() == "run.sh":
            return pid
    except OSError:
        pass
    return ""


def key_for(nodes, code: str) -> str:
    code = str(code).lower()
    if code == "xfs":
        return "1/xfs"
    return configuration.translate_retired("%d/%s" % (int(nodes), code))


def save_json(path: Path, data) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def migrate_bench(write: bool) -> None:
    path = ROOT / "bench.json"
    data = json.loads(path.read_text())
    out, entries, relabelled = {}, 0, 0
    for label, entry in data.items():
        if isinstance(entry, dict) and str(entry.get("dlm", "")).lower() in CODES + ("xfs",):
            if "nodes" not in entry:
                sys.exit("bench.json: %s names dlm=%s but no node count" % (label, entry["dlm"]))
            key = key_for(entry["nodes"], entry["dlm"])
            rebuilt = {}
            for field, value in entry.items():
                if field == "dlm":
                    rebuilt["configuration"] = key
                elif field == "fs" and str(value).lower() in CODES:
                    rebuilt["fs"] = key.replace("/", "-")
                else:
                    rebuilt[field] = value
            entry = rebuilt
            entries += 1
            match = LABEL.match(label)
            if match:
                label = "%s_%s_%s" % (match.group(1), key.replace("/", "-"), match.group(4))
                relabelled += 1
        if label in out:
            sys.exit("bench.json: two entries land on the label %s" % label)
        out[label] = entry
    print("bench.json: %d of %d entries carry a configuration; %d labels renamed"
          % (entries, len(data), relabelled))
    if write:
        save_json(path, out)


def migrate_yardsticks(write: bool) -> None:
    for path in sorted(ROOT.glob(".*.json")):
        match = YARDSTICK.match(path.name)
        if not match:
            continue
        shape = configuration.RETIRED[match.group(2)].replace("/", "-")
        target = path.with_name(".%s.%s%s.json" % (match.group(1), shape, match.group(3)))
        if target.exists():
            sys.exit("%s: %s already exists; nothing renamed" % (path.name, target.name))
        print("%s -> %s" % (path.name, target.name))
        if write:
            os.replace(path, target)


def migrate_state(name: str, write: bool) -> None:
    path = ROOT / name
    if not path.is_file():
        print("%s: absent" % name)
        return
    data = json.loads(path.read_text())
    if "configuration" in data:
        print("%s: already migrated" % name)
        return
    if "dlm" not in data:
        print("%s: no dlm field" % name)
        return
    key = key_for(data.get("nodes", 1), data["dlm"])
    rebuilt = {("configuration" if k == "dlm" else k): (key if k == "dlm" else v)
               for k, v in data.items()}
    print("%s: dlm=%s -> configuration=%s" % (name, data["dlm"], key))
    if write:
        save_json(path, rebuilt)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="apply the migration")
    args = parser.parse_args()
    holder = lock_held()
    if holder:
        sys.exit("run.sh %s holds %s; migrate when no run is in flight" % (holder, RUNLOCK))
    migrate_bench(args.write)
    migrate_yardsticks(args.write)
    for name in (".cluster_marker.json", ".last_run.json"):
        migrate_state(name, args.write)
    if not args.write:
        print("dry run: nothing written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
