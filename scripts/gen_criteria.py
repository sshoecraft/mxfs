#!/usr/bin/env python3
# gen_criteria.py — (re)generate /src/mxfs/criteria.json, the single source of
# truth for the test matrix + per-condition status.
#
# Bootstraps from the per-category manifests (tests/{suite,tooling,caw,tcp}/
# manifest) and folds in any existing per-category results files
# (.{cat}_results.json) as runs keyed by "<nodes>/<dlm>".
#
# After bootstrap, criteria.json is authoritative and updated in place by
# run_one (per-test status). Re-running this regenerates the MATRIX from the
# manifests while preserving existing runs already in criteria.json.

import json, os

REPO = os.environ.get("MXFS_REPO", "/src/mxfs")
CATS = [("suite", "any"), ("tooling", "any"), ("caw", "caw"), ("tcp", "tcp")]
OUT = os.path.join(REPO, "criteria.json")

# Single-node-only tests: applicable ONLY at N=1 (max_nodes=1). All tooling is
# single-node device ops; these suite tests are single-node correctness. Tests
# not listed (and not tooling) default to max_nodes=0 = unbounded.
SINGLE_NODE_SUITE = {"posix_single", "fsx", "fio_verify",
                     "integrity_filetypes", "fault_enospc"}


def default_max_nodes(category, name):
    if category == "tooling":
        return 1
    if name in SINGLE_NODE_SUITE:
        return 1
    return 0  # unbounded


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


# preserve runs already present in an existing criteria.json
existing = load_json(OUT)
prior_runs = {}
prior_max = {}
for cat in existing.get("categories", []):
    for t in cat.get("tests", []):
        prior_runs[t["name"]] = t.get("runs", {})
        if "max_nodes" in t:
            prior_max[t["name"]] = t["max_nodes"]

out = {"categories": []}
for cat, transport in CATS:
    man = os.path.join(REPO, "tests", cat, "manifest")
    legacy = load_json(os.path.join(REPO, f".{cat}_results.json"))
    tests = []
    if os.path.exists(man):
        with open(man) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                p = line.split()
                if len(p) < 2:
                    continue
                group, name = p[0], p[1]
                coord = p[2] if len(p) > 2 else "none"
                minn = int(p[3]) if len(p) > 3 and p[3].isdigit() else 1
                # BUDGET_S (RULE 0): per-test time budget in seconds, used by
                # run.sh both as the hard timeout and as the elapsed_s>budget_s
                # PASS->FAIL gate. Missing/non-numeric -> 300 (prior blanket
                # default), so an un-annotated manifest line still works.
                budget = int(p[4]) if len(p) > 4 and p[4].isdigit() else 300
                # SCALE (optional 6th column): "linear" means BUDGET_S is a
                # PER-NODE seconds coefficient (actual budget = BUDGET_S * N);
                # default "flat" means BUDGET_S applies as-is regardless of N.
                scale = p[5] if len(p) > 5 and p[5] in ("flat", "linear") else "flat"
                runs = dict(prior_runs.get(name, {}))           # keep already-recorded runs
                r = legacy.get(name)                            # fold legacy per-cat result
                if r and r.get("status") in ("PASS", "FAIL", "SKIP"):
                    cond = f"{r.get('nodes', '?')}/{r.get('dlm', 'tcp')}"
                    runs.setdefault(cond, {
                        "status": r["status"],
                        "measured": r.get("measured", ""),
                        "reason": r.get("reason", ""),
                        "iso": r.get("last_run_iso", ""),
                    })
                maxn = prior_max.get(name, default_max_nodes(cat, name))
                tests.append({"name": name, "group": group, "coord": coord,
                              "min_nodes": minn, "max_nodes": maxn,
                              "budget_s": budget, "budget_scale": scale, "runs": runs})
    out["categories"].append({"category": cat, "transport": transport, "tests": tests})

with open(OUT, "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")

n = sum(len(c["tests"]) for c in out["categories"])
print(f"wrote {OUT}: {len(out['categories'])} categories, {n} tests")
