#!/usr/bin/env python3
"""The platforms MXFS is released for, in development for, or planned for.

THE ONE WAY IN OR OUT of `data/platforms.json`, as tools/defects.py is for the defect queue.

A PLATFORM IS A RELEASE CLAIM, NOT A LIST OF HOPES. `status` is one of:

    released     a release claims it. Every release must pass the platform's build_check and
                 record a verification of that exact version on the platform's verify_env,
                 with the evidence path, before scripts/release.sh will publish.
    development  worked on, never claimed.
    planned      not started.

0.89.77 shipped a .deb that did not build on Proxmox VE 9 -- the product's target -- because the
only gate in the release path was the development rig, which runs a different kernel. This file
is what makes the target a gate.

    tools/platforms.py                         the platforms, one line each
    tools/platforms.py show pve9               one platform in full
    tools/platforms.py build-checks            print each released platform's build_check command
    tools/platforms.py verify pve9 --version 0.89.79 --evidence tests/evidence/<dir>/
                                               record that this version passed verify_tests there
    tools/platforms.py check --version 0.89.79 exit 1 unless every released platform was
                                               verified at exactly that version
    tools/platforms.py set ubuntu2404 --status released --verify-env "..."
                                               change a platform's status or its text fields
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "data" / "platforms.json"
STATUSES = ("released", "development", "planned")


def load() -> dict:
    with open(REGISTRY) as handle:
        data = json.load(handle)
    for key, entry in data["platforms"].items():
        if entry.get("status") not in STATUSES:
            sys.exit(f"platforms: {key} has status {entry.get('status')!r}; "
                     f"expected one of {list(STATUSES)}")
    return data


def save(data: dict) -> None:
    temporary = REGISTRY.with_suffix(".json.tmp")
    with open(temporary, "w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, REGISTRY)


def find(data: dict, key: str) -> dict:
    if key not in data["platforms"]:
        sys.exit(f"platforms: no platform {key!r}; known: {', '.join(data['platforms'])}")
    return data["platforms"][key]


def cmd_list(data: dict, args) -> int:
    order = {status: rank for rank, status in enumerate(STATUSES)}
    rows = sorted(data["platforms"].items(), key=lambda kv: (order[kv[1]["status"]], kv[0]))
    for key, entry in rows:
        verified = entry.get("verified", {}).get("version", "-")
        print("%-11s %-12s verified %-8s %s" % (key, entry["status"], verified, entry["name"]))
    return 0


def cmd_show(data: dict, args) -> int:
    entry = find(data, args.key)
    print(args.key)
    for field, value in entry.items():
        print("  %-13s %s" % (field, json.dumps(value) if not isinstance(value, str) else value))
    return 0


def cmd_build_checks(data: dict, args) -> int:
    for key, entry in data["platforms"].items():
        if entry["status"] == "released":
            if not entry.get("build_check"):
                sys.exit(f"platforms: released platform {key} has no build_check")
            print(entry["build_check"])
    return 0


def cmd_verify(data: dict, args) -> int:
    entry = find(data, args.key)
    evidence = args.evidence.strip()
    if not evidence:
        sys.exit("platforms: verify needs --evidence naming what was measured")
    for path in evidence.replace(",", " ").split():
        if not (ROOT / path).exists():
            sys.exit(f"platforms: evidence {path} does not exist under {ROOT}")
    entry["verified"] = {"version": args.version, "date": date.today().isoformat(),
                         "evidence": evidence}
    save(data)
    print(f"recorded: {args.key} verified at {args.version} ({evidence})")
    return 0


SETTABLE = ("name", "build_check", "verify_env", "verify_tests", "notes")


def cmd_set(data: dict, args) -> int:
    """Change a platform's status or text fields.

    A status change does not carry a verification with it: a platform promoted to released
    still fails `check` until `verify` records the release's exact version there.
    """
    entry = find(data, args.key)
    changed = []
    if args.status:
        if args.status not in STATUSES:
            sys.exit(f"platforms: status must be one of {list(STATUSES)}")
        if args.status == "released" and not (args.build_check or entry.get("build_check")):
            sys.exit(f"platforms: {args.key} has no build_check; a released platform needs one")
        entry["status"] = args.status
        changed.append("status")
    for field in SETTABLE:
        value = getattr(args, field)
        if value is not None:
            entry[field] = value
            changed.append(field)
    if not changed:
        sys.exit("platforms: set needs --status or at least one field to change")
    save(data)
    print(f"set: {args.key} {', '.join(changed)}")
    return 0


def cmd_check(data: dict, args) -> int:
    """Exit 1 unless every released platform was verified at exactly this version.

    A verification of an earlier version does not carry over: 0.89.77 and 0.89.78 differed in
    three places that each broke Proxmox.
    """
    failing = []
    for key, entry in data["platforms"].items():
        if entry["status"] != "released":
            continue
        have = entry.get("verified", {}).get("version")
        if have != args.version:
            failing.append(f"{key} ({entry['name']}): verified at {have or 'never'}, "
                           f"not {args.version}")
    if failing:
        print("PLATFORMS: a release claims these, and this version was not verified on them:")
        for line in failing:
            print("  " + line)
        return 1
    released = [k for k, e in data["platforms"].items() if e["status"] == "released"]
    print(f"platforms: every released platform verified at {args.version}: {', '.join(released)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="the platforms MXFS is released for",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("    tools/platforms.py")[0].strip())
    subs = parser.add_subparsers(dest="command")
    show = subs.add_parser("show", help="one platform in full")
    show.add_argument("key")
    subs.add_parser("build-checks", help="each released platform's build_check command")
    verify = subs.add_parser("verify", help="record a passed verification")
    verify.add_argument("key")
    verify.add_argument("--version", required=True)
    verify.add_argument("--evidence", required=True,
                        help="evidence path(s) under the repo, space or comma separated")
    check = subs.add_parser("check", help="exit 1 unless every released platform is verified")
    check.add_argument("--version", required=True)
    setter = subs.add_parser("set", help="change a platform's status or text fields")
    setter.add_argument("key")
    setter.add_argument("--status", choices=STATUSES)
    for field in SETTABLE:
        setter.add_argument("--" + field.replace("_", "-"), dest=field)
    args = parser.parse_args()
    data = load()
    return {"show": cmd_show, "build-checks": cmd_build_checks, "verify": cmd_verify,
            "check": cmd_check, "set": cmd_set}.get(args.command, cmd_list)(data, args)


if __name__ == "__main__":
    sys.exit(main())
