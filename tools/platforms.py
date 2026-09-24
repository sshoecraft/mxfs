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
    tools/platforms.py add debian13 --name "Debian 13" --status development --kernels 6.12.x \
                           --arch amd64
                                               a new platform (never released: verify it first)

`priority` orders the work within a status (1 first); the listing sorts by it.

A PLATFORM IS ALSO AN ARCHITECTURE. `arch` lists the CPU architectures the platform is claimed
on, by Debian name (amd64, arm64, armhf; the RPM names are x86_64, aarch64). The packages carry
compiled tools and the module is built per architecture, so a verification on one architecture
says nothing about another: `verified` holds one record per architecture, `verify` takes --arch
when a platform lists more than one, and `check` requires every listed architecture verified at
the release's version. `check` also refuses a released platform that lists an architecture
scripts/release.sh builds no packages for (PACKAGED_ARCHES).
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
ARCHES = ("amd64", "arm64", "armhf", "ppc64el", "s390x", "riscv64")
#: the architectures scripts/release.sh builds packages for
PACKAGED_ARCHES = ("amd64",)


def load() -> dict:
    with open(REGISTRY) as handle:
        data = json.load(handle)
    for key, entry in data["platforms"].items():
        if entry.get("status") not in STATUSES:
            sys.exit(f"platforms: {key} has status {entry.get('status')!r}; "
                     f"expected one of {list(STATUSES)}")
        # The registry before architectures: every package ever built was amd64, so a record
        # without `arch` was an amd64 claim, and a flat `verified` was an amd64 verification.
        # The next save writes the per-architecture shape.
        if "arch" not in entry:
            entry["arch"] = ["amd64"]
        if "version" in entry.get("verified", {}):
            entry["verified"] = {"amd64": entry["verified"]}
        bad = [a for a in entry["arch"] if a not in ARCHES]
        if not entry["arch"] or bad:
            sys.exit(f"platforms: {key} has arch {entry['arch']}; each must be one of {list(ARCHES)}")
    return data


def verified_text(entry: dict) -> str:
    """The version each architecture was verified at: one version, or arch=version pairs."""
    got = {a: entry.get("verified", {}).get(a, {}).get("version", "-") for a in entry["arch"]}
    if len(set(got.values())) == 1:
        return next(iter(got.values()))
    return ",".join(f"{a}={v}" for a, v in got.items())


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
    rows = sorted(data["platforms"].items(),
                  key=lambda kv: (order[kv[1]["status"]], kv[1].get("priority", 999), kv[0]))
    for key, entry in rows:
        priority = entry.get("priority", "-")
        print("%-11s %-12s p%-3s %-12s verified %-8s %s"
              % (key, entry["status"], priority, ",".join(entry["arch"]), verified_text(entry),
                 entry["name"]))
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
    arch = args.arch
    if arch is None:
        if len(entry["arch"]) > 1:
            sys.exit(f"platforms: {args.key} lists {entry['arch']}; say which one was verified "
                     f"with --arch")
        arch = entry["arch"][0]
    if arch not in entry["arch"]:
        sys.exit(f"platforms: {args.key} does not list {arch} (it lists {entry['arch']})")
    evidence = args.evidence.strip()
    if not evidence:
        sys.exit("platforms: verify needs --evidence naming what was measured")
    for path in evidence.replace(",", " ").split():
        if not (ROOT / path).exists():
            sys.exit(f"platforms: evidence {path} does not exist under {ROOT}")
    entry.setdefault("verified", {})[arch] = {"version": args.version,
                                              "date": date.today().isoformat(),
                                              "evidence": evidence}
    save(data)
    print(f"recorded: {args.key} {arch} verified at {args.version} ({evidence})")
    return 0


SETTABLE = ("name", "build_check", "verify_env", "verify_tests", "notes")


def apply_fields(entry: dict, args) -> list:
    """Write every field given on the command line into entry; return their names."""
    changed = []
    if args.priority is not None:
        entry["priority"] = args.priority
        changed.append("priority")
    for field in ("kernels", "packages", "arch"):
        if getattr(args, field) is not None:
            entry[field] = [v.strip() for v in getattr(args, field).split(",") if v.strip()]
            changed.append(field)
    if "arch" in changed:
        bad = [a for a in entry["arch"] if a not in ARCHES]
        if not entry["arch"] or bad:
            sys.exit(f"platforms: arch {entry['arch']}; each must be one of {list(ARCHES)}")
        # a verification of an architecture the platform no longer lists claims nothing
        for gone in [a for a in entry.get("verified", {}) if a not in entry["arch"]]:
            del entry["verified"][gone]
    for field in SETTABLE:
        value = getattr(args, field)
        if value is not None:
            entry[field] = value
            changed.append(field)
    return changed


def cmd_set(data: dict, args) -> int:
    """Change a platform's status or fields.

    A status change does not carry a verification with it: a platform promoted to released
    still fails `check` until `verify` records the release's exact version there.
    """
    entry = find(data, args.key)
    changed = apply_fields(entry, args)
    if args.status:
        if args.status == "released" and not entry.get("build_check"):
            sys.exit(f"platforms: {args.key} has no build_check; a released platform needs one")
        entry["status"] = args.status
        changed.append("status")
    if not changed:
        sys.exit("platforms: set needs --status or at least one field to change")
    save(data)
    print(f"set: {args.key} {', '.join(changed)}")
    return 0


def cmd_add(data: dict, args) -> int:
    """A new platform, as development or planned: a release claim comes only through
    `set --status released` on a platform that already exists, then `verify`."""
    if args.key in data["platforms"]:
        sys.exit(f"platforms: {args.key} already exists; use set")
    if not args.name:
        sys.exit("platforms: add needs --name")
    if not args.arch:
        sys.exit("platforms: add needs --arch (e.g. amd64, or amd64,arm64)")
    if args.status == "released":
        sys.exit("platforms: a platform is added as development or planned; release it with "
                 "set --status released once it has a build_check, then verify")
    entry = {"name": args.name, "status": args.status or "planned"}
    apply_fields(entry, args)
    data["platforms"][args.key] = entry
    save(data)
    print(f"added: {args.key} ({entry['status']})")
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
        for arch in entry["arch"]:
            if arch not in PACKAGED_ARCHES:
                failing.append(f"{key} ({entry['name']}) {arch}: scripts/release.sh builds no "
                               f"{arch} packages")
                continue
            have = entry.get("verified", {}).get(arch, {}).get("version")
            if have != args.version:
                failing.append(f"{key} ({entry['name']}) {arch}: verified at {have or 'never'}, "
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
    verify.add_argument("--arch", help="the architecture verified (needed when the platform "
                                       "lists more than one)")
    verify.add_argument("--evidence", required=True,
                        help="evidence path(s) under the repo, space or comma separated")
    check = subs.add_parser("check", help="exit 1 unless every released platform is verified")
    check.add_argument("--version", required=True)
    for command, text in (("set", "change a platform's status or text fields"),
                          ("add", "a new platform, as development or planned")):
        sub = subs.add_parser(command, help=text)
        sub.add_argument("key")
        sub.add_argument("--status", choices=STATUSES)
        sub.add_argument("--priority", type=int)
        sub.add_argument("--kernels", help="comma separated")
        sub.add_argument("--packages", help="comma separated")
        sub.add_argument("--arch", help="comma separated: " + ", ".join(ARCHES))
        for field in SETTABLE:
            sub.add_argument("--" + field.replace("_", "-"), dest=field)
    args = parser.parse_args()
    data = load()
    return {"show": cmd_show, "build-checks": cmd_build_checks, "verify": cmd_verify,
            "check": cmd_check, "set": cmd_set, "add": cmd_add}.get(args.command, cmd_list)(data, args)


if __name__ == "__main__":
    sys.exit(main())
