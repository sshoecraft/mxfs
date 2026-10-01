#!/usr/bin/env python3
"""What a configuration is, and the only thing that parses one.

    tools/configuration.py parse 8/net/mesh/direct     the normalised key, or why it is not one
    tools/configuration.py shell 8/net/mesh/direct     CFG_* assignments for `eval` in a harness
    tools/configuration.py slug  8/net/mesh/direct     the file-name form: 8-net-mesh-direct
    tools/configuration.py get   8/net/mesh/direct transport   one field, unquoted (see FIELDS)
    tools/configuration.py matches <pattern> <key>     exit 0 iff the pattern covers the key
    tools/configuration.py release-matrix [--nodes N]  what a release must have green
    tools/configuration.py list [--nodes N]            every implemented configuration
    tools/configuration.py selftest

A CONFIGURATION IS <nodes>/<class>/<method>/<attach>: how many nodes, where the DLM keeps lock
state (net or disk), which DLM implementation, and how the shared LUN reaches each node. The
definitions live in `data/configurations.json`; the design is `docs/attachment-methods.md`.

ONE PARSER. The rig used to name what it tested with condition codes -- tcp, cawd, cawp, caw --
each fusing the lock manager with the attachment, and every tool parsed them its own way. Exact
string matches then hid records: a defect tagged `caw` never appeared in a `cawd` view, and the
board's own configuration list had no cawd or cawp column at all. Every tool now asks this file.

A RETIRED CODE IS REFUSED, NEVER TRANSLATED. `8/cawd` names its replacement in the error and stops.
Accepting it quietly would keep the old vocabulary alive in every script that still types it, and
the migrations are the only code that is allowed to read one.

The native-XFS baseline is not a configuration of MXFS -- no module, no DLM, no cluster -- and is
spelled `1/xfs`.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFINITIONS = ROOT / "data" / "configurations.json"

BASELINE = "xfs"


class ConfigurationError(ValueError):
    pass


def definitions() -> dict:
    with DEFINITIONS.open() as handle:
        return json.load(handle)


DEFS = definitions()
CLASSES = tuple(DEFS["classes"])
METHODS = DEFS["methods"]
ATTACHES = DEFS["attaches"]
RETIRED = {k: v for k, v in DEFS["retired_keys"].items() if k != "_"}


@dataclass(frozen=True)
class Configuration:
    nodes: int
    cls: str
    method: str
    attach: str

    @property
    def baseline(self) -> bool:
        return self.cls == BASELINE

    @property
    def key(self) -> str:
        if self.baseline:
            return "%d/%s" % (self.nodes, BASELINE)
        return "%d/%s/%s/%s" % (self.nodes, self.cls, self.method, self.attach)

    @property
    def slug(self) -> str:
        """The key with its slashes turned into dashes, for file names and labels."""
        return self.key.replace("/", "-")

    @property
    def shape(self) -> str:
        """The configuration without its node count, dashed: net-mesh-direct, or xfs.

        What a per-rig yardstick is keyed by: a native-XFS baseline or a raw device ceiling
        describes the attachment and the DLM, and holds its own per-node-count entries inside.
        """
        return self.slug.split("-", 1)[1]

    @property
    def transport(self) -> str:
        """What the module and node prep consume: tcp, caw, or xfs for the baseline."""
        if self.baseline:
            return BASELINE
        return METHODS["%s/%s" % (self.cls, self.method)]["transport"]

    @property
    def device(self) -> str:
        """The rig's default guest device for this attachment."""
        if self.baseline:
            return DEFS["baseline"]["device"]
        return ATTACHES[self.attach]["device"]

    @property
    def rig_mode(self) -> str:
        return "" if self.baseline else ATTACHES[self.attach]["rig_mode"]

    def __str__(self) -> str:
        return self.key


def retired_hint(text: str) -> str:
    """The replacement for a retired condition code, as an error sentence, or empty."""
    match = re.fullmatch(r"\s*(\d+)\s*/\s*([A-Za-z]+)\s*", str(text))
    if match and match.group(2).lower() in RETIRED:
        return ("%s is a retired condition code; it is now %s/%s"
                % (text.strip(), match.group(1), RETIRED[match.group(2).lower()]))
    if str(text).strip().lower() in RETIRED:
        return ("%s is a retired condition code; it is now <nodes>/%s"
                % (text.strip(), RETIRED[str(text).strip().lower()]))
    return ""


def parse(text: str) -> Configuration:
    """`8/net/mesh/direct` or `1/xfs`, normalised. Anything else raises ConfigurationError."""
    raw = str(text).strip()
    hint = retired_hint(raw)
    if hint:
        raise ConfigurationError(hint)
    fields = [f.strip().lower() for f in raw.split("/")]
    if not fields[0].isdigit():
        raise ConfigurationError("%r: a configuration starts with a node count, "
                                 "e.g. 8/net/mesh/direct" % raw)
    nodes = int(fields[0])
    if nodes < 1:
        raise ConfigurationError("%r: node count must be at least 1" % raw)
    if fields[1:] == [BASELINE]:
        if nodes != 1:
            raise ConfigurationError("%r: the native-XFS baseline is single-node; it is 1/xfs" % raw)
        return Configuration(1, BASELINE, "", "")
    if len(fields) != 4:
        raise ConfigurationError("%r: wanted <nodes>/<class>/<method>/<attach>, "
                                 "e.g. 8/net/mesh/direct" % raw)
    nodes_text, cls, method, attach = fields
    if cls not in CLASSES:
        raise ConfigurationError("%r: class %r; expected one of %s" % (raw, cls, list(CLASSES)))
    pair = "%s/%s" % (cls, method)
    if pair not in METHODS:
        known = [m.split("/")[1] for m in METHODS if m.startswith(cls + "/")]
        raise ConfigurationError("%r: %s has no method %r; known: %s" % (raw, cls, method, known))
    if not METHODS[pair].get("implemented"):
        raise ConfigurationError("%r: %s is named in the design but not implemented" % (raw, pair))
    if attach not in ATTACHES:
        raise ConfigurationError("%r: attach %r; expected one of %s" % (raw, attach, list(ATTACHES)))
    if not ATTACHES[attach].get("implemented"):
        raise ConfigurationError("%r: attach %r is named in the design but not implemented"
                                 % (raw, attach))
    return Configuration(nodes, cls, method, attach)


def check_pattern(text: str) -> str:
    """A pattern over class/method/attach: `any`, `xfs`, `net`, `disk/caw`, `disk/caw/*`, ...

    Criteria say which configurations a row applies to with one, and defect records say which
    configurations their evidence reaches. Fields may be `*`; missing trailing fields are `*`.
    A value must be a known name (implemented or not) so a typo cannot silently match nothing.
    """
    raw = str(text).strip().lower()
    if raw in ("any", BASELINE):
        return raw
    hint = retired_hint(raw)
    if hint:
        raise ConfigurationError(hint)
    fields = raw.split("/")
    if len(fields) > 3:
        raise ConfigurationError("%r: a pattern is at most class/method/attach" % text)
    fields += ["*"] * (3 - len(fields))
    cls, method, attach = fields
    if cls != "*" and cls not in CLASSES:
        raise ConfigurationError("%r: class %r; expected one of %s" % (text, cls, list(CLASSES)))
    if method != "*":
        if cls == "*":
            raise ConfigurationError("%r: a method needs its class, e.g. disk/%s" % (text, method))
        if "%s/%s" % (cls, method) not in METHODS:
            raise ConfigurationError("%r: %s has no method %r" % (text, cls, method))
    if attach != "*" and attach not in ATTACHES:
        raise ConfigurationError("%r: attach %r; expected one of %s" % (text, attach, list(ATTACHES)))
    return "/".join(fields)


def pattern_fields(pattern: str) -> tuple:
    pattern = check_pattern(pattern)
    if pattern == "any":
        return ("*", "*", "*")
    if pattern == BASELINE:
        return (BASELINE, "", "")
    return tuple(pattern.split("/"))


def matches(pattern: str, config: Configuration | str) -> bool:
    """Does the pattern cover this configuration? `any` covers everything, the baseline too."""
    if isinstance(config, str):
        config = parse(config)
    fields = pattern_fields(pattern)
    if fields == ("*", "*", "*"):
        return True
    if fields[0] == BASELINE or config.baseline:
        return fields[0] == BASELINE and config.baseline
    return all(want in ("*", have)
               for want, have in zip(fields, (config.cls, config.method, config.attach)))


def overlaps(pattern: str, selector: tuple) -> bool:
    """Could a record reaching `pattern` block some configuration the `selector` names?

    A selector is what a view asks about: (class, method, attach) with None for a field the view
    left open -- `defects.py 8` asks about every configuration at 8 nodes, `8/disk` about every
    disk one. A record blocks the view if some configuration satisfies both.
    """
    fields = pattern_fields(pattern)
    if selector[0] == BASELINE:
        return fields == ("*", "*", "*") or fields[0] == BASELINE
    if fields[0] == BASELINE:
        #: Only a view that left the class open (`defects.py 1`) takes in the baseline.
        return selector[0] is None
    return all(want == "*" or have is None or want == have
               for want, have in zip(fields, selector))


def parse_selector(text: str) -> tuple:
    """`8`, `8/disk`, `8/disk/caw`, `8/disk/caw/direct` or `1/xfs` -> (nodes, (cls, method, attach)).

    Views may leave trailing fields open; a board cell may not (that takes `parse`).
    """
    raw = str(text).strip()
    hint = retired_hint(raw)
    if hint:
        raise ConfigurationError(hint)
    fields = [f.strip().lower() for f in raw.split("/")]
    if not fields[0].isdigit() or int(fields[0]) < 1:
        raise ConfigurationError("%r: a view starts with a node count, e.g. 8 or 8/disk/caw" % raw)
    nodes = int(fields[0])
    if fields[1:] == [BASELINE]:
        return nodes, (BASELINE, None, None)
    rest = fields[1:]
    if len(rest) > 3:
        raise ConfigurationError("%r: at most <nodes>/<class>/<method>/<attach>" % raw)
    if rest:
        check_pattern("/".join(rest))
    rest += [None] * (3 - len(rest))
    return nodes, tuple(rest)


def selector_label(nodes: int, selector: tuple) -> str:
    named = [f for f in selector if f]
    return "%d/%s" % (nodes, "/".join(named)) if named else "%d-node" % nodes


def implemented(nodes: int | None = None) -> list:
    """Every implemented configuration at the laddered node counts (or at one count)."""
    counts = [nodes] if nodes else DEFS["ladder_nodes"]
    out = []
    for count in counts:
        for pair, method in METHODS.items():
            if not method.get("implemented"):
                continue
            cls, name = pair.split("/")
            for attach, spec in ATTACHES.items():
                if spec.get("implemented"):
                    out.append(Configuration(count, cls, name, attach))
    return out


def release_matrix(nodes: int | None = None) -> list:
    matrix = [parse(k) for k in DEFS["release_matrix"]]
    return [c for c in matrix if nodes is None or c.nodes == nodes]


def board_configurations() -> list:
    """The columns the board declares: the baseline, then every implemented configuration."""
    return [DEFS["baseline"]["key"]] + [c.key for c in implemented()]


def translate_retired(key: str) -> str:
    """`8/cawd` -> `8/disk/caw/direct`, `1/xfs` unchanged. FOR THE MIGRATIONS ONLY."""
    match = re.fullmatch(r"(\d+)/([A-Za-z]+)", key)
    if not match:
        return key
    old = match.group(2).lower()
    if old == BASELINE:
        return key
    if old not in RETIRED:
        raise ConfigurationError("%r: not a retired condition code" % key)
    return "%s/%s" % (match.group(1), RETIRED[old])


#: What `get` answers, for shell code that needs one value rather than an `eval`.
FIELDS = ("key", "slug", "shape", "nodes", "cls", "method", "attach", "transport", "device",
          "rig_mode")


def shell(config: Configuration) -> str:
    values = {
        "CFG_KEY": config.key,
        "CFG_SLUG": config.slug,
        "CFG_SHAPE": config.shape,
        "CFG_NODES": config.nodes,
        "CFG_CLASS": "" if config.baseline else config.cls,
        "CFG_METHOD": config.method,
        "CFG_ATTACH": config.attach,
        "CFG_BASELINE": 1 if config.baseline else 0,
        "CFG_TRANSPORT": config.transport,
        "CFG_RIG_MODE": config.rig_mode,
        "CFG_DEV_DEFAULT": config.device,
    }
    return "\n".join("%s=%s" % (k, shlex.quote(str(v))) for k, v in values.items())


def selftest() -> int:
    failures = []

    def expect(label, got, want):
        if got != want:
            failures.append("%s: got %r, want %r" % (label, got, want))

    def refuses(label, func, *args):
        try:
            func(*args)
        except ConfigurationError as exc:
            return str(exc)
        failures.append("%s: accepted %r" % (label, args))
        return ""

    for config in implemented():
        again = parse(config.key)
        expect("round trip " + config.key, again, config)
        expect("slug " + config.key, parse(again.slug.replace("-", "/")), config)
    expect("baseline", parse("1/xfs").key, "1/xfs")
    expect("case/space", parse(" 8/NET/Mesh/direct ").key, "8/net/mesh/direct")
    expect("transport mesh", parse("2/net/mesh/direct").transport, "tcp")
    expect("transport caw", parse("2/disk/caw/mpath").transport, "caw")
    expect("transport xfs", parse("1/xfs").transport, "xfs")
    for old, new in RETIRED.items():
        text = refuses("retired " + old, parse, "8/" + old)
        if new not in text:
            failures.append("retired %s: error does not name %s: %r" % (old, new, text))
    refuses("xfs at 2", parse, "2/xfs")
    refuses("unimplemented method", parse, "8/net/server/direct")
    refuses("unimplemented attach", parse, "2/net/mesh/drbd")
    refuses("three fields", parse, "8/net/mesh")
    refuses("zero nodes", parse, "0/net/mesh/direct")
    refuses("bad pattern", check_pattern, "disk/cas")
    refuses("method without class", check_pattern, "*/caw")

    mesh, caw_mp, base = parse("8/net/mesh/direct"), parse("8/disk/caw/mpath"), parse("1/xfs")
    expect("any mesh", matches("any", mesh), True)
    expect("any baseline", matches("any", base), True)
    expect("class", matches("net", mesh), True)
    expect("class miss", matches("disk", mesh), False)
    expect("method", matches("disk/caw", caw_mp), True)
    expect("attach star", matches("disk/caw/*", caw_mp), True)
    expect("attach miss", matches("disk/caw/direct", caw_mp), False)
    expect("class vs baseline", matches("net", base), False)
    expect("xfs vs baseline", matches("xfs", base), True)
    expect("xfs vs mesh", matches("xfs", mesh), False)

    expect("selector bare", parse_selector("8"), (8, (None, None, None)))
    expect("selector class", parse_selector("8/disk"), (8, ("disk", None, None)))
    expect("overlap bare", overlaps("disk/caw/*", (None, None, None)), True)
    expect("overlap class", overlaps("disk/caw/*", ("disk", None, None)), True)
    expect("overlap miss", overlaps("disk/caw/*", ("net", None, None)), False)
    expect("overlap attach", overlaps("disk/caw/mpath", ("disk", "caw", "direct")), False)
    expect("overlap any", overlaps("*/*/*", ("net", "mesh", "direct")), True)
    expect("overlap xfs view", overlaps("disk/caw/*", (BASELINE, None, None)), False)
    expect("overlap xfs record", overlaps("xfs", (BASELINE, None, None)), True)
    expect("overlap xfs record, net view", overlaps("xfs", ("net", None, None)), False)
    expect("translate", translate_retired("32/caw"), "32/disk/caw/mpath")
    expect("translate xfs", translate_retired("1/xfs"), "1/xfs")
    expect("shape", parse("8/net/mesh/direct").shape, "net-mesh-direct")
    expect("shape xfs", parse("1/xfs").shape, "xfs")
    expect("release matrix", len(release_matrix()), 6)
    expect("release at 8", [c.key for c in release_matrix(8)],
           ["8/net/mesh/direct", "8/disk/caw/direct"])

    for line in failures:
        print("FAIL", line)
    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subs = parser.add_subparsers(dest="command", required=True)
    for name in ("parse", "shell", "slug"):
        subs.add_parser(name).add_argument("configuration")
    get = subs.add_parser("get")
    get.add_argument("configuration")
    get.add_argument("field", choices=FIELDS)
    match = subs.add_parser("matches")
    match.add_argument("pattern")
    match.add_argument("configuration")
    for name in ("release-matrix", "list"):
        subs.add_parser(name).add_argument("--nodes", type=int)
    subs.add_parser("selftest")
    args = parser.parse_args()

    try:
        if args.command == "parse":
            print(parse(args.configuration).key)
        elif args.command == "shell":
            print(shell(parse(args.configuration)))
        elif args.command == "slug":
            print(parse(args.configuration).slug)
        elif args.command == "get":
            print(getattr(parse(args.configuration), args.field))
        elif args.command == "matches":
            return 0 if matches(args.pattern, args.configuration) else 1
        elif args.command == "release-matrix":
            for config in release_matrix(args.nodes):
                print(config.key)
        elif args.command == "list":
            for config in implemented(args.nodes):
                print(config.key)
        elif args.command == "selftest":
            return selftest()
    except ConfigurationError as exc:
        print("configuration: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
