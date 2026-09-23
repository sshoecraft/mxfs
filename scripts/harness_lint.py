#!/usr/bin/env python3
"""harness_lint.py — where can a harness turn a failed capture into a verdict?

A harness helper of the shape `rs() { timeout N $SSH host cmd 2>/dev/null | filt; }`
discards the remote command's stderr, so a remote command that fails outright
leaves an EMPTY capture; a `grep -c` / `wc -l` over it then reads 0, and a
ck/ckge assertion turns that 0 into a statement about MXFS.  This lint lists
every assertion whose input is a count taken from a capture file that nothing
earlier in the same script proved to hold the shape the tool emits.

Guarded means: before the assertion line, the same capture path appears in a
`capture_require` / `require_shape` call, or in a `grep -q` whose failure
branch exits or aborts, or in an explicit `-s` / non-empty test that exits.
The check is textual and per file; it names candidates for a reader, it does
not adjudicate them.

A second class (design consult 2026-09-18: a fabricated FAIL is still a
verdict about MXFS taken from no measurement, and a producer can print the
expected value and then fail): an assertion whose input comes STRAIGHT from
a remote invocation — `ck "..." "$(rs 20 node cmd)" 0`, `$(cnt ...)` where
cnt runs ssh, `$(timeout N $SSH ...)` — or from a variable last assigned
from one.  Nothing observed the status or the shape.  The boundary for
these is window_count_into / value_now_into (tests/lib/rig.sh), which
assign in the parent and never appear inside `$(...)`.

Usage: scripts/harness_lint.py [--summary] [paths...]   (default: tests/*.sh scripts/*.sh)
Exit 0 always; the numbers are the output.
"""
import glob
import os
import re
import sys

ASSERT_RE = re.compile(r'\b(ck|ckge|ckle|assert_(?:equals|ge|le|zero|nonzero|count))\b')
# a count anywhere inside a command substitution: `$(cnt f x)`,
# `$(grep -ac x f)`, `$(grep -a 'desc ' f | grep -ac x)`, `$(... | wc -l)`
COUNT_RE = re.compile(r'\$\((?:[^()]|\([^()]*\))*?(?:\bcnt\b|grep\s+-[a-zA-Z]*c[a-zA-Z]*\b|wc\s+-l\b)')
PATH_RE = re.compile(r'"?\$\{?(OUT|TMP|tmpd|EV|EVD|LOG|WORK|D)\}?/([A-Za-z0-9_.${}-]+)"?')
GUARD_RE = re.compile(r'\b(capture_require|require_shape|cnt_require|grep\s+-q[a-zA-Z]*)\b')
EXIT_RE = re.compile(r'\b(exit\s+[0-9]|ABORT|INFRA)\b')
# `# capture-adjudicated: <why>` on the assertion line: a reader established
# that the count cannot be fed by a failed capture (e.g. the capture is the
# library's own failure record, under test) and wrote the reason down.  It is
# listed separately, never silently dropped.
ADJ_RE = re.compile(r'#\s*capture-adjudicated:\s*\S')


def capture_paths(text):
    return set(m.group(0).strip('"') for m in PATH_RE.finditer(text))


def guard_pattern(path):
    """A guard written inside a function names its capture with a positional
    tag (`$OUT/$2_join_journal.txt`); it guards every call site's file
    (`$OUT/1d_join_journal.txt`).  Turn the path into a regex where such a
    tag matches one word."""
    out = ''
    i = 0
    while i < len(path):
        m = re.match(r'\$\{?[0-9]\}?', path[i:])
        if m:
            # a call site's tag may itself hold a variable (`4${side}a`)
            out += r'[A-Za-z0-9_${}-]+'
            i += len(m.group(0))
        else:
            out += re.escape(path[i])
            i += 1
    return re.compile('^' + out + '$')


def is_guarded(path, guarded, loops=None):
    if path in guarded or any(g.match(path) for g in guarded if hasattr(g, 'match')):
        return True
    # a path written with a loop variable (`$OUT/dmesg_$n.txt` under
    # `for n in $A $B`) is guarded when every value's path is guarded by name
    if loops:
        for var, words in loops.items():
            if not re.search(r'\$\{?' + re.escape(var) + r'\}?', path):
                continue
            subst = [re.sub(r'\$\{?' + re.escape(var) + r'\}?', lambda m, w=w: w, path) for w in words]
            if subst and all(is_guarded(s, guarded) for s in subst):
                return True
    return False


LOOP_RE = re.compile(r'\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+(.+?)\s*;?\s*(?:do\b.*)?$')


def loop_words(text):
    """`"$H" "$W"` -> ['$H', '$W']; a `$(...)` or glob word list is not
    enumerable and yields nothing."""
    words = []
    for w in text.split():
        w = w.strip('"\'')
        if not w or '$(' in w or '*' in w or '{' in w and '}' in w and ',' in w:
            return []
        words.append(w)
    return words


def guard_functions(lines):
    """Names of functions whose body validates a positional argument with
    capture_require (`dump() { ...; capture_require "$1" ...; }`): a call
    `dump "$OUT/x.txt"` then guards that path."""
    names = set()
    cur = None
    # capture_require "$1" ...  /  measure node t "$1" ...  /  value_now_into var node t "$1" ...
    validates = re.compile(r'\b(?:(?:capture_require|capture_require_bg|prep_require)\s+"?\$\{?[0-9]\}?'
                           r'|measure\s+\S+\s+\S+\s+"?\$\{?[0-9]\}?'
                           r'|value_now_into\s+\S+\s+\S+\s+\S+\s+"?\$\{?[0-9]\}?)')
    for line in lines:
        m = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{(.*)$', line)
        if m:
            body = m.group(2)
            if body.rstrip().endswith('}'):
                # a one-line function: its whole body is on this line
                if validates.search(body):
                    names.add(m.group(1))
                cur = None
            else:
                cur = m.group(1)
                if validates.search(body):
                    names.add(cur)
            continue
        if cur and re.match(r'\}', line):
            cur = None
            continue
        if cur and validates.search(line):
            names.add(cur)
    return names


def function_bodies(lines):
    """name -> the text of each shell function (one-line or block form)."""
    bodies = {}
    cur = None
    for line in lines:
        m = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{(.*)$', line)
        if m:
            body = m.group(2)
            if body.rstrip().endswith('}'):
                bodies[m.group(1)] = body
                cur = None
            else:
                cur = m.group(1)
                bodies[cur] = body
            continue
        if cur and re.match(r'\}', line):
            cur = None
            continue
        if cur:
            bodies[cur] += '\n' + line
    return bodies


REMOTE_BASE = {'rs', 'rsx', 'sshq'}


def remote_helpers(lines):
    """The functions of this file that reach the rig: the library's, plus any
    whose body runs $SSH or calls one that does (fixed point)."""
    bodies = function_bodies(lines)
    names = set(REMOTE_BASE)
    changed = True
    while changed:
        changed = False
        for name, body in bodies.items():
            if name in names:
                continue
            if '$SSH' in body or re.search(r'\b(' + '|'.join(sorted(names)) + r')\s', body):
                names.add(name)
                changed = True
    return names


ASSIGN_HEAD_RE = re.compile(r'(?:^|;|&&|\|\|)\s*(?:local\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)=')


def assignments(line):
    """Every `VAR=value` on the line in order, including those after a `;`
    (`stmt; r=$(cat file)` re-assigns r), each value running to the next
    top-level `;`."""
    out = []
    if ASSERT_RE.search(line) and not ASSIGN_HEAD_RE.match(line):
        return out
    for m in ASSIGN_HEAD_RE.finditer(line):
        i = m.end()
        depth = 0
        q = None
        while i < len(line):
            c = line[i]
            if q:
                if c == '\\':
                    i += 2
                    continue
                if c == q:
                    q = None
            elif c in '\'"':
                q = c
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            elif c == ';' and depth <= 0:
                break
            i += 1
        out.append((m.group(1), line[m.end():i]))
    return out


# Third class (ledger D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE-AND-REPORT-IT-AS-MXFS):
# the block device a harness measures or prepares is chosen by a literal path
# that exists only on one rig (`/dev/mapper/mpatha` is the CAW multipath rig,
# the QNAP by-path is the condition-3 rig), as a hardcode, as the default
# behind MXFS_DEV or a positional, or inline in a remote command.  On the
# 2-node TCP rig the path is absent (the probe parses an error and reports it)
# or, worse, another valid device.  The conversion is mxfs_dev_resolve
# (tests/lib/rig.sh); a site a reader established is the rig-configuration
# subject itself (multipath setup, a path-latency probe) carries
# `# device-adjudicated: <why>` and is listed separately.
# /dev/sdX is the TCP rig's own spelling and the same class from the other
# rigs' side (a path member of the CAW multipath map there); run.sh and the
# node-side setup scripts resolve the transport default and are not harnesses.
DEVICE_RE = re.compile(r'/dev/(?:mapper/mpatha|disk/by-path/ip-192|sd[a-z]\b)')
DEV_ADJ_RE = re.compile(r'#\s*device-adjudicated:\s*\S')


def lint_devices(lines):
    """A `# device-adjudicated: <why>` in a script's header (its first 12
    lines) adjudicates every site in it: the script's whole subject is a
    rig's storage configuration (a target's backstore experiment, the
    multipath wiring check).  On a site line it adjudicates that line."""
    hits = []
    adj = []
    header = next((l.strip()[:160] for l in lines[:12] if l.lstrip().startswith('#') and DEV_ADJ_RE.search(l)), None)
    for n, line in enumerate(lines, 1):
        s = line.lstrip()
        if s.startswith('#') or not DEVICE_RE.search(line):
            continue
        if header:
            adj.append((n, 'file: ' + header))
        elif DEV_ADJ_RE.search(line):
            adj.append((n, line.strip()[:160]))
        else:
            hits.append((n, line.strip()[:160]))
    return hits, adj


def lint_file(path):
    try:
        lines = open(path, errors='replace').read().split('\n')
    except OSError:
        return None
    guarded = set()          # capture path expressions proven to hold a shape
    findings = []
    adjudicated = []
    remote = []              # class 2: a verdict fed straight from a remote invocation
    rnames = remote_helpers(lines)
    remote_sub = re.compile(r'\$\(\s*(?:timeout\s+\S+\s+)?(?:\$SSH\b|(?:' + '|'.join(sorted(map(re.escape, rnames))) + r')\b)')
    tainted = {}             # variable -> line of its last assignment from a remote substitution
    assign_re = re.compile(r'^\s*(?:local\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
    gfuncs = guard_functions(lines)
    gfunc_re = re.compile(r'\b(' + '|'.join(sorted(gfuncs)) + r')\s+"?\$') if gfuncs else None
    loops = {}               # loop variable -> the words it ranges over
    for n, line in enumerate(lines, 1):
        lm = LOOP_RE.match(line)
        if lm:
            ws = loop_words(lm.group(2))
            if ws:
                loops[lm.group(1)] = ws
            else:
                loops.pop(lm.group(1), None)
        # capture_require / require_shape / cnt_require exit on their own;
        # a bare grep -q counts only when its failure branch exits/aborts
        if gfunc_re and gfunc_re.search(line) and not re.match(r'\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\)', line):
            for p in capture_paths(line):
                guarded.add(p)
                if re.search(r'\$\{?[0-9]\}?', p):
                    guarded.add(guard_pattern(p))
        # `measure node t file shape what cmd` (tests/lib/rig.sh) is rsx +
        # capture_require on <file> in one statement
        if re.search(r'\b(capture_require|capture_require_bg|require_shape|cnt_require|measure|prep_require|value_now_into|window_into)\b', line):
            for p in capture_paths(line):
                guarded.add(p)
                if re.search(r'\$\{?[0-9]\}?', p):
                    guarded.add(guard_pattern(p))
        elif GUARD_RE.search(line) and (EXIT_RE.search(line) or
                                        (n < len(lines) and EXIT_RE.search(lines[n]))):
            guarded |= capture_paths(line)
        # a later local rs() definition shadows the library's: report it
        if re.match(r'\s*rs\(\)\s*\{', line) and any('lib/rig.sh' in l for l in lines[:n-1]):
            findings.append((n, '(helper)', 'local rs() shadows tests/lib/rig.sh after it was sourced'))
        # taint: a variable assigned from a remote substitution carries an
        # unvalidated measurement until it is assigned from something else
        for var, value in assignments(line):
            if remote_sub.search(value):
                tainted[var] = n
            else:
                tainted.pop(var, None)
        if ASSERT_RE.search(line):
            hit = False
            if COUNT_RE.search(line):
                for p in capture_paths(line):
                    if not is_guarded(p, guarded, loops):
                        hit = True
                        if ADJ_RE.search(line):
                            adjudicated.append((n, p, line.strip()[:160]))
                        else:
                            findings.append((n, p, line.strip()[:160]))
            if not hit:
                why = None
                site = n          # the line a rewrite must move across the boundary
                if remote_sub.search(line):
                    why = 'a remote substitution'
                else:
                    for v in sorted(tainted):
                        if re.search(r'\$\{?' + re.escape(v) + r'\b', line):
                            why = 'variable $' + v + ' assigned from a remote substitution'
                            site = tainted[v]
                            break
                if why:
                    if ADJ_RE.search(line):
                        adjudicated.append((n, why, line.strip()[:160]))
                    else:
                        remote.append((n, why, line.strip()[:160], site))
    devices, dev_adj = lint_devices(lines)
    return findings, adjudicated, remote, devices, dev_adj


def main(argv):
    summary = '--summary' in argv
    paths = [a for a in argv if not a.startswith('--')]
    if not paths:
        paths = sorted(glob.glob('tests/*.sh') + glob.glob('scripts/*.sh'))
    total = 0
    files = 0
    adj_total = 0
    rtotal = 0
    rfiles = 0
    dtotal = 0
    dfiles = 0
    dadj_total = 0
    for p in paths:
        r = lint_file(p)
        if not r:
            continue
        f, adj, rem, dev, dev_adj = r
        adj_total += len(adj)
        dadj_total += len(dev_adj)
        if dev:
            dfiles += 1
            dtotal += len(dev)
        if not summary:
            for n, cap, text in adj:
                print(f'{p}:{n}: adjudicated by reading, {cap}: {text}')
            for n, text in dev_adj:
                print(f'{p}:{n}: device adjudicated by reading: {text}')
            for n, text in dev:
                print(f'{p}:{n}: device chosen by a rig-specific path: {text}')
        if rem:
            rfiles += 1
            rtotal += len(rem)
            if not summary:
                for n, why, text, site in rem:
                    at = f' (assigned at {site})' if site != n else ''
                    print(f'{p}:{n}: verdict fed by {why}{at}: {text}')
        if not f:
            continue
        files += 1
        total += len(f)
        if not summary:
            for n, cap, text in f:
                print(f'{p}:{n}: unguarded count from {cap}: {text}')
    print(f'harness_lint: {total} assertion(s) fed by a count over an unguarded capture, in {files} file(s); '
          f'{rtotal} verdict(s) fed by an unvalidated remote substitution, in {rfiles} file(s); '
          f'over {len(paths)} script(s); {adj_total} adjudicated by reading; '
          f'{dtotal} device selection(s) by a rig-specific path in {dfiles} file(s), {dadj_total} device-adjudicated')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
