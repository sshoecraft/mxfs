#!/usr/bin/env python3
"""harness_cnt_rewrite.py — move a harness's per-assertion remote counts across
the capture boundary.

The shape being retired (D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS):

    cnt() { rs 20 "$V" "dmesg | sed -n \"/$MARK/,\\$p\" | grep -ac '$1'" | tr -dc '0-9'; }
    ck "no LOST" "$(cnt 'P-INACT-CERT-LOST')" 0

A failed ssh reads as a count of zero (or, after tr, as an empty string a
ckge treats as zero) and the assertion prints PASS.  The replacement is a
statement in the parent shell before the assertion, which acquires the
marked window into its own file, requires it to have run to its end and to
contain the mark, and counts locally into a variable (window_count_into,
tests/lib/rig.sh):

    window_count_into wc1 "$V" 20 "$MARK" 'P-INACT-CERT-LOST' "no LOST"
    ck "no LOST" "$wc1" 0

Usage:
    scripts/harness_cnt_rewrite.py --shape pat --node '"$V"' --mark '"$MARK"' FILE
        cnt takes ONE argument, the pattern; node and mark are fixed
        expressions given here.
    scripts/harness_cnt_rewrite.py --shape node-pat --mark '"$MARK"' FILE
        cnt takes TWO arguments: node and pattern; the mark is fixed.
    scripts/harness_cnt_rewrite.py --shape node-mark-pat FILE
        cnt takes THREE arguments: node, mark, pattern.
    --helper NAME     the helper's name (default cnt)
    --timeout N       the acquisition timeout (default 20)
    --write           rewrite FILE in place (default: print the rewritten
                      text to stdout and the count of rewrites to stderr)

Only assertion lines (ck/ckge/ckne...) whose helper substitution sits at the
top level of a "..." argument are rewritten; a substitution nested inside
another command (`$(( $(cnt x) + $(cnt y) ))`) is rewritten too, each into
its own variable.  Lines it cannot parse are left alone and listed.  The
helper's definition is not removed; delete it by hand once nothing calls it.
"""
import argparse
import os
import re
import sys

ASSERT_RE = re.compile(r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\)\s*)?(ck|ckge|ckle|ckne|ck_installed)\b')


def scan_call(text, start):
    """text[start:] begins just after '$(HELPER '.  Return (args, end) where
    args are the shell words up to the matching ')' and end is the index
    just past it, or None when the words cannot be parsed."""
    i = start
    args = []
    cur = ''
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "'" and depth == 0:
            j = text.find("'", i + 1)
            if j < 0:
                return None
            cur += text[i:j + 1]
            i = j + 1
            continue
        if c == '"':
            # a double-quoted word, honouring \" and $( ) inside it
            j = i + 1
            d = 0
            while j < n:
                if text[j] == '\\':
                    j += 2
                    continue
                if text[j] == '$' and j + 1 < n and text[j + 1] == '(':
                    d += 1
                    j += 2
                    continue
                if text[j] == ')' and d > 0:
                    d -= 1
                    j += 1
                    continue
                if text[j] == '"' and d == 0:
                    break
                j += 1
            if j >= n:
                return None
            cur += text[i:j + 1]
            i = j + 1
            continue
        if text.startswith('$((', i):
            # arithmetic: copy through its matching '))'
            j = i + 3
            d = 2
            while j < n and d > 0:
                if text[j] == '(':
                    d += 1
                elif text[j] == ')':
                    d -= 1
                j += 1
            cur += text[i:j]
            i = j
            continue
        if c == '$' and i + 1 < n and text[i + 1] == '(':
            depth += 1
            cur += '$('
            i += 2
            continue
        if c == ')':
            if depth > 0:
                depth -= 1
                cur += c
                i += 1
                continue
            if cur:
                args.append(cur)
            return args, i + 1
        if c.isspace() and depth == 0:
            if cur:
                args.append(cur)
                cur = ''
            i += 1
            continue
        cur += c
        i += 1
    return None


def rewrite(lines, helper, shape, node, mark, timeout):
    out = []
    seq = 0
    skipped = []
    call_re = re.compile(r'\$\(\s*' + re.escape(helper) + r'\s+')
    assign_re = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)=\$\(\s*' + re.escape(helper) + r'\s+')
    for ln, line in enumerate(lines, 1):
        if not ASSERT_RE.match(line) and assign_re.search(line):
            # `inc=$(cnt "$A" "$MK" 'X'); unp=$(cnt ...)` -> one
            # window_count_into statement per assignment, into that variable
            new = ''
            pos = 0
            ok = True
            while True:
                m = assign_re.search(line, pos)
                if not m:
                    new += line[pos:]
                    break
                r = scan_call(line, m.end())
                if r is None:
                    ok = False
                    break
                args, end = r
                if shape == 'pat' and len(args) == 1:
                    n_expr, m_expr, p_expr = node, mark, args[0]
                elif shape == 'node-pat' and len(args) == 2:
                    n_expr, m_expr, p_expr = args[0], mark, args[1]
                elif shape == 'node-mark-pat' and len(args) == 3:
                    n_expr, m_expr, p_expr = args
                else:
                    ok = False
                    break
                seq += 1
                var = m.group(1)
                new += line[pos:m.start()] + 'window_count_into %s %s %d %s %s "%s"' % (var, n_expr, timeout, m_expr, p_expr, var)
                pos = end
            if ok:
                out.append(new)
            else:
                skipped.append((ln, line.strip()[:120]))
                out.append(line)
            continue
        if not ASSERT_RE.match(line) or not call_re.search(line):
            out.append(line)
            continue
        indent = re.match(r'\s*', line).group(0)
        label_m = re.search(r'\b(?:ck|ckge|ckle|ckne|ck_installed)\s+"((?:[^"\\]|\\.)*)"', line)
        label = label_m.group(1) if label_m else 'line %d' % ln
        label = re.sub(r'[^A-Za-z0-9 _.,:=()/<>-]', ' ', label)[:70].strip()
        pre = []
        new = ''
        pos = 0
        ok = True
        while True:
            m = call_re.search(line, pos)
            if not m:
                new += line[pos:]
                break
            r = scan_call(line, m.end())
            if r is None:
                ok = False
                break
            args, end = r
            if shape == 'pat' and len(args) == 1:
                n_expr, m_expr, p_expr = node, mark, args[0]
            elif shape == 'node-pat' and len(args) == 2:
                n_expr, m_expr, p_expr = args[0], mark, args[1]
            elif shape == 'node-mark-pat' and len(args) == 3:
                n_expr, m_expr, p_expr = args
            else:
                ok = False
                break
            seq += 1
            var = 'wc%d' % seq
            pre.append('%swindow_count_into %s %s %d %s %s "%s"' % (indent, var, n_expr, timeout, m_expr, p_expr, label))
            new += line[pos:m.start()] + '$' + var
            pos = end
        if not ok:
            skipped.append((ln, line.strip()[:120]))
            out.append(line)
            continue
        out.extend(pre)
        out.append(new)
    return out, seq, skipped


def rewrite_fixed(lines, helper, node, mark, timeout, pat):
    """`ck "no shutdown" "$(shut)" 0` where shut counts a fixed pattern ->
    window_count_into into a variable, then the assertion."""
    out = []
    seq = 0
    skipped = []
    call_re = re.compile(r'"\$\(\s*' + re.escape(helper) + r'\s*\)"')
    for ln, line in enumerate(lines, 1):
        if not ASSERT_RE.match(line) or not call_re.search(line):
            out.append(line)
            continue
        indent = re.match(r'\s*', line).group(0)
        new = line
        pre = []
        while call_re.search(new):
            seq += 1
            var = '%sv%d' % (helper, seq)
            pre.append('%swindow_count_into %s %s %d %s %s "%s"' % (indent, var, node, timeout, mark, pat, helper))
            new = call_re.sub('"$' + var + '"', new, count=1)
        out.extend(pre)
        out.append(new)
    return out, seq, skipped


def rewrite_value(lines, helper, node, timeout, cmd, regex, what):
    """`ck "knob=2" "$(knob 2)" 2` where knob sets and reads a scalar ->
    value_now_into into a variable (exactly one result line, the status
    observed), then the assertion on the variable."""
    out = []
    seq = 0
    skipped = []
    call_re = re.compile(r'"\$\(\s*' + re.escape(helper) + r'\s+')
    for ln, line in enumerate(lines, 1):
        if not ASSERT_RE.match(line) or not call_re.search(line):
            out.append(line)
            continue
        indent = re.match(r'\s*', line).group(0)
        pre = []
        new = ''
        pos = 0
        ok = True
        while True:
            m = call_re.search(line, pos)
            if not m:
                new += line[pos:]
                break
            r = scan_call(line, m.end())
            if r is None or len(r[0]) < 1 or not line.startswith('"', r[1]):
                ok = False
                break
            args, end = r
            rcmd = cmd
            for k, arg in enumerate(args, 1):
                if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] in '"\'':
                    arg = arg[1:-1]
                rcmd = rcmd.replace('{%d}' % k, arg)
            seq += 1
            var = '%sv%d' % (helper, seq)
            f = '"$OUT/%s_%d.txt"' % (helper, seq)
            pre.append('%svalue_now_into %s %s %d %s \'%s\' "%s" "%s"' % (indent, var, node, timeout, f, regex, what, rcmd))
            new += line[pos:m.start()] + '"$' + var + '"'
            pos = end + 1   # past the closing quote
        if not ok:
            skipped.append((ln, line.strip()[:120]))
            out.append(line)
            continue
        out.extend(pre)
        out.append(new)
    return out, seq, skipped


#
# --shape remote: a verdict fed by a bare remote substitution, either
# assigned first
#     ino=$(rs 30 "$A" "stat -c %i $F" | tail -1 | tr -d '\n')
#     brm=$(rs 30 "$B" "rm $D/f1; echo B_RM rc=\$?" | tail -1)
#     nsv=$(timeout 15 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | filt | tr -dc 'A-F0-9')
# or straight in the assertion
#     ck "B mounted" "$(rs 20 "$B" "grep -c ' $MNT mxfs ' /proc/mounts")" 1
# Nothing observed the invocation's status or the output's shape: a failed
# ssh reads as an empty value (equal to an expected "" or, after tr, to 0),
# and a producer that printed the value and then failed reads as the value.
# The rewrite is one parent-shell statement per substitution:
#     value_now_into ino "$A" 30 "$OUT/rv_ino_1.txt" '^[0-9]+$' "ino on $A" "stat -c %i $F"
# with the SHAPE inferred from the remote command itself — the tag the
# command echoes as its result line (`echo B_RM rc=` -> '^B_RM rc='), or the
# well-known one-line tools (stat -c %i, srcversion, a knob read, grep -c,
# md5sum, date +%s).  A pipe that only strips the one validated line (tail
# -1, tr -d '\n', tr -dc of the shape's own alphabet) is dropped; any other
# pipe is re-applied to the validated line locally.  A canonical kernel-log
# window count (dmesg | sed -n /MARK/,$p | grep -ac PAT) becomes
# window_count_into.  A remote `grep -c` exits 1 on a legitimate zero, so
# `|| [ $? = 1 ]` is appended to state that expected status.  Anything whose
# shape cannot be inferred is left alone and listed: those are read and
# converted by hand.
#
#     scripts/harness_cnt_rewrite.py --shape remote [--write] FILE...

# a remote substitution's head: `$(rs T NODE CMD`, `$(rsx T NODE CMD`,
# `$(timeout T $SSH NODE CMD 2>/dev/null | filt`
REMOTE_HEAD_RE = re.compile(r'\$\(\s*(?:(rs|rsx)\s+|(timeout)\s+\S+\s+\$SSH\s+)')
STRIP_PIPES = [
    re.compile(r"^tail -(?:n ?)?1$"), re.compile(r"^head -(?:n ?)?1$"),
    re.compile(r"^tr -d '\\n'$"), re.compile(r"^tr -d '\\r\\n'$"), re.compile(r"^tr -d '\\r'$"),
]
TR_DC_RE = re.compile(r"^tr -dc '?([^']+)'?$")
# well-known one-line producers, matched against the command's LAST statement
KNOWN_SHAPES = [
    (re.compile(r'cat\s+/sys/module/mxfs/srcversion'), '^[0-9A-F]+$'),
    (re.compile(r'cat\s+/proc/sys/kernel/tainted'), '^[0-9]+$'),
    (re.compile(r'cat\s+(?:\$\{?(?:P|PARAMS|PARAM|KP)\}?/|/sys/module/mxfs/parameters/)\S+$'), '^-?[0-9]+$'),
    (re.compile(r'cat\s+\$PARAM$'), '^-?[0-9]+$'),
    (re.compile(r'stat\s+-c\s+[\'"]?%[isb][\'"]?\s'), '^[0-9]+$'),
    (re.compile(r"stat\s+-c\s+'%a_%s'\s"), '^[0-9]+_[0-9]+$'),
    (re.compile(r'date\s+\+%s'), '^[0-9]+$'),
    (re.compile(r'wc\s+-[lc]\b'), '^[0-9]+$'),
    (re.compile(r'md5sum\b.*\|\s*cut\s+-d.\s.\s+-f1$'), '^[0-9a-f]{32}$'),
    (re.compile(r'md5sum\b.*\|\s*(?:cut|awk)\b'), '^[0-9a-f]{32}$'),
    (re.compile(r'md5sum\b'), '^[0-9a-f]{32} '),
]
GREP_COUNT_RE = re.compile(r'grep\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*c[a-zA-Z]*\b')
WINDOW_RE = re.compile(r'^dmesg\s*\|\s*sed -n\s+\\?["\']?/(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/,\\*\$p\\?["\']?\s*\|\s*grep\s+-a?c\s+\'([^\']*)\'\s*(?:\|\|\s*true|;\s*true)?$')
ECHO_RE = re.compile(r'(?:^|[;&|]\s*)echo\s+(?:-n\s+)?[\'"]?([A-Za-z][A-Za-z0-9_-]*(?:=|:)?)')


def split_statements(cmd):
    """Top-level statements of a shell command string, split on ; && || |
    outside quotes and $( ).  Approximate (this is a rewriter that lists
    what it skipped, not a shell parser)."""
    out = []
    cur = ''
    i = 0
    depth = 0
    q = None
    n = len(cmd)
    while i < n:
        c = cmd[i]
        if q:
            cur += c
            if c == '\\' and i + 1 < n:
                cur += cmd[i + 1]
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in '\'"':
            q = c
            cur += c
            i += 1
            continue
        if c == '\\' and i + 1 < n:
            cur += cmd[i:i + 2]
            i += 2
            continue
        if cmd.startswith('$(', i) or c == '(':
            depth += 1
            cur += cmd[i:i + 2] if cmd.startswith('$(', i) else c
            i += 2 if cmd.startswith('$(', i) else 1
            continue
        if c == ')' and depth > 0:
            depth -= 1
            cur += c
            i += 1
            continue
        if depth == 0 and (c == ';' or cmd.startswith('&&', i) or cmd.startswith('||', i)):
            out.append(cur.strip())
            cur = ''
            i += 2 if c != ';' else 1
            continue
        cur += c
        i += 1
    if cur.strip():
        out.append(cur.strip())
    return out


TAG_RE = re.compile(r'echo\s+(?:-n\s+)?[\'"]?([A-Za-z0-9][A-Za-z0-9_.-]*(?:=|:)?)(.*)$')
WINDOW_HEAD_RE = re.compile(r'^dmesg\s*\|\s*sed -n\s+\\?["\']?/(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/,\\*\$p\\?["\']?\s*(?:\|\s*(.*))?$')
RING_HEAD_RE = re.compile(r'^dmesg\s*\|\s*(.*)$')


def unremote(s, q):
    """A pipeline written inside a remote command string, moved to the parent
    shell: the escapes the remote quoting needed are undone."""
    if q == '"':
        return s.replace('\\$', '$').replace('\\"', '"').replace('\\\\', '\\')
    return s


def infer_shape(cmd_word, pipes):
    """What the remote command's result line looks like.  Returns
    (kind, shape, cmd_word, extra):
      kind 'value'  -> one result line matching <shape>
      kind 'window' -> a kernel-log window from mark <extra[0]>, then the
                       local pipeline <extra[1]> extracts from it
      kind 'ring'   -> the whole kernel ring, then <extra[1]> extracts
      kind None     -> not inferable; <shape> holds why."""
    if len(cmd_word) < 2 or cmd_word[0] not in '"\'' or cmd_word[-1] != cmd_word[0]:
        return None, 'command is not one quoted word', cmd_word, None
    q = cmd_word[0]
    inner = cmd_word[1:-1]
    wm = WINDOW_HEAD_RE.match(inner)
    if wm:
        return 'window', None, cmd_word, (wm.group(1), unremote(wm.group(2) or '', q))
    rm = RING_HEAD_RE.match(inner)
    if rm and 'sed -n' not in inner:
        return 'ring', None, cmd_word, (None, unremote(rm.group(1), q))
    stmts = split_statements(inner)
    if not stmts:
        return None, 'empty command', cmd_word, None
    stmts = [re.sub(r'^(?:then|else|do)\s+', '', s) for s in stmts]
    body = [s for s in stmts if s not in ('fi', 'done', 'true') and not re.match(r'exit \d+$', s)]
    if not body:
        return None, 'empty command', cmd_word, None
    last = body[-1]
    # the tag the command echoes as its result line; an echo into a
    # redirect is a write, not output
    tags = []
    for s in body:
        m = TAG_RE.match(s)
        if m and not re.match(r'\s*>', m.group(2)):
            tags.append((m.group(1), m.group(2).strip()))
    uniq = []
    for t, rest in tags:
        if t not in uniq:
            uniq.append(t)

    def anchored(tok, rest):
        if tok.endswith('=') or tok.endswith(':'):
            return '^' + re.escape(tok)
        return '^' + re.escape(tok) + (' ' if rest else '$')
    lm = TAG_RE.match(last)
    if lm and not re.match(r'\s*>', lm.group(2)):
        if len(uniq) > 1 and re.search(r'\|\|\s*echo', inner):
            if all(not r for t, r in tags):
                return 'value', '^(%s)$' % '|'.join(re.escape(t) for t in uniq), cmd_word, None
            return 'value', '^(%s)' % '|'.join(re.escape(t) for t in uniq), cmd_word, None
        return 'value', anchored(lm.group(1), lm.group(2).strip()), cmd_word, None
    for rx, shape in KNOWN_SHAPES:
        if rx.search(last):
            fixed = cmd_word
            if GREP_COUNT_RE.search(last) and shape == '^[0-9]+$':
                # a remote grep -c exits 1 on a legitimate zero: the caller
                # states that expected status
                fix = ' || [ \\$? = 1 ]' if q == '"' else ' || [ $? = 1 ]'
                fixed = cmd_word[:-1] + fix + q
            return 'value', shape, fixed, None
    if GREP_COUNT_RE.search(last):
        fix = ' || [ \\$? = 1 ]' if q == '"' else ' || [ $? = 1 ]'
        return 'value', '^[0-9]+$', cmd_word[:-1] + fix + q, None
    # the local pipe names the result line: `| sed -n 's/^sb_uuid=//p'`
    for p in pipes:
        sm = re.match(r"^sed -n 's/\^([A-Za-z0-9_.-]+=)//p'$", p.strip())
        if sm:
            return 'value', '^' + re.escape(sm.group(1)), cmd_word, None
    # the command IS the workload (a read of the file under test, a digest,
    # an xattr, a tool whose output the harness parses): its content is the
    # finding, so no shape is imposed on it.  The command reports its own
    # status on a line of its own (printf: a read with no final newline,
    # `head -c 4`, would otherwise glue the record to its last line) and the
    # ssh's status is what ABORTs.  The harness's own pipe then runs over
    # the capture minus that record.
    if re.match(r'(?:\$\(|cat |head |md5sum |getfattr |stat |python3 |\$MM |\$DMA |sg_persist |mountpoint |journalctl |lsmod )', last) or re.search(r'\bcat |\bmd5sum |\bstat -c', last):
        tail = ("; printf '\\nREAD_RC=%s\\n' \\$?" if q == '"' else "; printf '\\nREAD_RC=%s\\n' $?")
        return 'workload', '^READ_RC=[0-9]+$', cmd_word[:-1] + tail + q, None
    return None, 'no shape inferable from: ' + last[:80], cmd_word, None


def parse_remote(text, start):
    """text[start:] is at `$(`.  Return dict(t, node, cmd, pipes, end) for a
    remote substitution, or None."""
    m = REMOTE_HEAD_RE.match(text, start)
    if not m:
        return None
    r = scan_call(text, m.end())
    if r is None:
        return None
    words, end = r
    if m.group(2):   # timeout T $SSH NODE CMD 2>/dev/null | filt ...
        tm = re.match(r'\$\(\s*timeout\s+(\S+)\s+', text[start:])
        t = tm.group(1)
        if len(words) < 2:
            return None
        node, cmd = words[0], words[1]
        rest = words[2:]
        rest = [w for w in rest if w not in ('2>/dev/null', '</dev/null')]
        if rest[:2] == ['|', 'filt']:
            rest = rest[2:]
        elif rest:
            return None
    else:
        if len(words) < 3:
            return None
        t, node, cmd = words[0], words[1], words[2]
        rest = words[3:]
    pipes = []
    cur = []
    if rest and rest[0] != '|':
        return None
    for w in rest:
        if w == '|':
            if cur:
                pipes.append(' '.join(cur))
                cur = []
            continue
        cur.append(w)
    if cur:
        pipes.append(' '.join(cur))
    return dict(t=t, node=node, cmd=cmd, pipes=pipes, end=end)


def classify_pipes(pipes, shape):
    """Which of the substitution's local pipes matter once exactly one
    validated line is in hand: None -> a join/count pipe (the capture is
    multi-line: measure it, then run the pipe locally); [] -> all dropped;
    else the pipes to re-apply to the one line."""
    keep = []
    alphabet = set()
    if shape in ('^[0-9]+$', '^-?[0-9]+$'):
        alphabet = {'0-9'}
    elif shape == '^[0-9A-F]+$':
        alphabet = {'A-F0-9', '0-9A-F', 'A-Z0-9'}
    elif shape.startswith('^[0-9a-f]{32}'):
        alphabet = {'a-f0-9', '0-9a-f'}
    for p in pipes:
        p = p.strip()
        if any(rx.match(p) for rx in STRIP_PIPES):
            continue
        tm = TR_DC_RE.match(p)
        if tm and tm.group(1) in alphabet:
            continue
        if re.match(r"^tr\s+'\\n'\s+' '$", p) or GREP_COUNT_RE.search(p) or re.match(r'^wc\b', p) or re.match(r'^sort\b', p):
            return None
        if re.match(r'^grep\b', p) and not re.search(r'\s-[a-zA-Z]*o', p):
            # a filtering grep selects lines from a multi-line capture; the
            # one validated result line is not what it selects from
            return None
        keep.append(p)
    return keep


def evidence_var(text):
    for v in ('OUT', 'EV', 'EVD', 'TMP', 'tmpd', 'WORK'):
        if re.search(r'^\s*(?:export\s+)?' + v + r'=', text, re.M):
            return v
    return None


def rewrite_remote(lines, default_timeout, only_lines=None):
    text = '\n'.join(lines)
    ev = evidence_var(text)
    out = []
    seq = 0
    skipped = []
    if ev is None:
        return lines, 0, [(0, 'no evidence directory variable (OUT/EV/TMP) assigned in this file')]
    if 'lib/rig.sh' not in text:
        return lines, 0, [(0, 'file does not source tests/lib/rig.sh')]
    assign_re = re.compile(r'(?:\b(local)\s+)?\b([A-Za-z_][A-Za-z0-9_]*)=(?=\$\()')
    for ln, line in enumerate(lines, 1):
        if only_lines is not None and ln not in only_lines:
            out.append(line)
            continue
        if line.lstrip().startswith('#') or re.match(r'\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{', line):
            out.append(line)
            continue
        pos = 0
        new = ''
        pre = []
        changed = False
        ok = True
        indent = re.match(r'\s*', line).group(0)
        while True:
            m = REMOTE_HEAD_RE.search(line, pos)
            if not m:
                new += line[pos:]
                break
            am = None
            for cand in assign_re.finditer(line, pos, m.start() + 2):
                if cand.end() == m.start():
                    am = cand
            r = parse_remote(line, m.start())
            if r is None:
                skipped.append((ln, 'unparsed substitution: ' + line.strip()[:120]))
                ok = False
                break
            kind, shape, cmd, extra = infer_shape(r['cmd'], r['pipes'])
            if kind is None:
                skipped.append((ln, shape + ': ' + line.strip()[:120]))
                ok = False
                break
            seq += 1
            node_inner = r['node'].strip('"')
            var = am.group(2) if am else 'rv%d' % seq
            what = '"%s on %s"' % (var, node_inner)
            f = '"$%s/rv_%s_%d.txt"' % (ev, var, seq)
            local_pipes = ' | '.join(p.strip() for p in r['pipes'])
            if kind in ('window', 'ring'):
                mark, rest = extra
                if not rest:
                    skipped.append((ln, 'a whole window assigned to a variable: ' + line.strip()[:120]))
                    ok = False
                    break
                if mark:
                    stmt = 'window_into %s %s %s "%s"' % (f, r['node'], r['t'], mark)
                else:
                    stmt = 'window_into %s %s %s' % (f, r['node'], r['t'])
                chain = rest + ((' | ' + local_pipes) if local_pipes else '')
                stmt += '; %s=$(cat %s | %s)' % (var, f, chain)
            elif kind == 'workload':
                stmt = 'measure %s %s %s \'%s\' %s %s; %s=$(grep -av \'^READ_RC=\' %s%s)' % (
                    r['node'], r['t'], f, shape, what, cmd, var, f, (' | ' + local_pipes) if local_pipes else '')
            else:
                keep = classify_pipes(r['pipes'], shape)
                if keep is None:
                    # a multi-line capture: across the boundary as a whole,
                    # then the harness's own pipe over it locally
                    stmt = 'measure %s %s %s \'%s\' %s %s; %s=$(cat %s | %s)' % (r['node'], r['t'], f, shape, what, cmd, var, f, local_pipes)
                else:
                    stmt = 'value_now_into %s %s %s %s \'%s\' %s %s' % (var, r['node'], r['t'], f, shape, what, cmd)
                    if keep:
                        stmt += '; %s=$(printf \'%%s\\n\' "$%s" | %s)' % (var, var, ' | '.join(keep))
            if am:
                # the assignment becomes the statement, in place
                head = line[pos:am.start()]
                if am.group(1):
                    head += 'local %s; ' % var
                new += head + stmt
                pos = r['end']
            else:
                pre.append(indent + stmt)
                # `"$(...)"` -> `"$var"`; a bare `$(...)` -> `"$var"` too
                s = m.start()
                e = r['end']
                if s > 0 and line[s - 1] == '"' and e < len(line) and line[e] == '"':
                    s -= 1
                    e += 1
                new += line[pos:s] + '"$%s"' % var
                pos = e
            changed = True
        if not ok or not changed:
            out.append(line)
            continue
        out.extend(pre)
        out.append(new)
    return out, seq, skipped


def rewrite_waitfor(lines, helper, mark):
    """--shape waitfor: `t=$(waitfor "$W" "P-X slot=$s" 60)` -> the
    parent-shell `wait_for_into t "$W" 60 "$MARK" "P-X slot=$s"`
    (tests/lib/rig.sh), whose timeout is only ever reported from a window
    that crossed the boundary."""
    out = []
    seq = 0
    skipped = []
    call_re = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)=\$\(\s*' + re.escape(helper) + r'\s+')
    for ln, line in enumerate(lines, 1):
        if re.match(r'\s*' + re.escape(helper) + r'\s*\(\)', line):
            out.append(line)
            continue
        new = ''
        pos = 0
        ok = True
        changed = False
        while True:
            m = call_re.search(line, pos)
            if not m:
                new += line[pos:]
                break
            r = scan_call(line, m.end())
            if r is None or len(r[0]) != 3:
                ok = False
                break
            (node, pat, bound), end = r
            seq += 1
            new += line[pos:m.start()] + 'wait_for_into %s %s %s %s %s' % (m.group(1), node, bound, mark, pat)
            pos = end
            changed = True
        if ok and changed:
            out.append(new)
        else:
            if not ok:
                skipped.append((ln, line.strip()[:120]))
            out.append(line)
    return out, seq, skipped


DEV_COMMENT = [
    '# the device under test by identity, not by path: the LUN this rig declares',
    '# (data/rigs.json), verified by its WWID on the node, and the node\'s live mxfs',
    '# mount when it has one; MXFS_DEV names a candidate that must be that LUN.',
    '# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults',
]
RIG_PATH = r'(?:/dev/mapper/mpatha|/dev/disk/by-path/ip-192[^\s"\'}]*|/dev/sd[a-z])'
DEV_DEFAULT_RE = re.compile(r'^(\s*)(export\s+)?(DEV|LUN|MXFS_DEV|MPDEV|VG_DEV|MXFS_DEV_MOUNT)=(["\']?)\$\{(MXFS_DEV|MXFS_DEV_MOUNT|DEV|[0-9])(?::-|:=)' + RIG_PATH + r'\}\4\s*(#.*)?$')
DEV_HARD_RE = re.compile(r'^(\s*)(export\s+)?(DEV|LUN|MXFS_DEV|MPDEV)=(["\']?)' + RIG_PATH + r'\4\s*(;.*|#.*)?$')
DEV_IFZ_RE = re.compile(r'^(\s*)\[ -z "\$(DEV|LUN)" \] && \2=' + RIG_PATH + r'\s*$')
DEV_COLON_RE = re.compile(r'^(\s*): "\$\{MXFS_DEV:=' + RIG_PATH + r'\}"\s*$')
NODE_DEF_RE = re.compile(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=("?)(\$\{[0-9]+:-test[0-9]+\}|\$\{MXFS_NODE_LIST%%,\*\}|test[0-9]+)\2\s*(?:;|#|$)')
# the same definition anywhere in a line (`LABEL=${1:?label}; A=${2:-test1};
# B=${3:-test2}`), a quoted default behind any variable (`PROBE_HOST="${PROBE_HOST:-test1}"`)
NODE_INLINE_RE = re.compile(r'(?:^|;\s*)(?:export\s+)?([A-Z][A-Z0-9_]*)=("?)(\$\{[A-Z0-9_]+:-test[0-9]+\}|\$\{MXFS_NODE_LIST%%,\*\}|test[0-9]+)\2\s*(?:;|#|$)')
NODE_LIST_RE = re.compile(r'^\s*(?:export\s+)?MXFS_NODE_LIST=')


def node_expr_above(lines, ln):
    """The node expression the resolver is called with at line ln: the first
    node variable defined above the site, else the head of MXFS_NODE_LIST
    when the list is defined above it; None when neither is."""
    for prev in lines[:ln - 1]:
        if prev.lstrip().startswith('#'):
            continue
        nm = NODE_DEF_RE.match(prev) or NODE_INLINE_RE.search(prev)
        if nm:
            return '"$%s"' % nm.group(1)
    if any(NODE_LIST_RE.match(p) for p in lines[:ln - 1]):
        return '"${MXFS_NODE_LIST%%,*}"'
    return None


def node_def_below(lines, ln, var):
    """For a site whose node is only named after it: the line number of the
    first node definition below the site, when no line in between reads the
    device variable (so the resolver can be placed there instead); else None."""
    ref = re.compile(r'\$\{?' + re.escape(var) + r'\b')
    for i in range(ln, len(lines)):
        line = lines[i]
        if line.lstrip().startswith('#'):
            continue
        nm = NODE_DEF_RE.match(line) or NODE_INLINE_RE.search(line)
        if nm:
            return i + 1, '"$%s"' % nm.group(1)
        if ref.search(line):
            return None
    return None


CK_LOCAL_RE = re.compile(r'^ck\(\)\s+\{ if \[ "\$2" = "\$3" \]; then echo "  PASS \$1 \(\$2\)"; else echo "  FAIL \$1 got=\$2 want=\$3"; fails=\$\(\(fails\+1\)\); fi; \}\s*$')
CKGE_LOCAL_RE = re.compile(r'^ckge\(\)\s+\{ if \[ "\$\{2:-0\}" -ge "\$3" \] 2>/dev/null; then echo "  PASS \$1 \(\$2 >= \$3\)"; else echo "  FAIL \$1 got=\$\{2:-\?\} want>=\$3"; fails=\$\(\(fails\+1\)\); fi; \}\s*$')


def rewrite_ck(lines):
    """--shape ck: the standard local ck/ckge one-liners become the library's
    (tests/lib/rig.sh), which ABORT on an EMPTY got instead of printing a
    FAIL about MXFS; only in a harness that sources the library above them."""
    out = []
    seq = 0
    skipped = []
    lib_line = next((i for i, l in enumerate(lines, 1) if 'lib/rig.sh' in l and not l.lstrip().startswith('#')), None)
    for ln, line in enumerate(lines, 1):
        if CK_LOCAL_RE.match(line) or CKGE_LOCAL_RE.match(line):
            if not lib_line or lib_line > ln:
                skipped.append((ln, 'tests/lib/rig.sh is not sourced above this definition: ' + line.strip()[:60]))
                out.append(line)
                continue
            out.append('# %s: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS' % line.split('(')[0])
            seq += 1
            continue
        out.append(line)
    return out, seq, skipped


def rewrite_device(lines, node):
    """--shape device: the harness's device-selection line — a rig-specific
    literal as the hardcode, as the default behind MXFS_DEV or a positional,
    or as `[ -z "$DEV" ] && DEV=...` — becomes the resolver, as a statement
    at the same place.  `--node auto` takes the first node variable defined
    above the site (`A=${MXFS_NODE_LIST%%,*}`, `W=${2:-test1}`); otherwise
    the given expression.  The library must be sourced above the site and
    the node variable defined above it, or the site is listed and left."""
    out = []
    seq = 0
    skipped = []
    text = '\n'.join(lines)
    has_lib = 'lib/rig.sh' in text
    lib_line = next((i for i, l in enumerate(lines, 1) if 'lib/rig.sh' in l and not l.lstrip().startswith('#')), None)
    deferred = {}            # line number of a node definition -> the statement to place after it
    for ln, line in enumerate(lines, 1):
        if ln in deferred:
            out.append(line)
            out.extend(deferred.pop(ln))
            seq += 1
            continue
        m = DEV_DEFAULT_RE.match(line) or DEV_HARD_RE.match(line) or DEV_IFZ_RE.match(line) or DEV_COLON_RE.match(line)
        if not m:
            out.append(line)
            continue
        indent = m.group(1)
        place_after = None
        if node == 'auto':
            nexpr = node_expr_above(lines, ln)
            if not nexpr:
                var = m.group(3) if DEV_DEFAULT_RE.match(line) or DEV_HARD_RE.match(line) else (m.group(2) if DEV_IFZ_RE.match(line) else 'MXFS_DEV')
                below = node_def_below(lines, ln, var)
                if not below:
                    skipped.append((ln, 'no node variable defined above the site: ' + line.strip()[:100]))
                    out.append(line)
                    continue
                place_after, nexpr = below
        else:
            nexpr = node
            nvar = re.sub(r'[^A-Za-z0-9_]', '', nexpr)
            if not re.search(r'^\s*(?:export\s+)?' + re.escape(nvar) + r'=', '\n'.join(lines[:ln - 1]), re.M):
                skipped.append((ln, 'node %s is not defined above the site: %s' % (nexpr, line.strip()[:100])))
                out.append(line)
                continue
        pre = list(DEV_COMMENT)
        eff_ln = place_after or ln
        if not has_lib or (lib_line and lib_line > eff_ln):
            pre.append('. "$(dirname "$0")/lib/rig.sh"')
            has_lib = True
            lib_line = eff_ln
        if DEV_IFZ_RE.match(line):
            var = m.group(2)
            stmt = '[ -n "${%s:-}" ] || { mxfs_dev_resolve %s; %s=$MXFS_DEV_RESOLVED; }' % (var, nexpr, var)
        elif DEV_COLON_RE.match(line):
            stmt = 'mxfs_dev_resolve %s; MXFS_DEV=$MXFS_DEV_RESOLVED' % nexpr
        elif DEV_DEFAULT_RE.match(line):
            exp, var, src = m.group(2) or '', m.group(3), m.group(5)
            if src.isdigit():
                stmt = '%s=${%s:-}; [ -n "$%s" ] || { mxfs_dev_resolve %s; %s=$MXFS_DEV_RESOLVED; }' % (var, src, var, nexpr, var)
            elif src == 'MXFS_DEV' or var == 'MXFS_DEV':
                stmt = 'mxfs_dev_resolve %s; %s%s=$MXFS_DEV_RESOLVED' % (nexpr, exp, var)
            else:
                stmt = '[ -n "${%s:-}" ] && %s=$%s || { mxfs_dev_resolve %s; %s=$MXFS_DEV_RESOLVED; }' % (src, var, src, nexpr, var)
                if exp:
                    stmt += '; export %s' % var
            if m.group(6):
                stmt += '  ' + m.group(6)
        else:
            exp, var = m.group(2) or '', m.group(3)
            tail = m.group(5) or ''
            stmt = 'mxfs_dev_resolve %s; %s%s=$MXFS_DEV_RESOLVED' % (nexpr, exp, var)
            if tail.startswith(';'):
                stmt += tail
            elif tail:
                stmt += '  ' + tail
        if place_after:
            # the node is only named below the site and nothing between reads
            # the device variable: the selection moves to just after that
            # definition, and the site itself becomes the pointer to it
            out.append(indent + '# device selection: after the node is named below (mxfs_dev_resolve)')
            deferred[place_after] = [indent + p for p in pre] + [indent + stmt]
            continue
        out.extend(indent + p for p in pre)
        out.append(indent + stmt)
        seq += 1
    return out, seq, skipped


HEADER_COMMENT = [
    '# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):',
    '# every capture a verdict is taken from crosses the boundary in the parent',
    '# shell first; a failed acquisition is an ABORT, never a count of zero or an',
    '# empty value.',
    '. "$(dirname "$0")/lib/rig.sh"',
]
# the two helper definitions ~130 harnesses carry, in their few spellings
FILT_DEF_RE = re.compile(r"^filt\(\)\s*\{\s*grep -av '\^Unauthorized\\\|\^Warning:\\\|\^If you(\\\|\^\$)?'(\s*\|\s*tr -d '\\r')?;\s*\}\s*$")
RS_DEF_RE = re.compile(r"^rs\(\)\s*\{\s*timeout \"\$1\" \$SSH \"\$2\" \"\$3\" (?:</dev/null )?2>/dev/null \| (?:filt|grep -av '[^']*')(?: \| tr -d '\\r')?;\s*\}\s*$")


def rewrite_header(lines):
    """--shape header: replace a harness's own filt()/rs() definitions with
    the library source line (and the comment that says why) at the first
    one's place.  A helper of another shape is left in place and reported."""
    text = '\n'.join(lines)
    if 'lib/rig.sh' in text:
        return lines, 0, [(0, 'already sources tests/lib/rig.sh')]
    out = []
    placed = False
    removed = 0
    skipped = []
    for ln, line in enumerate(lines, 1):
        if FILT_DEF_RE.match(line) or RS_DEF_RE.match(line):
            removed += 1
            if not placed:
                out.extend(HEADER_COMMENT)
                placed = True
            continue
        if re.match(r'^\s*(filt|rs)\(\)\s*\{', line):
            skipped.append((ln, 'helper of another shape kept: ' + line.strip()[:120]))
        out.append(line)
    return out, removed, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--shape', choices=['pat', 'node-pat', 'node-mark-pat', 'fixed', 'value', 'remote', 'header', 'waitfor', 'device', 'ck'], required=True)
    ap.add_argument('--node', default='"$V"')
    ap.add_argument('--mark', default='"$MARK"')
    ap.add_argument('--helper', default='cnt')
    ap.add_argument('--timeout', type=int, default=20)
    ap.add_argument('--pat', help='fixed: the pattern the zero-argument helper counts')
    ap.add_argument('--cmd', help='value: the remote command, {1} standing for the helper argument')
    ap.add_argument('--re', dest='regex', default='^[0-9]+$', help='value: the one result line')
    ap.add_argument('--what', help='value: what the measurement is, for the ABORT text')
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--only-lint', action='store_true',
                    help='remote: rewrite only the lines scripts/harness_lint.py names as feeding a verdict (a polling loop is not a measurement)')
    ap.add_argument('files', nargs='+')
    a = ap.parse_args()
    for path in a.files:
        text = open(path).read()
        lines = text.split('\n')
        if a.shape == 'fixed':
            out, n, skipped = rewrite_fixed(lines, a.helper, a.node, a.mark, a.timeout, a.pat)
        elif a.shape == 'value':
            out, n, skipped = rewrite_value(lines, a.helper, a.node, a.timeout, a.cmd, a.regex, a.what)
        elif a.shape == 'header':
            out, n, skipped = rewrite_header(lines)
        elif a.shape == 'waitfor':
            out, n, skipped = rewrite_waitfor(lines, a.helper, a.mark)
        elif a.shape == 'device':
            out, n, skipped = rewrite_device(lines, a.node)
        elif a.shape == 'ck':
            out, n, skipped = rewrite_ck(lines)
        elif a.shape == 'remote':
            only = None
            if a.only_lint:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                import harness_lint
                res = harness_lint.lint_file(path)
                only = set(site for _, _, _, site in res[2]) if res else set()
            out, n, skipped = rewrite_remote(lines, a.timeout, only)
        else:
            out, n, skipped = rewrite(lines, a.helper, a.shape, a.node, a.mark, a.timeout)
        result = '\n'.join(out)
        if a.write:
            if result != text:
                open(path, 'w').write(result)
        elif len(a.files) == 1:
            sys.stdout.write(result)
        print('%s: %d substitution(s) rewritten, %d line(s) skipped' % (path, n, len(skipped)), file=sys.stderr)
        for ln, t in skipped:
            print('  skipped %d: %s' % (ln, t), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
